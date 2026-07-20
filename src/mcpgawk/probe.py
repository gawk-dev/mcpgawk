"""OBSERVE — connect to an MCP server via the official `mcp` SDK and snapshot it.

We use the maintained protocol client (`ClientSession` + the stdio/streamable-http/sse
transports). The SDK negotiates the protocol version and tracks the spec by definition, so
mcpgawk rides protocol evolution instead of owning a stale fork. We are a *one-shot client*,
not a man-in-the-middle proxy — that keeps us off the runtime-enforcement lane.

Egress note: the only network here is the SDK talking to the server being scanned. Nothing
about the captured inventory is sent anywhere else.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info < (3, 11):
    # BaseExceptionGroup is a 3.11+ builtin; on 3.10 (our floor) use the `exceptiongroup` backport,
    # which is already present transitively via anyio (an mcp SDK dependency). Without this the
    # ExceptionGroup unwrapper below would NameError on 3.10.
    from exceptiongroup import BaseExceptionGroup

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client

from .servercard import fetch_card
from .transport import Candidate as _Candidate


@dataclass
class ServerSnapshot:
    """Everything we captured from one server. Raw wire-shape tool dicts, so measurement
    sees exactly what a model's context would see."""
    name: str
    transport: str
    protocol_version: str | None
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)
    server_card: dict[str, Any] | None = None   # self-declared .well-known card (http/sse only)
    error: str | None = None
    # Typed failure classification (closed set) — for messaging and so tests/canaries can assert on
    # the KIND of failure, not scrape a string. "unreachable" (connect/timeout/protocol never
    # completed), "misconfigured" (the config entry can't even be dispatched), "not-an-mcp-endpoint"
    # (a live URL that isn't MCP — e.g. an HTML docs page), "auth-required" (a real MCP endpoint that
    # refused us 401/403 — the user needs `--login`/`--header`, NOT a different URL),
    # "command-missing" (a stdio entry whose program is not on disk — see probe(), and note this is
    # a DIFFERENT user action from "unreachable": the entry is stale, not the server down).
    # None when there is no error.
    error_kind: str | None = None
    # Set by the permuting prober when the URL/transport that actually answered is NOT the one that
    # was declared (see transport.py). None means "the declaration was right" — the common case.
    resolved_url: str | None = None
    declared_transport: str | None = None

    @property
    def transport_corrected(self) -> bool:
        """True when we only got a measurement by ignoring the declared transport/URL. The report
        must SAY so: silently succeeding at a different endpoint would leave the user with a config
        that still doesn't work everywhere else."""
        return self.resolved_url is not None

    @property
    def is_failure(self) -> bool:
        """True whenever the probe did not yield a real measurement. This is the load-bearing
        CLEAN-safety property: a failure must NEVER render as CLEAN — a security tool reporting
        'nothing write- or exfil-capable' on a server it never actually scanned is its cardinal
        sin. It is the TYPED replacement for label.py's old substring match on caveat text, which
        silently false-cleaned the instant the caveat wording drifted."""
        return self.error is not None


def _dump(items: list[Any]) -> list[dict[str, Any]]:
    """Pydantic model -> wire-shape dict (by_alias gives `inputSchema`, `readOnlyHint`, ...)."""
    out = []
    for it in items:
        if hasattr(it, "model_dump"):
            out.append(it.model_dump(by_alias=True, exclude_none=True, mode="json"))
        elif isinstance(it, dict):
            out.append(it)
    return out


async def _snapshot(session: ClientSession, name: str, transport: str) -> ServerSnapshot:
    init = await session.initialize()
    snap = ServerSnapshot(
        name=name,
        transport=transport,
        protocol_version=getattr(init, "protocolVersion", None),
        server_info=(init.serverInfo.model_dump(mode="json") if getattr(init, "serverInfo", None) else {}),
    )
    # tools/list is the load-bearing surface; prompts/resources are optional per server.
    snap.tools = _dump((await session.list_tools()).tools)
    for attr, method in (("prompts", "list_prompts"), ("resources", "list_resources")):
        try:
            res = await getattr(session, method)()
            setattr(snap, attr, _dump(getattr(res, attr)))
        except Exception:
            pass  # server doesn't advertise that capability — not an error for us
    return snap


# Per-server wall-clock bound. A hung / slow-loris server must degrade to ONE error row, never
# block the whole scan.
#
# TWO budgets by transport, deliberately: a cold stdio server (`npx`/`uvx` first run) legitimately
# needs ~90s to download+launch before it can even answer `initialize`. A REMOTE server has no such
# excuse — if an HTTP/SSE endpoint hasn't completed the MCP handshake in 20s it is unreachable for
# any practical purpose, and 90s there is exactly the "scan hangs a minute and a half on a non-MCP
# URL" bug (an HTML docs page accepts the socket and simply never speaks MCP). One timeout for both
# transports cannot be right; splitting them is the fix, not a shorter blanket value.
DEFAULT_TIMEOUT = 90.0   # stdio: room for a cold npx/uvx install
HTTP_TIMEOUT = 20.0      # http/sse: a live MCP endpoint answers well within this
# Transport-permutation budgets (see probe_url). A fallback ladder must never be able to cost more
# than a single generous probe would have: the DECLARED endpoint keeps the full HTTP_TIMEOUT, each
# speculative candidate gets a short one, and the whole ladder is capped. Worst case is bounded and
# small — otherwise "try harder" quietly becomes the hang F2 was written to kill.
FALLBACK_TIMEOUT = 6.0   # per speculative candidate (a wrong path refuses fast)
PERMUTE_BUDGET = 45.0    # hard cap on the whole ladder, from the first attempt
MIN_ATTEMPT = 2.0        # below this, don't start another attempt — report it as not attempted


def _unwrap(exc: BaseException) -> BaseException:
    """Dig the real cause out of an ExceptionGroup / TaskGroup wrapper. The mcp SDK runs its
    transport under a TaskGroup, so a plain connection refusal can surface as the useless
    'unhandled errors in a TaskGroup (1 sub-exception)'. Recurse to the first concrete leaf so the
    error row names what actually went wrong. (Ported from the hosted scan endpoint's unwrapper.)"""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


async def _bounded(coro_factory, name: str, transport: str, timeout: float) -> ServerSnapshot:
    try:
        return await asyncio.wait_for(coro_factory(), timeout)
    except (asyncio.TimeoutError, TimeoutError) as e:
        return ServerSnapshot(name=name, transport=transport, protocol_version=None,
                              error=f"no MCP response within {timeout:.0f}s: {type(e).__name__}",
                              error_kind="unreachable")
    except Exception as e:  # noqa: BLE001 — surface, never crash the scan
        real = _unwrap(e)
        return ServerSnapshot(name=name, transport=transport, protocol_version=None,
                              error=f"{type(real).__name__}: {real}", error_kind=_kind_of(real))


def _kind_of(exc: BaseException) -> str:
    """Classify a probe failure by EXCEPTION TYPE, never by message text (F2's lesson). An
    HTTPStatusError means the host answered HTTP and then refused to speak MCP — that is a live URL
    that isn't an MCP endpoint (a docs page, a 404, a 405 on the wrong path), which is a different
    user action ("check the URL") from a dead host ("check the server is running")."""
    try:
        import httpx
    except ImportError:                                   # pragma: no cover - httpx is an mcp dep
        return "unreachable"
    if isinstance(exc, httpx.HTTPStatusError):
        # 401/403 is the endpoint telling us it IS there and we are not allowed in. Reporting that
        # as "not an MCP endpoint" sends the user to check their URL when the real fix is a token —
        # observed live against a real hosted server, which is why this case is split out.
        if exc.response is not None and exc.response.status_code in (401, 403):
            return "auth-required"
        return "not-an-mcp-endpoint"
    return "unreachable"


async def probe_stdio(name: str, command: str, args: list[str] | None = None,
                      env: dict[str, str] | None = None, timeout: float = DEFAULT_TIMEOUT) -> ServerSnapshot:
    async def _do():
        params = StdioServerParameters(command=command, args=args or [],
                                       env={**os.environ, **(env or {})})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                return await _snapshot(session, name, "stdio")
    return await _bounded(_do, name, "stdio", timeout)


def _no_redirect_http_client(headers=None, timeout=None, auth=None):
    """An MCP HTTP client that does NOT follow redirects — used ONLY on the authenticated (`--login`)
    scan path. A scanner must never let a credential ride a redirect to an attacker-controlled host.
    httpx already strips a static `Authorization` HEADER on a cross-origin redirect, but an httpx.Auth
    object (the SDK's OAuthClientProvider) re-runs its auth flow on the *redirected* request and could
    re-attach the OAuth token to the redirect target — a case header-stripping does NOT cover. So on
    the auth path we refuse redirects outright. Mirrors the SDK's client defaults otherwise."""
    import httpx
    kwargs: dict[str, Any] = {
        "follow_redirects": False,
        "timeout": timeout if timeout is not None else httpx.Timeout(30.0, read=60 * 5),
    }
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


async def probe_http(name: str, url: str, headers: dict[str, str] | None = None,
                     timeout: float = HTTP_TIMEOUT, auth: Any = None) -> ServerSnapshot:
    """Streamable-HTTP transport — for hosted MCPs. `headers` carries a user-supplied bearer/OAuth
    token for the MCP connection ONLY; the public Server Card fetch never sees it (see servercard.py).
    `auth` is an optional httpx.Auth (e.g. the SDK's OAuthClientProvider from `--login`) that drives
    an interactive OAuth flow; the token it obtains stays on this machine. When `auth` is present we
    force a no-redirect client so an OAuth credential can't leak across a redirect (see factory)."""
    async def _do():
        extra = {"httpx_client_factory": _no_redirect_http_client} if auth is not None else {}
        async with streamablehttp_client(url, headers=headers or {}, auth=auth, **extra) as (read, write, _sid):
            async with ClientSession(read, write) as session:
                snap = await _snapshot(session, name, "http")
        snap.server_card = await fetch_card(url)   # public, unauthenticated; tolerant
        return snap
    return await _bounded(_do, name, "http", timeout)


async def probe_sse(name: str, url: str, headers: dict[str, str] | None = None,
                    timeout: float = HTTP_TIMEOUT, auth: Any = None) -> ServerSnapshot:
    async def _do():
        extra = {"httpx_client_factory": _no_redirect_http_client} if auth is not None else {}
        async with sse_client(url, headers=headers or {}, auth=auth, **extra) as (read, write):
            async with ClientSession(read, write) as session:
                snap = await _snapshot(session, name, "sse")
        snap.server_card = await fetch_card(url)
        return snap
    return await _bounded(_do, name, "sse", timeout)


async def probe_url(name: str, url: str, headers: dict[str, str] | None = None,
                    timeout: float = HTTP_TIMEOUT, auth: Any = None,
                    declared: str = "http", permute: bool = True) -> ServerSnapshot:
    """Probe a remote server WITHOUT trusting the declared transport (roadmap principle 4).

    Tries the candidate matrix from `transport.candidates` in order and returns the first snapshot
    that actually completed an MCP handshake. Candidate #1 is always the declaration exactly as
    given, so a correct config costs one attempt — permutation is paid for only by a wrong one.

    Budgets, because a fallback ladder is exactly how you reinvent the 90s hang F2 killed:
      * candidate #1 gets the caller's full `timeout` (unchanged behaviour for the common case);
      * every fallback gets the short `FALLBACK_TIMEOUT` — a speculative guess does not deserve
        20s, and a live-but-wrong path refuses fast anyway;
      * the whole ladder is capped by `PERMUTE_BUDGET` measured from the first attempt, so total
        wall-clock is bounded no matter how many candidates exist. Candidates dropped to the cap are
        REPORTED as not-attempted rather than silently skipped (no silent caps).

    `permute=False` (used for the authenticated `--login` path) collapses this to a single attempt:
    an httpx.Auth OAuth provider re-runs its flow per attempt, so permuting would both re-open the
    browser repeatedly and offer a credential to speculative URLs the user never named. A scanner
    must not spray tokens at guesses.
    """
    from .transport import candidates as _candidates

    cands = _candidates(url, declared) if permute else [
        _Candidate(transport=(declared if declared in ("http", "sse") else "http"), url=url, declared=True)
    ]
    attempts: list[tuple[str, ServerSnapshot]] = []
    started = time.monotonic()
    skipped: list[str] = []

    for i, cand in enumerate(cands):
        if i == 0:
            budget = timeout
        else:
            remaining = PERMUTE_BUDGET - (time.monotonic() - started)
            if remaining < MIN_ATTEMPT:
                skipped.append(cand.label)
                continue
            budget = min(FALLBACK_TIMEOUT, remaining)
        probe_fn = probe_http if cand.transport == "http" else probe_sse
        snap = await probe_fn(name, cand.url, headers, budget, auth)
        if not snap.is_failure:
            if i != 0:
                snap.resolved_url = cand.url
                snap.declared_transport = declared
            return snap
        attempts.append((cand.label, snap))
        if snap.error_kind == "auth-required":
            # The endpoint answered "you're not allowed in" — it EXISTS. Guessing further paths
            # would be noise, and would offer any supplied credential to more URLs than the user
            # named. Stop and tell them the truth: get a token, don't change the URL.
            skipped.extend(c.label for c in cands[i + 1:])
            break

    return _aggregate_failure(name, declared, attempts, skipped)


def _aggregate_failure(name: str, declared: str, attempts: list[tuple[str, ServerSnapshot]],
                       skipped: list[str]) -> ServerSnapshot:
    """One honest error for the whole ladder. Reporting only the last attempt's error would be a
    lie by omission — the user needs to see that we tried the other transport and the other paths,
    or they will chase a "server down" that is really a typo (and vice versa)."""
    kinds = {s.error_kind for _, s in attempts}
    # Most specific, most actionable kind wins — each one sends the user somewhere different.
    if "auth-required" in kinds:
        kind = "auth-required"
    elif "not-an-mcp-endpoint" in kinds:
        kind = "not-an-mcp-endpoint"
    else:
        kind = "unreachable"

    # One attempt per LINE: httpx errors carry a "For more information check: <mdn url>" second line
    # that turns a 5-attempt ladder into an unreadable wall. Collapse each to a single line.
    lines = [f"  - {label}: {' '.join(snap.error.split())}" for label, snap in attempts]
    if skipped:
        why = ("endpoint found, it needs credentials" if kind == "auth-required"
               else f"time budget {PERMUTE_BUDGET:.0f}s exhausted")
        lines.append(f"  - not attempted ({why}): " + ", ".join(skipped))
    head = ("authentication required — the endpoint is live but refused this scan; "
            "retry with `--login` or `--header \"Authorization: Bearer …\"`"
            if kind == "auth-required" else
            f"no MCP endpoint found — tried {len(attempts)} transport/path permutation"
            f"{'s' if len(attempts) != 1 else ''}")
    return ServerSnapshot(name=name, transport=declared, protocol_version=None,
                          error="\n".join([head + ":", *lines]), error_kind=kind)


def _missing_program(command: str) -> bool:
    """Is this stdio entry pointing at a program that is not on disk?

    Checked BEFORE launching, for two reasons. It is the difference between "your server crashed"
    and "this entry is stale", which are different user actions — and until this existed both
    collapsed into UNREACHABLE, because classification happened by exception type and a missing
    executable is not one of the typed cases.

    An absolute path is checked directly; a bare name is resolved on PATH the way a launch would.
    """
    if not command:
        return False
    if "/" in command or "\\" in command:
        return not Path(command).expanduser().exists()
    return shutil.which(command) is None


async def probe(entry: dict[str, Any], name: str) -> ServerSnapshot:
    """Dispatch a config entry (mcp.json shape) to the right transport."""
    if entry.get("command"):
        command = entry["command"]
        if _missing_program(command):
            # Not launched: there is nothing to launch. Worth its own kind because a configured
            # entry pointing at a path that no longer exists is a standing, PRE-APPROVED execution
            # slot — whatever later lands at that path runs under every agent that still lists it,
            # with no fresh approval. Found by comparing this scanner against a general-purpose
            # agent, which flagged three clients still pointing at the same deleted binary.
            return ServerSnapshot(
                name=name, transport="stdio", protocol_version=None,
                error=f"the program this entry launches does not exist: {command}",
                error_kind="command-missing")
        return await probe_stdio(name, command, entry.get("args"), entry.get("env"))
    url = entry.get("url")
    if not url:
        return ServerSnapshot(name=name, transport="?", protocol_version=None,
                              error="entry has neither `command` (stdio) nor `url` (http/sse)",
                              error_kind="misconfigured")
    # A config entry's `transport` is a CLAIM, and a stale one more often than not — so it only sets
    # the order we try things in, never what we trust. See probe_url / transport.py.
    transport = entry.get("transport", "http")
    headers = entry.get("headers")
    return await probe_url(name, url, headers, declared=transport)
