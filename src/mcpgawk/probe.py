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
import sys
from dataclasses import dataclass, field
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
    # (a live URL that isn't MCP — e.g. an HTML docs page). None when there is no error.
    error_kind: str | None = None

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
                              error=f"{type(real).__name__}: {real}", error_kind="unreachable")


async def probe_stdio(name: str, command: str, args: list[str] | None = None,
                      env: dict[str, str] | None = None, timeout: float = DEFAULT_TIMEOUT) -> ServerSnapshot:
    async def _do():
        params = StdioServerParameters(command=command, args=args or [],
                                       env={**os.environ, **(env or {})})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                return await _snapshot(session, name, "stdio")
    return await _bounded(_do, name, "stdio", timeout)


async def probe_http(name: str, url: str, headers: dict[str, str] | None = None,
                     timeout: float = HTTP_TIMEOUT, auth: Any = None) -> ServerSnapshot:
    """Streamable-HTTP transport — for hosted MCPs. `headers` carries a user-supplied bearer/OAuth
    token for the MCP connection ONLY; the public Server Card fetch never sees it (see servercard.py).
    `auth` is an optional httpx.Auth (e.g. the SDK's OAuthClientProvider from `--login`) that drives
    an interactive OAuth flow; the token it obtains stays on this machine."""
    async def _do():
        async with streamablehttp_client(url, headers=headers or {}, auth=auth) as (read, write, _sid):
            async with ClientSession(read, write) as session:
                snap = await _snapshot(session, name, "http")
        snap.server_card = await fetch_card(url)   # public, unauthenticated; tolerant
        return snap
    return await _bounded(_do, name, "http", timeout)


async def probe_sse(name: str, url: str, headers: dict[str, str] | None = None,
                    timeout: float = HTTP_TIMEOUT, auth: Any = None) -> ServerSnapshot:
    async def _do():
        async with sse_client(url, headers=headers or {}, auth=auth) as (read, write):
            async with ClientSession(read, write) as session:
                snap = await _snapshot(session, name, "sse")
        snap.server_card = await fetch_card(url)
        return snap
    return await _bounded(_do, name, "sse", timeout)


async def probe(entry: dict[str, Any], name: str) -> ServerSnapshot:
    """Dispatch a config entry (mcp.json shape) to the right transport."""
    if entry.get("command"):
        return await probe_stdio(name, entry["command"], entry.get("args"), entry.get("env"))
    url = entry.get("url")
    if not url:
        return ServerSnapshot(name=name, transport="?", protocol_version=None,
                              error="entry has neither `command` (stdio) nor `url` (http/sse)",
                              error_kind="misconfigured")
    transport = entry.get("transport", "http")
    headers = entry.get("headers")
    return await (probe_sse if transport == "sse" else probe_http)(name, url, headers)
