"""Servers behind a browser sign-in — and the login you already completed.

`kite` is configured as `npx mcp-remote https://mcp.kite.trade/mcp`: a LOCAL command that proxies
to a REMOTE server behind an interactive OAuth sign-in. Verify launches it, mcp-remote wants a
browser, a verify run has no browser, and the row has always read *"needs your sign-in … re-running
will not change this"*. True, and a dead end.

It does not have to be. Two things already exist and were never connected:

* the wrapped URL is sitting in the server's own args (`mcp-remote <URL>`), and
* `mcpgawk scan --login` stores a real OAuth token for that URL under `~/.gawk/oauth/`,
  which `enforce` already reuses (`enforce/remote_auth.build_stored_auth`).

So the server can be verified as a REMOTE target with the stored bearer token attached — the
engine has always accepted `headers` for remote servers. No OAuth server of our own is needed for
this; the design doc's claim that G3 (OAuth mediation) is what unlocks these servers was wrong,
and this module is the cheap correct path.

WHY THIS IS OPT-IN, AND MUST STAY OPT-IN
Verifying an authenticated server is not a dry run. It makes REAL authenticated calls as you —
against a live brokerage account, in kite's case — and the engine records a 2000-character
excerpt of every response into the run's evidence archive (`verify-runs/<stamp>/audit.jsonl`).
That is your account data, on your disk, written by us. Both consequences are the operator's to
accept, per server, in advance. Nothing here runs on its own; `as_authenticated_remote` only
BUILDS the config, and the caller must have been told explicitly.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

#: Launchers that proxy to a remote server behind an interactive browser sign-in.
_WRAPPERS = ("mcp-remote", "mcp_remote")


def _store_dir() -> Path:
    """Where `oauth_login` really put the tokens — resolved at CALL time, honouring the override.

    This used to be `Path.home() / ".gawk" / "oauth"` bound at import: it duplicated the path
    without duplicating `GAWK_OAUTH_STORE`. An operator who relocated their token store therefore
    had this reader look in the empty default and return "" — which `stored_access_token` documents
    as "no login available". A relocated login reported as no login is the ambiguity rule again:
    the swallowed miss returns a value that reads as a real answer.
    """
    return Path(os.environ.get("GAWK_OAUTH_STORE") or (Path.home() / ".gawk" / "oauth"))


def wrapped_remote_url(entry: dict[str, Any]) -> str:
    """The remote URL a local wrapper proxies to, or "" if this is not that shape."""
    args = [str(a) for a in (entry.get("args") or [])]
    if not any(w in a for a in args for w in _WRAPPERS):
        return ""
    for a in args:
        if a.startswith("http://") or a.startswith("https://"):
            parsed = urlparse(a)
            if parsed.scheme and parsed.netloc:
                return a
    return ""


def _token_path(url: str) -> Path:
    """Same derivation as oauth_login.FileTokenStorage — one owner of the scheme would be better,
    but duplicating a sha256 prefix is safer than importing the login machinery into a read path."""
    return _store_dir() / f"{hashlib.sha256(url.encode()).hexdigest()[:16]}.json"


def stored_access_token(url: str) -> str:
    """The access token saved by `mcpgawk scan --login` for this URL, or "".

    Never raises: an unreadable or half-written token store means "no login available", which is
    the same honest answer as never having logged in.
    """
    try:
        doc = json.loads(_token_path(url).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    tokens = doc.get("tokens")
    if not isinstance(tokens, dict):
        return ""
    return str(tokens.get("access_token") or "")


def local_signin_key(name: str) -> str:
    """The token-store key for a LOCAL server's completed in-band sign-in. A local server has no
    URL, so the store — keyed by URL hash — had no place for the evidence that a person finished
    its own key flow; Revolut X's configure step said "Authentication is configured and the
    connection is working" and the Today card still asked for a sign-in (founder, 2026-09-08)."""
    return f"stdio:{name}"


def mark_local_signin(name: str) -> str:
    """Record a LOCAL server's completed in-band sign-in — same document and writer as kite's
    `mark_inband_login`, under `local_signin_key`. Returns the minted login_id."""
    from .oauth_login import mark_inband_login
    return mark_inband_login(local_signin_key(name))


def stored_login_id(url: str) -> str | None:
    """Which completed sign-in the stored tokens for `url` belong to, or None.

    None is a real answer with a real meaning — "this store predates the mark, or there is no
    login" — and `drift.compare` claims nothing when either side is None. Silence beats a guess:
    inventing an id here would report an account change on every store written before this existed.
    """
    try:
        doc = json.loads(_token_path(url).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    got = doc.get("login_id")
    return got if isinstance(got, str) and got else None


def stored_inband_at(url: str) -> str | None:
    """When a human completed this server's OWN in-band sign-in, or None if the mark is not in-band.

    An in-band sign-in is not a credential: kite binds its session to the one MCP connection that
    asked, so a completed flow says what happened on a date, never what is true now (measured
    2026-09-08 — a fresh `initialize` against mcp.kite.trade answers "Please log in first using the
    login tool", and no kite entry exists anywhere in ~/.mcp-auth). The panel must be able to tell
    the two kinds apart before it says the word "signed in".
    """
    try:
        doc = json.loads(_token_path(url).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not doc.get("inband_login"):
        return None
    got = doc.get("logged_in_at")
    return got if isinstance(got, str) and got else ""


def _auth_needed_path() -> Path:
    """Servers a scan found to be REFUSING us for lack of credentials, so the panel can offer
    sign-in on evidence instead of on a launcher's name. Written by scan, read by any surface.

    Resolved at CALL time from `MCPGAWK_AUTH_NEEDED`, because it was previously a constant bound at
    import with NO override — the third time that exact shape has been found here (behaviour.json,
    config.json, now this). The consequence was live: every full pytest run rewrote the founder's
    real ~/.mcpgawk/auth-needed.json, and nothing noticed until the suite's real-home tripwire was
    extended to cover ~/.mcpgawk on 2026-08-02. A test that quietly edits the operator's own state
    is the same defect as the product doing it.
    """
    override = os.environ.get("MCPGAWK_AUTH_NEEDED")
    return Path(override) if override else Path.home() / ".mcpgawk" / "auth-needed.json"


def _signin_aside_path() -> Path:
    """Servers the PERSON recorded as "not available to me", and when.

    WHY A FILE OF ITS OWN. robinhood-trading's MCP is not live for the founder's account. No store
    on this machine can know that: it sits in `auth-needed.json` with a URL and no vendor limit —
    indistinguishable from a working OAuth server until a callback that never comes. So it is a
    decision the person records, not a state we detect. It cannot live beside a muted finding in
    the trust store, because a muted finding is keyed by a TRACKED server and every server this
    exists for is untracked by definition: measured 2026-09-08, `history.resolve` answers None for
    all three of robinhood-trading, figma and plugin_figma_figma. Keying it there would have
    shipped a button that silently does nothing — which is the exact class of dead end this whole
    week was spent removing.

    Resolved at CALL time from `MCPGAWK_SIGNIN_ASIDE`. Every store in this package that bound its
    path at import has been caught rewriting the operator's own state (behaviour.json,
    config.json, auth-needed.json); this one is redirectable from the line it was written.
    """
    override = os.environ.get("MCPGAWK_SIGNIN_ASIDE")
    return Path(override) if override else Path.home() / ".mcpgawk" / "signin-aside.json"


def signin_aside(path: Path | None = None) -> dict[str, str]:
    """`{server name: ISO stamp}` the person has set aside. Never raises: an unreadable file means
    "nothing set aside", which is the safe answer — it can only ever ASK more, never less."""
    try:
        doc = json.loads((path or _signin_aside_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(k): str(v) for k, v in doc.items()} if isinstance(doc, dict) else {}


def set_signin_aside(name: str, aside: bool = True, path: Path | None = None) -> bool:
    """Record (or withdraw) "this server is not available to me". Returns whether the file now
    says what was asked — False means nothing was written and the caller must say so, never
    report a success it did not get."""
    if not name:
        return False
    target = path or _signin_aside_path()
    doc = signin_aside(target)
    if aside:
        doc[name] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    else:
        doc.pop(name, None)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
        tmp.replace(target)
    except OSError:
        return False
    return (name in signin_aside(target)) is bool(aside)


def record_auth_needed(found: dict[str, str], path: Path | None = None,
                       scanned: set[str] | None = None) -> None:
    """Remember `{server name: url}` for every server whose scan came back `auth-required`.

    WHY THIS EXISTS. A failed probe is never written to history (`should_record` drops it), so the
    one fact that would let a UI say "this needs your sign-in" — the server answered 401/403 —
    was thrown away the moment the scan ended. The panel could then only guess from the launch
    command, which meant a plain remote server that our own engine can authenticate
    (`scan --http <url> --login`) got no button at all.

    Cleared for what this scan actually LOOKED AT, not for everything. A server that no longer
    refuses us must stop being listed, or the offer outlives the problem — but `scanned` bounds
    that to the scope of this run. Without it a single `scan --http <url>` rewrote the file to
    that one ad-hoc server and every real server's sign-in offer vanished from the panel until
    somebody happened to run a full scan again. Measured on the founder's fleet 2026-08-27:
    scanning one URL erased notion's record, and notion went back to reading "configured, never
    used" while it was in fact waiting for a login.

    `scanned=None` keeps the original wholesale behaviour, which is what a full-fleet scan wants.
    """
    target = path or _auth_needed_path()
    doc = dict(found)
    if scanned is not None:
        keep = {k: v for k, v in auth_needed(path).items()
                if k not in scanned and k not in found}
        doc = {**keep, **found}
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
        tmp.replace(target)
    except OSError:
        pass                                  # a read-only HOME must never break a scan


def auth_needed(path: Path | None = None) -> dict[str, str]:
    """{server name: url} recorded by the last scan. Empty when unknown — and "unknown" is not
    "fine": callers must not render an empty result as "nothing needs a login"."""
    try:
        doc = json.loads((path or _auth_needed_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(k): str(v) for k, v in doc.items() if v} if isinstance(doc, dict) else {}


def refused_after_login(url: str, path: Path | None = None) -> bool | None:
    """Did the last scan's refusal happen AFTER the stored login? None when it cannot be told.

    Two true things look identical in the data — a token in the store and the server's name in the
    scan's refusal record — and they call for opposite screens:

      the login is STALE   (token issued, later scan refused it)  -> a sign-in must be offered
      the login is FRESH   (scan refused, then the user signed in) -> offering again is a re-run
                                                                      trap, and the next scan
                                                                      clears the record anyway

    Only the ORDER separates them. Neither file records an issued-at, so this compares the two
    files' mtimes, and returns None rather than guessing when either is missing — a caller must
    then fall back to its previous rule instead of inventing an answer from an absence.
    """
    try:
        refused = (path or _auth_needed_path()).stat().st_mtime
        issued = _token_path(url).stat().st_mtime
    except OSError:
        return None
    return refused > issued


def login_url(entry: dict[str, Any], name: str = "", path: Path | None = None) -> str:
    """Where a browser sign-in for this server would go, or "".

    Two shapes, both real: a local wrapper (mcp-remote) proxying to a remote URL, and a plain
    remote server that answered 401/403 on the last scan. The engine has always been able to
    OAuth the second (`oauth_login.build_login_provider`); only the panel's gating was narrower.
    """
    wrapped = wrapped_remote_url(entry)
    if wrapped:
        return wrapped
    url = str(entry.get("url") or "")
    if url and name and name in auth_needed(path):
        return url
    return ""


def has_stored_login(entry: dict[str, Any]) -> bool:
    """Could this browser-auth server be verified right now, using a login already completed?"""
    url = authenticated_url(entry)
    return bool(url) and bool(stored_access_token(url))


def authenticated_url(entry: dict[str, Any]) -> str:
    """The URL a stored login would belong to: the wrapped one, or the entry's own.

    Both helpers below asked only `wrapped_remote_url`, so a PLAIN remote server — the ordinary
    shape, `{"type": "http", "url": …}` — could complete a browser sign-in, have its token written
    to disk, and still be treated as having none. Measured on notion 2026-08-27: signed in
    successfully, and the very next scan said "needs credentials — not scanned".
    """
    return wrapped_remote_url(entry) or str(entry.get("url") or "")


def as_authenticated_remote(entry: dict[str, Any]) -> dict[str, Any] | None:
    """A REMOTE server config carrying the stored bearer token, or None if unavailable.

    The caller is responsible for having obtained explicit consent first — see the module
    docstring. This function deliberately does nothing but build the config.
    """
    url = authenticated_url(entry)
    if not url:
        return None
    token = stored_access_token(url)
    if not token:
        return None
    return {"url": url, "headers": {"Authorization": f"Bearer {token}"}}


def consent_text(name: str, entry: dict[str, Any]) -> str:
    """What the operator must be told BEFORE an authenticated verify, in their terms.

    States both consequences plainly. A consent line that mentions the benefit and omits that the
    responses land on disk is not consent, it is a sales pitch.
    """
    url = wrapped_remote_url(entry) or "the remote server"
    return (
        f"{name} can be verified using the sign-in you already completed for {url}. "
        f"Doing that makes REAL authenticated calls as you — the engine invokes the server's "
        f"read-only tools against your live account — and records up to 2000 characters of each "
        f"response into this run's evidence archive on this machine. Nothing is uploaded. "
        f"Verify it this way only if both of those are acceptable to you."
    )


#: Tool names that mean "this server signs you in through its own tool". kite and Revolut X both
#: work this way (measured 2026-08-14: kite's `login` returns the real
#: `https://mcp.kite.trade/authorize?session_id=…` URL plus a warning it asks clients to display).
#: Standard OAuth servers never get here — the panel tries the challenge/discovery flow first.
_INBAND_LOGIN_NAMES = ("login", "authorize", "authenticate", "connect")

#: Tools that don't return an auth URL but DO return the server's own sign-in instructions —
#: Revolut X's `check_auth_status` answers "Not configured" with numbered steps and explicitly
#: instructs clients to present them all. Relaying those verbatim IS the sign-in flow for this
#: class; there is nothing else to run.
#: AUTH-shaped names only. The first version included bare "setup" — which matched browserstack's
#: `setupBrowserStackAutomateTests` (test scaffolding, mandatory arguments), so the panel called
#: it with {} and rendered the raw validation error as "sign-in steps" (founder, live,
#: 2026-08-14). A generic word is not a shape; every name here must carry auth semantics.
_INBAND_STATUS_NAMES = ("check_auth_status", "auth_status", "login_status")

def inband_login(url: str | None = None, headers: dict[str, str] | None = None,
                 timeout: float = 30.0, *, command: str | None = None,
                 args: list[str] | None = None,
                 env: dict[str, str] | None = None) -> tuple[str, str] | None:
    """Drive a server's OWN sign-in surface and return (auth_url, server_text), or None.

    Three real shapes, measured on the founder's fleet 2026-08-14:
    * kite: a `login` tool returns the actual authorisation URL (plus a warning it instructs
      clients to display) — auth_url is that link.
    * Revolut X: no URL tool; `check_auth_status` returns numbered setup steps and instructs
      clients to present ALL of them — auth_url is "" and server_text carries the steps. Relaying
      them IS the flow.
    * Everything else: None, and the caller keeps its honest refusal.

    Works over HTTP (`url`) or stdio (`command`/`args`/`env` — Desktop extensions, resolved by
    dxt with Desktop's own defaults). Sync on purpose (panel background thread); any failure is
    None — "could not ask" falls back to the refusal, never to a hang.
    """
    import asyncio
    import re as _re

    async def _drive(session) -> tuple[str, str] | None:
        await session.initialize()
        tools = await session.list_tools()
        names = [t.name for t in tools.tools]
        target = next((n for n in names if n in _INBAND_LOGIN_NAMES
                       or "login" in n.lower()), None)
        kind = "login"
        if target is None:
            # OUR preference order, not the server's listing order: a status tool answers "what
            # should the user do right now", a generic instructions tool answers "what is this
            # server" — Revolut X has both, and the first is the sign-in surface.
            for want in _INBAND_STATUS_NAMES:
                target = next((n for n in names if want in n.lower()), None)
                if target:
                    break
            kind = "status"
        if target is None:
            return None
        result = await session.call_tool(target, {})
        text = " ".join(getattr(c, "text", "") or "" for c in result.content)
        # An ERROR is not a sign-in surface. A tool that refuses its arguments proves only that
        # we called the wrong tool — rendering its validation complaints as "sign-in steps" is
        # noise dressed as guidance. Fall through to the honest refusal instead.
        if getattr(result, "is_error", False) or getattr(result, "isError", False) \
                or text.lstrip().startswith("MCP error"):
            return None
        hit = _re.search(r"https?://\S+", text)
        auth_url = hit.group(0).rstrip(".,)*`") if hit else ""
        if kind == "login" and not auth_url:
            return None                       # a login tool that yields no link proves nothing
        return auth_url, text[:900]

    async def _go() -> tuple[str, str] | None:
        from mcp.client.session import ClientSession
        if command:
            from mcp.client.stdio import StdioServerParameters, stdio_client
            params = StdioServerParameters(command=command, args=list(args or []),
                                           env=dict(env or {}))
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    return await _drive(session)
        if url:
            from mcp.client.streamable_http import streamable_http_client
            async with streamable_http_client(url) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    return await _drive(session)
        return None

    try:
        return asyncio.run(asyncio.wait_for(_go(), timeout))
    except Exception:                              # noqa: BLE001 — the refusal owns failure
        return None


#: Guided in-band setup: the tool pairs that make "sign in" an executable flow rather than a
#: recited one. Revolut X: generate_keypair -> user registers the public key on Revolut's site ->
#: configure_api_key -> check_auth_status. Matched by SHAPE so the next server with this model
#: works without a special case.
_KEYGEN_NAMES = ("generate_keypair", "create_keypair", "generate_key", "keygen")
#: bare "configure" was greedy for the same reason bare "setup" was: key/auth context required.
_CONFIGURE_NAMES = ("configure_api_key", "set_api_key", "configure_key")


def _tool_input_schema(tool) -> dict:
    """The tool's input schema, whichever name the SDK gives the attribute. mcp 2.x renamed the
    model field to `input_schema` (the wire name `inputSchema` survives only as an alias for
    construction); reading `.inputSchema` raised AttributeError inside a swallow-all, and the
    founder's pasted Revolut X API key answered "configure tool did not answer; run mcpgawk
    verify" (2026-09-08) — advice that could never have shown the real error, because verify
    never calls configure."""
    schema = getattr(tool, "input_schema", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    return schema if isinstance(schema, dict) else {}


def configure_arg_name(tool) -> str:
    """The name the configure tool wants its secret under — from the tool's OWN schema (first
    required string, else the first property, else `api_key`), so the next server's
    configure(secret=...) works without a special case."""
    schema = _tool_input_schema(tool)
    props = schema.get("properties") or {}
    required = schema.get("required") or list(props)
    return next((r for r in required if (props.get(r) or {}).get("type", "string") == "string"),
                next(iter(props), "api_key"))


def _leaf_error(exc: BaseException) -> str:
    """The innermost message. anyio wraps a task's failure in ExceptionGroups whose own text is
    "unhandled errors in a TaskGroup (1 sub-exception)" — no better than "did not answer"."""
    import builtins
    group_type = getattr(builtins, "BaseExceptionGroup", None) or ()   # 3.11+; the floor is 3.10
    seen = 0
    while isinstance(exc, group_type) and exc.exceptions and seen < 8:
        exc = exc.exceptions[0]
        seen += 1
    text = " ".join(str(exc).split()) or type(exc).__name__
    return f"{type(exc).__name__}: {text}"[:300]


def inband_setup(command: str, args: list[str], env: dict[str, str],
                 step: str, value: str | None = None, timeout: float = 40.0) -> tuple[str, str] | None:
    """Execute ONE step of a server's own setup flow. Returns (kind, text) or None.

    kind="error": the step stopped before the server's verdict — the text is the innermost
    exception, ours or the server's. Callers MUST check the kind: an error is never the keypair
    steps and never a status. None means the server has no tool of that shape.

    step="start": run the server's key-generation tool; text is its verbatim output (the public
    key the user must register — PUBLIC by construction, so the caller may display it unscrubbed
    but always HTML-escaped).
    step="configure": run the configure tool with `value` (the API key the user pasted — passed
    straight to the tool, NEVER stored anywhere by the caller), then the status tool; text is the
    status tool's answer, which is the server's own verdict on whether sign-in now works.
    """
    import asyncio

    async def _go() -> tuple[str, str] | None:
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        params = StdioServerParameters(command=command, args=list(args), env=dict(env))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()

                def pick(wanted: tuple[str, ...]):
                    for want in wanted:
                        for t in listed.tools:
                            if want in t.name.lower():
                                return t
                    return None

                def text_of(result) -> str:
                    return " ".join(getattr(c, "text", "") or "" for c in result.content)

                if step == "start":
                    tool = pick(_KEYGEN_NAMES)
                    if tool is None:
                        return None
                    return "pubkey", text_of(await session.call_tool(tool.name, {}))[:1500]
                if step == "configure" and value:
                    tool = pick(_CONFIGURE_NAMES)
                    if tool is None:
                        return None
                    arg = configure_arg_name(tool)
                    out = text_of(await session.call_tool(tool.name, {arg: value}))
                    status = pick(_INBAND_STATUS_NAMES)
                    if status is not None:
                        out = text_of(await session.call_tool(status.name, {}))
                    return "status", out[:1200]
                return None

    try:
        return asyncio.run(asyncio.wait_for(_go(), timeout))
    except asyncio.TimeoutError:
        return ("error", f"no answer within {int(timeout)}s")
    except Exception as exc:                       # noqa: BLE001 — the caller reports, never hangs
        return ("error", _leaf_error(exc))


def _clip_notice(text: str, limit: int = 400) -> str:
    """The server's own notice, bounded, cut at a LINE — never mid-URL. `text[:400]` left kite's
    notice ending in `…session_id=kitemcp-dbb5f5a5-4bd7-4abb-bf80-fdf2a9c8` (founder's paste,
    2026-09-03): a link that looks broken, one line above the real one."""
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    head = text[:limit]
    cut = max(head.rfind("\n"), head.rfind(". "))
    if cut < limit // 2:
        cut = head.rfind(" ")
    return head[:cut if cut > 0 else limit].rstrip() + " …"


class HeldSessionEnded(RuntimeError):
    """Raised by a `HeldSession` method once its session is gone. A caller falls back to the
    ordinary probe and says so; it must never surface as a traceback in the middle of a scan."""


class HeldSession:
    """A live MCP session, kept open, that the caller can MEASURE THROUGH.

    THE DEFECT THIS EXISTS FOR (founder, 2026-08-27, `d011d04`): the sign-in button held a
    session in a thread that exposed nothing, so a login completed in the browser authorised a
    session that then slept for five minutes and closed, having measured nothing. kite binds a
    login to the ONE session that asked for it, so that discarded session was the only place the
    signed-in server could ever have been observed.

    WHY A HANDLE AND NOT THE SESSION. The session belongs to an event loop running in a daemon
    thread; an asyncio object touched from another thread is a race, not an API. Every method
    here marshals its work onto the owning loop, so the session never leaves the thread that
    created it and the caller still gets to drive it.
    """

    def __init__(self, *, auth_url: str, notice: str, login_tool: str,
                 loop: Any, session: Any, stop: Any, thread: Any) -> None:
        self.auth_url = auth_url
        self.notice = notice
        self.login_tool = login_tool
        self._loop = loop
        self._session = session
        self._stop = stop
        self._thread = thread

    def _run(self, coro: Any, timeout: float) -> Any:
        import asyncio
        # The hold is five minutes from CONNECT, and the caller may be waiting on a person at a
        # browser for longer than that. Once the loop has stopped, `run_coroutine_threadsafe`
        # raises a bare `RuntimeError: Event loop is closed` (or the future never resolves) —
        # which, uncaught, took the whole scan down with a traceback. Say what actually happened.
        if self._loop.is_closed() or not self._thread.is_alive():
            coro.close()
            raise HeldSessionEnded("the held session has already ended — the hold expired "
                                   "or the server closed it — so nothing can be measured "
                                   "through it")
        try:
            return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=timeout)
        except RuntimeError as e:
            # Only claim "the session ended" when it HAS: `.result()` also re-raises whatever the
            # coroutine itself raised, and a server-side RuntimeError must keep its own name.
            if self._loop.is_closed() or not self._thread.is_alive():
                raise HeldSessionEnded(f"the held session ended while it was being used: "
                                       f"{e}") from e
            raise

    def authorisation(self, timeout: float = 60.0) -> tuple[bool, str]:
        """Re-call the server's OWN login tool; report (authorised, the server's words).

        MECHANISM, NOT WORDING — deliberately. A login tool that hands back an auth URL is
        saying the session is NOT through; one that answers with no link and no error has
        nothing left to ask for. Matching kite's "You are already logged in as ..." would be a
        string only kite says, and this product's failure mode is reassurance that outlives the
        thing it was measured on. It is also the test `inband_login` already applies when it
        refuses a login tool that yields no link.

        MEASURED (2026-09-02, founder's account, one held session): before the browser flow the
        tool returns the authorize URL; after it, `You are already logged in as <name>`,
        is_error False, no URL. The tool surface was byte-identical either side.
        """
        import re as _re

        async def _ask() -> tuple[bool, str]:
            result = await self._session.call_tool(self.login_tool, {})
            text = " ".join(getattr(c, "text", "") or "" for c in result.content)
            errored = bool(getattr(result, "isError", False) or getattr(result, "is_error", False))
            has_url = bool(_re.search(r"https?://\S+", text))
            return (not errored and not has_url), text

        return self._run(_ask(), timeout)

    def measure(self, entry: dict[str, Any], name: str, timeout: float = 180.0) -> Any:
        """Measure the server through THIS session, via the one function that makes snapshots.

        Not a lookalike listing: the pin a baseline is compared against comes from `_snapshot`'s
        exact serialisation, so a hand-rolled one could mint a different pin for an identical
        surface and manufacture drift that is not there.
        """
        from .probe import probe_held
        return self._run(probe_held(self._session, entry, name), timeout)

    def close(self) -> None:
        """Release the session. Safe to call twice, and safe if the loop is already gone."""
        try:
            self._loop.call_soon_threadsafe(self._stop.set)
        except Exception:                          # noqa: BLE001 — already closed is not an error
            pass


def held_session(url: str | None = None, *, command: str | None = None,
                 args: list[str] | None = None, env: dict[str, str] | None = None,
                 headers: dict[str, str] | None = None,
                 hold_seconds: float = 300.0,
                 connect_timeout: float = 45.0) -> HeldSession | None:
    """Drive a server's in-band `login` tool and KEEP THE SESSION ALIVE, handing back a handle.

    The session closes when the handle is closed or `hold_seconds` elapses, whichever is first —
    the same five minutes the OAuth flow grants a human, unchanged.
    """
    import asyncio
    import queue
    import re as _re
    import threading

    out: queue.Queue = queue.Queue()

    def run() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def go() -> None:
            from mcp.client.session import ClientSession

            stop = asyncio.Event()

            async def drive(session: Any) -> bool:
                await session.initialize()
                listed = await session.list_tools()
                name = next((t.name for t in listed.tools
                             if t.name in _INBAND_LOGIN_NAMES or "login" in t.name.lower()), None)
                if name is None:
                    out.put(None)
                    return False
                result = await session.call_tool(name, {})
                text = " ".join(getattr(c, "text", "") or "" for c in result.content)
                hit = _re.search(r"https?://\S+", text)
                if not hit:
                    out.put(None)
                    return False
                out.put(HeldSession(auth_url=hit.group(0).rstrip(".,)*`"), notice=_clip_notice(text),
                                    login_tool=name, loop=loop, session=session, stop=stop,
                                    thread=threading.current_thread()))
                return True

            async def hold(session: Any) -> None:
                if not await drive(session):
                    return
                try:
                    await asyncio.wait_for(stop.wait(), hold_seconds)
                except asyncio.TimeoutError:
                    pass                           # the hold expired; closing is the right end

            if command:
                from mcp.client.stdio import StdioServerParameters, stdio_client
                params = StdioServerParameters(command=command, args=list(args or []),
                                               env=dict(env or {}))
                # The child's stderr is CAPTURED, as `probe_stdio` captures it: through the
                # inherited stderr, mcp-remote's `[pid] [Local→Remote] tools/call` chatter and its
                # shutdown `DOMException [AbortError]` stack trace landed in the middle of the
                # founder's report (live kite walk, 2026-09-03). Noise on success; on failure the
                # ordinary probe's own path is the one that reads it back.
                import tempfile
                with tempfile.TemporaryFile(mode="w+", encoding="utf-8",
                                            errors="replace") as errlog:
                    async with stdio_client(params, errlog=errlog) as (read, write):
                        async with ClientSession(read, write) as session:
                            await hold(session)
            elif url:
                from mcp.client.streamable_http import streamable_http_client
                from mcp.client.streamable_http import create_mcp_http_client
                # The entry's own headers ride along, as they do on every ordinary probe: a
                # server behind a static token would otherwise refuse the held session while
                # accepting the scan, and the sign-in would be reported as "does not sign in
                # through a login tool of its own" for a reason that is not the real one.
                http_client = create_mcp_http_client(headers=dict(headers or {}))
                async with streamable_http_client(url, http_client=http_client) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await hold(session)

        try:
            loop.run_until_complete(go())
        except Exception:                          # noqa: BLE001 — the queue carries the verdict
            try:
                out.put(None)
            except Exception:                      # noqa: BLE001
                pass
        finally:
            try:
                loop.close()
            except Exception:                      # noqa: BLE001
                pass

    threading.Thread(target=run, daemon=True, name="mcpgawk-held-login").start()
    try:
        got = out.get(timeout=connect_timeout)
    except queue.Empty:
        return None
    return got if isinstance(got, HeldSession) else None


def inband_login_held(url: str | None = None, *, command: str | None = None,
                      args: list[str] | None = None, env: dict[str, str] | None = None,
                      hold_seconds: float = 300.0,
                      connect_timeout: float = 45.0) -> tuple[str, str] | None:
    """Like `inband_login`, but KEEPS THE SESSION ALIVE after handing back the URL.

    The defect this exists for, found by the founder clicking the real link (2026-08-14): kite's
    `login` tool returns `.../authorize?session_id=<THIS session>` — the URL is bound to the MCP
    session that asked. The first implementation closed the session the moment it had the URL, so
    every link was dead on arrival: "session error" the instant a human opened it. The session now
    stays connected in a background thread for `hold_seconds` (the same five minutes the OAuth
    flow grants a human), which is what makes the link real.

    Kept as the tuple-returning shape for callers that only need the link. A caller that wants to
    MEASURE the signed-in server wants `held_session` and its handle instead.
    """
    held = held_session(url, command=command, args=args, env=env,
                        hold_seconds=hold_seconds, connect_timeout=connect_timeout)
    if held is None:
        return None
    return held.auth_url, held.notice
