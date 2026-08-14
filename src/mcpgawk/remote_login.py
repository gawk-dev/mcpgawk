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


def record_auth_needed(found: dict[str, str], path: Path | None = None) -> None:
    """Remember `{server name: url}` for every server whose scan came back `auth-required`.

    WHY THIS EXISTS. A failed probe is never written to history (`should_record` drops it), so the
    one fact that would let a UI say "this needs your sign-in" — the server answered 401/403 —
    was thrown away the moment the scan ended. The panel could then only guess from the launch
    command, which meant a plain remote server that our own engine can authenticate
    (`scan --http <url> --login`) got no button at all.

    Rewritten wholesale each scan, deliberately: a server that no longer refuses us must stop
    being listed, or the offer outlives the problem.
    """
    target = path or _auth_needed_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(found, sort_keys=True), encoding="utf-8")
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
    url = wrapped_remote_url(entry)
    return bool(url) and bool(stored_access_token(url))


def as_authenticated_remote(entry: dict[str, Any]) -> dict[str, Any] | None:
    """A REMOTE server config carrying the stored bearer token, or None if unavailable.

    The caller is responsible for having obtained explicit consent first — see the module
    docstring. This function deliberately does nothing but build the config.
    """
    url = wrapped_remote_url(entry)
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


def inband_login(url: str, headers: dict[str, str] | None = None,
                 timeout: float = 20.0) -> tuple[str, str] | None:
    """Call the server's OWN login tool and return (auth_url, server_notice), or None.

    The other way MCP servers do sign-in: not an OAuth challenge, but a tool that hands back an
    authorisation URL bound to THIS session. The caller's job is to put that URL in front of the
    human — which is exactly what the panel's banner link does. `server_notice` is whatever prose
    the tool returned around the URL (kite explicitly instructs clients to display its warning);
    the caller renders it through the normal scrubbing path, never raw.

    Sync on purpose: called from the panel's background action thread. Returns None on ANY
    failure — "no in-band login" and "could not ask" both mean the caller falls back to its
    honest refusal, which names the manual command.
    """
    import asyncio
    import re as _re

    async def _go() -> tuple[str, str] | None:
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        async with streamable_http_client(url) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                name = next((t.name for t in tools.tools
                             if t.name in _INBAND_LOGIN_NAMES
                             or "login" in t.name.lower()), None)
                if name is None:
                    return None
                result = await session.call_tool(name, {})
                text = " ".join(getattr(c, "text", "") or "" for c in result.content)
                hit = _re.search(r"https?://\S+", text)
                if not hit:
                    return None
                return hit.group(0).rstrip(".,)*`"), text[:400]

    try:
        return asyncio.run(asyncio.wait_for(_go(), timeout))
    except Exception:                              # noqa: BLE001 — fall back to the honest refusal
        return None
