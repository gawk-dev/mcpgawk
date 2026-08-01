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
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

#: Launchers that proxy to a remote server behind an interactive browser sign-in.
_WRAPPERS = ("mcp-remote", "mcp_remote")

_STORE_DIR = Path.home() / ".gawk" / "oauth"


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
    return _STORE_DIR / f"{hashlib.sha256(url.encode()).hexdigest()[:16]}.json"


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
