"""`gawk scan --login` — trigger the OAuth login for a remote MCP server, natively.

Wraps the `mcp` SDK's own `OAuthClientProvider` (already a dependency, no new install) so a remote
OAuth-protected server can be scanned: on first connect the system browser opens, the user approves
once, and the token is stored locally (`~/.gawk/oauth`, mode 0600) and refreshed automatically
thereafter. No Node/`mcp-remote`, no from-scratch OAuth stack — and the token never leaves the
machine (the local-first posture buyers in the MCP ecosystem explicitly ask for; the SDK handles
DCR + PKCE + refresh). A server that refuses Dynamic Client Registration is a DEAD END for this
flow — measured on figma 2026-08-14: its registration endpoint answers 403 and the SDK raises,
there is no automatic fallback. Naming that honestly is `last_flow_error`'s job below.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from pydantic import AnyUrl
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)

#: Where per-server tokens live. Overridable with GAWK_OAUTH_STORE, the same escape hatch
#: GAWK_LICENSE_CACHE provides for the licence cache — it lets CI, a self-host deployment or a
#: test point at an isolated store instead of ~/.gawk. Redirecting HOME is NOT an alternative:
#: the licence cache is deliberately machine-bound to hostname + home directory, so moving HOME
#: invalidates it (which is the anti-copy protection doing its job).
_STORE_DIR = Path(os.environ.get("GAWK_OAUTH_STORE") or (Path.home() / ".gawk" / "oauth"))


class _SdkFlowLog(logging.Handler):
    """The MCP SDK logs OAuth failures as `logger.exception("OAuth flow error")` — with no logging
    configured, Python's last-resort handler printed the FULL TRACEBACK into the founder's
    terminal mid-sign-in (figma, 2026-08-14). A traceback is not a message to a person. This
    handler keeps the SDK's own words for the caller to render honestly, and propagation stops so
    the terminal never sees the raw dump."""

    last: str | None = None

    def emit(self, record: logging.LogRecord) -> None:
        exc = record.exc_info[1] if record.exc_info else None
        _SdkFlowLog.last = str(exc) if exc else record.getMessage()


_sdk_auth_logger = logging.getLogger("mcp.client.auth")
_sdk_auth_logger.addHandler(_SdkFlowLog())
_sdk_auth_logger.propagate = False


def last_flow_error() -> str | None:
    """The SDK's own words for why the most recent OAuth flow died, or None if it did not."""
    return _SdkFlowLog.last


class FileTokenStorage:
    """Per-server token + client-registration store on the local disk (mode 0600). Local-first:
    a scanned credential is never transmitted anywhere — it only unlocks the connection mcpgawk
    makes from this machine."""

    def __init__(self, server_url: str) -> None:
        key = hashlib.sha256(server_url.encode()).hexdigest()[:16]
        self._path = _STORE_DIR / f"{key}.json"

    def _read(self) -> dict:
        try:
            return json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict) -> None:
        """Persist the token, never widening the window in which it is readable.

        This used to `write_text` and THEN `chmod(0o600)`, swallowing a chmod failure. Measured
        2026-08-13: a freshly created token file is 0644 under the default umask for the whole gap
        between the two calls, and if the chmod fails it stays 0644 with a live OAuth token in it —
        permanently, silently, because the OSError was passed. `os.open` with an explicit mode
        creates the file correct in ONE syscall, so there is no gap and no failure to swallow.

        The directory gets 0700 for the same reason. `~/.gawk` itself is already 0700, so today the
        parent is what protects this store — but a mode on the object survives a copy, a backup and
        a change to the parent, and every sibling store (`history.json`, `runs.db`,
        `enforce-audit.db`) is already 0600. This one was the exception.
        """
        _STORE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            _STORE_DIR.chmod(0o700)
        except OSError:
            pass                      # a directory we cannot narrow is not a reason to lose a login
        payload = json.dumps(data).encode("utf-8")
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
        # O_CREAT honours the mode only when the file is NEW; an existing file keeps whatever mode
        # it already had, including a 0644 left behind by the old code path. Narrow it explicitly so
        # a store written before this fix is repaired the next time a token is refreshed.
        try:
            self._path.chmod(0o600)
        except OSError:
            pass

    async def get_tokens(self) -> Optional[OAuthToken]:
        d = self._read().get("tokens")
        return OAuthToken.model_validate(d) if d else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        d = self._read()
        d["tokens"] = tokens.model_dump(mode="json", exclude_none=True)
        self._write(d)

    async def get_client_info(self) -> Optional[OAuthClientInformationFull]:
        d = self._read().get("client_info")
        return OAuthClientInformationFull.model_validate(d) if d else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        d = self._read()
        d["client_info"] = client_info.model_dump(mode="json", exclude_none=True)
        self._write(d)


def build_login_provider(server_url: str, scope: str = "") -> tuple[OAuthClientProvider, HTTPServer]:
    """Construct an OAuthClientProvider that opens the system browser for approval and catches the
    redirect on a local loopback port. Returns (provider, callback_server); the caller MUST call
    server.shutdown() when the scan is done."""
    _SdkFlowLog.last = None          # a stale reason must never explain a NEW flow's failure
    captured: dict[str, Optional[str]] = {"code": None, "state": None}
    done = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            qs = parse_qs(urlparse(self.path).query)
            # A cancelled or malformed callback has no code. Recorded as EMPTY, not None: the
            # waiter checks for a value, and an absent one must read as "no code came back".
            captured["code"] = (qs.get("code") or [""])[0]
            captured["state"] = (qs.get("state") or [""])[0]
            body = (b"<html><body style='font:16px system-ui;padding:3rem'>"
                    b"<h2>Sign-in complete.</h2><p>You can close this tab and return to your terminal.</p>"
                    b"</body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            done.set()

        def log_message(self, *args) -> None:  # silence default request logging
            pass

    # Bind first (port 0 = ephemeral) so the redirect URI is known before client registration.
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    redirect_uri = f"http://127.0.0.1:{server.server_port}/callback"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    client_metadata = OAuthClientMetadata(
        redirect_uris=[AnyUrl(redirect_uri)],
        token_endpoint_auth_method="none",              # public client + PKCE
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope=scope or None,
        client_name="mcpgawk",
    )

    async def _redirect(auth_url: str) -> None:
        print(f"\n  Opening your browser to sign in…\n"
              f"  If it doesn't open, paste this into a browser:\n    {auth_url}\n", flush=True)
        try:
            webbrowser.open(auth_url)
        except Exception:  # noqa: BLE001 — headless/no-browser: the printed URL is the fallback
            pass

    async def _callback() -> AuthorizationCodeResult:
        await asyncio.to_thread(done.wait, 300)
        if not captured["code"]:
            raise TimeoutError("no authorization code received within 5 minutes")
        return AuthorizationCodeResult(code=captured["code"], state=captured["state"])

    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=FileTokenStorage(server_url),
        redirect_handler=_redirect,
        callback_handler=_callback,
    )
    return provider, server
