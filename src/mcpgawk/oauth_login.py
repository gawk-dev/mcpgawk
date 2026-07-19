"""`gawk scan --login` — trigger the OAuth login for a remote MCP server, natively.

Wraps the `mcp` SDK's own `OAuthClientProvider` (already a dependency, no new install) so a remote
OAuth-protected server can be scanned: on first connect the system browser opens, the user approves
once, and the token is stored locally (`~/.gawk/oauth`, mode 0600) and refreshed automatically
thereafter. No Node/`mcp-remote`, no from-scratch OAuth stack — and the token never leaves the
machine (the local-first posture buyers in the MCP ecosystem explicitly ask for; the SDK handles
DCR + PKCE + refresh, and the pre-registered-client fallback for servers like GitHub that opt out
of Dynamic Client Registration).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

_STORE_DIR = Path.home() / ".gawk" / "oauth"


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
        _STORE_DIR.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data))
        try:
            self._path.chmod(0o600)  # a token is a credential — not world-readable
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
    captured: dict[str, Optional[str]] = {"code": None, "state": None}
    done = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            qs = parse_qs(urlparse(self.path).query)
            captured["code"] = (qs.get("code") or [None])[0]
            captured["state"] = (qs.get("state") or [None])[0]
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
        redirect_uris=[redirect_uri],
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

    async def _callback() -> tuple[str, Optional[str]]:
        await asyncio.to_thread(done.wait, 300)
        if not captured["code"]:
            raise TimeoutError("no authorization code received within 5 minutes")
        return captured["code"], captured["state"]

    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=FileTokenStorage(server_url),
        redirect_handler=_redirect,
        callback_handler=_callback,
    )
    return provider, server
