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
import time
import uuid
import webbrowser
from datetime import datetime, timezone
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
def _store_dir() -> Path:
    """Read the redirect AT USE, not at import. As a module constant it was fixed the moment
    this module was first imported — before the test session's redirect was set for any test
    file importing it at the top — so such a test wrote a token document into the founder's
    REAL `~/.gawk/oauth` (2026-09-03, caught by the real-home tripwire)."""
    return Path(os.environ.get("GAWK_OAUTH_STORE") or (Path.home() / ".gawk" / "oauth"))


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


def mark_inband_login(server_url: str) -> str:
    """Record that a human completed a server's OWN in-band sign-in for `server_url`, and return
    the minted `login_id`.

    kite issues no OAuth token — its login binds to the one MCP session that asked — so nothing
    in this store ever said "a person signed in here". The panel's tile therefore asked for a
    sign-in forever, including right after one succeeded (founder, 2026-09-04: "when i signed in
    to kite successfully still it shows the login to kite tile"). Same document, same writer and
    mode as the OAuth path; `tokens` (if a server has both) are left untouched. The id is minted
    per completed sign-in, exactly as `set_tokens` mints it for a browser flow, so `drift.compare`
    treats a second sign-in the same way for both kinds of server.
    """
    storage = FileTokenStorage(server_url)
    d = storage._read()
    d["login_id"] = uuid.uuid4().hex[:12]
    d["logged_in_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    d["inband_login"] = True
    storage._write(d)
    return d["login_id"]


def last_flow_error() -> str | None:
    """The SDK's own words for why the most recent OAuth flow died, or None if it did not."""
    return _SdkFlowLog.last


class FileTokenStorage:
    """Per-server token + client-registration store on the local disk (mode 0600). Local-first:
    a scanned credential is never transmitted anywhere — it only unlocks the connection mcpgawk
    makes from this machine."""

    def __init__(self, server_url: str) -> None:
        key = hashlib.sha256(server_url.encode()).hexdigest()[:16]
        self._path = _store_dir() / f"{key}.json"
        self._new_login = False

    def arm_new_login(self) -> None:
        """A human just completed the browser flow on THIS storage — stamp the next token write.

        Armed from the authorization-code callback, which a refresh never reaches. That is the
        whole discriminator: a refresh rewrites the tokens, a sign-in rewrites WHO.
        """
        self._new_login = True

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
        _store_dir().mkdir(parents=True, exist_ok=True)
        try:
            _store_dir().chmod(0o700)
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
        """Store the tokens, and stamp WHICH SIGN-IN they belong to.

        `login_id` is minted by our own act (a completed browser flow), not read off a credential:
        no MCP token on this machine is a JWT and none carries an `id_token`, so there is no issuer
        or subject to derive an account from — measured on the founder's store 2026-09-02, three
        stored logins, access tokens of 9/86/426 chars, not one JWT-shaped. What CAN be known is
        that the sign-in behind these tokens is a DIFFERENT sign-in from the one behind an approved
        baseline, which is exactly when reusing that baseline stops being safe.

        PRESERVED ACROSS REFRESHES BY CONSTRUCTION: this merges into the existing document and only
        re-mints when `arm_new_login` says a browser flow just completed. A value that moved on
        every refresh would be the notion bug again — new identity, first sighting, silence.
        """
        d = self._read()
        d["tokens"] = tokens.model_dump(mode="json", exclude_none=True)
        # WHEN these tokens were obtained. The SDK computes an expiry only for tokens it set in
        # the same process; a token loaded from disk has no expiry and is treated as valid
        # forever — sent stale, 401, browser flow, never a refresh (notion, 2026-09-03).
        d["tokens_obtained_at"] = time.time()
        if self._new_login or not d.get("login_id"):
            # Back-filling an existing store is safe: `drift.compare` claims nothing when either
            # side lacks the field, so a store that gains its first id does not report a change.
            d["login_id"] = uuid.uuid4().hex[:12]
            d["logged_in_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._new_login = False
        self._write(d)

    async def get_client_info(self) -> Optional[OAuthClientInformationFull]:
        d = self._read().get("client_info")
        return OAuthClientInformationFull.model_validate(d) if d else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        d = self._read()
        d["client_info"] = client_info.model_dump(mode="json", exclude_none=True)
        self._write(d)


#: The PINNED callback port for pre-registered OAuth clients. A DCR-refusing server (figma,
#: Slack — enterprise posture) only accepts redirect URIs registered in advance, and a redirect
#: that moves is exactly the bug Claude Code shipped 2.1.231 to fix. Dynamic registration keeps
#: its ephemeral port; pre-registered clients use this one, always.
PINNED_CALLBACK_PORT = 33418


def store_preregistered_client(server_url: str, client_id: str,
                               client_secret: str | None = None,
                               redirect_uri: str | None = None) -> str:
    """Store a PRE-REGISTERED OAuth client for a server that refuses Dynamic Client
    Registration (403 on the registration endpoint — figma's measured behaviour, 2026-08-14).

    Returns the redirect URI the operator must register with the provider — pinned, because a
    pre-registered client's redirect must match EXACTLY. The client info lands in the same
    0600 store the tokens use; `build_login_provider` then skips DCR and binds the pinned port.
    """
    uri = redirect_uri or f"http://127.0.0.1:{PINNED_CALLBACK_PORT}/callback"
    info = OAuthClientInformationFull(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=[AnyUrl(uri)],
        token_endpoint_auth_method="client_secret_post" if client_secret else "none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="mcpgawk",
    )
    storage = FileTokenStorage(server_url)
    # SYNCHRONOUS on purpose. This used to `asyncio.run(storage.set_client_info(info))`, and the
    # one caller — `cli._run`, an async function — is already inside a running loop, so the
    # shipped `--oauth-client-id` route died with "asyncio.run() cannot be called from a running
    # event loop" on its first real use (founder, figma, 2026-09-04). The unit test called this
    # helper from outside any loop and stayed green. `set_client_info` only does file IO.
    d = storage._read()
    d["client_info"] = info.model_dump(mode="json", exclude_none=True)
    # Mark it OPERATOR-registered: the SDK also stores client info after ordinary dynamic
    # registration (with an ephemeral redirect port), and pinning THAT port broke every
    # second login. Only a client the operator supplied carries an immovable redirect.
    d["preregistered"] = True
    storage._write(d)
    return uri


class LoginNeeded(RuntimeError):
    """The stored login cannot be refreshed and a browser sign-in is required. Raised INSTEAD of
    opening a browser by the refresh-only provider, so an unattended scan can classify it as
    auth-required and say so, rather than spawn a browser tab nobody asked for."""


def refresh_only_provider(server_url: str) -> Optional[OAuthClientProvider]:
    """An OAuth provider over the STORED login that refreshes an expired access token and never
    opens a browser. None when nothing refreshable is stored.

    THE DEFECT THIS CLOSES (measured on notion, 2026-09-03): the scan path attached the stored
    access token as a static `Authorization: Bearer …` header. notion's tokens live eight hours
    (`expires_in: 28800`); the store held one from 2026-08-27 22:26 AND a refresh token, and
    every scan since has said "needs credentials — not scanned". The refresh token was on disk
    the whole time; nothing on the scan path ever used it. `build_login_provider` does refresh —
    through the SDK — but it also starts a callback server and opens a browser when the refresh
    fails, which an unattended scan must never do. This is the same provider with the browser
    half replaced by a refusal.
    """
    storage = FileTokenStorage(server_url)
    doc = storage._read()
    tokens = doc.get("tokens") or {}
    if not tokens.get("refresh_token"):
        return None
    client_metadata = OAuthClientMetadata(
        redirect_uris=[AnyUrl("http://127.0.0.1:1/callback")],   # never used: no browser flow
        token_endpoint_auth_method=("none" if not doc.get("preregistered")
                                    else str(((doc.get("client_info") or {})
                                              .get("token_endpoint_auth_method")) or "none")),
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="mcpgawk",
    )

    async def _no_browser(auth_url: str) -> None:
        raise LoginNeeded(f"the stored login for {server_url} could not be refreshed — sign in "
                          f"again: mcpgawk scan --http {server_url} --login")

    async def _no_callback() -> AuthorizationCodeResult:
        raise LoginNeeded(f"the stored login for {server_url} could not be refreshed — sign in "
                          f"again: mcpgawk scan --http {server_url} --login")

    # THE EXPIRY THE SDK DOES NOT KNOW. `OAuthClientProvider._initialize` loads tokens from
    # storage and leaves `token_expiry_time` unset, so `is_token_valid()` is True for a token
    # that expired days ago; the refresh branch is skipped, the stale token is sent, the 401
    # goes straight to the browser flow. Hand it the real expiry from our own obtained-at
    # stamp — or, for a store written before that stamp existed, force a refresh before the
    # first request (an expiry of 1.0 — a POSITIVE instant in 1970; the SDK reads a zero as
    # "unknown" and therefore valid): one cheap round trip, and the refresh response sets the
    # real expiry from then on.
    obtained = doc.get("tokens_obtained_at")
    expires_in = tokens.get("expires_in")
    expiry = (float(obtained) + float(expires_in)
              if isinstance(obtained, (int, float)) and isinstance(expires_in, (int, float))
              else 1.0)

    class _KnowsExpiry(OAuthClientProvider):
        async def _initialize(self) -> None:
            await super()._initialize()
            self.context.token_expiry_time = expiry

    provider = _KnowsExpiry(server_url=server_url, client_metadata=client_metadata,
                            storage=storage, redirect_handler=_no_browser,
                            callback_handler=_no_callback)
    provider.known_expiry = expiry            # visible, so a test can pin the arithmetic
    return provider


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

    # A PRE-REGISTERED client (stored via store_preregistered_client) pins everything: its
    # redirect URI is registered with the provider and cannot move, so the callback binds that
    # exact port — loudly failing if it is taken beats silently authing with a mismatched
    # redirect (Claude Code 2.1.231's bug class). Otherwise: ephemeral port + DCR, as before.
    _pre_store = FileTokenStorage(server_url)
    # Read SYNCHRONOUSLY: this runs inside `cli._run`'s loop, where `asyncio.run` raises — the
    # second such line on the `--oauth-client-id` route to die on its first real use (figma,
    # 2026-09-04), one call after the first was fixed. The store is a file; no loop is needed.
    _pre_doc = _pre_store._read()
    _pre = (OAuthClientInformationFull.model_validate(_pre_doc["client_info"])
            if _pre_doc.get("preregistered") and _pre_doc.get("client_info") else None)
    if _pre is not None and _pre.redirect_uris:
        _pre_uri = urlparse(str(_pre.redirect_uris[0]))
        try:
            server = HTTPServer(("127.0.0.1", _pre_uri.port or PINNED_CALLBACK_PORT), _Handler)
        except OSError as exc:
            raise RuntimeError(
                f"the pre-registered redirect port {_pre_uri.port} is in use ({exc}) — a "
                f"registered redirect URI cannot move; free the port and retry") from exc
        redirect_uri = str(_pre.redirect_uris[0])
    else:
        # Bind first (port 0 = ephemeral) so the redirect URI is known before registration.
        server = HTTPServer(("127.0.0.1", 0), _Handler)
        redirect_uri = f"http://127.0.0.1:{server.server_port}/callback"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    client_metadata = OAuthClientMetadata(
        redirect_uris=[AnyUrl(redirect_uri)],
        token_endpoint_auth_method=(_pre.token_endpoint_auth_method
                                    if _pre is not None else "none"),  # public client + PKCE
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

    storage = FileTokenStorage(server_url)

    async def _callback() -> AuthorizationCodeResult:
        await asyncio.to_thread(done.wait, 300)
        if not captured["code"]:
            raise TimeoutError("no authorization code received within 5 minutes")
        # A code came back, so a PERSON just approved this in a browser. Only this path arms the
        # new-sign-in stamp; the SDK's refresh reaches `set_tokens` without ever coming through
        # here, which is what keeps a refresh from looking like a change of account.
        storage.arm_new_login()
        return AuthorizationCodeResult(code=captured["code"], state=captured["state"])

    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=_redirect,
        callback_handler=_callback,
    )
    return provider, server
