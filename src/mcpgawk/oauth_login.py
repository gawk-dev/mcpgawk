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
import base64
import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from pydantic import AnyUrl
from mcp.client.auth import OAuthClientProvider
from mcp.client.auth import oauth2 as _sdk_oauth2
from mcp.client.auth.utils import issuers_match
# The ORIGINAL check, from the module we never patch. Taking it from `oauth2`'s attribute made the
# shim capture itself when this module was re-imported, and recurse (full suite, 2026-09-24).
from mcp.client.auth.utils import validate_metadata_issuer as _sdk_validate_metadata_issuer
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


def _validate_metadata_issuer(oauth_metadata, expected_issuer: str) -> None:
    """The SDK's own issuer check, with the SDK's own root-slash rule applied on every path.

    Semgrep (2026-09-24): its resource metadata names its login host WITH a trailing slash, its
    authorization server metadata WITHOUT one. The SDK already treats a
    root issuer with and without its trailing slash as one server (`issuers_match`), but only
    on the legacy no-resource-metadata path, so this sign-in failed while Claude's succeeded.
    Nothing looser: a path issuer or a different origin is still refused by the SDK's check.
    """
    if issuers_match(str(oauth_metadata.issuer), expected_issuer):
        return
    _sdk_validate_metadata_issuer(oauth_metadata, expected_issuer)


_sdk_oauth2.validate_metadata_issuer = _validate_metadata_issuer


def _fit_auth_method_to_server(provider: OAuthClientProvider) -> OAuthClientProvider:
    """Send a client secret the way THIS server says it accepts, not the way we guessed.

    Basic is the default (RFC 6749 §2.3.1: every server MUST support it; the conformance suite's
    auth/pre-registration requires it). But servers advertise what they accept, and some list only
    body auth: HubSpot's metadata says `client_secret_post` alone (survey, 2026-09-24). So at token
    time, if the server lists its methods and ours is not among them, switch to one it does list.
    The server's own metadata is the quirk catalogue here; nothing is hard-coded per provider."""
    ctx = provider.context
    original = ctx.prepare_token_auth

    def prepare(data, headers=None):
        info, meta = ctx.client_info, ctx.oauth_metadata
        supported = getattr(meta, "token_endpoint_auth_methods_supported", None) if meta else None
        if info is not None and info.client_secret and supported \
                and info.token_endpoint_auth_method not in supported:
            for method in ("client_secret_basic", "client_secret_post"):
                if method in supported:
                    info.token_endpoint_auth_method = method
                    break
        return original(data, headers)

    ctx.prepare_token_auth = prepare  # type: ignore[method-assign]  # deliberate SDK wrap
    return provider


def lock_refreshes(provider: OAuthClientProvider, server_url: str) -> OAuthClientProvider:
    """T2-6: one refresh at a time per server, across processes.

    The gateway and the scanner share one stored sign-in. A provider that ROTATES refresh tokens
    invalidates the old one on use, so two simultaneous refreshes leave the loser holding a spent
    token — signed out. A per-server file lock is held from building the refresh request until its
    response is stored; whoever waited re-reads the store first and refreshes with the NEWEST
    token. No locking primitive (non-POSIX) or a lock not freed in 30 s: proceed unlocked —
    observing must never block traffic."""
    try:
        import fcntl
    except ImportError:                                   # pragma: no cover - Windows
        return provider
    lock_path = FileTokenStorage(server_url)._path.with_suffix(".lock")
    held: dict[str, Any] = {"fd": None}
    build, handle = provider._refresh_token, provider._handle_refresh_response

    def _release() -> None:
        fd, held["fd"] = held["fd"], None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    async def refresh_token():
        _release()                                        # a stale hold from a dead refresh
        _store_dir().mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held["fd"] = fd
                break
            except OSError:
                if time.monotonic() > deadline:
                    os.close(fd)
                    break
                await asyncio.sleep(0.05)
        latest = await provider.context.storage.get_tokens()
        if latest is not None and latest.refresh_token:
            provider.context.current_tokens = latest       # never spend a token someone else spent
        return await build()

    async def handle_refresh_response(response):
        try:
            return await handle(response)
        finally:
            _release()

    # Deliberate wraps of the SDK's refresh path (one refresh at a time, per server, across processes).
    provider._refresh_token = refresh_token  # type: ignore[method-assign]
    provider._handle_refresh_response = handle_refresh_response  # type: ignore[method-assign]
    provider._mcpgawk_refresh_lock = True  # type: ignore[attr-defined]  # our marker on the SDK object
    return provider


def _with_rfc7591_default(client_info: OAuthClientInformationFull) -> OAuthClientInformationFull:
    """A registration that issued a secret but named no method gets RFC 7591's default,
    `client_secret_basic`. Supabase (2026-09-24) registers exactly that; the SDK reads an absent
    method as "none", never sends the secret, and the token exchange answers 422. Only the
    absent case changes: an explicit "none" (Neon, which works) is left as the server said.
    Mutates in place because the SDK keeps this same object in its live context."""
    if client_info.client_secret and client_info.token_endpoint_auth_method is None:
        client_info.token_endpoint_auth_method = "client_secret_basic"
    return client_info


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


# --- T2-3: the store is encrypted at rest (FOUNDER 2026-09-24, "keychain ok") ---------------------
#
# AES-GCM over the whole per-server document. The 256-bit key lives in the macOS login Keychain
# (service below), created on first use — one system prompt, once. Elsewhere, or when the Keychain
# is unavailable, a 0600 key file beside the store. GAWK_OAUTH_KEY_BACKEND=keychain|file forces one;
# the test session and the demo force `file` so they can never touch a real Keychain.
# A plaintext document written before this is still read, and is encrypted on its next write.

_KEYCHAIN_SERVICE = "mcpgawk-oauth-store"
_ENC_AAD = b"mcpgawk-oauth-v1"
_store_key_cache: dict[str, bytes] = {}


def _reset_store_key_cache() -> None:
    _store_key_cache.clear()


def _key_backend() -> str:
    forced = (os.environ.get("GAWK_OAUTH_KEY_BACKEND") or "").strip().lower()
    if forced in ("keychain", "file"):
        return forced
    return "keychain" if sys.platform == "darwin" else "file"


def _file_key() -> bytes:
    path = _store_dir() / ".store-key"
    try:
        key = path.read_bytes()
        if len(key) == 32:
            return key
    except OSError:
        pass
    _store_dir().mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _keychain_key() -> bytes | None:
    account = str(_store_dir())          # one key per store location
    try:
        got = subprocess.run(["security", "find-generic-password", "-a", account,
                              "-s", _KEYCHAIN_SERVICE, "-w"],
                             capture_output=True, text=True, timeout=30)
        if got.returncode == 0 and got.stdout.strip():
            key = base64.b64decode(got.stdout.strip())
            if len(key) == 32:
                return key
        key = os.urandom(32)
        # The key crosses argv once, at creation, on this machine only; `security` offers no
        # stdin form for -w. It protects tokens at rest, not against a process watching argv.
        made = subprocess.run(["security", "add-generic-password", "-a", account,
                               "-s", _KEYCHAIN_SERVICE, "-w", base64.b64encode(key).decode(), "-U"],
                              capture_output=True, text=True, timeout=30)
        return key if made.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _store_key() -> bytes:
    cached = _store_key_cache.get(str(_store_dir()))
    if cached:
        return cached
    key = _keychain_key() if _key_backend() == "keychain" else None
    if key is None:
        key = _file_key()                # no Keychain (or it refused): a 0600 file, never plaintext
    _store_key_cache[str(_store_dir())] = key
    return key


def _encrypt_doc(data: dict) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(_store_key()).encrypt(nonce, json.dumps(data).encode("utf-8"), _ENC_AAD)
    return json.dumps({"mcpgawk_enc": 1, "nonce": base64.b64encode(nonce).decode(),
                       "ct": base64.b64encode(ct).decode()}).encode("utf-8")


def _decrypt_doc(doc: dict) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        plain = AESGCM(_store_key()).decrypt(base64.b64decode(doc["nonce"]),
                                             base64.b64decode(doc["ct"]), _ENC_AAD)
        return json.loads(plain)
    except Exception:  # noqa: BLE001 — a lost/changed key: the login is unusable, say so upstream
        print("mcpgawk: a stored sign-in could not be decrypted (its key changed) — sign in again",
              file=sys.stderr)
        return {}


def stored_login_unreadable(server_url: str) -> bool:
    """A sign-in IS stored for this server but cannot be decrypted (its key changed or was lost).
    Distinct from "never signed in", so the row can say what actually happened (RC3)."""
    try:
        doc = json.loads(FileTokenStorage(server_url)._path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not (isinstance(doc, dict) and doc.get("mcpgawk_enc") == 1):
        return False
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        AESGCM(_store_key()).decrypt(base64.b64decode(doc["nonce"]), base64.b64decode(doc["ct"]), _ENC_AAD)
        return False
    except Exception:  # noqa: BLE001 — any failure to open it is "unreadable"
        return True


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
            doc = json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
        if isinstance(doc, dict) and doc.get("mcpgawk_enc") == 1:
            return _decrypt_doc(doc)
        return doc if isinstance(doc, dict) else {}      # plaintext from before T2-3

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
        payload = _encrypt_doc(data)
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
        return _with_rfc7591_default(OAuthClientInformationFull.model_validate(d)) if d else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        _with_rfc7591_default(client_info)
        d = self._read()
        d["client_info"] = client_info.model_dump(mode="json", exclude_none=True)
        self._write(d)


#: The PINNED callback port for pre-registered OAuth clients. A DCR-refusing server (figma,
#: Slack — enterprise posture) only accepts redirect URIs registered in advance, and a redirect
#: that moves is exactly the bug Claude Code shipped 2.1.231 to fix. Dynamic registration keeps
#: its ephemeral port; pre-registered clients use this one, always.
PINNED_CALLBACK_PORT = 33418

#: mcpgawk's OAuth client ID as a Client ID Metadata Document (CIMD). The MCP spec deprecates Dynamic
#: Client Registration and says clients SHOULD support CIMD: the client ID is a URL we host, so there is
#: nothing to register, lose or redo, and no allow-list keyed on a registered name to fail (figma's 403
#: for "mcpgawk", 2026-09-03). The SDK uses it only where the server advertises support and falls back to
#: DCR elsewhere. The document is `site/oauth/client-metadata.json`; its redirect_uris MUST equal
#: CALLBACK_PORTS below (pinned by tests/test_oauth_architecture_constraints.py).
CLIENT_METADATA_URL = "https://mcp.gawk.dev/oauth/client-metadata.json"

#: The loopback ports a sign-in binds, in order. Fixed and few, so a redirect never moves between
#: sign-ins (the random port broke Supabase, 2026-09-24) and every one is listed in the CIMD document.
#: Not 33418: that is VS Code's documented loopback port (and PINNED_CALLBACK_PORT's legacy value).
CALLBACK_PORTS = (47391, 47392, 47393)


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
        # HTTP Basic, not body: RFC 6749 §2.3.1 obliges every server to support Basic, and the
        # official conformance suite's auth/pre-registration FAILED on body auth (2026-09-24).
        token_endpoint_auth_method="client_secret_basic" if client_secret else "none",
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


from mcp.client.auth.exceptions import OAuthFlowError as _OAuthFlowError  # noqa: E402


class SignInIncomplete(_OAuthFlowError):
    """The person did not finish the browser sign-in: no approval arrived in time, or they declined.
    Nothing broke. An OAuth-typed error so the scan reports it as a sign-in, never as "no MCP
    endpoint found" (K4, Attio 2026-09-24); `sign_in_incomplete` lets the classifier tell it from a
    sign-in that genuinely failed without importing this module."""
    sign_in_incomplete = True


class SignInTimedOut(SignInIncomplete, TimeoutError):
    """No authorization code within the wait. Still a TimeoutError for existing handlers."""


class SignInNotCompleted(SignInIncomplete, RuntimeError):
    """The authorization server returned an error (e.g. access_denied). Still a RuntimeError."""


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
        token_endpoint_auth_method=("none" if not doc.get("preregistered")  # type: ignore[arg-type]
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
        known_expiry: float | None = None

        async def _initialize(self) -> None:
            await super()._initialize()
            self.context.token_expiry_time = expiry

    provider = _KnowsExpiry(server_url=server_url, client_metadata=client_metadata,
                            storage=storage, redirect_handler=_no_browser,
                            callback_handler=_no_callback)
    provider.known_expiry = expiry            # visible, so a test can pin the arithmetic
    return lock_refreshes(_fit_auth_method_to_server(provider), server_url)


def build_login_provider(server_url: str, scope: str = "") -> tuple[OAuthClientProvider, HTTPServer]:
    """Construct an OAuthClientProvider that opens the system browser for approval and catches the
    redirect on a local loopback port. Returns (provider, callback_server); the caller MUST call
    server.shutdown() when the scan is done."""
    _SdkFlowLog.last = None          # a stale reason must never explain a NEW flow's failure
    captured: dict[str, Optional[str]] = {"code": None, "state": None, "iss": None, "error": None}
    done = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            qs = parse_qs(urlparse(self.path).query)
            # A cancelled or malformed callback has no code. Recorded as EMPTY, not None: the
            # waiter checks for a value, and an absent one must read as "no code came back".
            captured["code"] = (qs.get("code") or [""])[0]
            captured["state"] = (qs.get("state") or [""])[0]
            # RFC 9207 `iss`. Dropping it failed Linear, Sentry and Globalping (2026-09-24): they
            # advertise it, so the SDK refuses a redirect without it. None when absent, NEVER "":
            # the SDK reads any non-None value as present-and-must-match.
            captured["iss"] = qs["iss"][0] if qs.get("iss") else None
            captured["error"] = " — ".join(v[0] for k in ("error", "error_description")
                                           if (v := qs.get(k))) or None
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
        # A server that matches redirect_uri EXACTLY (Supabase, 2026-09-24) refuses a sign-in whose
        # loopback port differs from the one its earlier dynamic registration recorded — and the
        # SDK reuses that stored registration. So come back on the registered port; if it is taken,
        # drop the registration we can no longer serve and let the SDK register afresh.
        server = None
        _dyn = _pre_doc.get("client_info") or {}
        _dyn_port = next((urlparse(u).port for u in _dyn.get("redirect_uris") or []
                          if urlparse(u).hostname == "127.0.0.1" and urlparse(u).port), None)
        if _dyn_port:
            try:
                server = HTTPServer(("127.0.0.1", _dyn_port), _Handler)
            except OSError:
                _pre_doc.pop("client_info", None)
                _pre_store._write(_pre_doc)
        # A fresh sign-in binds the first free fixed port: every one is listed in the CIMD document,
        # and a DCR registration made on it stays valid for the next sign-in.
        for _port in CALLBACK_PORTS if server is None else ():
            try:
                server = HTTPServer(("127.0.0.1", _port), _Handler)
                break
            except OSError:
                continue
        if server is None:
            # All fixed ports busy (three sign-ins at once). An ephemeral port still works for DCR;
            # a CIMD server will refuse it, which the flow reports rather than hides.
            server = HTTPServer(("127.0.0.1", 0), _Handler)
        redirect_uri = f"http://127.0.0.1:{server.server_port}/callback"
    assert server is not None   # both branches above bind a server or raise
    threading.Thread(target=server.serve_forever, daemon=True).start()

    client_metadata = OAuthClientMetadata(
        redirect_uris=[AnyUrl(redirect_uri)],
        token_endpoint_auth_method=(_pre.token_endpoint_auth_method  # type: ignore[arg-type]
                                    if _pre is not None else "none"),  # public client + PKCE
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope=scope or None,
        client_name="mcpgawk",
    )

    async def _redirect(auth_url: str) -> None:
        print(f"\n  Opening your browser to sign in…\n"
              f"  If it doesn't open, paste this into a browser:\n    {auth_url}\n", flush=True)
        if os.environ.get("MCPGAWK_NO_BROWSER"):
            return                                  # the panel's/tests' guard; the printed URL stands
        try:
            webbrowser.open(auth_url)
        except Exception:  # noqa: BLE001 — headless/no-browser: the printed URL is the fallback
            pass

    storage = FileTokenStorage(server_url)

    async def _callback() -> AuthorizationCodeResult:
        await asyncio.to_thread(done.wait, 300)
        # One redirect answers one authorization. Without this a scope step-up (a second
        # authorization inside the same provider) got the FIRST sign-in's code and state back
        # at once (conformance auth/scope-step-up, 2026-09-24: "State parameter mismatch").
        done.clear()
        if captured["error"]:
            raise SignInNotCompleted(f"the sign-in was not completed: {captured['error']}")
        if not captured["code"]:
            raise SignInTimedOut("no authorization code received within 5 minutes")
        # A code came back, so a PERSON just approved this in a browser. Only this path arms the
        # new-sign-in stamp; the SDK's refresh reaches `set_tokens` without ever coming through
        # here, which is what keeps a refresh from looking like a change of account.
        storage.arm_new_login()
        return AuthorizationCodeResult(code=captured["code"], state=captured["state"], iss=captured["iss"])

    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=_redirect,
        callback_handler=_callback,
        # A pre-registered client already has its identity; everyone else offers the CIMD URL.
        client_metadata_url=None if _pre is not None else CLIENT_METADATA_URL,
    )
    return lock_refreshes(_fit_auth_method_to_server(provider), server_url), server
