"""The `--login` OAuth round-trip, driven for real against a real authorization server.

Nothing tested this before. `test_remote_login_verify.py` only checks that an ALREADY-stored token
gets replayed into a verify config; the flow that obtains one — discover the AS, register a client,
PKCE, catch the redirect on the loopback, exchange the code — had never been exercised by anything,
which for the product's own "#1 thing a real first run hits" is the wrong place to have no test.

What is real here: dynamic client registration, the S256 PKCE challenge/verifier pair (the fixture
recomputes and rejects a bad one), the ephemeral loopback callback server that `build_login_provider`
binds, the code-for-token exchange, and the authenticated MCP handshake that follows.

What is stubbed: exactly one thing — `webbrowser.open`, replaced by a fetch of the authorize URL
that follows the 302. That stands in for the human clicking "Approve", and nothing else.
"""
from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from mcpgawk import oauth_login
from mcpgawk.probe import probe_url

FIXTURE = Path(__file__).parent / "fixtures" / "oauth_mcp_server.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def oauth_base():
    """A real OAuth-protected MCP server in its own process; yields its base URL."""
    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(FIXTURE), "--port", str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.stdout.readline().startswith("LISTENING"):
                break
            if proc.poll() is not None:
                raise RuntimeError(f"fixture died: {proc.stderr.read()[:400]}")
        else:
            raise RuntimeError("fixture never reported LISTENING")
        yield f"http://127.0.0.1:{port}"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Redirect the token store. `_STORE_DIR` is read at import time, so the real ~/.gawk/oauth
    would otherwise be written to by a test run."""
    path = tmp_path / "oauth"
    monkeypatch.setattr(oauth_login, "_STORE_DIR", path)
    return path


@pytest.fixture
def clicks(monkeypatch):
    """The human at the browser. Returns the list of URLs the product asked to open, so a test can
    assert BOTH that sign-in happened once and that it did not happen twice."""
    opened: list[str] = []

    def fake_open(url, *args, **kwargs):
        opened.append(url)

        # In a thread: the provider is already awaiting the loopback callback, and following the
        # redirect is what delivers ?code= to it.
        def approve():
            try:
                httpx.get(url, follow_redirects=True, timeout=20)
            except Exception:  # noqa: BLE001 — a failure surfaces as the provider's own timeout
                pass

        threading.Thread(target=approve, daemon=True).start()
        return True

    monkeypatch.setattr(oauth_login.webbrowser, "open", fake_open)
    return opened


def _scan_with_login(base: str):
    """Exactly what `mcpgawk scan --http <url> --login` does: build the provider, probe with it,
    and never permute (a credential must not be offered to other paths)."""
    # Trailing slash on purpose: the fixture mounts the MCP app at /mcp, and the login path does
    # NOT permute, so there is no second candidate to fall back to if the mount redirects.
    auth, callback = oauth_login.build_login_provider(f"{base}/mcp/")
    try:
        return asyncio.run(probe_url("oauth", f"{base}/mcp/", auth=auth, permute=False))
    finally:
        callback.shutdown()


def test_login_signs_in_and_then_measures_the_server(oauth_base, store, clicks):
    """The whole point: after signing in, the server is MEASURED — not merely reachable."""
    snap = _scan_with_login(oauth_base)

    assert snap.error is None, f"authenticated scan failed: {snap.error}"
    assert {t["name"] for t in snap.tools} == {"list_repos", "read_issue"}
    assert len(clicks) == 1, "expected exactly one browser hand-off"
    # Proof the flow was the real one, not a shortcut: PKCE and a registered client id.
    assert "code_challenge_method=S256" in clicks[0]
    assert "client_id=dcr-" in clicks[0]


def test_the_token_is_stored_for_next_time_and_kept_private(oauth_base, store, clicks):
    _scan_with_login(oauth_base)

    files = list(store.glob("*.json"))
    assert len(files) == 1, f"expected one per-server token file, got {files}"
    assert oct(files[0].stat().st_mode & 0o777) == "0o600", "a token file must not be world-readable"
    saved = json.loads(files[0].read_text())
    assert saved["tokens"]["access_token"], "no access token was persisted"


def test_a_second_scan_reuses_the_token_and_never_opens_a_browser(oauth_base, store, clicks):
    """Sign in ONCE. A tool that re-prompts on every scan is one people stop running."""
    first = _scan_with_login(oauth_base)
    assert first.error is None
    assert len(clicks) == 1

    second = _scan_with_login(oauth_base)

    assert second.error is None, f"second scan failed: {second.error}"
    assert {t["name"] for t in second.tools} == {"list_repos", "read_issue"}
    assert len(clicks) == 1, "the stored token was not reused — the user was asked to sign in again"


def test_the_access_token_never_reaches_the_snapshot(oauth_base, store, clicks):
    """The credential is for the connection, not for anything we record or print."""
    snap = _scan_with_login(oauth_base)
    token = json.loads(next(iter(store.glob("*.json"))).read_text())["tokens"]["access_token"]

    assert token not in json.dumps(snap.tools)
    assert token not in (snap.error or "")
