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
    """Redirect the token store. the store dir is read at use (env GAWK_OAUTH_STORE), so the real ~/.gawk/oauth
    would otherwise be written to by a test run."""
    path = tmp_path / "oauth"
    monkeypatch.setenv("GAWK_OAUTH_STORE", str(path))   # read at use since 2026-09-03
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


def test_a_dead_flow_is_one_honest_line_never_a_traceback_or_a_circle():
    """figma, on the founder's terminal (2026-08-14): the SDK's raw 'OAuth flow error' traceback,
    then our scan-path message advising "retry with `--login`" — from INSIDE the login flow that
    had just failed. A DCR-refusing server (403 on registration) is a dead end; say so."""
    from mcpgawk.cli import _signin_failure_line

    line = _signin_failure_line(
        "figma", "authentication required — retry with `--login`",
        "Registration failed: 403 Forbidden")
    assert "refuses automatic client registration" in line
    assert "403" in line, "the server's own refusal must be quoted"
    # Pin updated deliberately 2026-08-15: BYO-client shipped, so the DCR refusal now names
    # the way THROUGH (--login WITH a pre-registered client) — that is an escape hatch, not
    # the circular bare-retry the original pin banned. The founder's next scan after the
    # feature shipped still read "check figma's documentation"; the message and the
    # capability must never drift apart again.
    assert "--oauth-client-id" in line, "the refusal must name the BYO-client way through"
    assert "developer console" in line and "redirect URI" in line
    assert "retry with `--login`" not in line, "bare retry advice is still circular"

    generic = _signin_failure_line(
        "x", "authentication required — the endpoint is live but refused this scan; "
             "retry with `--login` or `--header ...`", None)
    assert "retry with" not in generic, "we ARE --login; the advice is circular"
    assert "refused this scan" in generic, "the factual half must survive the trim"


def test_the_sdk_traceback_is_captured_not_printed():
    """With no logging configured, the SDK's `logger.exception` fell to Python's last-resort
    stderr handler — a full traceback mid-sign-in. The capture keeps the SDK's words for the
    failure line and stops propagation so the terminal never sees the dump."""
    import logging

    from mcpgawk import oauth_login

    sdk = logging.getLogger("mcp.client.auth.oauth2")
    root_seen: list[logging.LogRecord] = []

    class Root(logging.Handler):
        def emit(self, record):
            root_seen.append(record)

    root_handler = Root()
    logging.getLogger().addHandler(root_handler)
    try:
        try:
            raise ValueError("Registration failed: 403 Forbidden")
        except ValueError:
            sdk.exception("OAuth flow error")
        assert oauth_login.last_flow_error() == "Registration failed: 403 Forbidden"
        assert not root_seen, "the SDK record still propagates — the terminal gets the traceback"
    finally:
        logging.getLogger().removeHandler(root_handler)


def test_a_new_flow_never_wears_the_last_flows_failure():
    from mcpgawk import oauth_login

    oauth_login._SdkFlowLog.last = "Registration failed: 403 Forbidden"
    provider, server = oauth_login.build_login_provider("https://example.invalid/mcp")
    try:
        assert oauth_login.last_flow_error() is None
    finally:
        server.shutdown()


def test_a_preregistered_client_pins_its_redirect_and_skips_registration(tmp_path, monkeypatch):
    """The figma/Slack class: a server that 403s Dynamic Client Registration only accepts a
    client registered in advance — whose redirect URI must match EXACTLY (the Claude Code
    2.1.231 bug class). store_preregistered_client pins the port; build_login_provider binds
    that exact port and matches the stored auth method."""

    from mcpgawk import oauth_login
    monkeypatch.setenv("GAWK_OAUTH_STORE", str(tmp_path))   # read at use since 2026-09-03
    if True:
        uri = oauth_login.store_preregistered_client(
            "https://mcp.example.com/mcp", "client-abc", "sekret-xyz")
        assert uri == f"http://127.0.0.1:{oauth_login.PINNED_CALLBACK_PORT}/callback"

        provider, server = oauth_login.build_login_provider("https://mcp.example.com/mcp")
        try:
            assert server.server_port == oauth_login.PINNED_CALLBACK_PORT, \
                "a registered redirect URI cannot move"
            meta = provider.context.client_metadata
            assert str(meta.redirect_uris[0]) == uri
            assert meta.token_endpoint_auth_method == "client_secret_post"
        finally:
            server.shutdown()

        # A second binder on the pinned port fails LOUDLY, never silently re-registers elsewhere.
        import pytest as _pytest
        with _pytest.raises(RuntimeError, match="cannot move"):
            oauth_login.build_login_provider("https://mcp.example.com/mcp")


def test_sdk_child_cleanup_warnings_lose_their_traceback_but_keep_their_line(capsys):
    """The founder's first-run banner opened with the SDK's terminate_posix_process_tree
    traceback — twice (killpg EPERM on a macOS process group, logged with exc_info and printed
    by Python's last-resort handler, since this CLI configures none). The one-line fact is
    honest and stays; the stack frames are not for the operator's terminal. The filter lives on
    the HANDLER because the record comes from a child logger and propagated records skip
    ancestor loggers' filters."""
    import logging

    from mcpgawk import cli

    import sys as _sys

    cli.main(["runs"])                      # any command installs the last-resort filter
    capsys.readouterr()
    flt = next((f for f in logging.lastResort.filters
                if type(f).__name__ == "_SdkCleanupNoise"), None)
    assert flt is not None, "the last-resort filter was never installed"

    def rec(name: str) -> logging.LogRecord:
        try:
            raise PermissionError(1, "Operation not permitted")
        except PermissionError:
            return logging.LogRecord(
                name=name, level=logging.WARNING, pathname="utilities.py", lineno=32,
                msg="No permission to signal some of process group %d; waiting for it to "
                    "exit anyway", args=(38056,), exc_info=_sys.exc_info())

    sdk = rec("mcp.os.posix.utilities")
    assert flt.filter(sdk) is True, "the record must still be emitted — only the dump goes"
    rendered = logging.Formatter().format(sdk)
    assert "No permission to signal" in rendered, "the honest one-liner must survive"
    assert "Traceback" not in rendered, rendered

    other = rec("urllib3.connectionpool")
    flt.filter(other)
    assert other.exc_info is not None, "non-SDK records must keep their tracebacks"



def test_a_preregistered_client_can_be_stored_from_inside_a_running_loop(tmp_path, monkeypatch):
    """The one real caller, `cli._run`, is async. `store_preregistered_client` used to call
    `asyncio.run` and so raised "cannot be called from a running event loop" the first time the
    shipped `--oauth-client-id` route was used for real (founder, figma, 2026-09-04) — while this
    file's other test, calling it from outside any loop, stayed green."""
    import asyncio
    from mcpgawk import oauth_login, remote_login
    monkeypatch.setenv("GAWK_OAUTH_STORE", str(tmp_path))

    async def inside_a_loop():
        return oauth_login.store_preregistered_client(
            "https://mcp.example.com/mcp", "client-abc", "sekret-xyz",
            "http://localhost:23948/callback")

    uri = asyncio.run(inside_a_loop())
    assert uri == "http://localhost:23948/callback"
    doc = json.loads(remote_login._token_path("https://mcp.example.com/mcp").read_text())
    assert doc["client_info"]["client_id"] == "client-abc" and doc["preregistered"] is True
    assert doc["client_info"]["redirect_uris"] == ["http://localhost:23948/callback"]


def test_the_scan_runner_stores_the_preregistered_client_before_probing(tmp_path, monkeypatch):
    """Drives `cli._run` itself with --oauth-client-id: the store must happen inside its loop
    and the probe must then run — the path the founder's command takes."""
    import asyncio
    import types
    from mcpgawk import cli, oauth_login, probe as probe_mod, remote_login
    monkeypatch.setenv("GAWK_OAUTH_STORE", str(tmp_path))
    monkeypatch.setenv("SEKRET_ENV", "sekret-xyz")
    seen = {}

    async def fake_probe_url(label, url, headers, timeout, auth=None, **kw):
        seen["auth"] = auth
        return probe_mod.ServerSnapshot(name=label, transport="http", protocol_version="p", tools=[])

    # The REAL provider builder runs: a first draft of this test faked it, and the very next line
    # of the route (`build_login_provider`'s own `asyncio.run`) died on the founder's second try.
    monkeypatch.setattr(cli, "probe_url", fake_probe_url)
    real_build = oauth_login.build_login_provider
    def _spy(url):
        auth, server = real_build(url)
        seen["port"] = server.server_port
        return auth, server
    monkeypatch.setattr(oauth_login, "build_login_provider", _spy)
    args = types.SimpleNamespace(stdio=None, http="https://mcp.example.com/mcp", sse=None,
                                 header=[], login=True, config=None, only=None, yes=True,
                                 full=False, sign_in=False, oauth_client_id="client-abc",
                                 oauth_client_secret_env="SEKRET_ENV",
                                 oauth_redirect_uri="http://localhost:23957/callback")
    snaps, entries, skipped = asyncio.run(cli._run(args))
    assert len(snaps) == 1 and seen.get("auth") is not None
    assert seen.get("port") == 23957, "the pre-registered redirect port is the one bound"
    assert str(seen["auth"].context.client_metadata.redirect_uris[0]) == "http://localhost:23957/callback"
    doc = json.loads(remote_login._token_path("https://mcp.example.com/mcp").read_text())
    assert doc["preregistered"] is True and doc["client_info"]["client_id"] == "client-abc"
