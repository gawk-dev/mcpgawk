"""The panel binds 127.0.0.1, but DNS rebinding lets a web page reach it under the page's OWN
hostname. Its token-free routes (/api/state, the call-log export) must answer only loopback names
and refuse a cross-site browser request. Found 2026-11-05 in the shipped 0.1.82 panel."""
from __future__ import annotations

import http.client

import pytest

from mcpgawk import panel


def _get(port: int, path: str, headers: dict[str, str]) -> int:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", path, headers=headers)
    status = c.getresponse().status
    c.close()
    return status


def _serve_in_thread() -> int:
    """Self-contained copy (house idiom: public test files never import each other)."""
    import re
    import socket
    import threading
    import time
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    seen: list[str] = []
    threading.Thread(target=lambda: panel.serve(port=port, open_browser=False, log=seen.append),
                     daemon=True).start()
    for _ in range(100):
        time.sleep(0.05)
        if any(re.search(r"http://127\.0\.0\.1:\d+/\?t=", line) for line in seen):
            return port
    raise AssertionError(f"panel did not start; log was {seen!r}")


@pytest.fixture
def port(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    monkeypatch.setattr(panel, "collect", lambda *a, **k: {"entries": {}, "store": {"servers": {}}})
    return _serve_in_thread()


@pytest.mark.parametrize("host", ["attacker.example", "attacker.example:7718", "127.0.0.1.nip.io"])
def test_a_foreign_host_is_refused(port, host):
    assert _get(port, "/api/state", {"Host": host}) == 403


def test_a_cross_site_request_is_refused(port):
    assert _get(port, "/api/state", {"Host": f"127.0.0.1:{port}", "Sec-Fetch-Site": "cross-site"}) == 403


def test_a_post_from_a_foreign_host_is_refused(port):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", "/", body="token=x&act=approve", headers={
        "Host": "attacker.example", "Content-Type": "application/x-www-form-urlencoded"})
    assert c.getresponse().status == 403


@pytest.mark.parametrize("host", ["127.0.0.1:{p}", "localhost:{p}", "[::1]:{p}"])
def test_loopback_names_are_served(port, host):
    assert _get(port, "/api/state", {"Host": host.format(p=port), "Sec-Fetch-Site": "same-origin"}) == 200
