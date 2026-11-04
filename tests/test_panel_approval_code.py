"""approve / mute / pin / protect need the approval code printed in the panel's terminal.

FOUNDER 2026-11-05, option (a). The page token persists in ~/.mcpgawk/panel-token so links survive
restarts, which means an agent that can read the operator's files could POST act=approve with it.
The approval code is minted per process, held in memory, printed only in the terminal — in no file
and on no page — so the token alone can no longer move trust."""
from __future__ import annotations

import http.client
import json
import re
import socket
import threading
import time
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from mcpgawk import baseline, history, panel


def _start(tmp_path, monkeypatch):
    """Self-contained (this file may be public): start the panel, return (port, token, log)."""
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    (tmp_path / "history.json").write_text(json.dumps({"servers": {}}))
    monkeypatch.setattr(baseline, "approval_blocked_reason", lambda: None)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    seen: list[str] = []
    threading.Thread(target=lambda: panel.serve(port=port, open_browser=False, log=seen.append),
                     daemon=True).start()
    for _ in range(100):
        time.sleep(0.05)
        m = [re.search(r"http://127\.0\.0\.1:\d+/\?t=\S+", ln) for ln in seen]
        m = [x for x in m if x]
        if m:
            return port, parse_qs(urlparse(m[0].group(0)).query)["t"][0], seen
    raise AssertionError(f"panel did not start: {seen!r}")


def _code(seen: list[str]) -> str:
    codes = [m.group(1) for ln in seen for m in re.finditer(r"approval code — ([A-Z0-9]{4}-[A-Z0-9]{4})", ln)]
    assert codes, "the terminal must show the approval code"
    return codes[-1]


def _post(port: int, data: dict, cookie: str = "") -> http.client.HTTPResponse:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Content-Type": "application/x-www-form-urlencoded", "Host": f"127.0.0.1:{port}"}
    if cookie:
        h["Cookie"] = cookie
    c.request("POST", "/", body=urlencode(data), headers=h)
    r = c.getresponse()
    r.read()
    return r


def _get(port: int, path: str) -> str:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
    return c.getresponse().read().decode("utf-8", "replace")


@pytest.fixture
def approvals(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(history, "approve", lambda key, *a, **k: calls.append(key) or True)
    return calls


def test_the_token_alone_cannot_approve(tmp_path, monkeypatch, approvals):
    port, token, seen = _start(tmp_path, monkeypatch)
    r = _post(port, {"token": token, "act": "approve", "key": "mcp:srv"})
    assert r.status == 303 and approvals == []
    page = _get(port, f"/?t={token}")
    assert 'name="code"' in page and "needs the approval code" in page
    code = _code(seen)
    for path in (f"/?t={token}", f"/next?t={token}", "/api/state", "/"):
        assert code not in _get(port, path), f"the code leaked onto {path}"
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert code not in f.read_text(errors="replace"), f"the code was written to {f.name}"


def test_a_wrong_code_is_refused(tmp_path, monkeypatch, approvals):
    port, token, _ = _start(tmp_path, monkeypatch)
    _post(port, {"token": token, "act": "approve", "key": "mcp:srv", "code": "AAAA-AAAA"})
    assert approvals == []
    assert "does not match" in _get(port, f"/?t={token}")


def test_the_code_approves_and_unlocks_this_browser(tmp_path, monkeypatch, approvals):
    port, token, seen = _start(tmp_path, monkeypatch)
    r = _post(port, {"token": token, "act": "unlock", "then": "approve", "key": "mcp:srv",
                     "code": _code(seen).lower().replace("-", " ")})
    assert approvals == ["mcp:srv"]
    cookie = r.getheader("Set-Cookie") or ""
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    _post(port, {"token": token, "act": "approve", "key": "mcp:two"}, cookie=cookie.split(";")[0])
    assert approvals == ["mcp:srv", "mcp:two"]
    _post(port, {"token": token, "act": "approve", "key": "mcp:three"}, cookie=f"mcpgawk_unlock_{port}=forged")
    assert approvals == ["mcp:srv", "mcp:two"]


def test_ten_wrong_codes_void_the_code(tmp_path, monkeypatch, approvals):
    port, token, seen = _start(tmp_path, monkeypatch)
    first = _code(seen)
    for _ in range(panel._CODE_MAX_FAILS):
        _post(port, {"token": token, "act": "approve", "key": "k", "code": "ZZZZ-ZZZZ"})
    second = _code(seen)
    assert second != first
    _post(port, {"token": token, "act": "approve", "key": "k", "code": first})
    assert approvals == []
    _post(port, {"token": token, "act": "approve", "key": "k", "code": second})
    assert approvals == ["k"]


def test_unlock_cannot_be_aimed_at_another_action(tmp_path, monkeypatch, approvals):
    port, token, seen = _start(tmp_path, monkeypatch)
    r = _post(port, {"token": token, "act": "unlock", "then": "scan", "code": _code(seen)})
    assert r.status == 303 and not r.getheader("Set-Cookie")
