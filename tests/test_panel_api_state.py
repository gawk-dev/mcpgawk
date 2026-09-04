"""`/api/state` — the JSON face of the panel's state dict (ledger 108, step 1).

Three properties, each pinned because tonight (2026-09-04) showed how each fails:
  * an ALLOW-LIST, never a dump: a fixture fleet carries planted credentials in `headers` and
    `env`, and not one byte of them may reach the response;
  * every key `collect()` produces is either served or explicitly withheld — a new key cannot
    ship by accident;
  * the ROUTE is driven, not just the function: the panel's own handler answers with JSON.
"""
from __future__ import annotations

import json

from mcpgawk import panel

PLANTED_HEADER = "Bearer PLANTED-HEADER-TOKEN-9f3a"
PLANTED_ENV = "PLANTED-ENV-SECRET-7c1d"


def _fixture_state() -> dict:
    return {
        "errors": {}, "discovery_problems": [], "unscannable": [], "pending": [],
        "activity": {"calls": 3, "checked": 1, "deferred": 2, "denied": 0, "sessions": 1,
                     "servers": 2, "last_seen": "2026-09-04T05:00:00Z", "no_session": 0},
        "recent_calls": [{"ts": "2026-09-04T05:00:00Z", "session": "s", "server": "notion",
                          "tool": "search", "decision": "allow", "basis": "declared",
                          "adapter": "claude-code"}],
        "denied_servers": {"github"}, "session_calls": [], "fleet_calls": [],
        "hooks": {}, "hook_health": {}, "adapters": {}, "no_hook": {}, "runs": [],
        "observed": {}, "verified_runs": {}, "findings": [], "verify_at": "", "verify_blocked": None,
        "monitor": {}, "gateway": {"installed": False},
        "entries": {
            "notion": {"url": "https://mcp.notion.com/mcp",
                       "headers": {"Authorization": PLANTED_HEADER},
                       "_clients": ["claude-code"], "_names": {"claude-code": "notion"},
                       "_aliases": ["notion"], "_meta": {"ideToolTitles": {"x": "y"}}},
            "local": {"command": "npx", "args": ["some-server"],
                      "env": {"API_KEY": PLANTED_ENV}, "_clients": ["cursor"],
                      "_names": {"cursor": "local"}, "_aliases": ["local"]},
        },
        "store": {"servers": {"mcp:notion": {"aliases": ["notion"],
                                             "approved": {"pin": "abc", "measured_at": "t",
                                                          "tools": {"search": {"description": "d"}}},
                                             "history": [{"pin": "abc", "measured_at": "t",
                                                          "tools": {"search": {}},
                                                          "headers": {"Authorization": PLANTED_HEADER}}]}}},
    }


def test_planted_credentials_never_reach_the_api():
    body = json.dumps(panel.api_state(_fixture_state()), sort_keys=True)
    assert PLANTED_HEADER not in body and "PLANTED-HEADER" not in body
    assert PLANTED_ENV not in body and "PLANTED-ENV" not in body
    doc = json.loads(body)
    assert doc["entries"]["notion"]["header_names"] == ["Authorization"], "names yes, values no"
    assert doc["entries"]["local"]["env_names"] == ["API_KEY"]
    assert "headers" not in doc["entries"]["notion"] and "env" not in doc["entries"]["local"]
    assert "_meta" not in doc["entries"]["notion"], "a plugin's icon paths are not state"


def test_the_shape_is_a_contract():
    doc = panel.api_state(_fixture_state())
    assert doc["schema"] == panel.API_SCHEMA == 1
    assert doc["mcpgawk"] and doc["collected_at"].endswith("+00:00")
    assert doc["denied_servers"] == ["github"], "a set becomes a sorted list"
    assert doc["store"]["servers"]["mcp:notion"]["approved"]["tools"] == ["search"]
    assert "tree" in doc
    json.dumps(doc)                                  # fully serialisable, no default= fallback


def test_every_collect_key_is_served_or_withheld_on_purpose():
    """A key added to `collect()` tomorrow must be decided, not shipped by accident."""
    keys = set(panel.collect().keys())
    decided = set(panel.API_ALLOWED) | set(panel.API_WITHHELD)
    undecided = sorted(keys - decided)
    assert not undecided, f"collect() keys with no API decision: {undecided}"
    for k in panel.API_WITHHELD:
        assert k not in panel.API_ALLOWED


def _serve_in_thread() -> int:
    """The panel's own server in a thread on a free port (self-contained: this file is public,
    the fuller harness in test_panel_flow is not)."""
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


def test_the_route_answers_json(monkeypatch):
    monkeypatch.setattr(panel, "collect", _fixture_state)
    port = _serve_in_thread()
    import urllib.request
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=10) as r:
        assert r.headers.get("Content-Type", "").startswith("application/json")
        assert r.headers.get("Cache-Control") == "no-store"
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        body = r.read().decode("utf-8")
    doc = json.loads(body)
    assert doc["schema"] == 1 and doc["entries"]["notion"]["header_names"] == ["Authorization"]
    assert PLANTED_HEADER not in body


def test_an_unknown_object_never_leaks_its_repr():
    """`default=str`/`repr` is where secrets hide: an object that happens to carry a token in its
    repr must serialise as its TYPE NAME, nothing more."""
    class Holder:
        def __repr__(self):
            return f"Holder(token={PLANTED_ENV})"
    d = _fixture_state()
    d["monitor"] = {"client": Holder(), "last": "2026-09-04T05:00:00Z"}
    body = json.dumps(panel.api_state(d), sort_keys=True)
    assert PLANTED_ENV not in body and "PLANTED" not in body
    assert json.loads(body)["monitor"]["client"] == "Holder"
