"""The seamless-panel contract: our script runs, injected script cannot, and the refresh loop is
the NO-JS fallback only.

[FOUNDER] 2026-08-14: "the panel in real life should be seamless … i cannot accept your fact that
js files not secure." Correct — the threat on this page was never our own script; it is INJECTED
script riding server-controlled text (tool descriptions render here). CSP kills that by
allowlisting (`script-src 'self'` runs /panel.js, refuses every inline block), not by banning JS.
So: with JS, /events streams the pre-rendered banner (the SAME `_action_banner` fragment the full
page uses — one rendering path, one escaping path) and the page settles once when a run completes;
without JS, the old 5-second refresh still works — from inside <noscript>, where it can no longer
yank a JS-capable browser every 5 seconds for the length of a fleet verify.

Driven over real HTTP, not by calling render() — the serve-layer defect class this repo has paid
for before (see _serve_in_thread's docstring in test_local_surface_token.py).
"""
from __future__ import annotations

import json
import urllib.request

from tests.test_local_surface_token import _serve_in_thread


def _get(url: str, timeout: float = 5.0):
    req = urllib.request.Request(url)
    return urllib.request.urlopen(req, timeout=timeout)


def test_the_page_ships_exactly_our_script_and_a_noscript_fallback():
    from mcpgawk import panel

    html = panel.render(
        {"entries": {}, "store": {"servers": {}}, "pending": [], "findings": [],
         "recent_calls": [], "hooks": {}, "adapters": {}, "unscannable": [], "observed": {}},
        token="tok", action={"running": True, "label": "verify · fleet", "message": "",
                             "rows": [], "at": "2099-01-01T00:00:00Z"})
    assert html.count("<script") == 1, "exactly one script — ours — ever ships on this page"
    assert '<script src="/panel.js" defer></script>' in html
    assert '<noscript><meta http-equiv="refresh"' in html, \
        "the refresh must survive for no-JS viewers"
    assert html.count('<meta http-equiv="refresh"') == 1, \
        "a refresh OUTSIDE noscript would yank JS clients again — the exact haywire being removed"


def test_csp_allowlists_our_script_and_still_refuses_inline():
    url, token, port = _serve_in_thread(__import__("mcpgawk.panel", fromlist=["serve"]).serve)
    with _get(url) as r:
        csp = r.headers.get("Content-Security-Policy") or ""
    assert "script-src 'self'" in csp, csp
    assert "connect-src 'self'" in csp, csp
    # THE LOAD-BEARING ABSENCE: inline script stays dead, so a malicious tool description that
    # survives escaping somewhere still cannot execute. 'self' names our file, nothing inline.
    assert "unsafe-inline" not in csp.replace("style-src 'unsafe-inline'", ""), csp


def test_panel_js_and_events_are_served():
    url, token, port = _serve_in_thread(__import__("mcpgawk.panel", fromlist=["serve"]).serve)
    base = f"http://127.0.0.1:{port}"
    with _get(f"{base}/panel.js") as r:
        body = r.read().decode()
        assert r.headers.get("Content-Type", "").startswith("application/javascript")
        assert "EventSource" in body and "location.reload" in body
    with _get(f"{base}/events") as r:
        first = r.readline().decode()
        assert first.startswith("data: "), first
        payload = json.loads(first[len("data: "):])
        assert set(payload) == {"running", "html"}, payload
