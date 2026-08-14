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
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import parse_qs, urlparse


def _serve_in_thread(serve, **kw):
    """Self-contained copy of test_local_surface_token's helper: that file is deliberately NOT in
    PUBLIC_TESTS, so importing from it broke collection in the public repo (caught by the public
    suite, 2026-08-14). Same rationale as the original: drive the real HTTP surface, never the
    renderer alone."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    seen: list[str] = []
    t = threading.Thread(target=lambda: serve(port=port, open_browser=False, log=seen.append),
                         daemon=True)
    t.start()
    url = ""
    for _ in range(100):
        time.sleep(0.05)
        hit = [m.group(0) for line in seen
               for m in [re.search(r"http://127\.0\.0\.1:\d+/\?t=\S+", line)] if m]
        if hit:
            url = hit[0]
            break
    assert url, f"surface did not start; log was {seen!r}"
    return url, parse_qs(urlparse(url).query)["t"][0], port


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


def test_the_stream_is_token_gated_like_the_page():
    """The first SSE version wiped the tokened page's configure form mid-flow (it rendered a
    tokenless fragment) — and fixing THAT by always streaming the tokened fragment would leak the
    token to any local reader. The stream renders with the token only for a caller that proved it
    holds it: the same gate as the page."""
    import mcpgawk.panel as panel

    url, token, port = _serve_in_thread(panel.serve)
    panel._ACTION.update(running=False, label="login · x", message="paste it",
                         setup_text="-----BEGIN PUBLIC KEY-----abc", setup_key="x",
                         at=panel._now())
    try:
        base = f"http://127.0.0.1:{port}"
        with _get(f"{base}/events?t={token}") as r:
            tokened_first = r.readline().decode()
        with _get(f"{base}/events") as r:
            bare_first = r.readline().decode()
        assert "login-configure" in tokened_first, "the tokened stream lost the action form"
        assert "login-configure" not in bare_first, "the bare stream leaked the tokened form"
        assert token not in bare_first, "the bare stream leaked the token itself"
    finally:
        panel._ACTION.update(setup_text="", setup_key="")


def test_unknown_paths_are_404_not_the_page():
    """Every wrong URL used to serve the full page with a 200, so a typo looked exactly like the
    panel. Driven live 2026-08-14. A panel answers for the routes it has."""
    url, token, port = _serve_in_thread(__import__("mcpgawk.panel", fromlist=["serve"]).serve)
    try:
        _get(f"http://127.0.0.1:{port}/nonexistent")
        raise AssertionError("unknown path served a 200")
    except urllib.error.HTTPError as e:
        assert e.code == 404, e.code


def test_a_dead_panel_is_said_on_the_page_not_discovered_by_clicking():
    """Twice the founder clicked silently dead buttons on a tab whose panel process was gone
    (2026-08-14, root-caused both times). The client script must PROBE on stream error and, only
    when the probe itself fails, say the panel is gone — a stream-deadline reconnect (the panel
    is fine) must never false-alarm."""
    from mcpgawk import panel

    js = panel._PANEL_JS
    assert "onerror" in js, "no stream-error handler at all"
    assert 'fetch("/panel.js"' in js, "declaring death without probing is the false-alarm bug"
    assert "gone-note" in js and "es.close()" in js, "the dead-panel notice is missing"
    assert "mcpgawk panel" in js, "the notice must name the way back, not just the failure"


def test_a_synchronous_action_reports_under_its_own_label_and_clears_stale_state():
    """Driven live 2026-08-14: after a kite sign-in, 'Start monitoring' reported its result under
    the headline 'login-configure · __nosuch__' with a stale 'Open the sign-in page' link riding
    the banner. A banner that mixes two actions' state is wrong twice at once."""
    import mcpgawk.panel as panel

    url, token, port = _serve_in_thread(panel.serve)
    panel._ACTION.update(running=False, label="login · kite", message="old",
                         login_url="https://stale.example/authorize", at=panel._now())
    body = urllib.parse.urlencode({"act": "keep", "token": token}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body, method="POST")
    with urllib.request.urlopen(req, timeout=5):
        pass
    with _get(url) as r:
        page = r.read().decode()
    assert "keep blocked" in page, "the action's own label is missing from the banner"
    assert "Left blocked" in page, "the action's own message is missing"
    assert "stale.example" not in page, "the previous action's sign-in link rode this banner"
