"""The panel must never do work silently, and never overstate what it checked.

All four defects were REPRODUCED in a real browser (Claude in Chrome) against the shipped panel on
2026-08-13/14, not inferred:

* clicking a row's `verify` redirected to `/?t=…` with no fragment, so the page jumped to the top;
* the result banner renders BELOW the fold, so a verify that CONVICTED a server ("1 tool(s) with
  findings on vault-rag", styled red) was shown on a page that looked unchanged — the product
  found something and the operator could not see it;
* the banner printed only `message` — a naked "done", no subject, no time — while `label` and `at`
  were already stored on the action and simply never rendered;
* nothing expired it: the founder's real `last-action.json` held a result from three days earlier,
  still presented as the state of the machine.

And the one the audit called P0: the Activity headline printed `summary["calls"]` (every call
RECORDED) under the label "calls checked" — 860 "checked" where the CLI said 41 checked and 832
DECLINED. The honest numbers were already in the same dict.
"""
from __future__ import annotations


def test_the_activity_headline_never_calls_a_declined_call_checked():
    from mcpgawk.panel import _activity_headline

    out = _activity_headline({"calls": 873, "checked": 41, "deferred": 832})
    assert "873</b> seen" in out, out
    assert "41</b> checked" in out, out
    assert "832</b> NOT checked" in out, "the declined calls are not stated"
    assert "873</b> calls checked" not in out, "the ~20x overstatement is back"
    assert "warn" in out, "a declined call must be styled as a warning, not as normal"


def test_a_log_without_the_distinction_says_so_rather_than_guessing():
    from mcpgawk.panel import _activity_headline

    out = _activity_headline({"calls": 5, "checked": None, "deferred": 0})
    assert "not " in out and "recorded" in out, out
    assert "checked against" not in out, "it invented a checked count it does not have"


def test_a_completed_banner_carries_its_subject_and_its_time():
    """"done" is not feedback. WHAT finished, and WHEN."""
    from mcpgawk.panel import _action_banner, _now

    html = _action_banner({"running": False, "label": "verify · vault-rag",
                           "message": "1 tool(s) with findings", "rows": [], "at": _now()})
    assert "verify · vault-rag" in html, html
    assert "just now" in html or "m ago" in html, "no timestamp rendered"


def test_a_stale_result_is_not_presented_as_the_current_state():
    from mcpgawk.panel import _action_banner

    old = {"running": False, "label": "login · kite", "message": "done",
           "at": "2026-08-10T13:47:36Z"}
    assert _action_banner(old) == "", "a three-day-old result still rendered as current"


def test_an_undated_result_is_labelled_not_destroyed():
    """The first version of the expiry hid ANY undated banner — and an existing test caught it
    swallowing a real "rescanned" outcome. Losing a verdict is worse than showing an ambiguous
    one; the fix is to say the time is unrecorded, not to hide the result."""
    from mcpgawk.panel import _action_banner

    html = _action_banner({"running": False, "label": "scan", "message": "rescanned", "rows": []})
    assert "rescanned" in html, "an undated result was destroyed"
    assert "unrecorded" in html, "it must SAY the time is unknown"


def test_a_running_action_is_never_treated_as_stale():
    """A fleet verify legitimately runs for minutes; expiring its banner would recreate the exact
    'appears frozen while work happens invisibly' complaint."""
    from mcpgawk.panel import _action_banner

    html = _action_banner({"running": True, "label": "verify · fleet",
                           "message": "", "rows": [], "at": "2026-08-10T13:47:36Z"})
    assert "Running verify · fleet" in html, html


def test_the_post_action_redirect_anchors_at_the_result():
    """Reproduced in a browser: without a fragment the click threw the operator to the top of the
    page and the outcome rendered below the fold. Pinned on the source because the redirect is
    issued deep in the request handler."""
    from pathlib import Path

    src = Path(__file__).parent.parent / "src" / "mcpgawk" / "panel.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('#action"') >= 2, "a post-action redirect lost its anchor"
    assert 'id="action"' in text, "the anchor target does not exist in the page"


def test_a_denied_server_stays_blocked_beyond_the_display_window():
    """The Blocked TIER asked a 40-row display window, so a server the guard stopped 100 calls ago
    silently lost the tier while the banner still announced it. Reproduced on the founder's fleet
    2026-08-14: "Blocked → 0 of 17" beside 10 rendered deny chips."""
    from mcpgawk.panel import _classify

    d = {"denied_servers": {"resend"}, "recent_calls": [], "findings": [], "pending": []}
    assert _classify("resend", "mcp:resend", d) == "blocked"
    assert _classify("other", "mcp:other", d) != "blocked"


def test_the_verify_step_never_counts_more_servers_than_exist():
    """"25 of 11 server(s) watched running" — a numerator above its own denominator, on the step
    representing behavioural verification. `verified_runs` is keyed by every name ever recorded
    (aliases, removed servers); `entries` is what discovery sees now."""
    from mcpgawk.panel import journey_steps

    d = {"entries": {"a": {}, "b": {}},
         "verified_runs": {"a": {"toolsChecked": 3}, "gone": {"toolsChecked": 9},
                           "alias": {"toolsChecked": 1}},
         "store": {"servers": {}}, "pending": [], "findings": [], "recent_calls": [],
         "hooks": {}, "adapters": {}, "unscannable": [], "observed": {}}
    fact = next(s["fact"] for s in journey_steps(d) if s["key"] == "verify")
    assert fact.startswith("1 of 2 "), fact


def test_the_blocked_banner_names_where_those_servers_are():
    """The alarm said "blocked right now" and the servers carry the Changed tier — so the user
    filtered by Blocked and found nothing. The alarm must name its own subject's location."""
    from mcpgawk.panel import next_best_action

    text, tier = next_best_action({"pending": ["mcp:resend"], "findings": [], "hooks": {},
                                   "adapters": {}, "entries": {}, "store": {"servers": {}}})
    assert tier == "bad"
    assert "Changed" in text, text


def test_a_server_with_no_oauth_is_refused_fast_not_hung(monkeypatch):
    """The founder's actual complaint: "Running login · kite… " forever. Measured 2026-08-14 —
    `kite` answers `initialize` 200 with no auth challenge and 404s both OAuth discovery documents.
    Its sign-in is IN-BAND (one of its own tools returns a broker link), so there was never a
    browser flow to run; the panel started one anyway and sat for 330 seconds before blaming the
    sign-in. The button must now answer in seconds, with the reason."""
    from mcpgawk import panel

    monkeypatch.setattr(panel, "_oauth_unsupported_reason",
                        lambda url: "it answers without asking us to authenticate")

    def must_not_run(*a, **k):                       # noqa: ANN002, ANN003
        raise AssertionError("a login subprocess was started for a server with no OAuth")

    monkeypatch.setattr(panel, "_run_login_cli", must_not_run)
    # `run_login` imports these INSIDE the function, so patch the modules themselves.
    from mcpgawk import discover, remote_login
    monkeypatch.setattr(discover, "discover_servers",
                        lambda *a, **k: {"kite": {"url": "https://mcp.kite.trade/mcp"}})
    monkeypatch.setattr(remote_login, "login_url",
                        lambda entry, name="", path=None: "https://mcp.kite.trade/mcp")
    res = panel.run_login("kite")
    assert res["ok"] is False
    assert "does not offer a browser sign-in" in res["message"], res["message"]


def test_a_bare_403_is_not_mistaken_for_an_auth_challenge():
    """kite answers curl 200 and urllib 403 (a Cloudflare bot block). Reading that 403 as "it
    challenged us" is what kept the dead button on screen — the RFC signal is WWW-Authenticate."""
    import urllib.error

    from mcpgawk import panel

    class _Blocked(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("u", 403, "Forbidden", {}, None)   # no WWW-Authenticate

    def fake_urlopen(req, timeout=0):                # noqa: ANN001, ARG001
        raise _Blocked()

    import urllib.request
    real = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        reason = panel._oauth_unsupported_reason("https://mcp.kite.trade/mcp")
    finally:
        urllib.request.urlopen = real
    assert reason, "a bare 403 was treated as an OAuth challenge"
