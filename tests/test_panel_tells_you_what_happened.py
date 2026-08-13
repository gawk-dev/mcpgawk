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
