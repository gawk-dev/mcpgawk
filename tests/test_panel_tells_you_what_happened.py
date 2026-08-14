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
    # Both POST redirects go through the one _back URL, which carries the anchor AND the tab
    # the human acted from (tab state dies with a page load — founder, 2026-08-15).
    assert 'tab={_rtab}#action' in text, "the redirect lost its anchor or its tab"
    assert text.count('send_header("Location", _back)') >= 2, \
        "a post-action redirect stopped using the anchored, tab-carrying URL"
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
    # No in-band login tool either — the refusal path under test is the server that has NEITHER
    # flow. kite-class servers (in-band login tool) are covered by the test below.
    from mcpgawk import remote_login as _rl
    monkeypatch.setattr(_rl, "inband_login", lambda url=None, **kw: None)
    monkeypatch.setattr(_rl, "inband_login_held", lambda url=None, **kw: None)

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


def test_a_server_with_an_inband_login_tool_gets_a_real_link(monkeypatch):
    """[FOUNDER] 2026-08-14: "every time kite connects me to the webpage and i need to provide
    access" — and Revolut X does the same. These servers sign in through their OWN login tool,
    which returns the authorisation URL. The panel now makes that call and puts the link on the
    banner, instead of refusing with "look at the server's own tools"."""
    from mcpgawk import discover, panel, remote_login

    monkeypatch.setattr(panel, "_oauth_unsupported_reason", lambda url: "no oauth")
    monkeypatch.setattr(remote_login, "inband_login_held",
                        lambda url=None, **kw:
                        ("https://mcp.kite.trade/authorize?session_id=abc", "WARNING: markets."))
    monkeypatch.setattr(discover, "discover_servers",
                        lambda *a, **k: {"kite": {"url": "https://mcp.kite.trade/mcp"}})
    monkeypatch.setattr(remote_login, "login_url",
                        lambda entry, name="", path=None: "https://mcp.kite.trade/mcp")
    panel._ACTION.update(running=False, label="login · kite", message="", rows=[],
                         notice="", login_url="", at=panel._now())
    res = panel.run_login("kite")
    assert res["ok"] is True
    assert "sign-in link is ready" in res["message"], res["message"]
    banner = panel._action_banner({**dict(panel._ACTION), "running": False,
                                   "label": "login · kite", "message": res["message"],
                                   "at": panel._now()})
    assert "https://mcp.kite.trade/authorize?session_id=abc" in banner,         "the authorisation link must be ON the banner, not in a log"


def test_guided_setup_runs_the_servers_own_steps(monkeypatch):
    """Reciting "run the generate_keypair tool" at a user with no way to run it is a dead end
    ([FOUNDER] 2026-08-14: "it is not working"). The click now RUNS the server's keygen tool; the
    public key lands on the banner beside a form that finishes the job with the pasted API key —
    which travels POST -> tool call and is never stored."""
    from mcpgawk import discover, dxt, panel, remote_login

    entry = {"command": "node", "args": ["x.js"], "_manifest_dir": "/tmp"}
    monkeypatch.setattr(discover, "discover_servers", lambda *a, **k: {"Revolut X": entry})
    monkeypatch.setattr(dxt, "resolve_for_launch", lambda e: dict(e))
    monkeypatch.setattr(remote_login, "login_url", lambda e, name="", path=None: "")
    monkeypatch.setattr(remote_login, "inband_setup",
                        lambda c, a, e, step, value=None, timeout=40.0:
                        ("pubkey", "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"))
    panel._ACTION.update(running=False, label="login · Revolut X", message="", rows=[],
                         notice="", login_url="", setup_text="", setup_key="", at=panel._now())
    res = panel.run_login("Revolut X")
    assert res["ok"] is True and "keypair ready" in res["message"], res

    tokened = panel._action_banner({**dict(panel._ACTION), "running": False,
                                    "label": "login · Revolut X", "message": res["message"],
                                    "at": panel._now()}, token="secret-tok")
    assert "BEGIN PUBLIC KEY" in tokened, "the public key must be ON the banner to copy"
    assert "data-copy=" in tokened, "the Copy-key button is missing"
    assert 'name="act" value="login-configure"' in tokened, "the finish form is missing"
    assert 'type="password"' in tokened, "the API key input must not echo"

    bare = panel._action_banner({**dict(panel._ACTION), "running": False,
                                 "label": "login · Revolut X", "message": res["message"],
                                 "at": panel._now()})
    assert "login-configure" not in bare, "a tokenless viewer must not get the action form"


def test_setup_flow_renders_for_a_human():
    """The server's setup text is a prompt aimed at an AI client. The panel renders it for a
    PERSON: the key in its own copyable block, machine-directed steps dropped, the user's own
    steps kept verbatim — and if nothing parses, the raw text still renders (losing information
    is worse than losing polish)."""
    from mcpgawk import panel

    text = ("Display the public key below to the user.\n"
            "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n"
            "1. Copy the public key and paste it back here.\n"
            "2. Go to Settings -> API Keys on the website & register it.\n"
            "3. Run 'configure_api_key' with the resulting key.\n")
    html = panel._setup_flow_html(text)
    assert "data-copy=" in html and "BEGIN PUBLIC KEY" in html
    assert "Go to Settings -&gt; API Keys" in html, "the user-directed step must survive, escaped"
    assert "configure_api_key" not in html, "machine-directed steps must be dropped"
    assert "Copy the public key and paste it back here" not in html, \
        "steps the UI replaces must be dropped"
    assert "Paste the API key" in html, "the paste-form must be introduced as the last step"

    unparseable = "Contact support to enable API access & retry."
    fallback = panel._setup_flow_html(unparseable)
    assert "Contact support to enable API access &amp; retry." in fallback, \
        "unparseable text must render raw (escaped), never vanish"


def test_configure_reports_the_servers_own_verdict(monkeypatch):
    from mcpgawk import discover, dxt, panel, remote_login

    entry = {"command": "node", "args": ["x.js"]}
    monkeypatch.setattr(discover, "discover_servers", lambda *a, **k: {"Revolut X": entry})
    monkeypatch.setattr(dxt, "resolve_for_launch", lambda e: dict(e))
    calls = []

    def fake_setup(c, a, e, step, value=None, timeout=40.0):
        calls.append((step, value))
        return ("status", "Configured! Authentication is working.")

    monkeypatch.setattr(remote_login, "inband_setup", fake_setup)
    res = panel.run_login_configure("Revolut X", "rk-live-PASTED")
    assert calls == [("configure", "rk-live-PASTED")], "the pasted key must reach the tool"
    assert res["ok"] is True
    assert not panel._ACTION.get("setup_text"), "the spent flow must clear its state"


def test_a_scaffolding_tool_is_never_mistaken_for_a_sign_in_surface(monkeypatch):
    """browserstack, live (founder, 2026-08-14): bare "setup" matched
    `setupBrowserStackAutomateTests`, the panel called it with {}, and the raw argument-validation
    dump rendered as "sign-in steps". Two contracts, pinned separately: generic words are not
    auth shapes, and an ERROR result is never a sign-in surface."""
    from mcpgawk import panel

    entry = {"command": "npx", "args": ["browserstack-mcp"], "env": {"BROWSERSTACK_ACCESS_KEY": "x"}}

    class _FakeStore:
        @staticmethod
        def load():
            return {"servers": {"mcp:bs": {
                "aliases": ["browserstack"],
                "approved": {"tools": {"setupBrowserStackAutomateTests": "h1",
                                       "runTestsOnBrowserStack": "h2"}}}}}

    monkeypatch.setattr(panel, "history", _FakeStore, raising=False)
    from mcpgawk import history as real_history
    monkeypatch.setattr(real_history, "load", _FakeStore.load)
    assert panel._login_button_applicable(entry, "browserstack") is False, \
        "a test scaffolder put a sign-in button on an env-key server again"


def test_an_error_result_falls_through_to_the_honest_refusal():
    """The error-shape guard in remote_login: 'MCP error -32602: …' is a wrong-tool symptom, not
    guidance for the user."""
    from mcpgawk.remote_login import _INBAND_STATUS_NAMES

    assert "setup" not in _INBAND_STATUS_NAMES, "the greedy matcher is back"
    assert all("auth" in n or "login" in n for n in _INBAND_STATUS_NAMES), \
        "every status name must carry auth semantics"


def test_sign_in_button_carries_the_fleet_name_never_None(monkeypatch):
    """figma — a remote server with no store entry — rendered a sign-in button whose hidden key
    was the literal string 'None' (its absent store key), a dead button that failed with
    "no server named 'None'" when the founder clicked it (driven live 2026-08-14). run_login
    addresses by fleet NAME, so the form must carry the name."""
    from mcpgawk import panel, remote_login

    monkeypatch.setattr(remote_login, "login_url",
                        lambda entry, name="", path=None: "https://x.example/authorize")
    monkeypatch.setattr(remote_login, "stored_access_token", lambda url: None)
    html = panel.render(
        {"entries": {"figma": {"url": "https://mcp.figma.com/mcp"}},
         "store": {"servers": {}}, "pending": [], "findings": [], "recent_calls": [],
         "hooks": {}, "adapters": {}, "unscannable": [], "observed": {}},
        token="tok", action=None)
    assert 'value="None"' not in html, "a Python None leaked into a form key"
    import re as _re
    login_forms = [f for f in _re.findall(r"<form(?:(?!</form>).)*?</form>", html, _re.S)
                   if 'value="login"' in f]
    assert login_forms, "the qualifying remote server got no sign-in button"
    assert any('name="key" value="figma"' in f for f in login_forms), \
        "the sign-in form must carry the fleet name run_login resolves"


def test_a_stale_monitor_row_is_history_not_coverage():
    """Founder's tab audit 2026-08-15: 8 local servers last checked 13 days earlier rendered as
    green "checked" under "11 watched · RUNNING". Locals are excluded from polling by default
    (polling one spawns it with its config's credentials) — a row the daemon is not re-checking
    must say so, and the headline must not count it as watched."""
    from datetime import datetime, timedelta, timezone

    from mcpgawk.panel import _monitor_pane

    now = datetime.now(timezone.utc)
    fresh = (now - timedelta(minutes=30)).isoformat()
    old = (now - timedelta(days=13)).isoformat()
    pane = _monitor_pane({
        "installed": True, "running": True, "since": "2026-08-14T16:34:59",
        "db_present": True,
        "servers": [
            {"server_id": "brandfetch", "last_ok": True, "has_baseline": True,
             "open_alerts": 1, "last_check": fresh},
            {"server_id": "kite", "last_ok": True, "has_baseline": True,
             "open_alerts": 0, "last_check": old},
        ]})
    assert "stale — not being re-checked" in pane, "a 13-day-old check rendered as coverage"
    assert "1 server(s) watched live" in pane, pane[:400]
    assert "1 stale" in pane
    assert "--include-local" in pane, "the way to actually poll locals must be named"
    # The fresh row keeps its honest green.
    assert '<span class="chip ok">checked</span>' in pane


def test_schema_only_drift_never_renders_as_blocked():
    """The hook denies by tool-name projection, so a schema-only change leaves every call
    passing — the Decisions chip said "Blocked" anyway (browserstack, live 2026-08-15).
    Claiming enforcement that is not happening is the worst lie a security product renders."""
    from mcpgawk import panel

    store = {"servers": {
        "mcp:schema-only": {
            "aliases": ["schema-only"],
            "approved": {"items": {"tool.a": "f1"}, "schemas": {"tool.a": "s1"}},
            "history": [{"items": {"tool.a": "f1"}, "schemas": {"tool.a": "s2"}}]},
        "mcp:tools-added": {
            "aliases": ["tools-added"],
            "approved": {"items": {"tool.a": "f1"}},
            "history": [{"items": {"tool.a": "f1", "tool.evil": "f2"}}]},
    }}
    html = panel.render(
        {"entries": {}, "store": store, "pending": ["mcp:schema-only", "mcp:tools-added"],
         "findings": [], "recent_calls": [], "hooks": {}, "adapters": {},
         "unscannable": [], "observed": {}},
        token="tok", action=None)
    import re as _re
    rows = {m.group(1): m.group(0) for m in
            _re.finditer(r"<tr><td class=\"nm\">([\w-]+)</td>(?:(?!</tr>).)*</tr>", html, _re.S)}
    assert "NOT blocked" in rows.get("schema-only", ""), "schema-only drift claimed enforcement"
    assert ">Blocked<" in rows.get("tools-added", ""), "a genuinely blocked drift lost its chip"


def test_gateway_setup_writes_configs_but_never_a_secret_and_never_twice(monkeypatch, tmp_path):
    """[FOUNDER] 2026-08-15: "provide the option to configure the gateway". The affordance does
    the work — backends from the live fleet, env values as ${VAR} placeholders, principals file
    0600 — and hands over one command. It never starts a process (credential custody is the
    human's act, the approve invariant) and never overwrites what it generated."""
    from mcpgawk import panel

    monkeypatch.setattr(panel, "behaviour_profile_path", lambda: tmp_path / "behaviour.json")
    from mcpgawk import discover
    monkeypatch.setattr(discover, "discover_servers", lambda *a, **k: {
        "browserstack": {"command": "node", "args": ["bs.js"],
                         "env": {"BROWSERSTACK_ACCESS_KEY": "real-secret-value"}},
        "figma": {"url": "https://mcp.figma.com/mcp"},
        "pencil": {},                                    # nothing to launch or reach — folds
    })
    res = panel.run_gateway_setup()
    assert res["ok"], res
    cfg = (tmp_path / "gateway" / "gateway.yaml").read_text()
    pr = (tmp_path / "gateway" / "principals.json").read_text()
    assert "real-secret-value" not in cfg + pr, "a fleet secret reached the generated config"
    assert "${BROWSERSTACK_ACCESS_KEY}" in cfg, "env must become a placeholder, not vanish"
    assert "https://mcp.figma.com/mcp" in cfg
    assert "pencil" in cfg and "NOT included" in cfg, "un-backable servers must fold with names"
    assert "listen: 127.0.0.1:8080" in cfg, "the generated gateway must bind loopback"
    import stat as _stat
    assert _stat.S_IMODE((tmp_path / "gateway" / "principals.json").stat().st_mode) == 0o600
    assert "enforce serve" in res["message"], "the one command must be handed over"

    again = panel.run_gateway_setup()
    assert again["ok"] and "already generated" in again["message"], \
        "a re-click must not overwrite the operator's edited configs"


def test_gateway_setup_never_writes_a_url_embedded_credential(monkeypatch, tmp_path):
    """Caught on the feature's FIRST live run (2026-08-15): brandfetch's fleet URL embeds
    ?apiKey=… and the generator wrote it verbatim — the same credentials-in-URLs class as the
    monitor-alert leak. A credential-bearing URL folds with a reason; the secret never reaches
    the file."""
    from mcpgawk import discover, panel

    monkeypatch.setattr(panel, "behaviour_profile_path", lambda: tmp_path / "behaviour.json")
    monkeypatch.setattr(discover, "discover_servers", lambda *a, **k: {
        "brandfetch": {"url": "https://mcp.brandfetch.io/mcp?clientId=abc&apiKey=SECRETVALUE"},
        "figma": {"url": "https://mcp.figma.com/mcp"},
    })
    res = panel.run_gateway_setup()
    assert res["ok"], res
    cfg = (tmp_path / "gateway" / "gateway.yaml").read_text()
    assert "SECRETVALUE" not in cfg, "a URL-embedded credential reached the generated config"
    assert "brandfetch" in cfg and "embeds a credential" in cfg, \
        "the folded server must be named with the reason"
    assert "https://mcp.figma.com/mcp" in cfg, "a clean URL backend must still be included"
