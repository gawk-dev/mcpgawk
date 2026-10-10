"""Defects from the founder's first real run of 0.1.74 (2026-10-09) that are design fixes at one
site, not cross-surface rules — see docs/analysis-0.1.74-first-run-defects-2026-10-09.md.
The cross-surface rules live in tests/test_one_rule_every_surface.py."""
from __future__ import annotations

import types

from mcpgawk import cli
from mcpgawk.probe import ServerSnapshot
from mcpgawk.signals import detect_shadowing


def _snap(tools, name):
    return ServerSnapshot(name=name, transport="stdio", protocol_version="2025-06-18",
                          tools=[{"name": t, "description": "x"} for t in tools])


# --- item 4: tool-name shadowing is scoped to a shared context, once per pair ------------------
# kite (Claude Code) and kite#2 (Claude Desktop) are one server configured in two clients. The
# detector compared every snapshot against every other and printed 22 "exit 1: kite, kite#2:
# tool-name shadowing on <tool>" lines. Two clients do not share a context; a server cannot
# shadow one no agent sees beside it.

KITE = ["get_holdings", "place_order", "cancel_order"]


def test_the_same_server_in_two_clients_does_not_shadow_itself():
    snaps = [_snap(KITE, "kite"), _snap(KITE, "kite#2")]
    clients = {"kite": ["claude-code"], "kite#2": ["claude-desktop"]}
    assert detect_shadowing(snaps, clients=clients) == {}


def test_two_servers_in_one_client_shadow_once_per_pair_naming_every_tool():
    snaps = [_snap(["list_workspaces", "list_folders", "create_folder"], "dadan"),
             _snap(["list_workspaces", "list_folders", "rename_folder"], "supademo"),
             _snap(["unique"], "other")]
    clients = {"dadan": ["claude-code"], "supademo": ["claude-code"], "other": ["claude-code"]}
    out = detect_shadowing(snaps, clients=clients)
    assert set(out) == {"dadan", "supademo"}
    assert len(out["dadan"]) == 1, out["dadan"]             # one finding per PAIR, not per tool
    f = out["dadan"][0]
    assert f.kind == "shadowing:name-collision"
    assert "supademo" in f.evidence and "list_workspaces" in f.evidence and "list_folders" in f.evidence


def test_a_shared_client_or_an_unknown_client_still_fires():
    snaps = [_snap(KITE, "kite"), _snap(KITE, "evil-kite")]
    both = {"kite": ["claude-code", "cursor"], "evil-kite": ["cursor"]}
    assert set(detect_shadowing(snaps, clients=both)) == {"kite", "evil-kite"}
    # No attribution at all (an ad-hoc scan): the old rule, every snapshot shares a context.
    assert set(detect_shadowing(snaps)) == {"kite", "evil-kite"}
    assert set(detect_shadowing(snaps, clients={"kite": ["claude-code"]})) == {"kite", "evil-kite"}


# --- item 5: the bare command keeps the scan-phase sign-in offer -------------------------------
# Bare `mcpgawk` in a terminal printed "4 server(s) need credentials. Re-run in a terminal without
# --yes" — the user never typed --yes. _protect reused --yes to mean "consent already given", and
# --yes also means "never prompt" to the batched OAuth offer (1f4616b1). One flag, two questions.

def _drive_protect(monkeypatch, *, choice, blocked=None, on_dispatch=lambda: None):
    from mcpgawk import discover, history, protect
    captured: dict = {}
    monkeypatch.setattr(protect, "load_consent", lambda: choice)
    monkeypatch.setattr(history, "approval_blocked_reason", lambda: blocked)
    monkeypatch.setattr(discover, "discover_servers",
                        lambda *a, **k: {"acme-fs": {"command": "npx -y @acme/fs"}})
    monkeypatch.setattr(cli, "_dispatch",
                        lambda argv, *a, **k: (captured.setdefault("argv", list(argv)), on_dispatch()) and 0)
    monkeypatch.setattr(cli, "_store_or_say_why", lambda: ({}, None))
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)                 # skip verify
    monkeypatch.setattr(protect, "protection_report",
                        lambda store, guard_line, unchecked=None: captured.setdefault("unchecked", unchecked) or "r")
    cli._protect()
    return captured


def test_a_saved_launch_consent_does_not_pass_yes_to_the_scan(monkeypatch):
    from mcpgawk import protect
    from mcpgawk.consent import CONSENT_GIVEN_ENV
    from mcpgawk import consent
    monkeypatch.delenv(CONSENT_GIVEN_ENV, raising=False)
    seen = {}
    cap = _drive_protect(monkeypatch, choice=protect.LAUNCH_ALL,
                         on_dispatch=lambda: seen.setdefault("flag", consent.front_door_consented()))
    assert "--yes" not in cap["argv"], cap["argv"]
    assert seen["flag"] is True, "consent is carried by a process-local flag, for the one scan"
    assert consent.front_door_consented() is False, "and cleared after"
    assert cli.os.environ.get(CONSENT_GIVEN_ENV) is None, \
        "never through the env: a child process (the panel's scan button) would inherit it"


def test_the_consent_gate_honours_the_front_doors_answer_without_yes(monkeypatch):
    from mcpgawk import consent
    monkeypatch.delenv(consent.CONSENT_GIVEN_ENV, raising=False)
    targets = [("acme-fs", {"command": "npx"}), ("remote", {"url": "https://r.test/mcp"})]
    asked = []
    with consent.front_door_consent():
        out = consent.gate_stdio_consent(targets, assume_yes=False, stdin_isatty=True,
                                         ask=lambda: asked.append(1) or "n")
    assert out == targets and asked == [], "the front door already asked; the gate must not re-ask"
    # The env alone still consents to nothing without --yes: a child process inherits an env.
    monkeypatch.setenv(consent.CONSENT_GIVEN_ENV, "1")
    out = consent.gate_stdio_consent(targets, assume_yes=False, stdin_isatty=False)
    assert out == [("remote", {"url": "https://r.test/mcp"})]


class _Row:
    def __init__(self, name):
        self.name, self.url, self.needs_auth = name, f"https://{name}.example/mcp", True


def test_the_credentials_hint_names_the_real_next_step(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(AssertionError("prompted")))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    cli._offer_batched_auth([_Row("zoho")], types.SimpleNamespace(yes=True), {})
    assert "without --yes" in capsys.readouterr().err
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False, raising=False)
    cli._offer_batched_auth([_Row("zoho")], types.SimpleNamespace(yes=False), {})
    err = capsys.readouterr().err
    assert "--yes" not in err and "terminal" in err, err


# --- item 6: the closing report names every server this run could not measure -----------------
# Four servers needed credentials; the closing report never mentioned them. `unchecked` was fed
# only on a remote-only run, while protection_report promises the block is never omitted.

def test_the_closing_report_lists_servers_that_need_a_sign_in_or_were_set_aside(monkeypatch):
    from mcpgawk import protect, remote_login
    monkeypatch.setattr(remote_login, "auth_needed",
                        lambda *a, **k: {"zoho-mail-hello": "https://z.test/mcp",
                                         "robinhood-trading": "https://r.test/mcp"})
    monkeypatch.setattr(remote_login, "signin_aside", lambda *a, **k: {"robinhood-trading": "2026-10-01"})
    cap = _drive_protect(monkeypatch, choice=protect.LAUNCH_ALL)
    unchecked = dict(cap["unchecked"] or [])
    assert "zoho-mail-hello" in unchecked and "sign-in" in unchecked["zoho-mail-hello"], unchecked
    assert "robinhood-trading" in unchecked and "set aside" in unchecked["robinhood-trading"], unchecked


# --- items 8–11: the Today page ------------------------------------------------------------------
import re

from mcpgawk import panel


def _signin(state, vendor=""):
    return {"state": state, "terminal": state in ("blocked_vendor", "set_aside"),
            "actionable": state == "offered", "vendor": vendor, "headline": "", "sub": "",
            "row": "", "chip": "", "tag": "", "actions": [], "observed": {}, "url": "", "since": ""}


def _today(monkeypatch, tmp_path, *, entries, store=None, pending=(), signins=None, calls=()):
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    f = tmp_path / "calls.jsonl"
    f.write_text("".join(json.dumps({"ts": now, "decision": dec, "server": srv, "tool": "t"}) + "\n"
                         for dec, srv in calls))
    monkeypatch.setenv("MCPGAWK_SPOOL", str(f))
    signins = signins or {}
    monkeypatch.setattr(panel, "signin_asks", lambda e: [n for n in signins if n in e])
    monkeypatch.setattr(panel, "signin_state", lambda e, n, **k: _signin(*signins[n]) if n in signins else _signin("none"))
    d = {"entries": entries, "store": {"servers": store or {}}, "pending": list(pending), "activity": {},
         "recent_calls": [], "findings": [], "unscannable": [], "monitor": {}, "verify_at": ""}
    page = panel.render(d, token="t")
    today = page[page.index('id="p9"'):]
    return today[:today.index("</section>")]


FLEET = {"zoho": {"url": "https://z.test/mcp"}, "figma": {"url": "https://f.test/mcp"},
         "robinhood": {"url": "https://r.test/mcp"}, "plain": {"command": "npx plain"},
         "quiet": {"command": "npx quiet"}}
SIGNINS = {"zoho": ("offered",), "figma": ("blocked_vendor", "Figma"), "robinhood": ("set_aside",)}


def test_the_uncounted_cards_sit_under_the_counted_and_the_headline_says_both(monkeypatch, tmp_path):
    today = _today(monkeypatch, tmp_path, entries=FLEET, signins=SIGNINS)
    assert "2 cannot be finished from here" in today, today[:600]
    assert today.index("sign in — only you can") < today.index("cannot be signed into")
    assert today.index("sign in — only you can") < today.index("set aside by you")


def test_every_server_is_in_one_chip_and_one_row_or_group(monkeypatch, tmp_path):
    today = _today(monkeypatch, tmp_path, entries=FLEET, signins=SIGNINS)
    chips = {lbl: int(n) for n, lbl in re.findall(r'<i></i>(\d+) ([A-Za-z (\)]+?)</a>', today)}
    assert chips.get("Unverified") == 5, chips                     # the chip counts every server
    rows = today.count('class="tact"')                             # three sign-in rows
    groups = {m.group(1): int(m.group(2)) for m in re.finditer(r'<td colspan="5">([^<(]+?) \((\d+)\)', today)}
    assert rows == 3 and groups.get("unverified") == 2, (rows, groups)
    assert rows + sum(groups.values()) == sum(chips.values())


def test_the_observed_tier_has_a_group_line(monkeypatch, tmp_path):
    monkeypatch.setattr(panel, "_classify", lambda name, key, d: "observed" if name == "quiet" else "unverified")
    today = _today(monkeypatch, tmp_path, entries={"quiet": {"command": "npx q"}, "p": {"command": "npx p"}})
    assert "observed in your client" in today and "(1)" in today


def test_the_change_window_chip_reads_as_a_sentence(monkeypatch, tmp_path):
    from mcpgawk import history
    monkeypatch.setattr(history, "changed_within", lambda store, days=7: [("mcp:p", "2026-10-08")])
    today = _today(monkeypatch, tmp_path, entries={"p": {"command": "npx p"}},
                   store={"mcp:p": {"aliases": ["p"]}})
    assert "changed this week" in today and "first seen changed" not in today


def test_an_uncovered_call_is_told_the_remedy_its_state_allows(monkeypatch):
    from mcpgawk import remote_login
    monkeypatch.setattr(remote_login, "auth_needed", lambda *a, **k: {"zoho": "https://z.test/mcp"})
    d = {"entries": {"gitnexus": {"command": "npx g"}, "zoho": {"url": "https://z.test/mcp"}},
         "store": {"servers": {"mcp:connect": {"aliases": ["youspot"]}}}, "pending": ["mcp:connect"]}
    assert "decision" in panel.uncovered_remedy("youspot", d)
    assert "sign-in" in panel.uncovered_remedy("zoho", d)
    assert "run a scan" in panel.uncovered_remedy("gitnexus", d)
    assert "no scan can baseline" in panel.uncovered_remedy("claude-in-chrome", d)


# --- a server set aside is not asked for a sign-in again ------------------------------------------
# robinhood-trading was set aside on 15 Sep ("not available to me"); the panel honoured it, the
# scan's batched offer never read the record and asked again on 2026-10-09.

def test_a_set_aside_server_is_named_once_and_never_prompted_for(monkeypatch, capsys):
    from mcpgawk import remote_login
    monkeypatch.setattr(remote_login, "signin_aside", lambda *a, **k: {"robinhood": "2026-09-15"})
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "N")
    cli._offer_batched_auth([_Row("zoho"), _Row("robinhood")], types.SimpleNamespace(yes=False), {})
    out = capsys.readouterr()
    listed = out.out[out.out.index("These need credentials"):]
    assert "zoho" in listed and "robinhood" not in listed, listed
    assert "Set aside by you, not asked: robinhood" in out.err, out.err
    # Only set-aside servers: nothing to ask, and still named.
    cli._offer_batched_auth([_Row("robinhood")], types.SimpleNamespace(yes=False), {})
    out = capsys.readouterr()
    assert "These need credentials" not in out.out and "robinhood" in out.err


# --- the walk of every panel tab on the founder's 0.1.75/0.1.76 fleet (2026-10-09, evening) ---------

def test_the_agents_detail_knows_a_server_by_its_config_name():
    """youspot's record is `mcp:connect` (what the server calls itself) with alias "youspot" (what
    the config calls it). The Agents detail said "it has no baseline yet — a scan records one"
    about an approved server."""
    d = {"entries": {"youspot": {"url": "https://y.test/mcp"}, "fresh": {"url": "https://f.test/mcp"}},
         "store": {"servers": {"mcp:connect": {"aliases": ["youspot"], "approved": {"items": {}}}}}}
    out = {r["server"]: r for r in panel.uncovered_reasons(d, {"youspot": 232, "fresh": 3})}
    assert out["youspot"]["reason"] == "stale", out["youspot"]
    assert out["fresh"]["reason"] == "unscanned"


def test_the_activity_header_counts_the_charts_own_series(monkeypatch, tmp_path):
    """Header "4729 seen · 167 checked · 2026-10-01 → 10-08" over a chart reading 87 checked,
    3,510 not checked, 09-26 → 10-09: two windows and two row limits on one page."""
    today = _today(monkeypatch, tmp_path, entries={"p": {"command": "npx p"}},
                   calls=[("allow", "p")] * 3 + [("defer", "q")] * 5 + [("deny", "p")])
    # One row OUTSIDE the chart's 14-day window: summarise() counts it (lifetime over the rows
    # it reads), the chart does not. The header must follow the chart.
    import json, os
    from datetime import datetime, timedelta, timezone
    old = (datetime.now(timezone.utc) - timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(os.environ["MCPGAWK_SPOOL"], "a") as f:
        f.write(json.dumps({"ts": old, "decision": "allow", "server": "p", "tool": "t"}) + "\n")
    page = panel.render({"entries": {"p": {"command": "npx p"}}, "store": {"servers": {}}, "pending": [],
                         "activity": {"calls": 999, "checked": 1, "deferred": 998}, "recent_calls": [],
                         "findings": [], "unscannable": [], "monitor": {}, "verify_at": ""}, token="t")
    head = re.search(r"<b>(\d+)</b> seen · <b>(\d+)</b> checked against a baseline"
                     r"(?: · <span class=\"warn\"><b>(\d+)</b> NOT checked)?", page)
    assert head, "no activity headline"
    seen, checked, deferred = int(head.group(1)), int(head.group(2)), int(head.group(3) or 0)
    allowed = int(re.search(r"Checked and allowed \((\d+)\)", page).group(1))
    blocked = int(re.search(r"Blocked \((\d+)\)", page).group(1))
    not_checked = int(re.search(r"Not checked — no baseline \(([\d,]+)\)", page).group(1).replace(",", ""))
    assert (seen, checked, deferred) == (allowed + blocked + not_checked, allowed + blocked, not_checked), \
        (seen, checked, deferred, allowed, blocked, not_checked)
    assert (checked, deferred) == (4, 5)                      # not summarise's 1 / 998


def test_summary_from_series_is_the_chart_arithmetic():
    series = [{"day": "2026-10-08", "total": 10, "checked": 2, "blocked": 1, "not_checked": 8},
              {"day": "2026-10-09", "total": 5, "checked": 1, "blocked": 0, "not_checked": 4}]
    out = panel._summary_from_series(series, {"deferred_unscannable": 7, "calls": 999})
    assert (out["calls"], out["checked"], out["deferred"], out["deferred_unscannable"]) == (15, 3, 12, 7)
    assert panel._summary_from_series([], {"calls": 1}) == {"calls": 1}
