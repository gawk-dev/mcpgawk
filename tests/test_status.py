"""`mcpgawk status` — unit tests for the thinnest-tested surface of the free journey.

The rule the module exists to keep (its own words): coverage is stated PER AGENT, never in
aggregate — a cheerful aggregate "Protected" converts a gap into a belief of safety. These tests
pin that rule, the not-watching-is-never-implied-by-silence property of the spool fold, and the
per-agent row states, all against `render()` directly so every case is constructable.
"""
from __future__ import annotations

from mcpgawk import status


def _render(**overrides) -> str:
    base = dict(hook_health={}, guard_path=None, agents={},
                baseline_total=0, pending=[], behaviour_tools=None,
                enforce_available=False, last_activity=None, activity=None)
    base.update(overrides)
    return status.render(**base)


# --- per-agent rows, never an aggregate -------------------------------------------------------- #

def test_every_agent_gets_its_own_row_with_its_own_state():
    """Regression, eval 1.7. This test previously asserted that installing into Claude Code made
    Cursor read ON too — it pinned the defect rather than the rule, which is how a live
    "every MCP call checked" claim for an unwired agent survived a green suite. Health is per
    agent because the config file is per agent."""
    out = _render(hook_health={"claude-code": "ok"},
                  agents={"claude-code": 3, "cursor": 2, "vscode": 1})
    assert "Claude Code" in out and "ON" in out
    # Cursor is hook-capable but was never wired: it must NOT inherit Claude Code's installation.
    cursor_row = next(ln for ln in out.splitlines() if "Cursor" in ln)
    assert "ON" not in cursor_row
    assert "OFF" in cursor_row
    # VS Code has no hook point: its row must say the gap out loud, not vanish into an aggregate.
    vscode_row = next(ln for ln in out.splitlines() if "VS Code" in ln)
    assert "--" in vscode_row and "without a check" in vscode_row


def test_a_hook_capable_agent_without_the_guard_says_off_and_names_the_fix():
    out = _render(hook_health={}, agents={"claude-code": 4})
    row = next(ln for ln in out.splitlines() if "Claude Code" in ln)
    assert "OFF" in row and "unchecked" in row and "mcpgawk" in row


def test_no_agents_found_is_stated_not_blank():
    out = _render(agents={})
    assert "No MCP-using agents found" in out


def test_uncovered_agents_are_never_promoted_by_installing_the_guard():
    """Installing the hook covers hook-capable agents ONLY. The most dangerous regression this
    surface could have is a blanket ON."""
    out = _render(hook_health={"claude-desktop": "ok"}, agents={"claude-desktop": 2})
    row = next(ln for ln in out.splitlines() if "Claude Desktop" in ln)
    assert "ON" not in row
    assert "--" in row


def test_a_configured_but_unrunnable_hook_is_neither_on_nor_off():
    """Eval 1.8. A hook whose interpreter or script has gone (`uv tool install --force`, a moved
    venv) is CONFIGURED but cannot run, so every MCP call goes unchecked. Reported ON it is a lie;
    reported OFF it tells the user to run something they already ran, and hides that they are
    currently unprotected."""
    out = _render(hook_health={"claude-code": "broken"}, agents={"claude-code": 4})
    row = next(ln for ln in out.splitlines() if "Claude Code" in ln)
    assert "BROKEN" in row
    assert " ON " not in row
    assert "UNCHECKED" in row
    assert "guard install" in row, "the row must name the repair, not just the state"


def test_hook_health_is_read_per_agent_from_each_agents_own_config(monkeypatch):
    """The wiring, not just the rendering: `hook_health_by_client` must ask the guard about EACH
    adapter rather than deriving one machine-wide answer."""
    from mcpgawk import agents as agents_mod
    from mcpgawk import guard

    asked: list[str] = []

    def fake_health(adapter):
        asked.append(adapter.key)
        return "ok" if adapter.key == "claude-code" else "absent"

    monkeypatch.setattr(guard, "hook_health_for", fake_health)
    health = status.hook_health_by_client()
    assert set(asked) == set(agents_mod.ADAPTERS), "every adapter must be asked, not just one"
    assert health["claude-code"] == "ok"
    assert all(v == "absent" for k, v in health.items() if k != "claude-code")


# --- "not watching" is never implied by silence ------------------------------------------------ #

def test_an_empty_spool_says_it_cannot_distinguish_clear_from_unwatched():
    """The distinction that motivates the whole spool: configuration is not observation. An empty
    record must never render as reassurance."""
    for empty in (None, {}, {"calls": 0}):
        out = _render(activity=empty)
        assert "nothing recorded yet" in out
        assert "cannot yet be" in out and "distinguished" in out


def test_the_spool_fold_reports_what_was_actually_seen():
    out = _render(activity={"calls": 12, "checked": 12, "deferred": 0, "sessions": 3, "servers": 2,
                            "denied": 1, "last_seen": "2026-07-28T10:00:00Z"})
    assert "12 MCP call(s) seen" in out
    assert "12 actually checked" in out
    assert "3 agent session(s)" in out
    assert "1 denied" in out
    assert "2026-07-28T10:00:00Z" in out


def test_calls_the_guard_declined_to_check_are_never_counted_as_checked():
    """Eval 1.6, the real machine: `802 MCP call(s) checked … 1 denied`, exit 0, while the log
    held 801 declines and one deny and NOTHING was ever enforced. Seen and checked are different
    numbers, and the declines have to be visible as a gap the user can close."""
    out = _render(activity={"calls": 802, "checked": 1, "deferred": 801, "sessions": 4,
                            "servers": 6, "denied": 1, "last_seen": "2026-08-02T10:00:00Z"})
    assert "802 MCP call(s) seen" in out
    assert "802 MCP call(s) checked" not in out, "the total must never be presented as checked"
    assert "1 actually checked" in out
    assert "801 call(s) NOT checked" in out
    assert "mcpgawk scan" in out, "the gap must name the repair"


def test_a_log_predating_the_distinction_says_so_rather_than_guessing():
    """Rows written before `checked` existed cannot answer the question. Inferring it either way
    restates the same false claim — say the log cannot tell."""
    out = _render(activity={"calls": 50, "sessions": 2, "servers": 3, "denied": 0,
                            "last_seen": "2026-08-02T10:00:00Z"})
    assert "50 MCP call(s) seen" in out
    assert "not recorded in this log" in out
    assert "actually checked" not in out.replace("actually CHECKED", "")


def test_zero_denials_is_stated_explicitly_not_omitted():
    """'none denied' is information; a missing line is ambiguity."""
    out = _render(activity={"calls": 5, "sessions": 1, "servers": 1,
                            "denied": 0, "last_seen": "2026-07-28T10:00:00Z"})
    assert "none denied" in out


# --- what the checking is against -------------------------------------------------------------- #

def test_name_only_posture_is_announced_when_no_behaviour_profile_exists():
    out = _render(behaviour_tools=None)
    assert "by NAME only" in out, "no profile must be named as the weaker posture, not skipped"


def test_a_profile_that_observed_nothing_is_distinct_from_no_profile():
    out = _render(behaviour_tools=0)
    assert "0 tool(s) with observed behaviour" in out
    assert "by NAME only" not in out


def test_pending_drift_is_a_blocking_call_to_action():
    out = _render(pending=["notes", "figma"])
    assert "2 server(s) changed since their baseline" in out
    assert "notes" in out and "figma" in out
    assert "mcpgawk approve" in out


def test_muted_findings_count_is_visible_and_says_never_hidden():
    out = _render(muted_total=3)
    assert "3 finding(s) muted by you" in out
    assert "never hidden" in out
    assert "muted by you" not in _render(muted_total=0)


def test_collect_and_render_survives_every_store_being_broken(monkeypatch, tmp_path):
    """One unreadable store must degrade a line, never blank the whole answer."""
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "not-a-dir" / "history.json"))
    out = status.collect_and_render()
    assert "RUNTIME CHECKING" in out and "WHAT IT HAS ACTUALLY SEEN" in out


def test_the_on_row_claims_the_behavioural_tier_without_overclaiming_it():
    """B6: the free hook checks observed behaviour since B4 — an ON row that only mentions the
    baseline hides the stronger free tier; one that flatly claims it overclaims on a machine
    where verify has recorded nothing. The hedge is part of the wording."""
    out = _render(hook_health={"claude-code": "ok"}, agents={"claude-code": 1})
    row = next(ln for ln in out.splitlines() if "Claude Code" in ln)
    assert "observed behaviour" in row
    assert "where recorded" in row


# --------------------------------------------------------------------------- slice 4: status --json

def test_to_json_mirrors_the_rendered_facts_and_routes_the_panel_rows(monkeypatch):
    from mcpgawk import status
    fixture = {
        "errors": {}, "discovery_problems": [], "unscannable": [], "pending": ["mcp:notion"],
        "activity": {"calls": 3, "checked": 1, "deferred": 2, "denied": 0, "sessions": 1,
                     "servers": 1, "last_seen": "2026-09-05T07:00:00Z", "no_session": 0},
        "recent_calls": [], "denied_servers": set(), "session_calls": [], "fleet_calls": [],
        "hooks": {}, "hook_health": {}, "adapters": {}, "no_hook": {}, "runs": [],
        "observed": {}, "verified_runs": {}, "findings": [], "verify_at": "", "verify_blocked": None,
        "verified": {"notion": {"at": "2026-09-03T10:00:00Z", "backend": "proxy", "status": "clean",
                                "transport": "http", "checks_planned": 4, "checks_completed": 4}},
        "monitor": {}, "gateway": {"installed": False},
        "entries": {"notion": {"url": "https://mcp.notion.com/mcp", "_clients": ["claude-code"],
                               "_names": {"claude-code": "notion"}, "_aliases": ["notion"]}},
        "store": {"servers": {"mcp:notion": {
            "aliases": ["notion"],
            "approved": {"pin": "abc", "measured_at": "t", "tools": {"search": {}}},
            "approved_at": "2026-09-02T09:00:00+00:00", "approved_by": "someone@host",
            "history": [{"pin": "abd", "measured_at": "t2", "tools": {"search": {}}}]}}},
    }
    collected = dict(hook_health={"claude-code": "ok"}, guard_path=None,
                     agents={"claude-code": 1, "claude-desktop": 2}, baseline_total=1,
                     pending=["notion"], behaviour_tools=None, enforce_available=False,
                     last_activity="scan — findings at t", activity=fixture["activity"],
                     muted_total=0, behavioural_unavailable=None, monitor_open=None,
                     baseline_error=None, agents_error=None, unprotected=None)
    doc = status.to_json(collected, panel_data=fixture)
    assert doc["schema"] == "gawk.status/1"
    rows = {r["client"]: r for r in doc["agents"]}
    assert rows["claude-code"]["hook"] == "ok"
    assert rows["claude-desktop"]["hook"] == "unsupported"      # no hook shape: say so, not "off"
    assert doc["pending"] == ["notion"] and doc["activity"]["calls"] == 3
    (srv,) = doc["servers"]
    assert srv["name"] == "notion" and srv["key"] == "mcp:notion" and srv["tier"] == "changed"
    assert srv["approved"]["at"] == "2026-09-02T09:00:00+00:00"
    assert srv["approved"]["by"] == "someone@host"
    assert srv["seen_at"] == "t2" and srv["pending"] is True
    assert srv["verified"]["at"] == "2026-09-03T10:00:00Z" and srv["sandbox"] == "proxy"
    import json
    json.dumps(doc)


def test_to_json_never_dies_when_the_panel_cannot_collect(monkeypatch):
    from mcpgawk import panel, status
    def boom(*a, **k):
        raise OSError("store unreadable")
    monkeypatch.setattr(panel, "collect", boom)
    doc = status.to_json(dict(hook_health={}, agents={}, baseline_total=0, pending=[],
                              behaviour_tools=None, enforce_available=False, last_activity=None,
                              activity=None, muted_total=0, baseline_error="bad store"))
    assert doc["servers"] is None
    assert "store unreadable" in doc["errors"]["servers"] and doc["errors"]["baseline"] == "bad store"


def test_collect_and_render_is_render_over_collect():
    from mcpgawk import status
    collected = status.collect()
    assert isinstance(collected, dict) and "hook_health" in collected
    assert status.render(**collected) == status.collect_and_render()


def test_collect_reads_the_profile_the_rest_of_the_product_writes(tmp_path, monkeypatch):
    """`status` must resolve the behaviour profile THROUGH `behaviour_profile_path`, never a
    hardcoded `~/.gawk/behaviour.json`.

    panel.py states that rule in its own comment and decide.py copies it; status.py was the copy
    that never got made. MEASURED 2026-09-18 against the shipped 0.1.50: with
    GAWK_BEHAVIOUR_PROFILE pointing at a profile holding exactly 2 tools, `mcpgawk status` printed
    "29 tool(s) with observed behaviour" — the operator's own ~/.gawk file, which the rest of the
    product was not using. status is the screen that states what IS and is NOT protected, so it is
    the worst possible one to read a file nothing else reads.

    `Path.home` is redirected as well as the env var, and that is the half that makes this a real
    detector: without it the hardcoded line still finds a populated profile on a developer's own
    machine and the test passes with the bug intact.
    """
    from pathlib import Path

    from mcpgawk import status as status_mod

    fake_home = tmp_path / "fakehome"
    (fake_home / ".gawk").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))

    profile = tmp_path / "relocated" / "behaviour.json"
    profile.parent.mkdir(parents=True)
    profile.write_text(
        '{"servers": {"notes": {"read_notes": {}, "write_note": {}}}}', encoding="utf-8")
    monkeypatch.setenv("GAWK_BEHAVIOUR_PROFILE", str(profile))
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))

    assert status_mod.collect()["behaviour_tools"] == 2
