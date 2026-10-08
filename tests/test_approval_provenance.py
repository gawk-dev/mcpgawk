"""Every approval records the evidence that a person made it, and an approval without that evidence
is NAMED on every surface instead of reading as a clean "you approved it".

MEASURED 2026-10-05 (HANDOFF, matrix 5.12): an agent moved its own rug-pulled baseline two ways —
`env -u CLAUDECODE … MCPGAWK_APPROVE_NONINTERACTIVE=1 mcpgawk approve`, and a POST to a panel the
person started with the token read from `~/.mcpgawk/panel-token`. A same-user agent can always write
the store itself, so nothing makes self-approval impossible; FOUNDER decided ("Block + name it")
that an approval with no evidence of a person must be named, never a clean tick.
"""
from __future__ import annotations

import pytest

from mcpgawk import history

SIGHTING = {"pin": "p1", "tools": {"read": "aaaaaaaaaaaa"}, "items": {"tool.read": "aaaaaaaaaaaa"},
            "tools_basis": 1, "measured_at": "2026-10-01T00:00:00+00:00"}


def _store_with_sighting(tmp_path):
    path = str(tmp_path / "history.json")
    history.save({"servers": {"mcp:srv1": {"aliases": ["srv1"], "history": [dict(SIGHTING)]}}},
                 path)
    return path


@pytest.fixture
def person(monkeypatch):
    """A person at a terminal: a TTY, no agent markers, no agent process above us, no hatch."""
    monkeypatch.setattr(history, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(history, "_process_ancestry", lambda: ["zsh", "login", "Terminal"])
    monkeypatch.delenv("MCPGAWK_APPROVE_NONINTERACTIVE", raising=False)
    for m in history.AGENT_ENV_MARKERS:
        monkeypatch.delenv(m, raising=False)


@pytest.fixture
def automation(monkeypatch):
    """Route A's shape: no terminal, markers stripped, the hatch set."""
    monkeypatch.setattr(history, "_stdin_is_tty", lambda: False)
    monkeypatch.setattr(history, "_process_ancestry", lambda: ["sh", "python"])
    monkeypatch.setenv("MCPGAWK_APPROVE_NONINTERACTIVE", "1")
    for m in history.AGENT_ENV_MARKERS:
        monkeypatch.delenv(m, raising=False)


def _entry(path):
    return history.load(path)["servers"]["mcp:srv1"]


def test_a_persons_approval_records_that_a_person_was_present(tmp_path, person):
    path = _store_with_sighting(tmp_path)
    history.approve("mcp:srv1", path)
    ev = _entry(path)["approved_evidence"]
    assert ev["person_present"] is True and ev["terminal"] is True and ev["source"] == "cli"
    store = history.load(path)
    assert history.baseline_origin(store, "mcp:srv1") == "approve"
    assert history.unattended_reason(store, "mcp:srv1") is None
    assert history.changed_since(store, ["mcp:srv1"]) == "since you approved it"


def test_an_approval_through_the_hatch_with_no_terminal_is_named(tmp_path, automation):
    path = _store_with_sighting(tmp_path)
    history.approve("mcp:srv1", path)
    ev = _entry(path)["approved_evidence"]
    assert ev["person_present"] is False and ev["hatch"] is True and ev["terminal"] is False
    store = history.load(path)
    assert history.baseline_origin(store, "mcp:srv1") == "unattended"
    reason = history.unattended_reason(store, "mcp:srv1")
    assert reason and reason.startswith("approved without a person present")
    assert "no terminal" in reason and "automation" in reason
    assert history.APPROVE_OVERRIDE_ENV not in reason, \
        "every surface an agent can read must not teach it the hatch's name"
    assert "you approved" not in history.changed_since(store, ["mcp:srv1"])


def test_an_agent_process_above_the_approval_is_named_even_with_its_markers_stripped(
        tmp_path, automation, monkeypatch):
    """Route A as measured: CLAUDECODE unset, but `claude` is still a visible ancestor."""
    monkeypatch.setattr(history, "_process_ancestry", lambda: ["zsh", "claude", "-zsh", "login"])
    path = _store_with_sighting(tmp_path)
    history.approve("mcp:srv1", path)
    ev = _entry(path)["approved_evidence"]
    assert ev["agent_process"] == "claude" and ev["person_present"] is False
    assert "claude" in history.unattended_reason(history.load(path), "mcp:srv1")


def test_a_panel_approval_is_not_a_person_until_confirmed_at_a_terminal(tmp_path, person):
    """The panel's process belongs to the person who started it; the POST may not. Slice 2 adds the
    terminal confirmation; until then a panel approval is named."""
    path = _store_with_sighting(tmp_path)
    history.approve("mcp:srv1", path, source="panel")
    store = history.load(path)
    assert _entry(path)["approved_evidence"]["source"] == "panel"
    assert history.baseline_origin(store, "mcp:srv1") == "unattended"
    assert "panel" in history.unattended_reason(store, "mcp:srv1")


def test_a_fleet_approval_records_its_evidence_and_names_the_servers_it_vouches_for(
        tmp_path, automation):
    path = str(tmp_path / "history.json")
    history.save({"servers": {"mcp:srv1": {
        "aliases": ["srv1"], "history": [dict(SIGHTING)], "approved": dict(SIGHTING),
        "approved_via": "first-sighting"}}}, path)
    discovered = {"srv1": {"command": "srv1-server", "args": []}}
    history.approve_fleet(discovered, path)
    store = history.load(path)
    assert history.fleet_baseline(store)["evidence"]["person_present"] is False
    assert history.baseline_origin(store, "mcp:srv1") == "unattended", \
        "a first sighting vouched for by an unattended fleet approval is not a person's approval"
    assert history.unattended_reason(store, "mcp:srv1")


def test_an_older_approval_without_evidence_keeps_its_wording(tmp_path):
    """Approvals made before this field existed are not re-judged: unknown is not guessed."""
    path = str(tmp_path / "history.json")
    history.save({"servers": {"mcp:srv1": {
        "aliases": ["srv1"], "history": [dict(SIGHTING)], "approved": dict(SIGHTING),
        "approved_at": "2026-09-30T00:00:00+00:00", "approved_via": "approve"}}}, path)
    store = history.load(path)
    assert history.baseline_origin(store, "mcp:srv1") == "approve"
    assert history.unattended_reason(store, "mcp:srv1") is None


def test_an_approval_published_from_another_pillar_records_its_evidence(tmp_path, automation):
    """`baseline.publish` (monitor approve) is the third writer the gate guards; it is named too."""
    from mcpgawk import baseline
    path = _store_with_sighting(tmp_path)
    baseline.publish("mcp:srv1", pin="p9", tools={"read": "aaaaaaaaaaaa"},
                     approved_at="2026-10-05T00:00:00+00:00", path=path)
    store = history.load(path)
    assert _entry(path)["approved_evidence"]["person_present"] is False
    assert history.baseline_origin(store, "mcp:srv1") == "unattended"


# ---- every surface names an unattended baseline instead of calling it "you approved it" --------

AGENT_EVIDENCE = {"source": "cli", "terminal": False, "agent_markers": ["CLAUDECODE"],
                  "agent_process": "claude", "hatch": False, "person_present": False}


def _report(origin, prev_at):
    from mcpgawk import drift
    r = drift.DriftReport(pin_changed=True, added=["tool.b"], removed=[], changed=[],
                          token_delta=10, prev_at=prev_at)
    r.baseline_origin = origin
    return r


@pytest.mark.parametrize("prev_at", ["2026-10-01T00:00:00+00:00", None])
def test_the_drift_header_never_says_you_approved_an_unattended_baseline(prev_at):
    from mcpgawk import drift
    out = drift.render("srv1", _report("unattended", prev_at))
    assert "you approved" not in out, out
    assert "without a person present" in out, out


def _unattended_store():
    return {"mcp:x": {"aliases": ["x"], "approved_at": "2026-10-01T00:00:00+00:00",
                      "approved_by": "me", "approved_via": "approve",
                      "approved_evidence": dict(AGENT_EVIDENCE),
                      "approved": {"items": {"tool.a": "h1"}, "measured_at": "2026-10-01T00:00:00Z",
                                   "pin": "p", "cost_index": 1},
                      "history": [{"items": {"tool.a": "h1", "tool.b": "h2"},
                                   "seen": "2026-10-07T00:00:00Z",
                                   "measured_at": "2026-10-07T00:00:00Z", "pin": "p2",
                                   "cost_index": 2}]}}


def test_the_decide_screen_never_says_you_approved_an_unattended_baseline():
    from mcpgawk import panel
    html = panel.render_next({"store": {"servers": _unattended_store()}, "entries": {},
                              "monitor": {}, "verify_at": ""}, token="T")
    assert "you approved it" not in html, html[:500]
    assert "without a person present" in html, html[:500]


def test_baseline_listing_names_an_unattended_approval(tmp_path, capsys):
    from types import SimpleNamespace
    from mcpgawk import cli
    path = str(tmp_path / "history.json")
    history.save({"servers": _unattended_store()}, path)
    cli._baseline(SimpleNamespace(history=path, json=False, server=None))
    out = capsys.readouterr().out
    assert "without a person present" in out, out
    assert " by me" not in out, out
