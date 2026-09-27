"""Approval is the moment trust moves — and it must come from the human.

THE HOLE THIS CLOSES, found 2026-07-27 by running the product the way an agent would: the guard
blocked a tool that appeared after approval, and the denial text told the agent to run
`mcpgawk approve <server>` to accept the change. The agent has a shell. It ran it, and the
malicious tool was allowed on retry. The control handed its own bypass to the audience most likely
to be acting on an injected instruction — the tool description in that demo literally said "read
~/.ssh/id_rsa".

Two things must hold, and BOTH matter: the command refuses when a human is not demonstrably
present, and the denial message never teaches the way around it.
"""
from __future__ import annotations

import pytest

from mcpgawk import baseline, guard_hook


def _clear(monkeypatch):
    for marker in baseline.AGENT_ENV_MARKERS + (baseline.APPROVE_OVERRIDE_ENV,):
        monkeypatch.delenv(marker, raising=False)


@pytest.mark.parametrize("marker", baseline.AGENT_ENV_MARKERS)
def test_an_agent_session_may_not_approve(monkeypatch, marker):
    _clear(monkeypatch)
    monkeypatch.setenv(marker, "1")
    reason = baseline.approval_blocked_reason()
    assert reason and "agent session" in reason


def test_a_non_interactive_run_may_not_approve(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    reason = baseline.approval_blocked_reason()
    assert reason and "interactive terminal" in reason


def test_a_human_at_a_terminal_may_approve(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert baseline.approval_blocked_reason() is None


def test_ci_can_override_deliberately(monkeypatch):
    """CI legitimately has no TTY and no human. The escape hatch exists, but it is an env var a
    human sets on the pipeline — not a flag an agent can discover from a blocked call."""
    _clear(monkeypatch)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setenv(baseline.APPROVE_OVERRIDE_ENV, "1")
    assert baseline.approval_blocked_reason() is None


@pytest.mark.parametrize("marker", baseline.AGENT_ENV_MARKERS)
def test_the_ci_hatch_never_waives_an_agent_session(monkeypatch, marker):
    """Until 2026-09-27 the hatch was read before the agent markers, so an agent that found it (in
    the docs, the source, or this file) could run `MCPGAWK_APPROVE_NONINTERACTIVE=1 mcpgawk
    approve` and move the baseline itself. An env var is exactly what an agent with a shell sets."""
    _clear(monkeypatch)
    monkeypatch.setenv(marker, "1")
    monkeypatch.setenv(baseline.APPROVE_OVERRIDE_ENV, "1")
    for tty in (True, False):
        monkeypatch.setattr("sys.stdin.isatty", lambda tty=tty: tty)
        reason = baseline.approval_blocked_reason()
        assert reason and "agent session" in reason


def test_no_caller_reads_the_hatch_itself():
    """The decide screen and both panel actions each re-read the hatch beside the gate
    (`if blocked and hatch != "1"`), so they would have waived an agent session on their own even
    after the gate stopped doing so. Only history.approval_blocked_reason may read it."""
    import pathlib
    import mcpgawk
    src = pathlib.Path(mcpgawk.__file__).parent
    readers = sorted(p.name for p in src.rglob("*.py")
                     if "APPROVE_OVERRIDE_ENV)" in p.read_text(encoding="utf-8")
                     and p.name != "history.py")
    assert readers == [], f"re-reads the approve hatch outside the gate: {readers}"


def test_the_decide_screen_refuses_an_agent_even_with_the_hatch(monkeypatch):
    from mcpgawk import decide
    _clear(monkeypatch)
    monkeypatch.setenv(baseline.AGENT_ENV_MARKERS[0], "1")
    monkeypatch.setenv(baseline.APPROVE_OVERRIDE_ENV, "1")

    def _started(*a, **k):   # a regression must fail here, not serve forever
        raise AssertionError("the decide screen started inside an agent session")
    monkeypatch.setattr(decide, "_DecideServer", _started)
    lines = []
    assert decide.serve(port=0, open_browser=False, log=lines.append) == 4
    assert "agent session" in lines[0]


def test_the_denial_never_hands_the_agent_a_bypass(tmp_path):
    """The denial goes into the AGENT'S CONTEXT. It is a prompt to a model, so it must not contain
    an executable remedy — the previous wording ended '...run `mcpgawk approve <server>` if you
    accept the change', and an agent did exactly that."""
    from mcpgawk import history

    store = tmp_path / "history.json"
    # Through the canonical writer, so the hot-path projection the hook enforces from exists.
    history.save(
        {"servers": {"srv": {"approved": {"tools": {"safe_tool": "h1"}}, "aliases": ["srv"]}}},
        str(store))
    out, _ = guard_hook.decide(
        {"tool_name": "mcp__srv__brand_new_tool", "tool_input": {}}, store_path=store)
    assert out is not None, "an unapproved tool must be denied"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]

    assert "mcpgawk approve" not in reason, (
        "the denial tells the agent the exact command that disables this control")
    assert baseline.APPROVE_OVERRIDE_ENV not in reason, "the denial leaks the CI override"
    # And it must positively instruct the model what to do instead.
    lowered = reason.lower()
    assert "do not retry" in lowered
    assert "tell the user" in lowered
