"""The guard must find an approved server under the name the AGENT puts in the tool name.

MEASURED 2026-10-05 with a real Claude Code session (2.1.289, `claude -p`, init event): servers
configured as `dot.server`, `space server` and `slash/server` reach tools as `mcp__dot_server__…`,
`mcp__space_server__…`, `mcp__slash_server__…` — every character outside `[A-Za-z0-9_-]` becomes
`_`. The hook looked up `dot_server` verbatim, found nothing, and DEFERRED: the session's own hook log
read `dot_server defer` beside `plain allow`. After a rug pull on both, the installed hook denied
`plain` and passed `dot.server` with "not approved on this machine, so not checked" — an approved
server, unguarded, in the default mode. Strict mode denied it, but as "no baseline", which blocks
the legitimate calls of a server the person approved.
"""
from __future__ import annotations

import pytest

from mcpgawk import guard_hook, history

OLD = {"pin": "p1", "tools": {"read": "aaaaaaaaaaaa"}, "items": {"tool.read": "aaaaaaaaaaaa"},
       "tools_basis": 1, "measured_at": "2026-10-01T00:00:00+00:00"}
#: The same tool, its description rewritten after approval: the rug pull.
PULLED = {"pin": "p2", "tools": {"read": "bbbbbbbbbbbb"}, "items": {"tool.read": "bbbbbbbbbbbb"},
          "tools_basis": 1, "measured_at": "2026-10-02T00:00:00+00:00"}

#: Config name → the server segment Claude Code 2.1.289 put in the tool name (measured, above).
#: `claude.ai Gmail` is Claude Code's own account connector, seen in a live session's tool list as
#: `mcp__claude_ai_Gmail__…` the same day: the everyday case, not an exotic name.
CLAUDE_CODE_NAMES = {"dot.server": "dot_server", "space server": "space_server",
                     "slash/server": "slash_server", "claude.ai Gmail": "claude_ai_Gmail"}


@pytest.fixture(autouse=True)
def _no_behaviour(tmp_path, monkeypatch):
    """No behavioural profile: these are declared-tier decisions only."""
    monkeypatch.setenv("GAWK_BEHAVIOUR", str(tmp_path / "absent-behaviour.json"))


def _approved(aliases: list[str], *, pulled: bool = False, tools: dict | None = None) -> dict:
    approved = dict(OLD) if tools is None else {**OLD, "tools": tools, "items": {
        f"tool.{t}": h for t, h in tools.items()}}
    history_rows = [dict(approved)] + ([dict(PULLED)] if pulled else [])
    return {"aliases": aliases, "history": history_rows, "approved": approved,
            "approved_at": "2026-09-30T00:00:00+00:00"}


def _save(tmp_path, servers: dict, *, strict: bool):
    path = tmp_path / "history.json"
    store = {"servers": servers}
    if strict:
        store["guard"] = {"strict": True}
    history.save(store, str(path))
    return path


def _call(path, server: str, tool: str = "read"):
    output, _note = guard_hook.decide({"tool_name": f"mcp__{server}__{tool}", "tool_input": {}},
                                      path)
    return output


def _denied(output) -> bool:
    return output is not None and output["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("configured, agent_name", sorted(CLAUDE_CODE_NAMES.items()))
def test_a_rug_pull_on_an_approved_server_is_denied_under_the_agents_name(tmp_path, configured,
                                                                           agent_name):
    """THE BYPASS, normal mode: the approved server changed after approval; the call must be
    refused under the name the agent actually sends."""
    path = _save(tmp_path, {f"mcp:{configured}": _approved([configured], pulled=True)},
                 strict=False)
    assert _denied(_call(path, agent_name)), \
        f"a rug pull on approved {configured!r} passed when called as {agent_name!r}"


def test_a_tool_the_approved_baseline_never_had_is_denied_under_the_agents_name(tmp_path):
    path = _save(tmp_path, {"mcp:dot.server": _approved(["dot.server"])}, strict=False)
    assert _denied(_call(path, "dot_server", "write"))
    assert _call(path, "dot_server", "read") is None, "an unchanged approved tool must pass"


def test_strict_mode_lets_an_approved_server_run_under_the_agents_name(tmp_path):
    """Strict refused it as 'no baseline' — a server the person approved, unusable."""
    path = _save(tmp_path, {"mcp:dot.server": _approved(["dot.server"])}, strict=True)
    assert _call(path, "dot_server") is None
    assert _denied(_call(path, "dot_server", "write"))


def test_an_unchanged_call_is_checked_not_declined(tmp_path):
    """The hook log said `defer` for the approved dotted server: a pass must be a CHECKED pass."""
    path = _save(tmp_path, {"mcp:dot.server": _approved(["dot.server"])}, strict=False)
    _output, note, _basis, checked, _reason, _context = guard_hook._decide(
        {"tool_name": "mcp__dot_server__read", "tool_input": {}}, path, "claude")
    assert checked, "an approved server's unchanged call was logged as a decline"
    assert note is None


def test_a_server_literally_named_like_the_rewrite_still_answers_to_its_own_baseline(tmp_path):
    """`a.b` and `a_b` reach the agent under ONE name. Exact identity still picks `a_b`, and the
    other server's baseline is consulted too: the hook only ever adds denials."""
    path = _save(tmp_path, {
        "mcp:a_b": _approved(["a_b"], tools={"read": "aaaaaaaaaaaa", "extra": "cccccccccccc"}),
        "mcp:a.b": _approved(["a.b"]),
    }, strict=False)
    assert _call(path, "a_b") is None
    assert _denied(_call(path, "a_b", "extra")), \
        "'a.b' never had `extra`; a call that may be reaching it must be refused"


def test_two_servers_rewritten_to_one_name_are_ambiguous_and_strict_refuses(tmp_path):
    """`a.b` and `a b` both become `a_b`, and no server is keyed `a_b`: no baseline can be shown to
    apply. Strict refuses; normal mode says so rather than guessing."""
    servers = {"mcp:a.b": _approved(["a.b"]), "mcp:a b": _approved(["a b"])}
    for sub in ("s", "n", "p"):
        (tmp_path / sub).mkdir()
    assert _denied(_call(_save(tmp_path / "s", servers, strict=True), "a_b"))
    _output, note, *_rest = guard_hook._decide(
        {"tool_name": "mcp__a_b__read", "tool_input": {}},
        _save(tmp_path / "n", servers, strict=False), "claude")
    assert note and "a_b" in note
    pulled = {"mcp:a.b": _approved(["a.b"], pulled=True), "mcp:a b": _approved(["a b"])}
    assert _denied(_call(_save(tmp_path / "p", pulled, strict=False), "a_b")), \
        "either candidate's rug pull must refuse the call"


# ── 0.1.71 false block (MEASURED 2026-10-06): the rewrite is Claude Code's, not every agent's ──────

def _windsurf(path, server, tool):
    """Windsurf supplies the RAW config name (agents._parse_windsurf composes mcp__<raw>__<tool>)."""
    event = {"tool_info": {"mcp_server_name": server, "mcp_tool_name": tool,
                           "mcp_tool_arguments": {}}}
    output, *_rest = guard_hook._decide(event, path, "windsurf")
    return output


def _collision(tmp_path, *, strict=False):
    return _save(tmp_path, {
        "mcp:a_b": _approved(["a_b"], tools={"read": "aaaaaaaaaaaa", "extra": "cccccccccccc"}),
        "mcp:a.b": _approved(["a.b"]),
    }, strict=strict)


def test_a_raw_name_is_not_judged_against_a_server_whose_name_merely_rewrites_to_it(tmp_path):
    """Windsurf's `a_b` IS `a_b`: `a.b`'s baseline has no say over it. 0.1.71 denied a_b's own
    approved tool `extra` because a.b lacks it."""
    path = _collision(tmp_path)
    assert _windsurf(path, "a_b", "extra") is None, "a false block on a_b's own approved tool"
    assert _windsurf(path, "a_b", "read") is None


def test_a_raw_dotted_name_is_still_guarded_by_its_own_baseline(tmp_path):
    path = _save(tmp_path, {"mcp:dot.server": _approved(["dot.server"], pulled=True)}, strict=False)
    # Windsurf denies by exit code, so any output from the hook is the deny.
    assert _windsurf(path, "dot.server", "read") is not None, "a rug pull reached through Windsurf passed"


def test_a_collision_deny_names_the_server_whose_baseline_refused(tmp_path):
    """Claude Code really cannot tell `a.b` from `a_b`, so refusing is right; saying a_b's baseline
    lacks `extra` is not — it is a.b's."""
    path = _collision(tmp_path)
    output = _call(path, "a_b", "extra")
    assert _denied(output)
    reason = output["hookSpecificOutput"]["permissionDecisionReason"]
    assert "approved baseline for MCP server 'a_b'" not in reason, reason
    assert "'a.b'" in reason, reason
    # Neither server "added" anything: the truth is that two servers share one name in the agent.
    assert "added a tool" not in reason, reason
    assert "cannot tell which" in reason, reason
    # The true sentence is kept — it is what the spool and panel classify the deny by.
    assert "'extra' is not in the approved baseline for MCP server 'a.b'" in reason, reason
    from mcpgawk import decision
    assert decision.reason_code(reason) == decision.REASON_TOOL_ADDED, reason
    assert reason.count("SECURITY BLOCK") == 1 and reason.count("[mcpgawk guard]") <= 1, reason
    human = output.get("systemMessage") or ""
    assert "was not there when you approved" not in human, human
    assert "a_b" in human and "a.b" in human, human
