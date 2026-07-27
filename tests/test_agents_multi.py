"""Multi-agent adapters — Cursor and Codex, over the SAME decision core.

`status` reported six agents on this machine as having "no hook point". That was true of our
implementation, not of the agents: five of the seven expose a pre-execution hook. What matters in
these tests is that adding an agent adds a payload reader and a verdict writer — never a second
opinion about whether a call is safe.

The security-relevant asymmetries, each pinned:

  * Cursor's verdict shape is `{"permission": "deny"}` with SNAKE_CASE messages. Emitting Claude's
    shape reads to Cursor as a malformed hook — and a malformed hook ALLOWS the call.
  * Cursor sends `tool_input` as a JSON *string*, not an object.
  * Exit 2 denies on Cursor and Codex. It must NOT be used for Claude Code, where a non-zero exit
    means the hook itself failed — the founding rule is that our failure is never read as a verdict.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcpgawk import agents, guard

HOOK = Path(__file__).resolve().parents[1] / "src" / "mcpgawk" / "guard_hook.py"
APPROVED = {"servers": {"mcp:notes": {"aliases": ["notes"],
                                      "approved": {"tools": {"read_note": "h1"}}}}}


def _store(tmp_path: Path) -> Path:
    p = tmp_path / "history.json"
    p.write_text(json.dumps(APPROVED), encoding="utf-8")
    return p


def _run(fmt: str, event: dict, store: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOK), "--format", fmt], input=json.dumps(event), text=True,
        capture_output=True, timeout=60,
        env={"MCPGAWK_HISTORY": str(store), "MCPGAWK_SPOOL": str(store.parent / "c.jsonl"),
             "PATH": "/usr/bin:/bin", "HOME": str(store.parent)})


# --- one decision, three dialects -------------------------------------------------------------- #

@pytest.mark.parametrize("fmt", ["claude", "cursor", "codex"])
def test_an_unapproved_tool_is_denied_in_every_dialect(tmp_path, fmt):
    store = _store(tmp_path)
    args = json.dumps({"x": 1}) if fmt == "cursor" else {"x": 1}
    r = _run(fmt, {"tool_name": "mcp__notes__evil", "tool_input": args}, store)
    payload = json.loads(r.stdout)
    verdict = payload.get("permission") or payload["hookSpecificOutput"]["permissionDecision"]
    assert verdict == "deny"


@pytest.mark.parametrize("fmt", ["claude", "cursor", "codex"])
def test_an_approved_tool_passes_in_every_dialect(tmp_path, fmt):
    store = _store(tmp_path)
    args = json.dumps({}) if fmt == "cursor" else {}
    r = _run(fmt, {"tool_name": "mcp__notes__read_note", "tool_input": args}, store)
    assert r.returncode == 0
    assert not r.stdout.strip(), "an approved call must produce no verdict at all"


def test_cursor_gets_cursors_shape_not_claudes(tmp_path):
    """Emitting the wrong shape is not a formatting slip — Cursor treats a malformed hook response
    as a failure, and a failed hook ALLOWS the call."""
    store = _store(tmp_path)
    payload = json.loads(_run("cursor", {"tool_name": "mcp__notes__evil",
                                         "tool_input": "{}"}, store).stdout)
    assert payload["permission"] == "deny"
    assert "user_message" in payload and "agent_message" in payload
    assert "hookSpecificOutput" not in payload


def test_cursor_tool_input_arrives_as_a_json_string(tmp_path):
    """Cursor documents tool_input as a JSON-stringified string. Decoded in the adapter so the
    decision core keeps exactly one input shape."""
    name, args = agents.parse_event("cursor", {"tool_name": "t", "tool_input": '{"a": 1}'})
    assert (name, args) == ("t", {"a": 1})
    # Malformed JSON must degrade to empty args, never raise on the hot path.
    assert agents.parse_event("cursor", {"tool_name": "t", "tool_input": "{oops"}) == ("t", {})


def test_exit_two_denies_only_where_it_means_deny(tmp_path):
    """Claude Code reads a non-zero exit as OUR failure, not as a verdict; Cursor and Codex
    document exit 2 as a deny. Using one rule for all three would either weaken Cursor or make
    every Claude Code block look like a crashed hook."""
    store = _store(tmp_path)
    evt = {"tool_name": "mcp__notes__evil", "tool_input": {}}
    assert _run("claude", evt, store).returncode == 0
    assert _run("codex", evt, store).returncode == 2
    assert _run("cursor", {**evt, "tool_input": "{}"}, store).returncode == 2


# --- installation ------------------------------------------------------------------------------ #

def test_cursor_install_sets_failClosed(tmp_path, monkeypatch):
    """THE one that matters. Cursor ALLOWS the call when a hook errors unless failClosed is set, so
    omitting it installs something that looks like protection and is not."""
    cfg = tmp_path / "hooks.json"
    adapter = agents.AgentAdapter(key="cursor", label="Cursor", config=cfg, fmt="cursor",
                                  parse=agents._parse_cursor, deny=agents._deny_cursor)
    guard.install_for(adapter)
    data = json.loads(cfg.read_text())
    entry = data["hooks"]["beforeMCPExecution"][0]
    assert entry["failClosed"] is True
    assert data["version"] == 1
    assert "--format cursor" in entry["command"]


def test_install_is_idempotent_and_preserves_other_hooks(tmp_path):
    cfg = tmp_path / "hooks.json"
    cfg.write_text(json.dumps({"version": 1, "hooks": {
        "beforeMCPExecution": [{"command": "/somebody/elses/hook.sh"}]}}), encoding="utf-8")
    adapter = agents.AgentAdapter(key="cursor", label="Cursor", config=cfg, fmt="cursor",
                                  parse=agents._parse_cursor, deny=agents._deny_cursor)
    guard.install_for(adapter)
    guard.install_for(adapter)
    entries = json.loads(cfg.read_text())["hooks"]["beforeMCPExecution"]
    assert sum(1 for e in entries if guard.MARKER in e.get("command", "")) == 1
    assert any("/somebody/elses/hook.sh" in e.get("command", "") for e in entries)


def test_uninstall_removes_only_ours(tmp_path):
    cfg = tmp_path / "hooks.json"
    cfg.write_text(json.dumps({"version": 1, "hooks": {
        "beforeMCPExecution": [{"command": "/somebody/elses/hook.sh"}]}}), encoding="utf-8")
    adapter = agents.AgentAdapter(key="cursor", label="Cursor", config=cfg, fmt="cursor",
                                  parse=agents._parse_cursor, deny=agents._deny_cursor)
    guard.install_for(adapter)
    guard.uninstall_for(adapter)
    entries = json.loads(cfg.read_text())["hooks"]["beforeMCPExecution"]
    assert entries == [{"command": "/somebody/elses/hook.sh"}]


def test_agents_without_a_hook_point_are_named_with_the_reason():
    """VS Code and Claude Desktop genuinely cannot block a call. Saying nothing would let a gap
    read as coverage."""
    assert set(agents.NO_HOOK_POINT) == {"vscode", "claude-desktop"}
    assert all("proxy" in why for why in agents.NO_HOOK_POINT.values())
