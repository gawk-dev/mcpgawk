"""`mcpgawk guard` — the PreToolUse hook that puts the approved baseline in the agent's loop.

Two things get pinned here that are easy to get wrong and expensive to get wrong:
  1. the DECISION TABLE, especially the cases where the guard must NOT act (never-approved
     servers, non-MCP tools, its own internal errors) — a security hook that blocks everything on
     a machine that never ran `approve` is worse than no hook at all;
  2. the INSTALLER's treatment of a file it does not own. It edits the user's real Claude Code
     settings, so "preserves other hooks", "atomic", and "uninstall removes only ours" are
     correctness, not niceties.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcpgawk import guard
from mcpgawk.guard_hook import approved_for, decide, parse_mcp_tool_name

HOOK_SCRIPT = Path(guard.hook_script_path())


def _store(tmp_path: Path, servers: dict) -> Path:
    p = tmp_path / "history.json"
    p.write_text(json.dumps({"servers": servers}))
    return p


def _approved(tools: dict[str, str], aliases: list[str] | None = None) -> dict:
    # Mirrors what baseline.publish() actually writes: `aliases` is a SIBLING of `approved`.
    rec: dict = {"approved": {"pin": "abc123", "tools": tools,
                              "measured_at": "2026-07-27T00:00:00Z"}}
    if aliases:
        rec["aliases"] = aliases
    return rec


# --------------------------------------------------------------------------- name parsing


def test_parse_mcp_tool_name():
    assert parse_mcp_tool_name("mcp__figma__get_file") == ("figma", "get_file")
    # a TOOL name may itself contain __; the server name is the first segment
    assert parse_mcp_tool_name("mcp__srv__a__b") == ("srv", "a__b")
    for not_mcp in ("Bash", "Edit", "mcp__", "mcp__only", "", "mcp____x"):
        assert parse_mcp_tool_name(not_mcp) is None, not_mcp


# --------------------------------------------------------------------------- decision table


def test_unapproved_tool_on_an_approved_server_is_denied(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    out, _ = decide({"tool_name": "mcp__figma__delete_everything"}, store)
    assert out is not None
    decision = out["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert decision["hookEventName"] == "PreToolUse"
    assert "delete_everything" in decision["permissionDecisionReason"]
    assert "mcpgawk approve" in decision["permissionDecisionReason"]  # names the remedy


def test_approved_tool_defers(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    out, _ = decide({"tool_name": "mcp__figma__get_file"}, store)
    assert out is None


def test_never_approved_server_defers_rather_than_blocking_everything(tmp_path):
    """THE most important case. Most machines have never run `mcpgawk approve`; a guard that
    denied there would break every MCP tool call the moment it was installed."""
    store = _store(tmp_path, {"other": _approved({"x": "h"})})
    out, _ = decide({"tool_name": "mcp__figma__anything"}, store)
    assert out is None


def test_non_mcp_tools_are_not_our_business(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    for tool in ("Bash", "Edit", "Write", "Read"):
        assert decide({"tool_name": tool}, store) == (None, None)


def test_missing_or_corrupt_store_defers(tmp_path):
    assert decide({"tool_name": "mcp__x__y"}, tmp_path / "absent.json") == (None, None)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert decide({"tool_name": "mcp__x__y"}, bad) == (None, None)


def test_alias_keyed_approval_is_found(tmp_path):
    """A server approved under its asserted identity must still match the config name the agent
    uses in the tool string."""
    store = _store(tmp_path, {"sha-identity": _approved({"get_file": "h1"}, aliases=["figma"])})
    assert approved_for("figma", store) == {"get_file": "h1"}
    out, _ = decide({"tool_name": "mcp__figma__other_tool"}, store)
    assert out is not None  # denied: known server, unknown tool


def test_the_guard_never_returns_allow(tmp_path):
    """`permissionDecision: allow` means 'skip the prompt the user would have seen'. A security
    hook emitting it would silently auto-approve calls, REDUCING protection. Only deny/defer."""
    store = _store(tmp_path, {"s": _approved({"good": "h"})})
    for tool in ("mcp__s__good", "mcp__s__bad", "mcp__unknown__t", "Bash"):
        out, _ = decide({"tool_name": tool}, store)
        if out is not None:
            assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


# --------------------------------------------------------------------------- the real process


def _run_hook(event: dict, store: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)], input=json.dumps(event), text=True,
        capture_output=True, env={"MCPGAWK_HISTORY": str(store), "PATH": "/usr/bin:/bin",
                                 "HOME": str(store.parent)}, timeout=60,
    )


def test_hook_runs_as_a_real_process_and_emits_valid_json(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    proc = _run_hook({"tool_name": "mcp__figma__evil", "tool_input": {}}, store)
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_exits_zero_and_stays_silent_on_garbage_input(tmp_path):
    """Never non-zero: a non-zero PreToolUse exit is an error condition, and our own failure must
    not be read as a verdict either way."""
    store = _store(tmp_path, {})
    for bad in ("", "   ", "not json at all", "[1,2,3]"):
        proc = subprocess.run([sys.executable, str(HOOK_SCRIPT)], input=bad, text=True,
                              capture_output=True, env={"MCPGAWK_HISTORY": str(store)}, timeout=60)
        assert proc.returncode == 0, bad
        assert proc.stdout.strip() == "", bad


def test_hook_imports_no_heavy_dependencies():
    """The hot path runs on EVERY MCP tool call. Importing the package pulls the MCP SDK in
    through __init__ (measured ~190ms); running the file by path is ~10ms. This asserts the
    module's imports stay stdlib-only so that stays true."""
    source = HOOK_SCRIPT.read_text()
    for banned in ("import mcp", "from mcp", "import httpx", "import tiktoken", "from ."):
        assert banned not in source, f"guard_hook.py must stay stdlib-only, found {banned!r}"


# --------------------------------------------------------------------------- baseline contract


def test_lean_reader_agrees_with_the_canonical_baseline_loader(tmp_path):
    """guard_hook re-reads history.json instead of importing mcpgawk.baseline, for speed. A second
    reader is exactly how this repo has drifted before, so pin them together: if the canonical
    shape changes, this fails HERE rather than in a user's agent."""
    from mcpgawk import baseline

    key = "srv"
    store = tmp_path / "history.json"
    # Written by the product's OWN writer, so the file under test is genuinely canonical rather
    # than a shape this test invented.
    baseline.publish(key, pin="abc123", tools={"alpha": "h1", "beta": "h2"},
                     approved_at="2026-07-27T00:00:00Z", alias="friendly-name", path=str(store))

    canonical = baseline.approved_tools(key, str(store))
    lean = approved_for(key, store)
    assert lean == canonical, (lean, canonical)
    assert canonical  # not vacuously equal because both are empty

    # ...and the alias path resolves against the file the real writer produced. This is what
    # caught the reader looking for `aliases` INSIDE the approved record: publish() writes it
    # alongside, and only a canonically-written file exposes the difference.
    assert approved_for("friendly-name", store) == canonical


# --------------------------------------------------------------------------- the installer


def test_install_is_idempotent_and_preserves_other_hooks(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "model": "opus",
        "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "someone-elses-tool"}]},
        ]},
    }))

    guard.install(settings)
    guard.install(settings)          # twice: must not duplicate

    data = json.loads(settings.read_text())
    assert data["model"] == "opus"   # unrelated settings survive
    groups = data["hooks"]["PreToolUse"]
    ours = [h for g in groups for h in g["hooks"] if guard.MARKER in h["command"]]
    theirs = [h for g in groups for h in g["hooks"] if "someone-elses-tool" in h["command"]]
    assert len(ours) == 1, "re-install duplicated the hook"
    assert len(theirs) == 1, "another vendor's hook was destroyed"
    assert ours[0]["timeout"] == guard.HOOK_TIMEOUT_S
    assert [g for g in groups if any(guard.MARKER in h["command"] for h in g["hooks"])][0]["matcher"] == "mcp__.*"


def test_uninstall_removes_only_ours(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "someone-elses-tool"}]},
    ]}}))
    guard.install(settings)
    guard.uninstall(settings)

    data = json.loads(settings.read_text())
    flat = [h for g in data["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert len(flat) == 1
    assert "someone-elses-tool" in flat[0]["command"]
    assert settings.is_file()  # never deletes the file


def test_uninstall_tidies_up_when_we_were_the_only_hook(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"model": "opus"}))
    guard.install(settings)
    guard.uninstall(settings)
    data = json.loads(settings.read_text())
    assert data == {"model": "opus"}     # back to exactly what it was
    assert "hooks" not in data


def test_install_refuses_to_touch_unparseable_settings(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text("{ this is not json")
    with pytest.raises(guard.GuardError, match="not readable JSON"):
        guard.install(settings)
    assert settings.read_text() == "{ this is not json"  # left exactly alone


def test_install_backs_up_the_previous_file(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"model": "opus"}))
    guard.install(settings)
    backup = settings.with_suffix(".json.mcpgawk-backup")
    assert backup.is_file()
    assert json.loads(backup.read_text()) == {"model": "opus"}


def test_install_into_a_fresh_machine_with_no_settings_file(tmp_path):
    settings = tmp_path / "nested" / "settings.json"
    guard.install(settings)
    assert guard.is_installed(json.loads(settings.read_text()))


def test_status_reports_all_three_states(tmp_path):
    settings = tmp_path / "settings.json"
    assert "NOT installed" in guard.status(settings)

    settings.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "other"}]}]}}))
    text = guard.status(settings)
    assert "NOT installed" in text and "other PreToolUse hook" in text

    guard.install(settings)
    text = guard.status(settings)
    assert "INSTALLED" in text
    assert "nothing leaves this machine" in text


def test_cli_wires_guard(tmp_path, capsys):
    from mcpgawk.cli import main as cli_main

    settings = tmp_path / "settings.json"
    assert cli_main(["guard", "install", "--settings", str(settings)]) == 0
    assert cli_main(["guard", "status", "--settings", str(settings)]) == 0
    assert "INSTALLED" in capsys.readouterr().out
    assert cli_main(["guard", "uninstall", "--settings", str(settings)]) == 0
