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
    # Through the canonical writer, so the hot-path projection the hook enforces from exists.
    from mcpgawk import history

    p = tmp_path / "history.json"
    history.save(json.loads(json.dumps(APPROVED)), str(p))
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


# --- Kimi CLI: the TOML adapter ---------------------------------------------------------------- #

def _kimi_adapter(tmp_path: Path):
    return agents.AgentAdapter(key="kimi", label="Kimi CLI", config=tmp_path / "config.toml",
                               fmt="kimi", parse=agents._parse_kimi, deny=agents._deny_kimi)


def test_kimi_install_uninstall_round_trips_byte_identically(tmp_path):
    """Kimi's hooks live inside its MAIN config, a TOML file full of the user's own settings and
    comments. Our writer is textual — one fenced block — precisely so everything that is not ours
    survives byte for byte. This is the acceptance pin: original bytes in, original bytes out."""
    cfg = tmp_path / "config.toml"
    original = ('# my kimi settings — hands off\n'
                'model = "kimi-k2"\n\n'
                '[[hooks]]\n'
                'event = "PostToolUse"\n'
                'command = "/somebody/elses/hook.sh"\n')
    cfg.write_text(original, encoding="utf-8")

    adapter = _kimi_adapter(tmp_path)
    guard.install_for(adapter)
    installed = cfg.read_text(encoding="utf-8")
    assert guard.MARKER in installed
    assert "/somebody/elses/hook.sh" in installed, "another vendor's hook was destroyed"

    import tomllib
    parsed = tomllib.loads(installed)
    ours = [h for h in parsed["hooks"] if guard.MARKER in h.get("command", "")]
    assert len(ours) == 1
    assert ours[0]["event"] == "PreToolUse"
    assert ours[0]["matcher"] == guard.MCP_MATCHER
    assert "--format kimi" in ours[0]["command"]
    assert parsed["model"] == "kimi-k2"

    guard.uninstall_for(adapter)
    assert cfg.read_text(encoding="utf-8") == original, "uninstall must be byte-identical"


def test_kimi_install_is_idempotent(tmp_path):
    import tomllib

    adapter = _kimi_adapter(tmp_path)
    guard.install_for(adapter)
    guard.install_for(adapter)
    parsed = tomllib.loads(adapter.config.read_text(encoding="utf-8"))
    assert sum(1 for h in parsed["hooks"] if guard.MARKER in h.get("command", "")) == 1
    assert guard.is_installed_for(adapter)


def test_kimi_install_refuses_unparseable_toml(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("model = 'unterminated\n", encoding="utf-8")
    adapter = _kimi_adapter(tmp_path)
    with pytest.raises(guard.GuardError, match="TOML"):
        guard.install_for(adapter)
    assert cfg.read_text(encoding="utf-8") == "model = 'unterminated\n", "left exactly alone"


def test_kimi_denies_by_exit_two_with_the_deny_shape(tmp_path):
    """Kimi blocks on exit code 2 (its documented deny channel); the JSON alongside carries the
    reason in the Claude-compatible shape its hook system is modelled on."""
    store = _store(tmp_path)
    r = _run("kimi", {"tool_name": "mcp__notes__evil", "tool_input": {}}, store)
    assert r.returncode == 2
    payload = json.loads(r.stdout)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "notes" in payload["hookSpecificOutput"]["permissionDecisionReason"]


def test_kimi_approved_call_exits_zero_and_silent(tmp_path):
    store = _store(tmp_path)
    r = _run("kimi", {"tool_name": "mcp__notes__read_note", "tool_input": {}}, store)
    assert r.returncode == 0
    assert not r.stdout.strip()


def test_kimi_decisions_are_recorded_under_their_own_adapter(tmp_path):
    from mcpgawk import spool

    store = _store(tmp_path)
    _run("kimi", {"tool_name": "mcp__notes__read_note", "tool_input": {},
                  "session_id": "sess-k"}, store)
    rows = spool.read(path=str(tmp_path / "c.jsonl"))
    assert rows and rows[0]["adapter"] == "kimi"


def test_kimi_servers_are_discovered(tmp_path):
    from mcpgawk.discover import discover_servers

    (tmp_path / ".kimi").mkdir()
    (tmp_path / ".kimi" / "mcp.json").write_text(json.dumps(
        {"mcpServers": {"notes": {"command": "npx", "args": ["-y", "notes-mcp"]}}}),
        encoding="utf-8")
    found = discover_servers(home=tmp_path, platform="darwin")
    assert any("kimi" in entry.get("_clients", []) for entry in found.values()), found


# --- Gemini CLI: BeforeTool, decision/reason ---------------------------------------------------- #

def _gemini_adapter(tmp_path: Path):
    return agents.AgentAdapter(key="gemini-cli", label="Gemini CLI",
                               config=tmp_path / "settings.json", fmt="gemini",
                               parse=agents._parse_gemini, deny=agents._deny_gemini)


def test_gemini_denies_in_its_own_shape_with_exit_two(tmp_path):
    """Gemini's documented verdict is {"decision": "deny", "reason": ...} — not Claude's nested
    shape — plus exit 2. Emitting the wrong dialect is a malformed hook, not a block."""
    store = _store(tmp_path)
    r = _run("gemini", {"tool_name": "mcp__notes__evil", "tool_input": {},
                        "mcp_context": {}, "original_request_name": "evil"}, store)
    assert r.returncode == 2
    payload = json.loads(r.stdout)
    assert payload["decision"] == "deny"
    assert "notes" in payload["reason"]
    assert "hookSpecificOutput" not in payload


def test_gemini_approved_call_exits_zero_and_silent(tmp_path):
    store = _store(tmp_path)
    r = _run("gemini", {"tool_name": "mcp__notes__read_note", "tool_input": {}}, store)
    assert r.returncode == 0
    assert not r.stdout.strip()


def test_gemini_install_targets_beforetool_and_preserves_settings(tmp_path):
    """The hook goes under hooks.BeforeTool (Gemini's event name, not PreToolUse), inside the
    same settings.json that carries the user's servers and preferences."""
    cfg = tmp_path / "settings.json"
    cfg.write_text(json.dumps({
        "mcpServers": {"notes": {"command": "npx"}},
        "theme": "dark",
        "hooks": {"BeforeTool": [{"matcher": ".*",
                                  "hooks": [{"type": "command",
                                             "command": "/somebody/elses/hook.sh"}]}]},
    }), encoding="utf-8")
    adapter = _gemini_adapter(tmp_path)
    guard.install_for(adapter)
    guard.install_for(adapter)                       # idempotent

    data = json.loads(cfg.read_text())
    assert data["mcpServers"] == {"notes": {"command": "npx"}}
    assert data["theme"] == "dark"
    assert "PreToolUse" not in data["hooks"], "wrong event name would install dead config"
    groups = data["hooks"]["BeforeTool"]
    ours = [h for g in groups for h in g.get("hooks", []) if guard.MARKER in h.get("command", "")]
    assert len(ours) == 1
    assert "--format gemini" in ours[0]["command"]
    assert any("/somebody/elses/hook.sh" in h.get("command", "")
               for g in groups for h in g.get("hooks", []))


def test_gemini_uninstall_round_trips(tmp_path):
    cfg = tmp_path / "settings.json"
    original = {"mcpServers": {"notes": {"command": "npx"}},
                "hooks": {"BeforeTool": [{"matcher": ".*",
                                          "hooks": [{"type": "command",
                                                     "command": "/somebody/elses/hook.sh"}]}]}}
    cfg.write_text(json.dumps(original), encoding="utf-8")
    adapter = _gemini_adapter(tmp_path)
    guard.install_for(adapter)
    guard.uninstall_for(adapter)
    assert json.loads(cfg.read_text()) == original


def test_gemini_decisions_are_recorded_under_their_own_adapter(tmp_path):
    from mcpgawk import spool

    store = _store(tmp_path)
    _run("gemini", {"tool_name": "mcp__notes__read_note", "tool_input": {},
                    "session_id": "sess-g"}, store)
    rows = spool.read(path=str(tmp_path / "c.jsonl"))
    assert rows and rows[0]["adapter"] == "gemini-cli"


# --- Windsurf (user level): pre_mcp_tool_use, exit-2 deny --------------------------------------- #

def _windsurf_adapter(tmp_path: Path):
    return agents.AgentAdapter(key="windsurf", label="Windsurf",
                               config=tmp_path / "hooks.json", fmt="windsurf",
                               parse=agents._parse_claude, deny=agents._deny_windsurf)


def test_windsurf_denies_by_exit_two(tmp_path):
    """Windsurf's deny channel is the exit code — the JSON alongside is informational.

    Uses Windsurf's REAL payload. This test previously passed a Claude-shaped event, which
    Windsurf never sends — so it went green against an adapter that could not read its own
    agent and silently allowed every call.
    """
    store = _store(tmp_path)
    r = _run("windsurf", {"agent_action_name": "pre_mcp_tool_use",
                          "tool_info": {"mcp_server_name": "notes", "mcp_tool_name": "evil",
                                        "mcp_tool_arguments": {}}}, store)
    assert r.returncode == 2
    payload = json.loads(r.stdout)
    assert payload["decision"] == "deny"
    assert "notes" in payload["reason"]


def test_windsurf_approved_call_exits_zero_and_silent(tmp_path):
    store = _store(tmp_path)
    r = _run("windsurf", {"tool_name": "mcp__notes__read_note", "tool_input": {}}, store)
    assert r.returncode == 0
    assert not r.stdout.strip()


def test_windsurf_install_targets_pre_mcp_tool_use_and_round_trips(tmp_path):
    """User-level ~/.codeium/windsurf/hooks.json: our entry under pre_mcp_tool_use, other
    vendors' hooks preserved, uninstall returns exactly the original structure. System-level
    (root-protected) install is deliberately NOT this task — enterprise, not v1."""
    cfg = tmp_path / "hooks.json"
    original = {"hooks": {"pre_mcp_tool_use": [{"command": "/somebody/elses/hook.sh"}]}}
    cfg.write_text(json.dumps(original), encoding="utf-8")

    adapter = _windsurf_adapter(tmp_path)
    guard.install_for(adapter)
    guard.install_for(adapter)                       # idempotent

    entries = json.loads(cfg.read_text())["hooks"]["pre_mcp_tool_use"]
    ours = [e for e in entries if guard.MARKER in e.get("command", "")]
    assert len(ours) == 1
    assert "--format windsurf" in ours[0]["command"]
    assert ours[0]["timeout"] == guard.HOOK_TIMEOUT_S
    assert any("/somebody/elses/hook.sh" in e.get("command", "") for e in entries)

    guard.uninstall_for(adapter)
    assert json.loads(cfg.read_text()) == original


def test_windsurf_decisions_are_recorded_under_their_own_adapter(tmp_path):
    from mcpgawk import spool

    store = _store(tmp_path)
    # Windsurf's real payload — see WINDSURF_EVENT and _parse_windsurf.
    _run("windsurf", {"agent_action_name": "pre_mcp_tool_use", "session_id": "sess-w",
                      "tool_info": {"mcp_server_name": "notes",
                                    "mcp_tool_name": "read_note",
                                    "mcp_tool_arguments": {}}}, store)
    rows = spool.read(path=str(tmp_path / "c.jsonl"))
    assert rows and rows[0]["adapter"] == "windsurf"


# --- Windsurf: the only payload that shares NO field with the others -------------------------- #

#: Verbatim from docs.devin.ai/desktop/cascade/hooks. Kept literal on purpose: this adapter
#: originally reused the Claude parser, which reads a top-level `tool_name` that does not exist
#: here — so every Windsurf call parsed as "not an MCP tool" and was silently allowed AND never
#: logged, while `status` reported Windsurf as covered. A test written against our own assumed
#: shape would have passed. Only the vendor's real payload catches it.
WINDSURF_EVENT = {
    "agent_action_name": "pre_mcp_tool_use",
    "tool_info": {
        "mcp_server_name": "notes",
        "mcp_tool_name": "evil",
        "mcp_tool_arguments": {"owner": "code-owner", "repo": "my-cool-repo"},
    },
}


def test_windsurf_real_payload_is_understood():
    """Server and tool arrive SEPARATELY and the tool name is bare, so the canonical
    `mcp__server__tool` is composed rather than read."""
    name, args = agents.parse_event("windsurf", WINDSURF_EVENT)
    assert name == "mcp__notes__evil"
    assert args == {"owner": "code-owner", "repo": "my-cool-repo"}


def test_windsurf_real_payload_is_actually_blocked(tmp_path):
    """THE regression test. Before the fix this exited 0 with no verdict and no spool row — an
    adapter that installs, reports as covered, and checks nothing."""
    store = _store(tmp_path)
    r = _run("windsurf", WINDSURF_EVENT, store)
    assert r.returncode == 2, "Windsurf denies by exit code 2; 0 means the call went through"
    assert json.loads(r.stdout)["decision"] == "deny"


def test_windsurf_records_the_call_it_judged(tmp_path):
    """The silent-allow bug also lost the LOG. 'Nothing blocked' must never be indistinguishable
    from 'nothing watched' — that is the whole reason the spool exists."""
    store = _store(tmp_path)
    _run("windsurf", WINDSURF_EVENT, store)
    rows = [json.loads(ln) for ln in (store.parent / "c.jsonl").read_text().splitlines() if ln.strip()]
    assert rows and rows[-1]["server"] == "notes" and rows[-1]["tool"] == "evil"
    assert rows[-1]["adapter"] == "windsurf"


def test_windsurf_approved_tool_still_passes(tmp_path):
    store = _store(tmp_path)
    ok = {"agent_action_name": "pre_mcp_tool_use",
          "tool_info": {"mcp_server_name": "notes", "mcp_tool_name": "read_note",
                        "mcp_tool_arguments": {}}}
    r = _run("windsurf", ok, store)
    assert r.returncode == 0 and not r.stdout.strip()


@pytest.mark.parametrize("bad", [
    {},                                                        # no tool_info at all
    {"tool_info": "not-an-object"},
    {"tool_info": {"mcp_tool_name": "evil"}},                  # server missing
    {"tool_info": {"mcp_server_name": "notes"}},               # tool missing
    {"tool_info": {"mcp_server_name": "", "mcp_tool_name": "evil"}},
])
def test_a_malformed_windsurf_payload_defers_rather_than_crashing(bad):
    """Defer, never crash: an exception on the hot path would surface as a broken hook mid-session,
    and Windsurf fails OPEN on hook error — so a crash here would allow the call anyway."""
    assert agents.parse_event("windsurf", bad) == (None, {})


def test_no_adapter_silently_reuses_a_parser_that_cannot_read_its_payload():
    """The class of bug, pinned. Every adapter must extract the tool name from a payload shaped
    the way ITS agent actually sends one — proven by running each parser against its own sample."""
    samples = {
        "claude":   {"tool_name": "mcp__s__t", "tool_input": {}},
        "codex":    {"tool_name": "mcp__s__t", "tool_input": {}},
        "kimi":     {"tool_name": "mcp__s__t", "tool_input": {}},
        "gemini":   {"tool_name": "mcp__s__t", "tool_input": {}},
        "cursor":   {"tool_name": "mcp__s__t", "tool_input": "{}"},
        "windsurf": {"tool_info": {"mcp_server_name": "s", "mcp_tool_name": "t",
                                   "mcp_tool_arguments": {}}},
    }
    for fmt, event in samples.items():
        name, _ = agents.parse_event(fmt, event)
        assert name == "mcp__s__t", f"{fmt} could not read its own agent's payload"


# --- B4: the free hook consumes the behavioural tier ------------------------------------------- #

def _run_behavioural(tmp_path: Path, event: dict, profile: dict) -> subprocess.CompletedProcess:
    store = _store(tmp_path)
    behaviour = tmp_path / "behaviour.json"
    behaviour.write_text(json.dumps({"schema": "gawk.behaviour/1", "servers": profile}),
                         encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(HOOK)], input=json.dumps(event), text=True, capture_output=True,
        timeout=60,
        env={"MCPGAWK_HISTORY": str(store), "MCPGAWK_SPOOL": str(tmp_path / "c.jsonl"),
             "GAWK_BEHAVIOUR": str(behaviour), "PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})


#: mail.read_inbox observed delivering untrusted content; notes.read_note observed egressing.
#: Keyed by the CONFIG NAME the agent uses in `mcp__<name>__<tool>` — that is the identity the
#: hook can see at call time. Both tools sit on APPROVED surfaces (see _store: `notes` aliases
#: `mcp:notes`), so the DECLARED tier defers on every call — any deny below is the behavioural
#: tier's own work.
_PROFILE = {"mail": {"read_inbox": {"source": True}},
            "notes": {"read_note": {"sink": True}}}


def test_the_free_hook_blocks_an_observed_sink_after_an_observed_source(tmp_path):
    """The product sentence, on a free install: the call is verified against expected BEHAVIOUR.
    Same session: source fires (defers, recorded in the spool), then the sink call is denied on
    the observed basis — no paid engine anywhere in this test."""
    src = {"tool_name": "mcp__mail__read_inbox", "tool_input": {}, "session_id": "sess-b4"}
    r1 = _run_behavioural(tmp_path, src, _PROFILE)
    assert r1.returncode == 0 and not r1.stdout.strip(), "the source call itself defers"

    sink = {"tool_name": "mcp__notes__read_note", "tool_input": {}, "session_id": "sess-b4"}
    r2 = _run_behavioural(tmp_path, sink, _PROFILE)
    payload = json.loads(r2.stdout)
    reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "OBSERVED" in reason and "read_inbox" in reason

    from mcpgawk import spool

    rows = spool.read(path=str(tmp_path / "c.jsonl"))
    denied = [r for r in rows if r["decision"] == "deny"]
    assert denied and denied[0]["basis"] == "observed", \
        "the record must carry the observed basis, not the declared one"


def test_a_different_session_does_not_inherit_the_source(tmp_path):
    """Session memory is per session — yesterday's untrusted content must not poison today."""
    src = {"tool_name": "mcp__mail__read_inbox", "tool_input": {}, "session_id": "sess-one"}
    _run_behavioural(tmp_path, src, _PROFILE)
    sink = {"tool_name": "mcp__notes__read_note", "tool_input": {}, "session_id": "sess-two"}
    r = _run_behavioural(tmp_path, sink, _PROFILE)
    assert r.returncode == 0 and not r.stdout.strip()


def test_the_profile_never_clears_a_declared_deny_in_the_hook(tmp_path):
    """Positive-only, end to end: an unapproved tool stays denied on the DECLARED basis with a
    profile present."""
    evt = {"tool_name": "mcp__notes__evil", "tool_input": {}, "session_id": "sess-b4"}
    r = _run_behavioural(tmp_path, evt, _PROFILE)
    payload = json.loads(r.stdout)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "approved baseline" in payload["hookSpecificOutput"]["permissionDecisionReason"]

    from mcpgawk import spool

    rows = spool.read(path=str(tmp_path / "c.jsonl"))
    assert rows[0]["basis"] == "declared"


def test_no_profile_leaves_the_hook_exactly_as_before(tmp_path):
    """The tier is absent without observations — never guessed from names in the free hook."""
    store = _store(tmp_path)
    r = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"tool_name": "mcp__notes__read_note", "tool_input": {},
                          "session_id": "s"}),
        text=True, capture_output=True, timeout=60,
        env={"MCPGAWK_HISTORY": str(store), "MCPGAWK_SPOOL": str(tmp_path / "c.jsonl"),
             "GAWK_BEHAVIOUR": str(tmp_path / "absent.json"),
             "PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
    assert r.returncode == 0 and not r.stdout.strip()
