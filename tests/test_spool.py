"""The runtime evidence spool — every decision the agent hook makes.

Closes the gap that made "nothing was blocked" indistinguishable from "nothing was watching": the
hook inspected every MCP call a developer's agent made and recorded none of them.

The properties pinned here are the ones that make it safe to run on a hot path hundreds of times a
session, plus the one that makes it safe to KEEP:

  * arguments are never written — the spool must not become the richest target on the machine;
  * a failure to record never raises, because a lost record must never cost a verdict or break the
    agent session the hook is protecting;
  * every checked call is recorded, not only denials — recording only denials reproduces the exact
    ambiguity this exists to remove;
  * concurrent agent sessions interleave whole lines (O_APPEND), never corrupt each other;
  * a torn line is skipped by the reader, not fatal — the writer can be killed mid-write.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from mcpgawk import spool

HOOK = Path(__file__).resolve().parents[1] / "src" / "mcpgawk" / "guard_hook.py"


def _event(tool: str = "mcp__vault-rag__vault_search", secret: str = "TOP-SECRET-VALUE") -> str:
    return json.dumps({
        "hook_event_name": "PreToolUse",
        "session_id": "sess-1",
        "tool_name": tool,
        "tool_input": {"query": secret, "token": secret},
    })


def _run_hook(spool_path: Path, event: str, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "MCPGAWK_SPOOL": str(spool_path)}
    return subprocess.run([sys.executable, str(HOOK), *args], input=event, capture_output=True,
                          text=True, timeout=60, env=env)


# --- the privacy property -------------------------------------------------------------------- #

def test_tool_arguments_never_reach_the_spool(tmp_path):
    """A security tool whose own log becomes the best place to find secrets has failed at its own
    premise. Arguments routinely carry tokens, file contents and personal data."""
    path = tmp_path / "calls.jsonl"
    r = _run_hook(path, _event(secret="TOP-SECRET-VALUE"))
    assert r.returncode == 0
    written = path.read_text(encoding="utf-8")
    assert written.strip(), "the call was not recorded at all"
    assert "TOP-SECRET-VALUE" not in written
    row = json.loads(written.splitlines()[0])
    assert set(row) <= {"ts", "session", "server", "tool", "decision", "basis", "adapter", "reason"}


# --- the availability property --------------------------------------------------------------- #

def test_an_unwritable_spool_never_breaks_the_hook(tmp_path):
    """Logging is a duty, not a precondition. If the spool cannot be written the call must still
    be decided and the agent must not see an error."""
    blocked = tmp_path / "nope"
    blocked.write_text("i am a file, not a directory", encoding="utf-8")
    r = _run_hook(blocked / "calls.jsonl", _event())
    assert r.returncode == 0, "the hook failed because it could not log"


def test_append_returns_false_instead_of_raising(tmp_path):
    blocked = tmp_path / "f"
    blocked.write_text("x", encoding="utf-8")
    assert spool.append({"a": 1}, path=str(blocked / "sub" / "calls.jsonl")) is False


# --- the completeness property ---------------------------------------------------------------- #

def test_every_checked_call_is_recorded_not_only_denials(tmp_path):
    """Recording only denials makes an empty log mean either 'all clear' or 'not running'."""
    path = tmp_path / "calls.jsonl"
    for _ in range(3):
        _run_hook(path, _event())
    rows = spool.read(path=str(path))
    assert len(rows) == 3
    assert all(r["decision"] in ("defer", "deny", "allow") for r in rows)
    assert {r["server"] for r in rows} == {"vault-rag"}
    assert {r["session"] for r in rows} == {"sess-1"}


def test_a_cursor_event_is_recorded_as_cursor_not_claude_code(tmp_path):
    """The log is the product; a mislabelled log is a wrong log. A Cursor event — with Cursor's
    documented JSON-STRING `tool_input` — must be recorded under its own adapter with the right
    tool name, not silently attributed to Claude Code."""
    path = tmp_path / "calls.jsonl"
    event = json.dumps({
        "hook_event_name": "beforeMCPExecution",
        "session_id": "sess-cursor",
        "tool_name": "mcp__vault-rag__vault_search",
        "tool_input": json.dumps({"query": "CURSOR-SECRET-VALUE"}),
    })
    r = _run_hook(path, event, "--format", "cursor")
    assert r.returncode == 0
    written = path.read_text(encoding="utf-8")
    assert "CURSOR-SECRET-VALUE" not in written, "arguments leaked into the spool"
    row = json.loads(written.splitlines()[0])
    assert row["adapter"] == "cursor"
    assert row["server"] == "vault-rag"
    assert row["tool"] == "vault_search"
    assert row["session"] == "sess-cursor"


def test_a_codex_event_is_recorded_as_codex(tmp_path):
    """Same mislabelling class as Cursor: each agent's decisions must carry its own name."""
    path = tmp_path / "calls.jsonl"
    r = _run_hook(path, _event(), "--format", "codex")
    assert r.returncode == 0
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert row["adapter"] == "codex"
    assert row["tool"] == "vault_search"


def test_a_claude_event_is_recorded_under_the_registry_key(tmp_path):
    """The default format records the adapter registry key, so spool rows line up with the same
    ids `status` and `discover` use — never a hand-invented label."""
    path = tmp_path / "calls.jsonl"
    r = _run_hook(path, _event())
    assert r.returncode == 0
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert row["adapter"] == "claude-code"


def test_non_mcp_tool_calls_are_not_recorded(tmp_path):
    """The hook only judges MCP calls; logging a Bash or Edit call would be surveillance of work
    this product has no business recording."""
    path = tmp_path / "calls.jsonl"
    _run_hook(path, json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                "tool_input": {"command": "ls"}}))
    assert not path.exists() or not path.read_text().strip()


# --- durability / concurrency ------------------------------------------------------------------ #

def test_concurrent_writers_interleave_whole_lines(tmp_path):
    """Two agent sessions run at once routinely. O_APPEND makes a record this size atomic, so no
    line may be torn — that is what makes a lock-free hot path safe."""
    path = tmp_path / "calls.jsonl"
    procs = [subprocess.Popen([sys.executable, str(HOOK)], stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                              env={**os.environ, "MCPGAWK_SPOOL": str(path)})
             for _ in range(8)]
    for p in procs:
        p.communicate(_event(), timeout=60)
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 8
    for line in lines:
        json.loads(line)                            # every line is whole, parseable JSON


def test_a_torn_line_is_skipped_not_fatal(tmp_path):
    path = tmp_path / "calls.jsonl"
    path.write_text('{"ts":"a","tool":"good1"}\n{"ts":"b","too\n{"ts":"c","tool":"good2"}\n',
                    encoding="utf-8")
    tools = {r.get("tool") for r in spool.read(path=str(path))}
    assert {"good1", "good2"} <= tools


def test_rotation_keeps_the_spool_bounded(tmp_path, monkeypatch):
    """A spool that grows without bound eventually fills a laptop, and finding that out during an
    incident is the worst possible time."""
    path = tmp_path / "calls.jsonl"
    monkeypatch.setattr(spool, "MAX_BYTES", 200)
    for i in range(50):
        spool.record_decision(server="s", tool=f"t{i}", decision="defer",
                              adapter="test", path=str(path))
    assert path.stat().st_size <= 400
    assert (tmp_path / "calls.jsonl.1").is_file(), "the previous generation should be kept"


def test_summarise_counts_what_a_human_asks_for(tmp_path):
    path = tmp_path / "calls.jsonl"
    spool.record_decision(server="a", tool="t", decision="defer", adapter="h",
                          session="s1", path=str(path))
    spool.record_decision(server="b", tool="t", decision="deny", adapter="h",
                          session="s2", path=str(path))
    s = spool.summarise(path=str(path))
    assert (s["calls"], s["denied"], s["sessions"], s["servers"]) == (2, 1, 2, 2)


def test_summarise_never_counts_a_decline_as_a_check(tmp_path):
    """Eval 1.6 at the counting layer. `calls` is everything the guard SAW; `checked` is only what
    it evaluated against an approved surface. Folding declines into `checked` is what produced
    "802 MCP call(s) checked" over 801 declines — so they must be counted apart here, not merely
    rendered apart upstream.
    """
    path = tmp_path / "calls.jsonl"
    for _ in range(8):
        spool.record_decision(server="a", tool="t", decision="defer", adapter="h",
                              session="s1", path=str(path))
    spool.record_decision(server="a", tool="t", decision="allow", adapter="h",
                          session="s1", path=str(path))
    spool.record_decision(server="b", tool="t", decision="deny", adapter="h",
                          session="s2", path=str(path))

    s = spool.summarise(path=str(path))
    assert s["calls"] == 10, "every call the guard saw"
    assert s["checked"] == 2, "only the allow + the deny were checked against anything"
    assert s["deferred"] == 8
    assert s["denied"] == 1


def test_a_missing_spool_reads_as_empty_not_an_error(tmp_path):
    assert spool.read(path=str(tmp_path / "absent.jsonl")) == []
    assert spool.summarise(path=str(tmp_path / "absent.jsonl"))["calls"] == 0


# --- the latency budget ------------------------------------------------------------------------ #

def test_appends_stay_inside_the_hot_path_budget(tmp_path):
    """The 17 ms hook budget and the 0.027 ms measured append
    (docs/architecture-runtime-monitoring-2026-07-27.md §2) were measurements, not gates — nothing
    failed if the append quietly grew a database, a lock, or an import. This is the gate: 500
    appends, generously bounded (CI machines vary wildly; the bound is ~75x the measured cost, so
    only a CLASS change — sqlite, locking, an O(n) re-read — can trip it, not a noisy runner)."""
    import time

    path = tmp_path / "calls.jsonl"
    n = 500
    start = time.perf_counter()
    for i in range(n):
        spool.record_decision(server="s", tool=f"t{i}", decision="defer",
                              adapter="budget", session="sess", path=str(path))
    elapsed_ms = (time.perf_counter() - start) * 1000
    per_append_ms = elapsed_ms / n
    assert per_append_ms < 2.0, (
        f"spool append cost {per_append_ms:.3f} ms — the measured baseline is 0.027 ms, so "
        f"something structural changed on the hot path (this runs on EVERY MCP tool call)."
    )
    assert len(spool.read(path=str(path))) == n, "the timed appends must actually have landed"
