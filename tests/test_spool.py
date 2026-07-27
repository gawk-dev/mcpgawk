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


def _run_hook(spool_path: Path, event: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "MCPGAWK_SPOOL": str(spool_path)}
    return subprocess.run([sys.executable, str(HOOK)], input=event, capture_output=True,
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


def test_a_missing_spool_reads_as_empty_not_an_error(tmp_path):
    assert spool.read(path=str(tmp_path / "absent.jsonl")) == []
    assert spool.summarise(path=str(tmp_path / "absent.jsonl"))["calls"] == 0
