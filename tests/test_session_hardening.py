"""Session memory that survives load, rotation, and key drift — Phase 1 task 3.

The sequence check's memory previously read the last 500 spool rows GLOBALLY: a busy parallel
session evicted this session's earlier source calls and the control faded out silently.
Rotation wiped memory outright. And session identity was one exact dict key. Each fix is
pinned here, including the eviction scenario that used to fail.
"""
from __future__ import annotations


from mcpgawk import spool
from mcpgawk import guard_hook


def _row(session: str, server: str = "srv", tool: str = "fetch") -> dict:
    return {"ts": "2026-07-29T00:00:00Z", "session": session,
            "server": server, "tool": tool, "decision": "defer",
            "basis": "declared", "adapter": "claude-code"}


def test_read_session_survives_parallel_session_eviction(tmp_path):
    target = str(tmp_path / "calls.jsonl")
    spool.append(_row("A", server="web-reader", tool="fetch_page"), path=target)
    for _ in range(600):                       # another session's traffic, past the old 500 cap
        spool.append(_row("B"), path=target)
    assert spool.read(path=target, limit=500)[499].get("session") == "B", \
        "precondition: a global 500-row read no longer reaches session A"
    rows = spool.read_session("A", path=target)
    assert [(r["server"], r["tool"]) for r in rows] == [("web-reader", "fetch_page")]


def test_read_session_consults_previous_generation(tmp_path):
    target = str(tmp_path / "calls.jsonl")
    spool.append(_row("A", server="web-reader", tool="fetch_page"), path=target)
    import os
    os.replace(target, target + ".1")          # a rotation happened mid-session
    spool.append(_row("A", server="notes", tool="list"), path=target)
    rows = spool.read_session("A", path=target)
    servers = {r["server"] for r in rows}
    assert servers == {"web-reader", "notes"}, "rotation must not wipe session memory"


def test_session_sources_reach_past_global_cap(tmp_path, monkeypatch):
    target = str(tmp_path / "calls.jsonl")
    monkeypatch.setenv(spool.SPOOL_ENV, target)
    spool.append(_row("A", server="web-reader", tool="fetch_page"), path=target)
    for _ in range(600):
        spool.append(_row("B"), path=target)
    behaviour = {"web-reader": {"fetch_page": {"source": True}}}
    sources = guard_hook._session_sources("A", behaviour)
    assert ("web-reader", "fetch_page") in sources, \
        "the sequence check must not fade out under a parallel session's load"


def test_session_id_accepts_common_variants():
    assert guard_hook._session_id({"session_id": "s1"}) == "s1"
    assert guard_hook._session_id({"sessionId": "s2"}) == "s2"
    assert guard_hook._session_id({"session_id": ""}) is None
    assert guard_hook._session_id({"session_id": 42}) is None
    assert guard_hook._session_id({}) is None


def test_summarise_counts_missing_session_identity(tmp_path):
    target = str(tmp_path / "calls.jsonl")
    spool.append(_row("A"), path=target)
    no_id = _row("A")
    no_id["session"] = None
    spool.append(no_id, path=target)
    assert spool.summarise(path=target)["no_session"] == 1


def test_status_reports_no_session_calls(tmp_path, monkeypatch):
    target = str(tmp_path / "calls.jsonl")
    monkeypatch.setenv(spool.SPOOL_ENV, target)
    no_id = _row("A")
    no_id["session"] = None
    spool.append(no_id, path=target)
    from mcpgawk import status as status_mod
    text = status_mod.collect_and_render()
    assert "no session identity" in text
