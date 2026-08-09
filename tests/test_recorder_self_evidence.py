"""The recorder proves its own failures — an error storm must not look like an idle machine.

Phase 1 task 2: `append` notes its own failure to a sidecar, `recorder_health` reads it back,
and `status` renders it loudly. None of it may ever raise into the hook's hot path.
"""
from __future__ import annotations

import os
import stat

from mcpgawk import spool


def test_append_failure_writes_the_sidecar(tmp_path):
    # A directory where the spool file should be: open() fails, sidecar is still writable.
    target = tmp_path / "calls.jsonl"
    target.mkdir()
    ok = spool.append({"server": "s", "tool": "t"}, path=str(target))
    assert ok is False
    health = spool.recorder_health(path=str(target))
    assert health is not None, "a dropped record must leave self-evidence"
    assert health["ts"] and health["reason"]
    mode = stat.S_IMODE(os.stat(str(target) + spool.ERR_SUFFIX).st_mode)
    assert mode == 0o600, "the recorder's own health file follows the 0600 rule"


def test_successful_append_leaves_no_failure_note(tmp_path):
    target = tmp_path / "calls.jsonl"
    assert spool.append({"server": "s", "tool": "t"}, path=str(target)) is True
    assert spool.recorder_health(path=str(target)) is None


def test_note_failure_never_raises_even_when_unwritable(tmp_path):
    # Deepest failure: even the sidecar location is unwritable. Must degrade to nothing.
    spool.note_failure("boom", path=str(tmp_path / "nope" / "deep" / "calls.jsonl"))
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        spool.note_failure("boom", path=str(ro / "calls.jsonl"))
    finally:
        ro.chmod(0o700)


def test_last_failure_wins(tmp_path):
    target = str(tmp_path / "calls.jsonl")
    spool.note_failure("first", path=target)
    spool.note_failure("second", path=target)
    assert spool.recorder_health(path=target)["reason"] == "second"


def test_status_renders_recorder_failure(tmp_path, monkeypatch):
    target = tmp_path / "calls.jsonl"
    monkeypatch.setenv(spool.SPOOL_ENV, str(target))
    spool.note_failure("PermissionError: denied", path=str(target))
    from mcpgawk import status as status_mod
    text = status_mod.collect_and_render()
    assert "RECORDER FAILURE" in text
    assert "incomplete" in text


def test_status_quiet_when_recorder_healthy(tmp_path, monkeypatch):
    monkeypatch.setenv(spool.SPOOL_ENV, str(tmp_path / "calls.jsonl"))
    from mcpgawk import status as status_mod
    assert "RECORDER FAILURE" not in status_mod.collect_and_render()


def test_sidecar_is_ignored_by_spool_readers(tmp_path):
    target = str(tmp_path / "calls.jsonl")
    spool.record_decision(server="s", tool="t", decision="defer", adapter="claude-code",
                          path=target)
    spool.note_failure("boom", path=target)
    rows = spool.read(path=target)
    assert len(rows) == 1 and rows[0]["server"] == "s"
    assert spool.summarise(path=target)["calls"] == 1
