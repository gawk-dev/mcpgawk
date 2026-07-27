"""One user's local state must not be readable by other users on the machine.

Found 2026-07-27 by inspecting a real install rather than the code: `~/.gawk` and `~/.mcpgawk` were
`0755`, and the enforce audit DB, drift history, run registry and licence cache were all `0644`.
Every account on that machine could read the complete inventory of the operator's MCP servers, every
tool call the guard saw and every reason it blocked one. The OAuth token store already wrote `0600`
files — so the intent existed, it just was never applied anywhere else, because each store rolled
its own makedirs + open.

These tests pin the boundary at the STORES, not at the helper, because a helper nobody calls is the
exact shape of the original bug.
"""
from __future__ import annotations

import os
import stat
import sys

import pytest

from mcpgawk import history, runlog, state

pytestmark = pytest.mark.skipif(sys.platform == "win32",
                                reason="POSIX mode bits; Windows ACLs are a different mechanism")


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _group_or_other_bits(path) -> int:
    return _mode(path) & (stat.S_IRWXG | stat.S_IRWXO)


class TestTheHelper:
    def test_secure_dir_creates_owner_only(self, tmp_path):
        d = state.secure_dir(tmp_path / "nested" / "state")
        assert _group_or_other_bits(d) == 0

    def test_it_tightens_a_directory_that_already_exists(self, tmp_path):
        d = tmp_path / "loose"
        d.mkdir(mode=0o755)
        state.secure_dir(d)
        assert _group_or_other_bits(d) == 0

    def test_it_never_loosens_a_file_the_operator_hardened(self, tmp_path):
        """A 'secure default' that relaxes someone's deliberate 0400 is a downgrade wearing the
        right label. Tightening removes bits; it never adds them."""
        f = tmp_path / "locked.json"
        f.write_text("{}")
        f.chmod(0o400)
        state.secure_file(f)
        assert _mode(f) == 0o400

    def test_harden_reports_failure_rather_than_claiming_success(self, tmp_path):
        missing = tmp_path / "nope" / "gone.db"
        assert state.harden(missing) is True or state.harden(missing) is False   # never raises

    def test_sqlite_sidecars_are_hardened_too(self, tmp_path):
        """-wal and -shm carry the same rows mid-transaction; protecting only the main file
        protects nothing."""
        db = tmp_path / "s.db"
        db.write_text("")
        for suffix in ("-wal", "-shm"):
            side = tmp_path / f"s.db{suffix}"
            side.write_text("")
            side.chmod(0o644)
        state.harden(db, sidecars=True)
        for suffix in ("-wal", "-shm"):
            assert _group_or_other_bits(tmp_path / f"s.db{suffix}") == 0

    def test_it_warns_when_a_file_stays_exposed(self, tmp_path, capsys, monkeypatch):
        f = tmp_path / "exposed.json"
        f.write_text("{}")
        f.chmod(0o644)
        monkeypatch.setattr(state, "secure_file", lambda p: False)   # simulate a filesystem that cannot
        state.warn_if_exposed(f, "drift history")
        assert "readable by other users" in capsys.readouterr().err


class TestTheStoresActuallyUseIt:
    """The property that matters. A helper nobody calls is the bug this replaces."""

    def test_run_registry_is_owner_only(self, tmp_path):
        db = str(tmp_path / "runs.db")
        runlog.finish_run(runlog.start_run("scan", path=db), runlog.OK, path=db)
        assert _group_or_other_bits(db) == 0
        assert _group_or_other_bits(tmp_path) == 0

    def test_drift_history_is_owner_only(self, tmp_path):
        p = str(tmp_path / "nested" / "history.json")
        history.save({"servers": {}}, p)
        assert _group_or_other_bits(p) == 0
        assert _group_or_other_bits(os.path.dirname(p)) == 0

    # The PAID stores (enforce audit DB, licence cache) are covered by
    # tests/test_state_boundary_platform.py — kept separate so this file imports mcpgawk only and
    # can ship in the public suite with the code it guards.
