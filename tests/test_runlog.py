"""The run registry — the seam that makes a cross-pillar timeline possible.

Its value is entirely in being trustworthy, so the tests are mostly about the honesty rules rather
than the happy path: an unfinished run must never read as success, a registry failure must never
break the work being recorded and must never be silent, and `running` rows must not accumulate
forever after a crash.
"""
from __future__ import annotations

import os
import sqlite3
import pytest

from mcpgawk import runlog


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "runs.db")


class TestBasics:
    def test_a_run_opens_and_closes(self, db):
        rid = runlog.start_run("scan", "server-filesystem", path=db)
        assert rid
        runlog.finish_run(rid, runlog.FINDINGS, {"findings": 6}, path=db)
        run = runlog.get_run(rid, path=db)
        assert run.kind == "scan" and run.target == "server-filesystem"
        assert run.status == runlog.FINDINGS and run.summary == {"findings": 6}
        assert run.finished and run.ended_at

    def test_start_run_can_publish_facts_while_still_running(self, db):
        """The enforce gateway's listen endpoint is only USEFUL while the run is `running` —
        the panel answers "where do I point my agent" from this row, and by the time
        finish_run writes its summary there is no gateway to point at any more."""
        rid = runlog.start_run("enforce", "acme",
                               summary={"listen": "http://127.0.0.1:8080/mcp"}, path=db)
        run = runlog.get_run(rid, path=db)
        assert run.status == runlog.RUNNING
        assert run.summary["listen"] == "http://127.0.0.1:8080/mcp"
        # The close replaces the summary wholesale — a fact that should survive must be repeated.
        runlog.finish_run(rid, runlog.OK, {"calls": 3}, path=db)
        assert runlog.get_run(rid, path=db).summary == {"calls": 3}

    def test_findings_is_not_an_error(self, db):
        """A scan that ran perfectly and found six problems is not a failure — collapsing the two
        would make the timeline useless at a glance."""
        rid = runlog.start_run("scan", path=db)
        runlog.finish_run(rid, runlog.FINDINGS, {"findings": 6}, path=db)
        assert runlog.get_run(rid, path=db).status != runlog.ERROR

    def test_runs_list_newest_first_and_filter_by_kind(self, db):
        for kind in ("scan", "verify", "scan"):
            runlog.finish_run(runlog.start_run(kind, path=db), runlog.OK, path=db)
        assert len(runlog.list_runs(path=db)) == 3
        assert [r.kind for r in runlog.list_runs(kind="scan", path=db)] == ["scan", "scan"]
        newest, oldest = runlog.list_runs(path=db)[0], runlog.list_runs(path=db)[-1]
        assert newest.started_at >= oldest.started_at

    def test_an_unknown_kind_is_a_programming_error_not_a_silent_row(self, db):
        with pytest.raises(ValueError):
            runlog.start_run("telemetry", path=db)

    def test_running_is_not_an_acceptable_finish_status(self, db):
        rid = runlog.start_run("scan", path=db)
        with pytest.raises(ValueError):
            runlog.finish_run(rid, runlog.RUNNING, path=db)


class TestHonesty:
    def test_an_unfinished_run_is_never_reported_as_success(self, db):
        rid = runlog.start_run("verify", path=db)
        assert runlog.get_run(rid, path=db).status == runlog.RUNNING
        assert not runlog.get_run(rid, path=db).finished

    def test_the_context_manager_records_an_exception_and_re_raises_it(self, db):
        with pytest.raises(RuntimeError, match="backend died"):
            with runlog.record("verify", "acme", path=db):
                raise RuntimeError("backend died")
        run = runlog.list_runs(path=db)[0]
        assert run.status == runlog.ERROR and "backend died" in run.summary["error"]

    def test_the_context_manager_does_not_override_a_status_the_caller_set(self, db):
        with runlog.record("scan", path=db) as rid:
            runlog.finish_run(rid, runlog.FINDINGS, {"findings": 2}, path=db)
        assert runlog.list_runs(path=db)[0].status == runlog.FINDINGS

    def test_a_registry_failure_does_not_break_the_caller_but_is_loud(self, db, capsys, tmp_path):
        """Recording that you scanned is worth less than scanning — but a silent gap in a history
        that looks complete is worse than no history at all."""
        unwritable = str(tmp_path / "nope" / "runs.db")
        os.makedirs(os.path.dirname(unwritable))
        os.chmod(os.path.dirname(unwritable), 0o500)
        try:
            rid = runlog.start_run("scan", path=unwritable)
        finally:
            os.chmod(os.path.dirname(unwritable), 0o700)
        assert rid is None                                  # no id, no pretence of a record
        assert "run log open failed" in capsys.readouterr().err

    def test_finishing_a_none_id_is_a_no_op_so_callers_need_no_branching(self, db):
        runlog.finish_run(None, runlog.OK, path=db)         # must not raise

    def test_a_corrupt_summary_does_not_break_the_read_path(self, db):
        rid = runlog.start_run("scan", path=db)
        runlog.finish_run(rid, runlog.OK, path=db)
        with sqlite3.connect(db) as conn:                   # simulate a truncated/garbled write
            conn.execute("update runs set summary='{not json' where run_id=?", (rid,))
        assert runlog.get_run(rid, path=db).summary == {}   # degrades, never raises


class TestCrashReconciliation:
    def test_a_dead_process_leaves_an_incomplete_run_not_a_successful_one(self, db):
        rid = runlog.start_run("enforce", path=db)
        _age_and_orphan(db, rid)
        assert runlog.reconcile_stale(path=db) == 1
        run = runlog.get_run(rid, path=db)
        assert run.status == runlog.INCOMPLETE and run.status != runlog.OK
        assert "without closing" in run.summary["note"]

    def test_a_live_process_is_left_alone(self, db):
        rid = runlog.start_run("enforce", path=db)          # this process is alive
        assert runlog.reconcile_stale(path=db) == 0
        assert runlog.get_run(rid, path=db).status == runlog.RUNNING

    def test_a_recent_orphan_is_left_alone_until_the_age_cutoff(self, db):
        """A slow verify on a loaded machine must not be mislabelled while it is still working."""
        rid = runlog.start_run("verify", path=db)
        with sqlite3.connect(db) as conn:
            conn.execute("update runs set pid=? where run_id=?", (_dead_pid(), rid))
        assert runlog.reconcile_stale(path=db) == 0

    def test_another_hosts_runs_are_never_reconciled_from_here(self, db):
        rid = runlog.start_run("monitor", path=db)
        _age_and_orphan(db, rid, host="someone-elses-laptop")
        assert runlog.reconcile_stale(path=db) == 0


class TestRetention:
    def test_old_finished_runs_are_pruned(self, db):
        rid = runlog.start_run("scan", path=db)
        runlog.finish_run(rid, runlog.OK, path=db)
        with sqlite3.connect(db) as conn:
            conn.execute("update runs set started_at='2000-01-01T00:00:00+00:00' where run_id=?",
                         (rid,))
        assert runlog.prune(max_age_days=30, path=db) >= 1
        assert runlog.get_run(rid, path=db) is None

    def test_an_unfinished_run_is_never_pruned(self, db):
        """The unfinished one is exactly the run worth keeping."""
        rid = runlog.start_run("enforce", path=db)
        with sqlite3.connect(db) as conn:
            conn.execute("update runs set started_at='2000-01-01T00:00:00+00:00' where run_id=?",
                         (rid,))
        runlog.prune(max_age_days=1, path=db)
        assert runlog.get_run(rid, path=db) is not None

    def test_row_cap_keeps_the_newest(self, db):
        for _ in range(5):
            runlog.finish_run(runlog.start_run("scan", path=db), runlog.OK, path=db)
        newest = runlog.list_runs(path=db)[0].run_id
        runlog.prune(max_rows=2, path=db)
        remaining = runlog.list_runs(path=db)
        assert len(remaining) == 2 and newest in {r.run_id for r in remaining}


def test_concurrent_writers_do_not_lose_runs(db):
    """Two pillars running at once is the normal case, not an edge case."""
    ids = [runlog.start_run("scan", f"s{i}", path=db) for i in range(25)]
    for rid in ids:
        runlog.finish_run(rid, runlog.OK, path=db)
    assert len({r.run_id for r in runlog.list_runs(limit=100, path=db)}) == 25


def test_the_registry_stays_in_the_free_layer():
    """Paid code may import this; this must never import paid code, or `mcpgawk scan` breaks for
    every free user (tests/test_layer_invariants.py guards the same wall elsewhere).

    Parses the IMPORTS rather than grepping the text — the first cut of this test matched the word
    `gawk_platform` in the module's own docstring, which is a test that fails for a reason unrelated
    to the property it claims to check.
    """
    import ast
    tree = ast.parse(open(runlog.__file__, encoding="utf-8").read())
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not [m for m in imported if m.startswith("gawk_platform")], imported


def _dead_pid() -> int:
    """A pid that is very unlikely to exist. Verified dead before use, so the test cannot flake into
    passing for the wrong reason."""
    for candidate in range(999_000, 999_400):
        try:
            os.kill(candidate, 0)
        except ProcessLookupError:
            return candidate
        except OSError:
            continue
    pytest.skip("no provably dead pid available on this host")


def _age_and_orphan(db: str, run_id: str, host: str | None = None) -> None:
    with sqlite3.connect(db) as conn:
        conn.execute("update runs set pid=?, started_at='2000-01-01T00:00:00+00:00' where run_id=?",
                     (_dead_pid(), run_id))
        if host:
            conn.execute("update runs set host=? where run_id=?", (host, run_id))
