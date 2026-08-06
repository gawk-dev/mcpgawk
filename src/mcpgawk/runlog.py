"""Local run registry — the one place that answers "what did I run, and when, and how did it go".

Default: `$MCPGAWK_RUNS` or `~/.mcpgawk/runs.db`. Local SQLite, never leaves the machine, same
posture as `history.json` beside it.

WHY THIS EXISTS. Awareness was spread across four stores that did not know about each other: the
enforce audit DB (`~/.gawk/enforce-audit.db`), the monitor DB (`~/.gawk/monitor.db`), the drift
baseline (`~/.mcpgawk/history.json`) and the hosted receipts table. None shared an identifier, and
`scan`/`verify` left no durable record at all — so "show me everything my sessions did" was
unanswerable by ANY surface, local or hosted, because the joinable data did not exist. This is that
seam: every pillar opens a run here, gets a `run_id`, and stamps its own rows with it. The timeline
reads this table and follows the id outwards.

It lives in the FREE layer deliberately. `mcpgawk scan` cannot import `gawk_platform` (see
tests/test_layer_invariants.py), so a registry the paid pillars own could never record a free scan —
and a timeline missing every scan is not a timeline. Paid code imports this; never the reverse.

HONESTY RULES, because this is a record people will trust:

* A run that never finished is NEVER reported as success. It stays `running`, and once the process
  is provably gone it becomes `incomplete` — never `ok`. Absence of a completion is not completion.
* A registry write that fails is loud on stderr and never fails the caller's actual work: recording
  that you scanned is worth less than scanning. But it must not be SILENT, because a gap in a
  history that looks complete is worse than no history (the same rule the audit log follows).
* `status` distinguishes `ok` from `findings`. A scan that ran perfectly and found six problems is
  not an error, and collapsing the two would make the timeline useless at a glance.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from . import state

#: Run kinds. Kept as a closed set so the timeline can rely on them; add here, not ad hoc.
KINDS = ("scan", "verify", "enforce", "monitor", "guard")

#: Terminal statuses. `running` is the only non-terminal one.
RUNNING = "running"
OK = "ok"
FINDINGS = "findings"
ERROR = "error"
INCOMPLETE = "incomplete"
STATUSES = (RUNNING, OK, FINDINGS, ERROR, INCOMPLETE)

#: A `running` row is only reconciled to `incomplete` after this long, even when the pid is gone.
#: Short enough to be useful, long enough that a slow verify on a loaded machine is never mislabelled
#: while it is still working.
STALE_AFTER = timedelta(hours=6)

_SCHEMA = """
create table if not exists runs (
  run_id      text primary key,
  kind        text not null,
  target      text,
  started_at  text not null,
  ended_at    text,
  status      text not null,
  summary     text,
  host        text,
  pid         integer
);
create index if not exists runs_started_idx on runs (started_at desc);
create index if not exists runs_kind_idx    on runs (kind, started_at desc);
"""


def default_path() -> str:
    return os.environ.get("MCPGAWK_RUNS") or os.path.expanduser("~/.mcpgawk/runs.db")


@dataclass(frozen=True)
class Run:
    run_id: str
    kind: str
    target: str | None
    started_at: str
    ended_at: str | None
    status: str
    summary: dict[str, Any]
    host: str | None
    pid: int | None

    @property
    def finished(self) -> bool:
        return self.status != RUNNING


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(path: str | None = None) -> sqlite3.Connection:
    path = path or default_path()
    parent = os.path.dirname(path)
    if parent:
        state.secure_dir(parent)          # owner-only; see state.py
    # timeout: concurrent pillars are the normal case (a scan in one terminal, the proxy in
    # another), and the default 5s turns routine contention into an exception.
    conn = sqlite3.connect(path, timeout=15.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("pragma journal_mode=WAL")     # concurrent readers during a write
        conn.execute("pragma synchronous=NORMAL")
    except sqlite3.DatabaseError:
        pass                                        # a filesystem that refuses WAL still works
    conn.executescript(_SCHEMA)
    # After the file exists (and after WAL creates its sidecars): what you ran and when is your
    # business, not every account on the machine's.
    state.harden(path, sidecars=True)
    return conn


def _report(action: str, exc: Exception) -> None:
    """Never silent. See the module docstring's honesty rules."""
    import sys
    print(f"mcpgawk: run log {action} failed ({type(exc).__name__}: {exc}). "
          f"Your work is unaffected; this run may be missing from `mcpgawk runs`.",
          file=sys.stderr)


def start_run(kind: str, target: str | None = None, *, summary: dict[str, Any] | None = None,
              path: str | None = None) -> str | None:
    """Open a run and return its id, or None if the registry could not be written (the caller
    carries on regardless — a None id simply means this run will not appear in the timeline).

    `summary` at OPEN time exists for facts that matter while the run is still `running` — the
    enforce gateway's listen endpoint is the motivating case: a UI that wants to say "a gateway is
    up, point your agent at http://…/mcp" can only say it while the process is alive, which is
    exactly when `finish_run`'s summary does not exist yet. `finish_run` replaces it wholesale, so
    a caller that wants a fact to survive the run must repeat it there."""
    if kind not in KINDS:
        raise ValueError(f"unknown run kind {kind!r}; add it to runlog.KINDS deliberately")
    run_id = uuid.uuid4().hex
    try:
        with _connect(path) as conn:
            conn.execute("begin immediate")
            conn.execute(
                "insert into runs (run_id, kind, target, started_at, status, summary, host, pid) "
                "values (?,?,?,?,?,?,?,?)",
                (run_id, kind, target, _now(), RUNNING,
                 json.dumps(summary, sort_keys=True) if summary else None,
                 socket.gethostname(), os.getpid()),
            )
            conn.execute("commit")
        return run_id
    except Exception as exc:  # noqa: BLE001 - recording must never break the work being recorded
        _report("open", exc)
        return None


def finish_run(run_id: str | None, status: str, summary: dict[str, Any] | None = None,
               *, path: str | None = None) -> None:
    """Close a run. A no-op for a None id, so callers need no branching around a failed open."""
    if run_id is None:
        return
    if status not in STATUSES or status == RUNNING:
        raise ValueError(f"{status!r} is not a terminal run status")
    try:
        with _connect(path) as conn:
            conn.execute("begin immediate")
            conn.execute("update runs set ended_at=?, status=?, summary=? where run_id=?",
                         (_now(), status, json.dumps(summary or {}, sort_keys=True), run_id))
            conn.execute("commit")
    except Exception as exc:  # noqa: BLE001
        _report("close", exc)


@contextmanager
def record(kind: str, target: str | None = None, *, path: str | None = None) -> Iterator[str | None]:
    """Wrap a unit of work. Exits `error` on an exception (re-raised), `ok` otherwise — a caller
    wanting `findings` calls `finish_run` itself, which this then leaves alone.

    Deliberately does NOT swallow the caller's exception: the run log records what happened, it does
    not change what happens.
    """
    run_id = start_run(kind, target, path=path)
    try:
        yield run_id
    except BaseException as exc:                     # noqa: BLE001 - recorded, then re-raised
        finish_run(run_id, ERROR, {"error": f"{type(exc).__name__}: {exc}"}, path=path)
        raise
    else:
        if _status_of(run_id, path) == RUNNING:      # caller did not set a richer status
            finish_run(run_id, OK, path=path)


def _status_of(run_id: str | None, path: str | None) -> str | None:
    if run_id is None:
        return None
    try:
        with _connect(path) as conn:
            row = conn.execute("select status from runs where run_id=?", (run_id,)).fetchone()
        return row["status"] if row else None
    except Exception:  # noqa: BLE001 - treated as "unknown", which leaves the run alone
        return None


def _pid_alive(pid: int | None) -> bool:
    """Best effort. Pid reuse can make a dead run look alive, which only DELAYS reconciliation to
    the age cutoff — it never marks an unfinished run as successful, so the honest direction of the
    error is preserved."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                                  # exists, owned by someone else
    except OSError:
        return True                                  # unknown: assume alive, do not over-claim
    return True


def reconcile_stale(*, path: str | None = None) -> int:
    """Mark runs that can no longer be running as `incomplete`. Returns how many.

    A killed proxy, a closed laptop or a crashed scan leaves a `running` row forever; a timeline
    full of eternal "in progress" entries is noise that trains people to ignore it. Only rows from
    THIS host are touched — another machine's pids mean nothing here.
    """
    cutoff = (datetime.now(timezone.utc) - STALE_AFTER).isoformat()
    changed = 0
    try:
        with _connect(path) as conn:
            rows = conn.execute(
                "select run_id, pid, started_at from runs where status=? and host=?",
                (RUNNING, socket.gethostname()),
            ).fetchall()
            stale = [r["run_id"] for r in rows
                     if not _pid_alive(r["pid"]) and r["started_at"] < cutoff]
            if stale:
                conn.execute("begin immediate")
                conn.executemany(
                    "update runs set status=?, ended_at=?, summary=? where run_id=?",
                    [(INCOMPLETE, _now(),
                      json.dumps({"note": "process ended without closing this run"}), rid)
                     for rid in stale])
                conn.execute("commit")
                changed = len(stale)
    except Exception as exc:  # noqa: BLE001
        _report("reconcile", exc)
    return changed


def list_runs(*, kind: str | None = None, limit: int = 100, since: str | None = None,
              path: str | None = None) -> list[Run]:
    """Most recent first. The timeline's read path."""
    sql = "select * from runs"
    where, args = [], []
    if kind:
        where.append("kind=?")
        args.append(kind)
    if since:
        where.append("started_at>=?")
        args.append(since)
    if where:
        sql += " where " + " and ".join(where)
    sql += " order by started_at desc limit ?"
    args.append(max(1, min(limit, 5000)))
    try:
        with _connect(path) as conn:
            rows = conn.execute(sql, args).fetchall()
    except Exception as exc:  # noqa: BLE001
        _report("read", exc)
        return []
    return [_row_to_run(r) for r in rows]


def get_run(run_id: str, *, path: str | None = None) -> Run | None:
    try:
        with _connect(path) as conn:
            row = conn.execute("select * from runs where run_id=?", (run_id,)).fetchone()
    except Exception as exc:  # noqa: BLE001
        _report("read", exc)
        return None
    return _row_to_run(row) if row else None


def _row_to_run(row: sqlite3.Row) -> Run:
    try:
        summary = json.loads(row["summary"]) if row["summary"] else {}
    except (json.JSONDecodeError, TypeError):
        summary = {}
    if not isinstance(summary, dict):
        summary = {"value": summary}
    return Run(run_id=row["run_id"], kind=row["kind"], target=row["target"],
               started_at=row["started_at"], ended_at=row["ended_at"], status=row["status"],
               summary=summary, host=row["host"], pid=row["pid"])


def prune(*, max_age_days: int = 90, max_rows: int = 20_000, path: str | None = None) -> int:
    """Bounded growth, on the same principle as the monitor store's retention. Never deletes a run
    that is still `running` — an unfinished run is exactly the one worth keeping."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
    removed = 0
    try:
        with _connect(path) as conn:
            conn.execute("begin immediate")
            cur = conn.execute("delete from runs where status<>? and started_at<?",
                               (RUNNING, cutoff))
            removed += cur.rowcount or 0
            cur = conn.execute(
                "delete from runs where status<>? and run_id not in "
                "(select run_id from runs order by started_at desc limit ?)",
                (RUNNING, max_rows))
            removed += cur.rowcount or 0
            conn.execute("commit")
    except Exception as exc:  # noqa: BLE001
        _report("prune", exc)
    return removed
