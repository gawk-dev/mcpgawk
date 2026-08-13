"""`runs.db` must not record the credential the operator typed on the command line.

Fourth increment of the 2026-08-13 persistence sweep. `runlog` records one row per run:
`{kind, target, started_at, status, summary, host, pid}`. Two of those are not chosen from a menu:

* `target` is built from argv — `_scan_target` returns `http:<the URL you passed>`, so
  `mcpgawk scan --http https://host/mcp?apiKey=…` wrote the key into `runs.db`. Measured, at the
  real entry point.
* `summary` routinely carries `{"error": f"{type(exc).__name__}: {exc}"}` — the same exception-text
  channel that printed a credential from the panel's timed-out sign-in two days earlier.

The gate went in at both writers (`start_run`, `finish_run`). Its FIRST version masked correctly
and mangled the column: handing `http:https://…` to a URL parser produced `http:///https://…`. A
run log whose target column is corrupted has traded one defect for another, so
`test_ordinary_targets_survive_unchanged` is not decoration — it is half the contract.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

CANARY = "CANARY_RUNS_98765"
URL = f"https://host.invalid/mcp?clientId=abc&apiKey={CANARY}"


@pytest.fixture
def rows() -> list[tuple]:
    """One real `mcpgawk scan --http <credentialled url>`, then the rows it wrote."""
    tmp = Path(tempfile.mkdtemp(prefix="runlog-canary-"))
    db = tmp / "runs.db"
    env = {**os.environ, "MCPGAWK_RUNS": str(db), "MCPGAWK_HISTORY": str(tmp / "h.json"),
           "HOME": str(tmp)}
    subprocess.run([sys.executable, "-m", "mcpgawk.cli", "scan", "--http", URL, "--yes"],
                   capture_output=True, text=True, timeout=180, env=env, cwd=str(tmp))
    assert db.exists(), "no runs.db was written — every assertion below would be vacuous"
    out = sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(
        "select kind, target, status, summary from runs").fetchall()
    assert out, "runs.db has no rows — vacuous"
    return out


def test_the_run_registry_does_not_record_the_url_credential(rows: list[tuple]):
    blob = " ".join(str(r) for r in rows)
    assert CANARY not in blob, "the command-line credential was written to runs.db"
    assert "apiKey=***" in blob, "sanity: the target is still recorded, with the value masked"


def test_the_target_column_stays_readable(rows: list[tuple]):
    """The first version of this gate produced `http:///https://…`. An operator has to be able to
    read the run log and see WHICH endpoint was scanned."""
    target = rows[0][1]
    assert target.startswith("http:https://host.invalid/mcp?"), f"target column mangled: {target}"
    assert "///" not in target, f"target column mangled: {target}"


@pytest.mark.parametrize("value", [
    "stdio:python fake",
    "scan:/Users/me/.config/mcp.json",
    "fleet",
    None,
])
def test_ordinary_targets_survive_unchanged(value):
    from mcpgawk import runlog

    assert runlog._mask(value) == value


def test_an_exception_summary_is_masked_too():
    """The channel that leaked from the panel: an exception stringifies with whatever it carries."""
    from mcpgawk import runlog

    masked = runlog._mask({"error": f"FileNotFoundError: 'https://h.invalid/x?token={CANARY}'",
                           "exit_code": 1})
    assert CANARY not in str(masked)
    assert masked["exit_code"] == 1, "non-string fields must pass through untouched"
