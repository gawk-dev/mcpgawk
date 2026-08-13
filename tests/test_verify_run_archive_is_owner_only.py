"""Every file and directory in the verify run archive is owner-only.

Eighth and final increment of the 2026-08-13 sweep — the two "just check the modes" items, which
turned into four findings because each one was measured instead of reasoned about.

| object | before | writer |
|---|---|---|
| `~/.mcpgawk/calls.jsonl` | **0600 already** — a genuine PASS, `spool.append` uses `os.open(..., 0o600)` | — |
| `verify-runs/<run>/audit.jsonl` | 0644 (27 of them on the founder's machine) | `writeFileSync` with no mode |
| `verify-runs/<run>/` | 0755 | plain `mkdir` |
| `verify-runs/` (the PARENT) | 0755 | `Path.mkdir(mode=…, parents=True)` applies the mode to the FINAL component only |
| `verify-runs/<run>/report.json` | 0644 | `shutil.copyfile`, which does NOT carry the source's permissions (`copy2` would) — so the archive was 0644 while the report it copies is 0600 |

The last two were found only because the first fix was re-measured rather than assumed complete:
securing the run directory did not secure its parent, and the run directory held a THIRD file
nobody had accounted for.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "toy_mcp_server.py"


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture(scope="module")
def archive(tmp_path_factory) -> Path:
    """A real verify run through the panel action — the path that builds the archive."""
    from mcpgawk import verify as verify_mod

    if verify_mod.unavailable_reason() is not None:
        pytest.skip("verify unavailable here")
    home = tmp_path_factory.mktemp("home")
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {
        "toy": {"command": sys.executable, "args": [str(FIXTURE)]}}}), encoding="utf-8")
    for key, value in (("HOME", str(home)), ("USERPROFILE", str(home)),
                       ("GAWK_BEHAVIOUR_PROFILE", str(home / ".gawk" / "behaviour.json")),
                       ("MCPGAWK_HISTORY", str(home / "history.json"))):
        os.environ[key] = value
    cwd = os.getcwd()
    os.chdir(home)
    try:
        from mcpgawk import panel
        panel.run_verify_fleet("toy")
    finally:
        os.chdir(cwd)
    root = home / ".gawk" / "verify-runs"
    assert root.is_dir(), "no run archive was created — every assertion below would be vacuous"
    assert list(root.glob("*/*")), "the archive is empty — nothing is being asserted"
    return root


def test_the_archive_root_is_owner_only(archive: Path):
    """`Path.mkdir(mode=…, parents=True)` applies the mode to the final component only, so securing
    the run directory left this at 0755. Found by re-measuring a fix instead of assuming it."""
    assert _mode(archive) == 0o700


def test_every_run_directory_and_file_is_owner_only(archive: Path):
    for run_dir in archive.glob("*"):
        assert _mode(run_dir) == 0o700, f"{run_dir.name} is not owner-only"
        for entry in run_dir.iterdir():
            assert _mode(entry) == 0o600, f"{run_dir.name}/{entry.name} is not owner-only"


def test_the_archive_actually_contains_the_evidence(archive: Path):
    """Non-vacuity, and the contract: a permissions fix that emptied the archive would pass every
    assertion above."""
    names = {entry.name for run in archive.glob("*") for entry in run.iterdir()}
    assert "audit.jsonl" in names and "report.json" in names, names


def test_the_runtime_decision_log_is_owner_only(tmp_path: Path):
    """`calls.jsonl` was already correct — pinned so it stays that way, not because it was broken."""
    from mcpgawk import spool

    target = tmp_path / "calls.jsonl"
    assert spool.append({"ts": "t", "server": "s", "tool": "t", "decision": "allow"},
                        path=str(target)) is True
    assert _mode(target) == 0o600
