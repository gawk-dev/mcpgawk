"""One baseline, read by every pillar.

The product kept three memories of "what did this server look like when I trusted it":
history.py (scan), packages/verify/src/pins.ts (verify) and monitor/store.py (the daemon). You
could approve a server in one and still be told it had drifted by another — which is why no flow
felt joined up. This is the shared view they all read.

Deliberately a NARROW VIEW over history.json rather than a fourth file: a new store would need
migrating into, keeping in sync, and would itself become another memory to disagree with.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcpgawk import baseline, history

REC = {
    "measured_at": "2026-07-27T10:00:00Z",
    "pin": "abc123def4567890",
    "tools": {"read_file": "9c98141c4c35", "write_file": "aac5a0de16f1"},
}


@pytest.fixture
def store(tmp_path: Path) -> str:
    return str(tmp_path / "history.json")


def test_nothing_is_approved_until_someone_approves_it(store):
    history.record("srv", REC, path=store)
    # First sighting is trust-on-first-use in scan, so this IS approved; a second, different
    # sighting must NOT move it.
    history.record("srv", {**REC, "pin": "ffffffffffffffff"}, path=store)
    assert baseline.approved_pin("srv", store) == REC["pin"], "a sighting is not an approval"


def test_approve_moves_the_shared_baseline(store):
    history.record("srv", REC, path=store)
    moved = {**REC, "pin": "ffffffffffffffff", "tools": {"read_file": "111111111111"}}
    history.record("srv", moved, path=store)
    history.approve("srv", path=store)
    assert baseline.approved_pin("srv", store) == "ffffffffffffffff"
    assert baseline.approved_tools("srv", store) == {"read_file": "111111111111"}


def test_a_name_the_user_typed_resolves_to_the_key_it_is_stored_under(store):
    """Identity key and configured name are different strings, and the same server is routinely
    configured under different names in different tools. Without this the shared baseline silently
    does nothing for half the fleet."""
    history.record("mcp:abc123", REC, path=store, alias="slack")
    assert baseline.resolve("slack", store) == "mcp:abc123"
    assert baseline.resolve("mcp:abc123", store) == "mcp:abc123"
    assert baseline.resolve("never-heard-of-it", store) is None


def test_export_carries_only_approved_state(store):
    """A sighting must never cross the boundary: handing verify the last thing SEEN would give it
    the poisoned surface as though it were trusted."""
    history.record("approved-one", REC, path=store)
    history.approve("approved-one", path=store)

    raw = json.loads(Path(store).read_text())
    raw["servers"]["seen-only"] = {"seen": [REC]}          # sighted, never approved
    Path(store).write_text(json.dumps(raw))

    data = baseline.export(store)
    assert data["schema"] == baseline.SCHEMA
    assert "approved-one" in data["servers"]
    assert "seen-only" not in data["servers"]


def test_never_approved_is_none_not_empty(store):
    """'Never approved' and 'approved as empty' must not collapse: the second reports drift on a
    server the operator has never looked at."""
    assert baseline.approved_pin("unknown", store) is None
    assert baseline.approved_tools("unknown", store) == {}


def test_the_cli_emits_the_cross_runtime_shape(store, tmp_path):
    """`mcpgawk baseline --json` is the contract verify reads. If this shape moves, verify breaks."""
    history.record("srv", REC, path=store)
    history.approve("srv", path=store)

    r = subprocess.run(
        [sys.executable, "-m", "mcpgawk.cli", "baseline", "--json"],
        capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "MCPGAWK_HISTORY": store, "HOME": str(tmp_path)},
    )
    assert r.returncode == 0, r.stdout + r.stderr
    data = json.loads(r.stdout)
    assert data["schema"] == "gawk.baseline/1"
    assert data["servers"]["srv"]["tools"] == REC["tools"]
    assert data["servers"]["srv"]["pin"] == REC["pin"]


def test_asking_for_an_unapproved_server_fails_loudly(store, tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "mcpgawk.cli", "baseline", "--server", "nope"],
        capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "MCPGAWK_HISTORY": store, "HOME": str(tmp_path)},
    )
    assert r.returncode == 2
    assert "nothing approved" in r.stderr.lower()
