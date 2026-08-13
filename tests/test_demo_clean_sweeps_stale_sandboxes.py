"""`mcpgawk demo --clean` must leave NO demo sandbox behind — including earlier runs'.

Found 2026-08-13 by driving the beta guide's exact steps against the SHIPPED 0.1.26: run the demo
(sandbox kept, path printed), then run `demo --clean` as the page instructs — the flag re-ran the
demo, deleted only its own new sandbox, and the tester's original one stayed on disk. The page's
promise ("deleted with `mcpgawk demo --clean`") was false for the sandbox it mattered for.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from mcpgawk.demo import _sweep_stale_sandboxes


def _fake_sandbox(name: str, *, with_markers: bool) -> Path:
    root = Path(tempfile.gettempdir()) / name
    root.mkdir(parents=True, exist_ok=True)
    if with_markers:
        (root / "mcp.json").write_text("{}", encoding="utf-8")
        (root / "fixture_server.py").write_text("# fixture", encoding="utf-8")
    else:
        (root / "notes.txt").write_text("mine", encoding="utf-8")
    return root


def test_a_stale_demo_sandbox_is_removed():
    stale = _fake_sandbox("mcpgawk-demo-teststale", with_markers=True)
    current = _fake_sandbox("mcpgawk-demo-testcurrent", with_markers=True)
    try:
        removed = _sweep_stale_sandboxes(keep=current)
        assert not stale.exists(), "the earlier run's sandbox survived --clean"
        assert current.exists(), "the sweep must never delete the CURRENT run's root"
        assert removed >= 1
    finally:
        import shutil
        for p in (stale, current):
            shutil.rmtree(p, ignore_errors=True)


def test_an_unrelated_directory_with_our_prefix_is_never_touched():
    """Deletion is gated on our marker files, not the name alone — a user's own
    `mcpgawk-demo-notes` folder must survive."""
    bystander = _fake_sandbox("mcpgawk-demo-bystander", with_markers=False)
    current = _fake_sandbox("mcpgawk-demo-cur2", with_markers=True)
    try:
        _sweep_stale_sandboxes(keep=current)
        assert bystander.exists(), "a directory that is not ours was deleted"
        assert (bystander / "notes.txt").exists()
    finally:
        import shutil
        for p in (bystander, current):
            shutil.rmtree(p, ignore_errors=True)
