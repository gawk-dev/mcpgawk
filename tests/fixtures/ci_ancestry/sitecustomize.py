"""TEST SCAFFOLDING ONLY — never shipped, never on a user's PYTHONPATH.

The approval gate refuses when an agent is an ANCESTOR of the process (2026-11-06, run 2 in
docs/design-approve-presence-2026-11-05.md). The suite emulates a CI run: tests/conftest.py clears
the agent env markers, and replaces the in-process ancestry walk with CI's (no agent). A subprocess
child (the shipped CLI, the demo's sandbox commands, the e2e harness) walks the REAL process tree,
which on a developer's machine has the agent that launched pytest in it.

conftest puts this directory on PYTHONPATH and sets MCPGAWK_TEST_ANCESTRY, so every Python child
the suite spawns sees the tree the test chose: "" = CI (no agent above); "zsh,claude" = run from
inside an agent. Unset = this file does nothing, and the product reads no such variable — this is
emulation in the test harness, the same as clearing CLAUDECODE, not a waiver in the product.
"""
import importlib.abc
import importlib.machinery
import os
import sys

_chain = os.environ.get("MCPGAWK_TEST_ANCESTRY")


class _PatchAncestryOnImport(importlib.abc.MetaPathFinder):
    """Patch `mcpgawk.history` WHEN something imports it — never import it from here.

    LAZY ON PURPOSE (measured 2026-11-06): an eager `from mcpgawk import history` at startup loaded
    the installed package before a child's own sys.path edits, and
    test_version_banner_names_the_running_code then read the wrong `mcpgawk`. A child that never
    imports mcpgawk is untouched."""

    def __init__(self, names):
        self.names = names

    def find_spec(self, fullname, path, target=None):
        if fullname != "mcpgawk.history" or path is None:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return spec
        run, names = spec.loader.exec_module, self.names

        def exec_module(module):
            run(module)
            module._process_ancestry = lambda: list(names)

        spec.loader.exec_module = exec_module
        return spec


if _chain is not None:
    sys.meta_path.insert(0, _PatchAncestryOnImport([n for n in _chain.split(",") if n]))


# ── the approval anchor (2026-11-06) ──────────────────────────────────────────────────────────────
# The anchor lives at a FIXED, root-owned path and follows no environment variable in the product
# (an override would let the hook decide "unlocked" while `approvals status` says LOCKED). Once the
# founder locked this machine, every child the suite spawned read the real anchor and ~40 tests went
# red. MCPGAWK_TEST_ANCHOR_DIR moves it for THIS test harness only: after any copy of
# approval_lock.py executes — imported as mcpgawk.approval_lock, or loaded by path by the guard hook
# as _mcpgawk_approval_lock — its ANCHOR_DIRS point there. Unset = untouched.
_anchor_dir = os.environ.get("MCPGAWK_TEST_ANCHOR_DIR")

if _anchor_dir:
    from importlib.machinery import SourceFileLoader as _SFL
    from pathlib import Path as _Path

    _run_source = _SFL.exec_module

    def _exec_then_move_anchor(self, module):
        _run_source(self, module)
        if str(getattr(module, "__file__", "") or "").endswith(os.sep + "approval_lock.py") \
                and isinstance(getattr(module, "ANCHOR_DIRS", None), dict):
            module.ANCHOR_DIRS = {p: _Path(_anchor_dir) for p in module.ANCHOR_DIRS}

    _SFL.exec_module = _exec_then_move_anchor
