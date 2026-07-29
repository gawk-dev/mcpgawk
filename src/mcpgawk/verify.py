"""`mcpgawk verify` — behavioural verification, in the FREE layer.

TASK 0 (2026-07-28, founder): the free tier gets behavioural verification and the sandbox ships in
the free package. B1 moved the engine and `sandbox.py` here; this module is what makes the COMMAND
free, which is the half that was missed — the code moved while `GATED` still contained `verify`, so
a free install had the engine on disk and a paywall in front of it.

Why free needs this at all: everything else in the free tier reads what a server DECLARES — the
tool names and descriptions it advertises. That catches a server changing what it says. It cannot
catch a tool that keeps its exact name, description and schema and starts exfiltrating, which is
the attack this product exists to stop. Only running the server and watching it does that, so
without this the product's own sentence — "every call verified against expected behaviour" — was
unreachable on a free install.

This is a LAUNCHER, not a second engine. It locates node and the bundled TS CLI and execs it; the
observation logic lives in `_bundled/verify`. The paid pillars keep their own runner for the flags
that genuinely belong to them (`--audit-source` reaches into `gawk_platform.source_audit`), and it
delegates the launching here rather than keeping a second copy of it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

#: Where the compiled engine lives once installed. A checkout's dev build wins over it — see
#: `resolve_cli_js`.
BUNDLE_REL = Path("_bundled") / "verify" / "dist" / "cli.js"


def resolve_cli_js() -> Path | None:
    """Find the compiled, standalone-runnable verify CLI.

    In a CHECKOUT the repo dev build wins: `_bundled/` is a gitignored leftover of the last wheel
    build, and preferring it once served a stale UI for days while the source was already fixed.
    Outside a checkout there is no repo path, so an install uses the wheel-bundled copy that
    `hatch_build.py` produced.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "packages" / "verify" / "dist" / "cli.js"
        if candidate.is_file():
            return candidate
    bundled = here.parent / BUNDLE_REL
    return bundled if bundled.is_file() else None


def unavailable_reason() -> str | None:
    """Why behavioural verification cannot run here, or None if it can.

    Named separately from `run` so `status` can report coverage honestly WITHOUT starting anything.
    A free tier that silently falls back to name-only checking would be the "capability that looks
    present and does nothing" pattern this whole decision was made to avoid.
    """
    if shutil.which("node") is None:
        return ("node is not installed, so a server cannot be run and watched. Checks fall back to "
                "what servers DECLARE, which cannot see a tool that keeps its name and changes "
                "what it does. Install Node 20+ to enable behavioural verification.")
    if resolve_cli_js() is None:
        return ("the verification engine is not present in this install "
                "(expected at mcpgawk/_bundled/verify). Reinstall mcpgawk, or run "
                "`pnpm run build` in a checkout.")
    return None


def run(argv: list[str], timeout: float | None = None) -> int:
    """Exec the bundled engine. Returns its exit code, or 3 when it cannot run, or 4 on timeout.

    Exit 3 rather than 1 deliberately: 1 means "verification ran and found something", and a
    machine that cannot verify must never be confused with a machine that verified cleanly. Same
    rule as everywhere else here — absence of a finding is not a finding of absence. 4 is kept
    distinct from 3 for the same reason: a run that STARTED and was cut off is incomplete, and an
    incomplete run must never be read as either clean or impossible.
    """
    reason = unavailable_reason()
    if reason is not None:
        print(f"mcpgawk verify: {reason}", file=sys.stderr)
        return 3
    node = shutil.which("node")
    cli_js = resolve_cli_js()
    try:
        return subprocess.run([node, str(cli_js), *argv],
                              env={**os.environ}, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        print("mcpgawk verify: timed out — this run is INCOMPLETE, not clean", file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        print(f"mcpgawk verify: could not start the engine ({exc})", file=sys.stderr)
        return 3
