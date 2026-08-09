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
import signal
import subprocess
import sys
from pathlib import Path

from .node_runtime import find_node, install_hint

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
    if find_node() is None:
        return ("node is not installed, so a server cannot be run and watched. Checks fall back to "
                "what servers DECLARE, which cannot see a tool that keeps its name and changes "
                f"what it does. To enable behavioural verification, {install_hint()}.")
    if resolve_cli_js() is None:
        return ("the verification engine is not present in this install "
                "(expected at mcpgawk/_bundled/verify). Reinstall mcpgawk, or run "
                "`pnpm run build` in a checkout.")
    return None


def run_captured(argv: list[str], timeout: float | None = None) -> tuple[int, str]:
    """Same engine as `run`, but the engine's OWN WORDS come back instead of going to a terminal.

    `run` returns one int. That is fine for a CLI, where the engine's per-server lines stream past
    the user's eyes — and useless for the GUI, which was left announcing a count it had to invent
    (it reported every server it ATTEMPTED as verified while the tiles, which read the profile,
    did not move). A control surface that can only say "all fine" or "all failed", and then tells
    you to go and run a terminal command to find out which, is not a control surface.

    Returns (exit code, combined output). Same code vocabulary as `run`: 3 = could not run,
    4 = timed out and therefore INCOMPLETE, never clean.
    """
    reason = unavailable_reason()
    if reason is not None:
        return 3, f"mcpgawk verify: {reason}"
    node = find_node()
    if node is None:
        # `unavailable_reason` above already looks for Node, but it calls `find_node` separately —
        # so this is a second lookup, and only this one's result is handed to subprocess. Passing
        # None as argv[0] raises a TypeError from deep inside subprocess instead of the actionable
        # sentence the caller is built to print.
        return 3, f"mcpgawk verify: {install_hint()}"
    cli_js = resolve_cli_js()
    try:
        proc = subprocess.run([node, str(cli_js), *argv], env={**os.environ}, timeout=timeout,
                              capture_output=True, text=True, errors="replace")
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or ""))
    except subprocess.TimeoutExpired as exc:
        partial = ""
        for stream in (exc.stdout, exc.stderr):    # keep whatever it managed to say first
            if stream:
                partial += stream if isinstance(stream, str) else stream.decode("utf-8", "replace")
        return 4, partial + "\nmcpgawk verify: timed out — this run is INCOMPLETE, not clean"
    except KeyboardInterrupt:
        return 130, ""
    except OSError as exc:
        return 3, f"mcpgawk verify: could not start the engine ({exc})"


#: Flags that belong to gawk Platform's SOURCE AUDITOR, not to the TS engine. They are handled on
#: the Python side (the auditor is Python). Before 2026-08-07 the free wrapper passed them
#: straight through to an engine that had never heard of them: `--audit-source` was silently
#: ignored, and `--source-dir <path>`'s PATH was read as the positional config argument — a run
#: that looked normal while auditing nothing. Silent-and-wrong is the exact shape the exit-3
#: vocabulary exists to prevent.
def _wants_source_audit(argv: list[str]) -> bool:
    return any(a in ("--audit-source", "--source-dir") or a.startswith("--source-dir=")
               for a in argv)


_AUDIT_NEEDS_PLATFORM = (
    "mcpgawk verify --audit-source: source audit is a gawk Platform capability and the Platform "
    "isn't installed in this environment.\n"
    "  £29/month, 7-day free trial — https://mcp.gawk.dev/pricing.html\n"
    "Behavioural verification itself is free: re-run without --audit-source / --source-dir."
)


def run(argv: list[str], timeout: float | None = None) -> int:
    """Exec the bundled engine. Returns its exit code, or 3 when it cannot run, or 4 on timeout.

    Exit 3 rather than 1 deliberately: 1 means "verification ran and found something", and a
    machine that cannot verify must never be confused with a machine that verified cleanly. Same
    rule as everywhere else here — absence of a finding is not a finding of absence. 4 is kept
    distinct from 3 for the same reason: a run that STARTED and was cut off is incomplete, and an
    incomplete run must never be read as either clean or impossible.
    """
    if _wants_source_audit(argv):
        try:
            from gawk_platform.cli import run_source_audit
        except ImportError:
            print(_AUDIT_NEEDS_PLATFORM, file=sys.stderr)
            return 3
        argv, rc = run_source_audit(argv)
        if rc is not None:
            return rc
    reason = unavailable_reason()
    if reason is not None:
        print(f"mcpgawk verify: {reason}", file=sys.stderr)
        return 3
    node = find_node()
    cli_js = resolve_cli_js()
    # start_new_session so the engine leads its own process GROUP. `subprocess.run`'s timeout kills
    # only the direct child, and this child spawns `docker run` containers per server — so a
    # timeout or a Ctrl-C left the engine reparented to PID 1, still launching containers, still
    # writing into ~/.gawk/verify-runs, indefinitely. Observed live: two orphans and four
    # containers survived their parents by minutes and had to be killed by hand.
    if node is None:                       # same second-lookup gap as `run` above
        return 3
    proc = subprocess.Popen([node, str(cli_js), *argv], env={**os.environ}, start_new_session=True)

    def _kill_the_whole_group() -> None:
        """Take the containers down with the engine. Never raises: we are already on a failure
        path, and a cleanup that explodes would replace a clear timeout with a confusing crash."""
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()

    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_the_whole_group()
        print("mcpgawk verify: timed out — this run is INCOMPLETE, not clean", file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        _kill_the_whole_group()
        return 130
    except OSError as exc:
        print(f"mcpgawk verify: could not start the engine ({exc})", file=sys.stderr)
        return 3
