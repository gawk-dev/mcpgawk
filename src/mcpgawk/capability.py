"""Can THIS machine actually run behavioural checking? — asked, answered, never assumed.

Task 0 made behavioural verification free, which made Node.js and a container runtime free-tier
dependencies. B5 is the honesty rule that comes with that: when either is missing, every surface
that talks about protection says BEHAVIOURAL CHECKING IS UNAVAILABLE and why — it never quietly
falls back to name-only checks and lets the narrower guarantee wear the stronger one's clothes.
(The same failure class as the Windsurf adapter that installed cleanly and checked nothing:
looking covered while degraded is worse than being visibly degraded.)

One probe, consumed by `status` and the scan. Pure lookups, no subprocesses — this runs on
surfaces a user sees every day, and `shutil.which` is the same evidence the tools themselves use.
"""
from __future__ import annotations

import shutil


def behavioural_checking() -> tuple[bool, list[str]]:
    """(available, what is missing). Available means both halves of the free behavioural tier can
    actually run here: Node executes the bundled verify engine, and a container runtime is what
    the sandbox requires — `SubprocessSandbox` REFUSES to run unsandboxed by design, and that
    refusal must stay a refusal rather than become a silent fallback."""
    missing: list[str] = []
    if shutil.which("node") is None:
        missing.append("Node.js (runs the verify engine)")
    if shutil.which("docker") is None:
        missing.append("a container runtime (docker — the sandbox refuses to run unsandboxed)")
    return not missing, missing


def unavailable_line() -> str | None:
    """The one sentence every surface shares, or None when behavioural checking can run. One
    wording everywhere, so the degraded state reads the same in `status` and in a scan."""
    ok, missing = behavioural_checking()
    if ok:
        return None
    return ("behavioural checking is UNAVAILABLE on this machine — missing "
            + " and ".join(missing) + ". Until installed, calls are checked against the "
            "DECLARED surface only (names a server author chooses), which is a weaker guarantee.")
