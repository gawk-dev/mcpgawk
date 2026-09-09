"""mcpgawk — local-first MCP measurement.

gawk at an MCP server before you trust it: measure what it costs and exposes,
without the server's inventory ever leaving your machine.

Pipeline: Observe (probe) -> Bound (measure) -> Attest (label).
"""
from .probe import ServerSnapshot, probe_stdio, probe_http, probe_sse, probe_url
from .measure import Measurement, measure
from .label import build_label

# Single source of truth: the version is whatever the installed package metadata says (which comes
# from `[project] version` in pyproject.toml at build time). No hand-maintained literal to go stale
# — the prior `__version__ = "0.1.0"` disagreed with the published 0.1.3 and with pyproject. In a
# raw source tree with no install at all, metadata is absent; report an honest non-version sentinel
# rather than assert a number that could be wrong.
# METADATA DESCRIBES THE INSTALLED DISTRIBUTION, NOT THE CODE THAT WAS IMPORTED. Those are the
# same thing right up until they are not: with this repo's `src/` ahead of an older install on
# sys.path, `python -m mcpgawk --version` printed "0.1.34 — OUT OF DATE" while executing 0.1.40
# (measured 2026-09-09). Every word of that was wrong, and it is the one banner a person reads to
# find out what they are running. An editable install fails the same way the moment pyproject is
# bumped, because its recorded version is fixed at install time.
#
# So: if a pyproject.toml sits above this package, we are running from a source tree and IT is the
# truth. Otherwise metadata is. Installed users pay one `is_file()` check and nothing else.


def _source_tree_version() -> str | None:
    """`[project] version` from a pyproject.toml above this package, or None if there isn't one."""
    from pathlib import Path
    here = Path(__file__).resolve().parent
    for root in (here.parent.parent, here.parent):      # src/mcpgawk/.. -> src/.. and src/..
        pp = root / "pyproject.toml"
        if not pp.is_file():
            continue
        try:
            raw = pp.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            import tomllib                              # 3.11+; regex fallback keeps 3.10 working
            return str(tomllib.loads(raw)["project"]["version"])
        except Exception:                               # noqa: BLE001 — never fail an import
            import re
            m = re.search(r'^\s*version\s*=\s*["\']([^"\']+)["\']', raw, re.M)
            return m.group(1) if m else None
    return None


def _resolve_version() -> str:
    # Imported INSIDE, not at module scope. The names used to be module-level and `del`d right
    # after the first call, so a second call raised NameError — a resolver that works once and is
    # broken forever after. Found by its own test, which is the only thing that ever calls it twice.
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version
    try:
        meta: str | None = _pkg_version("mcpgawk")
    except PackageNotFoundError:                        # raw source tree, no install at all
        meta = None
    try:
        src = _source_tree_version()
    except Exception:                                   # noqa: BLE001 — a version must never raise
        src = None
    if src:
        return src
    return meta or "0+unknown"


__version__ = _resolve_version()
__all__ = [
    "ServerSnapshot", "probe_stdio", "probe_http", "probe_sse", "probe_url",
    "Measurement", "measure", "build_label", "__version__",
]
