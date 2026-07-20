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
from importlib.metadata import version as _pkg_version, PackageNotFoundError
try:
    __version__ = _pkg_version("mcpgawk")
except PackageNotFoundError:  # running from source with no (editable) install
    __version__ = "0+unknown"
del _pkg_version, PackageNotFoundError
__all__ = [
    "ServerSnapshot", "probe_stdio", "probe_http", "probe_sse", "probe_url",
    "Measurement", "measure", "build_label", "__version__",
]
