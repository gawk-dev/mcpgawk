"""mcpgawk — local-first MCP measurement.

gawk at an MCP server before you trust it: measure what it costs and exposes,
without the server's inventory ever leaving your machine.

Pipeline: Observe (probe) -> Bound (measure) -> Attest (label).
"""
from .probe import ServerSnapshot, probe_stdio, probe_http, probe_sse
from .measure import Measurement, measure
from .label import build_label

__version__ = "0.1.0"
__all__ = [
    "ServerSnapshot", "probe_stdio", "probe_http", "probe_sse",
    "Measurement", "measure", "build_label", "__version__",
]
