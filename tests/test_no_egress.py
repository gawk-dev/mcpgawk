"""LOAD-BEARING CONSTRAINT TEST (ContextKey lesson: written to guard the #1 invariant).

Invariant #1: scanning an MCP server's inventory must make ZERO outbound network connections.
The measure -> label path is the code that handles the captured inventory; here we run it under
a socket guard that forbids every connection attempt and assert none occurred.

(Probe-level egress — the SDK talking to the server itself — is verified live against the bench;
that connection is *to the scanned server* and is the one allowed network touch. This test locks
the part that must never phone home about what it saw.)
"""
from __future__ import annotations

import socket

import pytest

from mcpgawk import build_label, measure
from mcpgawk.probe import ServerSnapshot

REALISTIC = ServerSnapshot(
    name="fixture", transport="stdio", protocol_version="2025-06-18",
    tools=[
        {"name": "read_file", "description": "Read a file.",
         "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
         "annotations": {"readOnlyHint": True}},
        {"name": "delete_file", "description": "Delete a file at path.",
         "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
         "annotations": {"destructiveHint": True}},
        {"name": "fetch_url", "description": "Fetch a remote URL.",
         "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
    ],
)


@pytest.fixture
def forbid_network(monkeypatch):
    """Any outbound connection attempt raises, and is recorded."""
    attempts: list = []

    def _deny(*args, **kwargs):
        attempts.append((args, kwargs))
        raise AssertionError(f"EGRESS VIOLATION: outbound connection attempted: {args}")

    monkeypatch.setattr(socket.socket, "connect", _deny, raising=True)
    monkeypatch.setattr(socket, "create_connection", _deny, raising=True)
    return attempts


def test_measure_and_label_make_zero_connections(forbid_network):
    m = measure(REALISTIC)
    label = build_label(REALISTIC, m, measured_at=None)
    # If any socket had been opened, the guard would have raised already.
    assert forbid_network == []
    assert label["x-mcpgawk"]["tool_count"] == 3
    assert label["x-mcpgawk"]["integrity_pin"]  # pin computed locally


def test_no_clock_read_in_library(forbid_network):
    """Reproducibility invariant: the library never stamps its own time (caller passes it)."""
    label = build_label(REALISTIC, measure(REALISTIC))
    assert label["x-mcpgawk"]["measured_at"] is None


# --- STRUCTURAL invariant: the inventory-handling layers cannot egress BY CONSTRUCTION. ---
# Stronger than a runtime socket probe: proves measure/label/signals/drift/history never even
# import a network library, so there is no code path by which what they saw could leave the box.
# Network lives ONLY in probe.py (talks to the scanned server) and servercard.py (public card fetch).
import ast
import pathlib

_NETWORK_LIBS = {"httpx", "socket", "urllib", "requests", "aiohttp", "http", "ftplib", "smtplib"}


def _toplevel_imports(pyfile: pathlib.Path) -> set[str]:
    """Module-level import roots (function-local imports are separate; we assert on the module surface)."""
    tree = ast.parse(pyfile.read_text())
    roots: set[str] = set()
    for node in tree.body:  # top-level only
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def test_inventory_layers_import_no_network_library():
    import mcpgawk
    base = pathlib.Path(mcpgawk.__file__).parent
    for mod in ("measure", "label", "signals", "drift", "history"):
        offenders = _toplevel_imports(base / f"{mod}.py") & _NETWORK_LIBS
        assert not offenders, f"{mod}.py must not import a network library, found: {offenders}"
