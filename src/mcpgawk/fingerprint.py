"""Canonical tool-surface fingerprinting — ONE definition, reused everywhere a rug-pull is anchored.

Before this module (audit finding B2, 2026-07-23) the running MONITOR daemon pinned on a hash of
each tool's NAME + DESCRIPTION only, while the on-demand SCAN drift detector (`mcpgawk/drift.py`)
covered the input schema and annotations too. So a rug-pull that kept every name and description
byte-identical but WIDENED an input schema (a new `webhook_url` param) or flipped
`readOnlyHint: true → false` was caught by SCAN and INVISIBLE to the 24/7 monitor — the pillar sold
on "drift is the moat" had the weaker detector.

Everything now pins over the same basis: name + description + canonical input schema + annotations.
The canonical serialisation matches `mcpgawk/drift.py._canonical` (sorted keys, fixed separators)
so a server that reserialises its schema between runs does not read as a change and mute the alarm.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical(obj: Any) -> str:
    """Order-independent JSON for hashing — a schema's key order is not semantic, so it must not
    read as a change. Matches `mcpgawk/drift.py._canonical`."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _tool_basis(t: dict) -> str:
    """The full comparable surface of one tool: what a model READS (name, description) AND what it
    can be made to SEND (input schema) AND what it claims about itself (annotations)."""
    return "\x1f".join([
        str(t.get("name", "")),
        str(t.get("description", "")),
        canonical(t.get("inputSchema") or {}),
        canonical(t.get("annotations") or {}),
    ])


def surface_pin(tools: list[dict]) -> str:
    """Deterministic 16-hex digest over the WHOLE tool surface — changes iff any tool's name,
    description, input schema, or annotations change. The rug-pull anchor. Same input → same pin."""
    basis = "\n".join(sorted(_tool_basis(t) for t in tools))
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def surface_hashes(tools: list[dict]) -> list[tuple[str, str]]:
    """Per-tool `(name, 12-hex surface hash)`, sorted by name — so a diff can name WHICH tool's
    schema/annotations changed, not merely that the overall pin moved. Same basis as `surface_pin`."""
    return sorted(
        (str(t.get("name", "")), hashlib.sha256(_tool_basis(t).encode()).hexdigest()[:12])
        for t in tools
    )
