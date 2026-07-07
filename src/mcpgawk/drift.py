"""Drift / rug-pull detection — pure diff over stored measurements.

The integrity pin (measure.py) already changes when a server silently rewrites its tools. Drift
turns that into an actionable, per-tool diff: what was ADDED, REMOVED, or CHANGED (same tool name,
different description = the classic tool-poisoning rug-pull signature) since you last trusted it.

Pure functions, no I/O, no clock (the caller stamps time). history.py handles the local store.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .measure import Measurement
from .probe import ServerSnapshot


def _tool_hashes(snap: ServerSnapshot) -> dict[str, str]:
    """name -> hash(description). Detects silent description edits per tool."""
    return {t.get("name", "?"): hashlib.sha256((t.get("description") or "").encode()).hexdigest()[:12]
            for t in snap.tools}


def build_record(snap: ServerSnapshot, m: Measurement, measured_at: str | None = None) -> dict[str, Any]:
    """A storable snapshot: enough to diff, small enough to keep forever."""
    return {
        "measured_at": measured_at,
        "pin": m.integrity_pin,
        "tool_count": m.tool_count,
        "cost_index": m.total_tokens,
        "tokenizer": m.tokenizer,          # so token_delta isn't compared across tokenizers
        "protocol_version": snap.protocol_version,
        "tools": _tool_hashes(snap),
    }


@dataclass
class DriftReport:
    pin_changed: bool
    added: list[str]
    removed: list[str]
    changed: list[str]       # same name, description hash differs = rug-pull signature
    token_delta: int
    prev_at: str | None

    @property
    def any(self) -> bool:
        return self.pin_changed or bool(self.added or self.removed or self.changed)


def compare(prev: dict[str, Any] | None, curr: dict[str, Any]) -> DriftReport | None:
    """None if there's no prior record (first sighting — nothing to drift from)."""
    if not prev:
        return None
    pa, ca = prev.get("tools", {}), curr.get("tools", {})
    added = sorted(set(ca) - set(pa))
    removed = sorted(set(pa) - set(ca))
    changed = sorted(n for n in (set(pa) & set(ca)) if pa[n] != ca[n])
    # token_delta is only meaningful when both runs used the same tokenizer; else it lies (an
    # index change from swapping tiktoken, not a real server change). Rug-pull detection (pin +
    # description hashes) is tokenizer-independent, so it stays correct.
    same_tok = prev.get("tokenizer") == curr.get("tokenizer")
    delta = (curr.get("cost_index", 0) - prev.get("cost_index", 0)) if same_tok else 0
    return DriftReport(
        pin_changed=prev.get("pin") != curr.get("pin"),
        added=added, removed=removed, changed=changed,
        token_delta=delta,
        prev_at=prev.get("measured_at"),
    )


def render(name: str, r: DriftReport) -> str:
    since = f" since {r.prev_at}" if r.prev_at else ""
    lines = [f"    ⟳ DRIFT on {name}{since} — server changed after you last saw it:"]
    if r.changed:
        lines.append(f"        ! description CHANGED (rug-pull signature): {', '.join(r.changed)}")
    if r.added:
        lines.append(f"        + tools added: {', '.join(r.added)}")
    if r.removed:
        lines.append(f"        - tools removed: {', '.join(r.removed)}")
    if r.token_delta:
        lines.append(f"        Δ cost index: {r.token_delta:+d} tok")
    return "\n".join(lines)
