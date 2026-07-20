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


def _hash(text: str | None) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()[:12]


def _tool_hashes(snap: ServerSnapshot) -> dict[str, str]:
    """name -> hash(description). LEGACY shape, tools only — still written to every record so an
    older installed mcpgawk reading a newer history file keeps working instead of false-alarming."""
    return {t.get("name", "?"): _hash(t.get("description")) for t in snap.tools}


#: The surfaces a rug-pull can attack. All three are model-visible text: a prompt IS injected text,
#: and a resource description steers which resource the model reads. Fingerprinting only tools left
#: two of the three injection surfaces able to change silently.
ITEM_KINDS = ("tool", "prompt", "resource")


def _item_hashes(snap: ServerSnapshot) -> dict[str, str]:
    """`{type}.{name}` -> hash(description), across tools AND prompts AND resources.

    Typed keys are load-bearing, not cosmetic: a prompt and a tool may share a name, and with bare
    names one would silently mask the other's drift."""
    out: dict[str, str] = {}
    for kind, items in (("tool", snap.tools), ("prompt", snap.prompts), ("resource", snap.resources)):
        for it in items:
            ident = it.get("name") or it.get("uri") or "?"
            out[f"{kind}.{ident}"] = _hash(it.get("description"))
    return out


def build_record(snap: ServerSnapshot, m: Measurement, measured_at: str | None = None) -> dict[str, Any]:
    """A storable snapshot: enough to diff, small enough to keep forever."""
    return {
        "measured_at": measured_at,
        "pin": m.integrity_pin,
        "tool_count": m.tool_count,
        "cost_index": m.total_tokens,
        "tokenizer": m.tokenizer,          # so token_delta isn't compared across tokenizers
        "protocol_version": snap.protocol_version,
        "tools": _tool_hashes(snap),      # legacy shape, kept for older readers (see _tool_hashes)
        "items": _item_hashes(snap),      # the real fingerprint: tools + prompts + resources
    }


@dataclass
class DriftReport:
    pin_changed: bool
    added: list[str]
    removed: list[str]
    changed: list[str]       # same name, description hash differs = rug-pull signature
    token_delta: int
    prev_at: str | None
    #: True when the prior record predates prompt/resource fingerprinting. Their baseline starts
    #: NOW, so this run cannot claim (or clear) drift on them — and must say so rather than
    #: reporting every prompt as newly "added".
    baseline_extended: bool = False

    @property
    def any(self) -> bool:
        return self.pin_changed or bool(self.added or self.removed or self.changed)

    def of_kind(self, kind: str) -> dict[str, list[str]]:
        """Split the typed `{kind}.{name}` keys back out for rendering."""
        pre = f"{kind}."
        return {field: [k[len(pre):] for k in getattr(self, field) if k.startswith(pre)]
                for field in ("added", "removed", "changed")}


def _fingerprints(rec: dict[str, Any]) -> tuple[dict[str, str], bool]:
    """A record's `{type}.{name}` -> hash map, plus whether it came from the LEGACY tools-only
    shape. Old records are upgraded in memory (never rewritten) so an existing history file keeps
    working across the version boundary."""
    items = rec.get("items")
    if isinstance(items, dict):
        return items, False
    return {f"tool.{n}": h for n, h in (rec.get("tools") or {}).items()}, True


def compare(prev: dict[str, Any] | None, curr: dict[str, Any]) -> DriftReport | None:
    """None if there's no prior record (first sighting — nothing to drift from)."""
    if not prev:
        return None
    pa, legacy = _fingerprints(prev)
    ca, _ = _fingerprints(curr)
    if legacy:
        # The prior record only ever fingerprinted tools. Comparing it against a full tools+prompts
        # +resources map would report every prompt and resource as "added" — a fleet-wide false
        # rug-pull alarm the first time a user upgrades. Compare the surface both records actually
        # cover, and flag that the rest starts its baseline now.
        ca = {k: v for k, v in ca.items() if k.startswith("tool.")}
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
        baseline_extended=legacy,
    )


_KIND_LABEL = {"tool": "tools", "prompt": "prompts", "resource": "resources"}


def render(name: str, r: DriftReport) -> str:
    since = f" since {r.prev_at}" if r.prev_at else ""
    lines = [f"    ⟳ DRIFT on {name}{since} — server changed after you last saw it:"]
    for kind in ITEM_KINDS:
        split = r.of_kind(kind)
        if split["changed"]:
            lines.append(f"        ! {kind} description CHANGED (rug-pull signature): "
                         f"{', '.join(split['changed'])}")
        if split["added"]:
            lines.append(f"        + {_KIND_LABEL[kind]} added: {', '.join(split['added'])}")
        if split["removed"]:
            lines.append(f"        - {_KIND_LABEL[kind]} removed: {', '.join(split['removed'])}")
    if r.token_delta:
        lines.append(f"        Δ cost index: {r.token_delta:+d} tok")
    if r.baseline_extended:
        lines.append("        (prompts/resources were not fingerprinted before now — their "
                     "baseline starts with this scan)")
    return "\n".join(lines)
