"""The one answer to "what did this server look like when I trusted it".

The product kept three memories of that: `history.py` (scan), `packages/verify/src/pins.ts`
(verify) and `monitor/store.py` (the daemon). You could approve a server in one and still be told
it had drifted by another, which is why no flow felt joined up — there wasn't one spine, there were
three.

This is the spine. It is deliberately a NARROW VIEW over the store that already exists
(`history.json`) rather than a fourth file: a new store would have to be migrated into, kept in
sync, and would itself become another memory to disagree with. The canonical record was already
there — `servers[key]["approved"]` — it simply had no name and no reader outside scan.

What makes one shared baseline possible at all is that the fingerprint is now identical everywhere:
`fingerprint.surface_pin` is computed by scan (through `measure`), by monitor, and — since the
schema-2.0 change — byte-for-byte by verify in TypeScript. Before that, sharing a baseline would
have meant sharing a number the three pillars each interpreted differently.

Shape (stable, and the contract other runtimes read through `mcpgawk baseline --json`):

    {"schema": "gawk.baseline/1",
     "servers": {"<key>": {"pin": "<16-hex>", "tools": {"<name>": "<hash>"},
                           "approved_at": "<iso8601>", "aliases": [...]}}}
"""

from __future__ import annotations

from typing import Any

from . import history

#: Bumped only when the exported shape changes incompatibly. Readers check it rather than guessing.
SCHEMA = "gawk.baseline/1"


def approved_record(key: str, path: str | None = None) -> dict[str, Any] | None:
    """The full approved record for one server, or None if nothing has been approved yet."""
    store = history.load(path or history.default_path())
    return history.approved(store, key)


def approved_pin(key: str, path: str | None = None) -> str | None:
    """The approved whole-surface pin — the single value every pillar compares against.

    None means "never approved", which is NOT the same as "approved as empty": a caller that
    conflates them reports drift against a baseline that does not exist, on a server the operator
    has never looked at. Trust-on-first-use is scan's job (see history.record); this only reports.
    """
    rec = approved_record(key, path)
    return (rec or {}).get("pin")


def approved_tools(key: str, path: str | None = None) -> dict[str, str]:
    """`{tool name: hash}` from the approved record. Empty dict when nothing is approved."""
    rec = approved_record(key, path) or {}
    tools = rec.get("tools")
    return dict(tools) if isinstance(tools, dict) else {}


def approved_annotations(key: str, path: str | None = None) -> dict[str, dict[str, Any]]:
    """`{tool name: annotations}` as they were WHEN APPROVED.

    The distinction that makes this worth having: `enforce` can already derive a policy from the
    annotations a server declares at connect time — but that is the server's CURRENT claim about
    itself. A server that quietly flips `readOnlyHint` to true would have the guard relax to match
    it. Deriving from the approved record instead means the policy reflects the operator's decision,
    and a server changing its story does not change what it is allowed to do.

    Records store typed keys (`tool.read_file`) because a prompt and a tool may share a name; only
    tools carry scopes, so only tools come back.
    """
    rec = approved_record(key, path) or {}
    raw = rec.get("annotations")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for ident, ann in raw.items():
        if not isinstance(ident, str) or not ident.startswith("tool."):
            continue
        if isinstance(ann, dict):
            out[ident[len("tool."):]] = dict(ann)
    return out


def export(path: str | None = None) -> dict[str, Any]:
    """The whole approved baseline, in the shape other runtimes read.

    Only APPROVED state crosses this boundary — never the sighting history. What a server looked
    like last Tuesday is scan's business; what the operator has agreed to trust is everyone's.
    """
    store = history.load(path or history.default_path())
    out: dict[str, Any] = {}
    for key, entry in (store.get("servers") or {}).items():
        if not isinstance(entry, dict):
            continue
        rec = entry.get("approved")
        if not isinstance(rec, dict):
            continue  # seen but never approved — deliberately absent, not exported as empty
        out[key] = {
            "pin": rec.get("pin"),
            "tools": dict(rec.get("tools") or {}),
            "approved_at": rec.get("measured_at"),
            "aliases": list(entry.get("aliases") or []),
            "annotations": {
                ident[len("tool."):]: dict(ann)
                for ident, ann in (rec.get("annotations") or {}).items()
                if isinstance(ident, str) and ident.startswith("tool.") and isinstance(ann, dict)
            },
        }
    return {"schema": SCHEMA, "servers": out}


def publish(key: str, *, pin: str, tools: dict[str, str], approved_at: str,
            alias: str | None = None, path: str | None = None) -> None:
    """Write an approval INTO the spine from another pillar.

    The read path (`export`) alone makes the spine a one-way mirror: verify and monitor could see
    what scan approved, but an operator approving a drift in `gawk-monitor approve` left scan still
    reporting it. A shared baseline that only one pillar can move is three memories again, with
    extra steps.

    Deliberately narrow — pin, per-tool hashes, when. A monitor Snapshot carries more (grade,
    signals, verification state) and that stays in monitor's own store: the spine is the answer to
    "what surface did we agree to trust", not a general-purpose replica.
    """
    p = path or history.default_path()
    with history.locked(p):
        store = history.load(p)
        entry = store.setdefault("servers", {}).setdefault(key, {})
        entry["approved"] = {
            **(entry.get("approved") or {}),
            "measured_at": approved_at,
            "pin": pin,
            "tools": dict(tools),
        }
        if alias:
            entry["aliases"] = sorted(set(entry.get("aliases", [])) | {alias})
        history.save(store, p)


def resolve(name: str, path: str | None = None) -> str | None:
    """Map a name the user typed to the key the baseline is stored under.

    A server's identity key and the name it is configured under in an AI tool are not the same
    string, and the same server is routinely configured under different names in different tools.
    Without this, `approve slack` in one pillar and a lookup of `slack-mcp` in another miss each
    other and the shared baseline silently does nothing.
    """
    store = history.load(path or history.default_path())
    servers = store.get("servers") or {}
    if name in servers:
        return name
    for key, entry in servers.items():
        if isinstance(entry, dict) and name in (entry.get("aliases") or []):
            return key
    return None
