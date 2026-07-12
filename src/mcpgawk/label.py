"""ATTEST — build the MCP Label as a Server-Card extension, and render it.

The label complements the emerging LF `.well-known` Server Card standard rather than competing:
standard-ish card fields at the top, our measurements under the `x-mcpgawk` namespace. Nothing
here is a verdict — token cost is a named index; capabilities are facts; there are no risk
'scores' in v1.
"""
from __future__ import annotations

from typing import Any

from .grade import grade
from .measure import Measurement
from .probe import ServerSnapshot
from .servercard import compare_to_reality

LABEL_SCHEMA = "mcpgawk/label@0.1"


def _trust_surface(m: Measurement) -> dict[str, Any]:
    total = m.tool_count
    write = sum(1 for t in m.tools if t.write)
    exfil = sum(1 for t in m.tools if t.exfil_capable)
    destructive = sum(1 for t in m.tools if (t.annotations or {}).get("destructiveHint") is True)
    return {
        "write_pct": round(100 * write / total) if total else 0,
        "exfil_pct": round(100 * exfil / total) if total else 0,
        "write_count": write,
        "exfil_count": exfil,
        "destructive_declared_count": destructive,
    }


def build_label(snap: ServerSnapshot, m: Measurement, measured_at: str | None = None,
                bounded_signals: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """measured_at is passed in (the library never reads the clock — keeps output reproducible).
    bounded_signals (optional) are BOUNDED-layer heuristic findings — kept in their own key,
    never merged into the EXACT tool facts."""
    g = grade(m)
    heavy = sorted(m.tools, key=lambda t: t.tokens, reverse=True)[:3]
    return {
        # ---- Server-Card-compatible surface ----
        "name": snap.name,
        "transport": snap.transport,
        "protocolVersion": snap.protocol_version,
        "serverInfo": snap.server_info or None,
        # ---- our independent measurement extension ----
        "x-mcpgawk": {
            "schema": LABEL_SCHEMA,
            "measured_at": measured_at,
            "tokenizer": m.tokenizer,
            "cost_index_tokens": m.total_tokens,     # INDEX (tokenizer named above)
            "tool_count": m.tool_count,
            "prompt_count": m.prompt_count,
            "resource_count": m.resource_count,
            "integrity_pin": m.integrity_pin,        # EXACT — rug-pull anchor
            "top_heavy_tools": [{"name": t.name, "tokens": t.tokens} for t in heavy],
            "trust_surface": _trust_surface(m),
            "annotation_completeness": {
                "score": g.hygiene_score, "annotated": g.annotated, "total": g.total,
            },
            # server's self-declaration checked against what we measured (http/sse only)
            "server_card": (compare_to_reality(snap.server_card, [t.name for t in m.tools])
                            if snap.server_card else {"present": False}),
            "tools": [
                {"name": t.name, "tokens": t.tokens,
                 "write": t.write, "exfil_capable": t.exfil_capable,
                 "annotations": t.annotations or None}
                for t in m.tools
            ],
            "caveats": m.caveats or None,
            # BOUNDED layer — heuristic signals, kept apart from the EXACT facts above.
            "bounded_signals": bounded_signals or None,
            "disclaimer": "Local measurement. Token cost is a comparable index, not an absolute "
                          "Claude count. Capabilities are structural facts, not risk verdicts. "
                          "annotation_completeness/top_heavy_tools/trust_surface are transparent "
                          "composites of the facts above, not risk verdicts. "
                          "bounded_signals are heuristic pointers for a human to review, not verdicts.",
        },
    }


def render_cli(label: dict[str, Any], verbose: bool = False) -> str:
    x = label["x-mcpgawk"]
    ts = x["trust_surface"]
    ac = x["annotation_completeness"]
    lines = [
        f"● {label['name']:<22} [{label['transport']}]  proto={label.get('protocolVersion') or '?'}",
        f"    {x['tool_count']:>3} tools   {x['cost_index_tokens']:>6} tok@connect   pin:{x['integrity_pin']}",
        f"    coverage: {x['tool_count']} tools, {x['prompt_count']} prompts, {x['resource_count']} resources",
        f"    trust surface: {ts['write_pct']}% write ({ts['write_count']})  "
        f"{ts['exfil_pct']}% exfil-capable ({ts['exfil_count']})  "
        f"{ts['destructive_declared_count']} destructive-declared",
        f"    annotation completeness: {ac['score']}% ({ac['annotated']}/{ac['total']} declare read/write intent)",
    ]
    if x["top_heavy_tools"]:
        heavy = ", ".join(f"{t['name']} ({t['tokens']} tok)" for t in x["top_heavy_tools"])
        lines.append(f"    heaviest tools: {heavy}")
    if verbose:
        lines.append("    per-tool:")
        for t in x["tools"]:
            caps = []
            if t["write"]:
                caps.append("write")
            if t["exfil_capable"]:
                caps.append("exfil-capable")
            ann = t.get("annotations") or {}
            if ann.get("destructiveHint") is True:
                caps.append("destructive-declared")
            if not ann:
                caps.append("no-annotation")
            lines.append(f"      · {t['name']:<28} {t['tokens']:>5} tok   {', '.join(caps) or 'read'}")
    else:
        flagged = [t for t in x["tools"] if t["write"] or t["exfil_capable"]]
        for t in flagged:
            caps = []
            if t["write"]:
                caps.append("write" if (t.get("annotations") or {}) else "write/no-annotation")
            if t["exfil_capable"]:
                caps.append("exfil-capable")
            if (t.get("annotations") or {}).get("destructiveHint") is True:
                caps.append("destructive-declared")
            lines.append(f"      · {t['name']:<28} {t['tokens']:>5} tok   {', '.join(caps)}")
    for s in (x.get("bounded_signals") or []):
        lines.append(f"    ⚠ SIGNAL {s['kind']:<26} [{s['tool']}]  — review: {s['evidence']!r}")
    sc = x.get("supply_chain")
    if sc is not None:
        if sc.get("error"):
            lines.append(f"    supply-chain: {sc['ecosystem']}:{sc['package']} — lookup failed ({sc['error']})")
        elif sc.get("checked") is False:
            lines.append(f"    supply-chain: {sc['reason']}")
        else:
            flag = "⚠ DEPRECATED/YANKED" if sc["deprecated"] else "ok"
            lines.append(f"    supply-chain: {sc['ecosystem']}:{sc['package']}@{sc['version']}  {flag}"
                         + (f" — {sc['detail']}" if sc.get("detail") else ""))
    if "oauth_scopes" in x:
        os_ = x["oauth_scopes"]
        if os_ is None:
            lines.append("    oauth scopes: no bearer token supplied")
        elif os_.get("token_type") == "opaque":
            lines.append(f"    oauth scopes: {os_['note']}")
        elif os_.get("error"):
            lines.append(f"    oauth scopes: {os_['error']}")
        else:
            lines.append(f"    oauth scopes: {', '.join(os_.get('scopes') or []) or '(none declared)'}")
    if x.get("caveats"):
        lines.append(f"    ! {'; '.join(x['caveats'])}")
    return "\n".join(lines)


def render_summary(labels: list[dict[str, Any]]) -> str:
    tools = sum(l["x-mcpgawk"]["tool_count"] for l in labels)
    toks = sum(l["x-mcpgawk"]["cost_index_tokens"] for l in labels)
    flagged = sum(1 for l in labels for t in l["x-mcpgawk"]["tools"] if t["write"] or t["exfil_capable"])
    tzs = {l["x-mcpgawk"]["tokenizer"] for l in labels}
    return ("-" * 70 + f"\nTOTAL: {tools} tools | {toks} tok loaded at connect | "
            f"{flagged} capability-flagged | tokenizer: {', '.join(tzs)}\n"
            "Nothing was uploaded. Re-run for identical numbers.")
