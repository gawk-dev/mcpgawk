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

# Human lead phrase per bounded-signal family (the part of `kind` before the ':'). Keeps each
# finding named as ITSELF in the CLI report — see the render loop. Adding a new signal family
# without a lead here falls back to a neutral "review signal in" rather than silently mislabelling.
_SIGNAL_LEAD = {
    "injection": "possible prompt-injection in",
    "dispatch": "tools hidden behind dynamic dispatch in",
    "shadowing": "tool-name shadowing on",
    "servercard": "server-card mismatch on",
}


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
            # TYPED failure signal — the render layer decides CLEAN vs UNREACHABLE from this, not by
            # scraping caveat text. is_failure True => this server was NOT measured; it must never
            # read CLEAN. error_kind explains why (unreachable / misconfigured / not-an-mcp-endpoint).
            "is_failure": m.is_failure,
            "error_kind": m.error_kind,
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
    tools = x["tools"]
    n = x["tool_count"]
    cost = x["cost_index_tokens"]
    write_c, exfil_c = ts["write_count"], ts["exfil_count"]
    has_risk = write_c > 0 or exfil_c > 0
    heavy = cost >= 3000
    unannotated = ac["total"] > 0 and ac["annotated"] == 0
    # A probe that errored (unreachable host, wrong URL, an HTML docs page instead of an MCP
    # endpoint, a timeout) must NEVER read as CLEAN. A failed scan reporting "nothing write- or
    # exfil-capable" is a security tool's cardinal sin — a failure reading as all-clear.
    caveats = x.get("caveats") or []
    # Primary signal is the TYPED flag set by measure() from the snapshot. The substring check is
    # kept only as belt-and-suspenders: neither alone can let a failed probe slip through as CLEAN,
    # and if one mechanism ever regresses the other still catches it.
    failed = bool(x.get("is_failure")) or any(("probe error" in c) or ("scan failed" in c) for c in caveats)

    # Verdict: derived only from the real numbers, so the headline can't lie.
    if failed:
        verdict = "UNREACHABLE"
    elif not has_risk and not heavy:
        verdict = "CLEAN"
    else:
        verdict = " · ".join(p for p, on in
                             (("HEAVY", heavy), ("HIGH-REACH", has_risk), ("UNANNOTATED", unannotated)) if on) or "REVIEW"

    lines = [f"● {label['name']}   [{label['transport']}]   {verdict}"]

    if failed:
        raw = next((c for c in caveats if "probe error" in c or "scan failed" in c), "")
        detail = raw.split("error:", 1)[-1].strip().rstrip(":").strip() if "error:" in raw else raw.strip()
        if not detail or detail.lower().startswith("timeouterror"):
            detail = "no MCP response (timed out)"
        lines.append(f"    ✗ could not scan — {detail}. This did NOT pass; it was not measured.")
        lines.append("      Is it a live MCP endpoint? A docs / repo / package URL is not one.")
        lines.append("      A local server needs:  mcpgawk scan --stdio \"<launch command>\"")
        return "\n".join(lines)

    if not has_risk and not heavy:
        lines.append(f"    {n} tool{'s' if n != 1 else ''} · {cost:,} tokens at connect · nothing write- or exfil-capable.")
    else:
        pct = round(cost / 200_000 * 100)
        note = f"   (~{pct}% of a 200k context window, every request)" if cost >= 1000 else ""
        lines += [
            "",
            f"    COST   {cost:,} tokens loaded into every session — before you type a word.{note}",
            "",
            f"    What these {n} tools can do to you:",
            f"      change things    {write_c:>2} of {n}   create / update / delete / upload",
            f"      send data out    {exfil_c:>2} of {n}   read + reach the network — a leak path",
            f"      declare intent   {ac['annotated']:>2} of {n}   "
            + ("← none, so your agent trusts them all blindly" if ac["annotated"] == 0 else "how safe they are"),
        ]

    # Tool detail: verbose shows every tool; default surfaces only the ones that can bite,
    # scariest first (can both change data AND send it out), capped.
    if verbose:
        lines.append("    all tools (heaviest first):")
        for t in sorted(tools, key=lambda t: -t["tokens"]):
            tags = [c for c, on in (("write", t["write"]), ("exfil", t["exfil_capable"]),
                                    ("no-annotation", not (t.get("annotations") or {}))) if on]
            lines.append(f"      · {t['name']:<32} {t['tokens']:>5} tok   {', '.join(tags) or 'read-only'}")
    elif has_risk:
        flagged = sorted((t for t in tools if t["write"] or t["exfil_capable"]),
                         key=lambda t: (0 if (t["write"] and t["exfil_capable"]) else 1 if t["write"] else 2, -t["tokens"]))
        both = [t for t in flagged if t["write"] and t["exfil_capable"]]
        lines.append("")
        # Only claim "BOTH" for tools that genuinely can do both; never let the header overclaim.
        if both:
            lines.append("    Look at these first — can BOTH change data AND send it out:")
            shown = both[:5]
        else:
            lines.append("    Tools that can change data or send it out:")
            shown = flagged[:5]
        for t in shown:
            tag = "write + exfil" if (t["write"] and t["exfil_capable"]) else ("write" if t["write"] else "exfil")
            lines.append(f"      · {t['name']:<32} {t['tokens']:>5} tok   {tag}")
        remaining = len(flagged) - len(shown)
        if remaining > 0:
            lines.append(f"      (+ {remaining} more that can change or send data · --verbose for all {n})")

    # Bounded heuristic signals — one actionable line each. Each KIND is a DISTINCT finding and must
    # be named as itself: filing dynamic-dispatch, tool-shadowing and server-card-mismatch under
    # "possible prompt-injection" (the old bug) is precisely the kind of report deviation that erodes
    # trust in a security tool. Lead phrase is chosen from the kind's family prefix.
    for s in (x.get("bounded_signals") or []):
        kind = s.get("kind", "")
        family = kind.split(":", 1)[0]
        lead = _SIGNAL_LEAD.get(family, "review signal in")
        evidence = s.get("evidence")
        detail = f" — review: {evidence!r}" if evidence else ""
        lines.append(f"    ⚠  {lead} {s.get('tool', '?')} ({kind}){detail}")

    if verbose:
        lines.append(f"    coverage: {x['tool_count']} tools, {x['prompt_count']} prompts, {x['resource_count']} resources")
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
    ns = len(labels)
    return ("─" * 64 + f"\n{ns} server{'s' if ns != 1 else ''} · {tools} tools · "
            f"{toks:,} tokens loaded into every session · {flagged} can change or send data.\n"
            "Scanned locally — nothing left your machine.")
