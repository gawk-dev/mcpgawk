"""ATTEST — build the MCP Label as a Server-Card extension, and render it.

The label complements the emerging LF `.well-known` Server Card standard rather than competing:
standard-ish card fields at the top, our measurements under the `x-mcpgawk` namespace. Nothing
here is a verdict — token cost is a named index; capabilities are facts; there are no risk
'scores' in v1.
"""
from __future__ import annotations

import textwrap
from typing import Any

from .grade import cost_phrase, grade
from .ambient import detect_ambient, summarize
from .measure import Measurement
from .probe import ServerSnapshot
from .servercard import compare_to_reality

LABEL_SCHEMA = "mcpgawk/label@0.1"

# Human lead phrase per bounded-signal family (the part of `kind` before the ':'). Keeps each
# finding named as ITSELF in the CLI report — see the render loop. Adding a new signal family
# without a lead here falls back to a neutral "review signal in" rather than silently mislabelling.
#: Per-KIND overrides, consulted before the family lead. A family phrase that is right for one of
#: its kinds can be actively wrong for another: "tool-name shadowing on X" misdescribes a
#: cross-server REFERENCE, where the names differ entirely and the issue is one server instructing
#: the agent about another's tool. A finding named inaccurately sends the reader to check the wrong
#: thing.
_SIGNAL_LEAD_BY_KIND = {
    "shadowing:cross-server-reference": "cross-server tool reference from",
}

_SIGNAL_LEAD = {
    "injection": "possible prompt-injection in",
    "dispatch": "tools hidden behind dynamic dispatch in",
    "shadowing": "tool-name shadowing on",
    "servercard": "server-card mismatch on",
    # Obfuscation is its OWN class, not a flavour of injection (Invariant separates them too: W021
    # vs E001). Hiding text is evidence of intent; what it hides is reported by its own detector.
    "obfuscation": "text hidden with invisible characters in",
}


#: Above this, the connect-time cost is worth raising on its own. One definition, used by both the
#: JSON risk flag and the rendered verdict, so they cannot disagree.
HEAVY_TOKENS = 3000


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
    _ts = _trust_surface(m)
    heavy = sorted(m.tools, key=lambda t: t.tokens, reverse=True)[:3]
    label: dict[str, Any] = {
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
            "trust_surface": _ts,
            # The risk CLASSIFICATION, kept machine-readable. The human headline is now a sentence
            # ("REVIEW — 2 things worth a look") rather than the old HEAVY/HIGH-REACH/UNANNOTATED
            # tags, so anything automated must read these booleans instead of parsing prose.
            "risk_flags": {
                "heavy": m.total_tokens >= HEAVY_TOKENS,
                "high_reach": _ts["write_count"] > 0 or _ts["exfil_count"] > 0,
                "unannotated": g.total > 0 and g.annotated == 0,
            },
            "annotation_completeness": {
                "score": g.hygiene_score, "annotated": g.annotated, "total": g.total,
            },
            # server's self-declaration checked against what we measured (http/sse only)
            "server_card": (compare_to_reality(snap.server_card, [t.name for t in m.tools])
                            if snap.server_card else {"present": False}),
            # Filled in below, once the label exists to compute it from. THE prose, so every
            # renderer tells the same story — see build_narrative.
            "narrative": None,
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
    # Computed from the finished label so there is exactly one place the report's wording is decided.
    label["x-mcpgawk"]["narrative"] = build_narrative(label)
    return label


def _pl(count: int, singular: str, plural: str | None = None) -> str:
    """`3 tools` / `1 tool`. Prose that says "None of the 1 tools" reads as machine output and
    undermines the point of writing prose at all."""
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _wrap(text: str, indent: str) -> list[str]:
    """Wrap to a terminal-safe width with a hanging indent. Prose has to wrap or the narrative
    turns into one unreadable line the moment a tool name is long."""
    return textwrap.wrap(text, width=94, initial_indent=indent, subsequent_indent=indent) or [indent.rstrip()]


def _dominates(tools: list[dict[str, Any]], cost: int) -> dict[str, Any] | None:
    """The single heaviest tool, but only when it is a big enough share of the bill to be worth
    naming. Telling someone to disable a 218-token tool out of 4,032 is noise dressed as advice."""
    if not tools or not cost:
        return None
    top = max(tools, key=lambda t: t["tokens"])
    return top if top["tokens"] >= cost * 0.15 else None


def _concerns(n: int, cost: int, write_c: int, exfil_c: int, ac: dict[str, Any],
              tools: list[dict[str, Any]], heavy: bool, injections: list[dict[str, Any]],
              expensive: bool) -> list[tuple[str, list[str]]]:
    """The things worth a human's attention, MOST IMPORTANT FIRST.

    This ordering is the whole point of the narrative report. The old renderer gave every fact the
    same weight — a table of counts — which left the reader to work out what mattered. Insight is
    saying *this one first, and here is the specific mechanism by which it bites you*.

    Each concern explains a MECHANISM, never just a count. "3 tools can send data out" is a
    statistic; "read + network in one tool means a poisoned document can make it forward your data"
    is the thing that makes someone act.
    """
    out: list[tuple[str, list[str]]] = []

    if injections:
        names = ", ".join(sorted({s.get("tool", "?") for s in injections})[:3])
        out.append(("Instruction-like text hidden in tool descriptions", [
            f"{len(injections)} finding{'s' if len(injections) != 1 else ''} in: {names}.",
            "Descriptions are read by your agent, not by you — text there is an instruction it may",
            "follow. Details on the ⚠ lines below.",
        ]))

    if exfil_c:
        named = sorted((t for t in tools if t["exfil_capable"]),
                       key=lambda t: -t["tokens"])[:2]
        which = ", ".join(t["name"] for t in named)
        head = (f"{exfil_c} of {n} tools can read your content AND reach the network"
                if exfil_c > 1 else
                f"1 tool can read your content AND reach the network — {which}")
        body = ["That pairing is the leak path" + (f" ({which})." if exfil_c > 1 else "."),
                "One poisoned document is enough: it instructs the tool, the tool has the reach, "
                "and your data leaves. Neither half is a flaw on its own — the combination is the "
                "exposure."]
        out.append((head, body))

    if write_c and ac["annotated"] == 0:
        if n == 1:
            out.append(("The only tool here declares nothing, and it can change data", [
                "It doesn't say whether it only reads or can destroy, so your agent has no signal "
                "to be careful with it.",
            ]))
        else:
            out.append((f"Nothing declares its intent, including {write_c} that can change data", [
                f"None of the {_pl(n, 'tool')} say whether they only read or can destroy — so your "
                f"agent has no signal to treat the {'one' if write_c == 1 else write_c} that can "
                "delete or overwrite any more carefully than the harmless ones.",
            ]))

    # Cost is only a CONCERN when it is actually poor value. `heavy` is an absolute threshold, so a
    # large-but-efficient server tripped it — and then the report said "lean for a server this size"
    # two lines above "it costs too much". Contradicting yourself in the same breath is exactly the
    # credibility loss this rewrite is meant to fix.
    if heavy and expensive:
        pct = round(cost / 200_000 * 100)
        body = [f"{cost:,} tokens are loaded before you type a word, whether or not you use a tool."]
        top = _dominates(tools, cost)
        if top:
            body.append(f"{top['name']} alone accounts for {top['tokens']:,} of that.")
        out.append((f"It costs ~{pct}% of your context window on every message", body))

    return out


def _flagged_table(tools: list[dict[str, Any]], n: int) -> list[str]:
    """The tools behind the exposure, scariest first (can change data AND send it out), capped.
    Only claims "BOTH" for tools that genuinely can do both — the header must never overclaim."""
    flagged = sorted((t for t in tools if t["write"] or t["exfil_capable"]),
                     key=lambda t: (0 if (t["write"] and t["exfil_capable"]) else 1 if t["write"] else 2,
                                    -t["tokens"]))
    if not flagged:
        return []
    both = [t for t in flagged if t["write"] and t["exfil_capable"]]
    shown = both[:5] if both else flagged[:5]
    # Self-describing header: this table can follow any of the concerns, so a back-reference like
    # "the tools behind that" would point at whichever one happened to render last.
    head = ("    The tools that can BOTH change data AND send it out:" if both
            else "    The tools that can change data or send it out:")
    out = ["", head]
    for t in shown:
        tag = ("write + exfil" if (t["write"] and t["exfil_capable"])
               else ("write" if t["write"] else "exfil"))
        out.append(f"      · {t['name']:<32} {t['tokens']:>5} tok   {tag}")
    remaining = len(flagged) - len(shown)
    if remaining > 0:
        out.append(f"      (+ {remaining} more that can change or send data · --verbose for all {n})")
    return out


def _actions(exfil_c: int, write_c: int, ac: dict[str, Any], heavy: bool,
             tools: list[dict[str, Any]], cost: int = 0) -> list[str]:
    """Only actions that CANNOT be wrong. A passive scan cannot tell you a server is safe to
    install, so this never says so — it suggests steps that are correct regardless of whether the
    server turns out to be benign."""
    acts: list[str] = []
    if exfil_c or write_c:
        acts.append("If you don't need write access, connect with a read-only token instead.")
    acts.append("Re-scan with --track before you trust it again — descriptions are the surface "
                "that gets rewritten, and that rewrite is the attack.")
    top = _dominates(tools, cost) if heavy else None
    if top:
        acts.append(f"Disable the tools you never call — {top['name']} alone costs "
                    f"{top['tokens']:,} tokens on every message.")
    if write_c and ac["annotated"] == 0:
        acts.append(f"Treat the {_pl(write_c, 'write-capable tool')} as unreviewed — this server "
                    f"gives your agent no safety hints about {'it' if write_c == 1 else 'them'}.")
    return acts[:3]


def build_narrative(label: dict[str, Any]) -> dict[str, Any]:
    """THE prose, computed once, as structure.

    Both renderers used to derive their own sentences from the same label: `render_cli` here and
    `site/assets/report-render.js` there. They diverged — different framing, different wording, and
    the web one showed a letter grade the CLI had deliberately dropped from the headline. Two
    renderers telling different stories about the same scan is doctrine principle 9 (single source
    of truth) broken on the most public surface, and it is the kind of drift no test catches because
    each side passes its own.

    So the engine decides what the report SAYS; a renderer decides only how it looks.
    """
    x = label["x-mcpgawk"]
    ts, ac = x["trust_surface"], x["annotation_completeness"]
    tools, n = x["tools"], x["tool_count"]
    cost = x["cost_index_tokens"]
    write_c, exfil_c = ts["write_count"], ts["exfil_count"]
    has_risk = write_c > 0 or exfil_c > 0
    heavy = cost >= HEAVY_TOKENS
    caveats = x.get("caveats") or []
    failed = bool(x.get("is_failure")) or any(("probe error" in c) or ("scan failed" in c) for c in caveats)
    has_dispatch = any((s.get("kind") or "").startswith("dispatch:") for s in (x.get("bounded_signals") or []))
    injections = [s for s in (x.get("bounded_signals") or []) if (s.get("kind") or "").startswith("injection:")]
    phrase = cost_phrase(round(cost / n) if n else 0)
    expensive = "expensive" in phrase or "mid-range" in phrase
    concerns = _concerns(n, cost, write_c, exfil_c, ac, tools, heavy, injections, expensive)

    if failed:
        state = "auth-required" if x.get("error_kind") == "auth-required" else "unreachable"
        verdict = "AUTH REQUIRED" if state == "auth-required" else "UNREACHABLE"
    elif not has_risk and not heavy:
        state = "incomplete" if has_dispatch else "clean"
        verdict = "INCOMPLETE" if has_dispatch else "CLEAN"
    else:
        state = "review"
        k = len(concerns)
        risk = f"REVIEW — {k} thing{'s' if k != 1 else ''} worth a look" if k else "REVIEW"
        verdict = f"INCOMPLETE · {risk}" if has_dispatch else risk

    failure = None
    if failed:
        raw = next((c for c in caveats if "probe error" in c or "scan failed" in c), "")
        detail = raw.split("error:", 1)[-1].strip().rstrip(":").strip() if "error:" in raw else raw.strip()
        if not detail or detail.lower().startswith("timeouterror"):
            detail = "no MCP response (timed out)"
        failure = {"detail": detail, "auth": state == "auth-required"}

    pct = round(cost / 200_000 * 100)
    window = f"about {pct}% of a 200k context window" if pct >= 1 else "under 1% of a 200k context window"
    return {
        "verdict": verdict,
        "state": state,
        "failure": failure,
        "dispatch": has_dispatch,
        "cost_sentence": (f"{n} tool{'s' if n != 1 else ''} costing {cost:,} tokens — {window}, spent on "
                          f"every message before you type a word. {phrase.capitalize()}."),
        "concerns": [{"title": t, "body": b} for t, b in concerns],
        "actions": _actions(exfil_c, write_c, ac, heavy, tools, cost),
        # Hedged and conditional, always: we only saw the tools the server chose to show us, and we
        # only pattern-match. It disappears entirely the moment anything is actually found.
        "reassurance": (None if (failed or injections or has_dispatch or (not has_risk and not heavy))
                        else f"Nothing here looks malicious in the {n} visible tool"
                             f"{'s' if n != 1 else ''} — this is exposure, not evidence of an attack."),
    }


def render_cli(label: dict[str, Any], verbose: bool = False) -> str:
    x = label["x-mcpgawk"]
    ts = x["trust_surface"]
    tools = x["tools"]
    n = x["tool_count"]
    cost = x["cost_index_tokens"]
    write_c, exfil_c = ts["write_count"], ts["exfil_count"]
    has_risk = write_c > 0 or exfil_c > 0
    heavy = cost >= HEAVY_TOKENS
    # These three now come from the narrative's `state`, which build_narrative derived once. Deriving
    # them again here is exactly how the two renderers drifted apart in the first place.
    # THE prose comes from the label, not from here. This function decides layout only — see
    # build_narrative. A label from an older engine has no narrative, so compute it rather than
    # render an empty report.
    nar = x.get("narrative") or build_narrative(label)
    concerns = [(c["title"], c["body"]) for c in nar["concerns"]]
    verdict = nar["verdict"]
    failed = nar["state"] in ("unreachable", "auth-required")
    has_dispatch = nar["dispatch"]

    lines = [f"● {label['name']}   [{label['transport']}]   {verdict}"]

    if failed:
        detail = nar["failure"]["detail"]
        lines.append(f"    ✗ could not scan — {detail}. This did NOT pass; it was not measured.")
        # The next-step hint must match the KIND of failure. Telling someone whose endpoint answered
        # 401 that "a docs URL is not an MCP endpoint" sends them to debug a URL that was right.
        if x.get("error_kind") == "auth-required":
            lines.append("      The endpoint is real — it needs credentials, not a different URL.")
        else:
            lines.append("      Is it a live MCP endpoint? A docs / repo / package URL is not one.")
            lines.append("      A local server needs:  mcpgawk scan --stdio \"<launch command>\"")
        return "\n".join(lines)

    if has_dispatch:
        # Prominent, right under the verdict — a dispatcher hides its real catalog behind a meta-tool,
        # so this passive scan is INCOMPLETE by construction. Say so plainly in both the clean and the
        # risk case; the hidden tools are enumerable only at runtime (verify). Never a silent clean.
        lines.append(f"    ⚠ dynamic dispatch — {n} tools visible, but the real catalog is larger and NOT")
        lines.append("      statically analysable. This scan is INCOMPLETE; a clean result is not proof of a")
        lines.append("      clean server. Any permission allowlist keyed on tool NAMES (the common MCP auth")
        lines.append("      pattern) fails OPEN on these hidden tools. Enumerate them at runtime:  gawk verify")

    if not has_risk and not heavy:
        suffix = " among the visible tools" if has_dispatch else ""
        lines.append(f"    {n} tool{'s' if n != 1 else ''} · {cost:,} tokens at connect · nothing write- or exfil-capable{suffix}.")
    else:
        # ── The narrative: what this server IS, what to look at first, what to do. ──────────────
        lines.append("")
        lines += _wrap(nar["cost_sentence"], "    ")

        for i, (title, body) in enumerate(concerns):
            lines += ["", f"    ▸ {'Look at this first' if i == 0 else 'Also true'}"]
            lines += _wrap(title + ".", "      ")
            for b in body:
                lines += _wrap(b, "      ")

        # Supporting evidence sits directly under the concern it supports, before the advice —
        # claim, then proof, then what to do.
        if not verbose and has_risk:
            lines += _flagged_table(tools, n)

        actions = nar["actions"]
        if actions:
            lines += ["", "    Worth doing"]
            for i, a in enumerate(actions, 1):
                wrapped = _wrap(f"{i}. {a}", "      ")
                lines += [wrapped[0]] + [f"   {w}" for w in wrapped[1:]]

        # The reassurance is HEDGED and conditional, always. We only ever looked at the tools the
        # server chose to show us, and we only pattern-match — so this may never read as a clean
        # bill of health, and it disappears entirely if anything was actually found.
        if nar["reassurance"]:
            lines.append("")
            lines += _wrap(nar["reassurance"], "    ")

    # Tool detail: verbose shows every tool; default surfaces only the ones that can bite,
    # scariest first (can both change data AND send it out), capped.
    if verbose:
        lines.append("    all tools (heaviest first):")
        for t in sorted(tools, key=lambda t: -t["tokens"]):
            tags = [c for c, on in (("write", t["write"]), ("exfil", t["exfil_capable"]),
                                    ("no-annotation", not (t.get("annotations") or {}))) if on]
            lines.append(f"      · {t['name']:<32} {t['tokens']:>5} tok   {', '.join(tags) or 'read-only'}")

    # Bounded heuristic signals — one actionable line each. Each KIND is a DISTINCT finding and must
    # be named as itself: filing dynamic-dispatch, tool-shadowing and server-card-mismatch under
    # "possible prompt-injection" (the old bug) is precisely the kind of report deviation that erodes
    # trust in a security tool. Lead phrase is chosen from the kind's family prefix.
    for s in (x.get("bounded_signals") or []):
        kind = s.get("kind", "")
        family = kind.split(":", 1)[0]
        lead = _SIGNAL_LEAD_BY_KIND.get(kind) or _SIGNAL_LEAD.get(family, "review signal in")
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


def render_summary(labels: list[dict[str, Any]], local_servers: int = 0) -> str:
    tools = sum(l["x-mcpgawk"]["tool_count"] for l in labels)
    toks = sum(l["x-mcpgawk"]["cost_index_tokens"] for l in labels)
    flagged = sum(1 for l in labels for t in l["x-mcpgawk"]["tools"] if t["write"] or t["exfil_capable"])
    exfil = sum(1 for l in labels for t in l["x-mcpgawk"]["tools"] if t["exfil_capable"])
    ns = len(labels)
    out = ("─" * 64 + f"\n{ns} server{'s' if ns != 1 else ''} · {tools} tools · "
           f"{toks:,} tokens loaded into every session · {flagged} can change or send data.\n"
           "Scanned locally — nothing left your machine.")
    # What those local servers inherit but no config declares. Only ever printed when there is both
    # something to inherit and something to inherit it — see ambient.summarize.
    ambient_lines = summarize(detect_ambient(), local_servers, exfil)
    if ambient_lines:
        out += "\n\n" + "\n".join(ambient_lines)
    return out
