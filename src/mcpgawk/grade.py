"""A transparent CRAFT grade for an MCP server.

Design (accuracy-critical):
- The grade composes ONLY axes a server can improve without losing function:
  cost efficiency (tokens/tool) and annotation hygiene (declared read/write intent).
- Capability (write/exfil) is a FACT, never graded — a server needs its tools.
- Bounded signals are NEVER in the grade — they stay flags for human review.
- Bands are empirical (from the real roster), so the rubric is reproducible.
- A grade means "well-crafted" (lean, honest), NOT "safe". State that everywhere.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .measure import Measurement

DISCLAIMER = ("Grade = craft (lean + honest), not a safety verdict. A server can be "
              "well-crafted and still do something you don't want. Signals are pointers, not part of the grade.")

# Documented weights (published rubric — tunable, but transparent).
W_COST, W_HYGIENE = 0.5, 0.5


@dataclass
class Grade:
    letter: str
    score: int
    cost_score: int          # 0-100, from tokens/tool
    hygiene_score: int        # 0-100, annotated / total
    tokens_per_tool: int
    annotated: int
    total: int
    fixes: list[str] = field(default_factory=list)


def _cost_score(tpt: int) -> int:
    """tokens/tool -> 0-100. Piecewise-linear bands fit to a sample of real-world MCP servers
    scanned during development (anonymised — see the bands below, not named vendors)."""
    if tpt <= 200:      s = 100 - (tpt - 100) * 0.10          # 100->100, 200->90
    elif tpt <= 350:    s = 90 - (tpt - 200) * (15 / 150)     # 200->90, 350->75
    elif tpt <= 550:    s = 75 - (tpt - 350) * (20 / 200)     # 350->75, 550->55
    else:               s = 55 - (tpt - 550) * (55 / 650)     # 550->55, 1200->~0
    return max(0, min(100, round(s)))


def _letter(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F"


def _is_annotated(ann: dict) -> bool:
    # "annotated" = the tool declares its read/write intent (the trust-relevant hints).
    return bool(ann) and ("readOnlyHint" in ann or "destructiveHint" in ann)


def grade(m: Measurement) -> Grade:
    total = m.tool_count
    tpt = round(m.total_tokens / total) if total else 0
    cost = _cost_score(tpt) if total else 100
    annotated = sum(1 for t in m.tools if _is_annotated(t.annotations or {}))
    hygiene = round(100 * annotated / total) if total else 100
    overall = round(W_COST * cost + W_HYGIENE * hygiene)
    letter = _letter(overall)

    fixes: list[str] = []
    if total and hygiene < 90:
        missing = total - annotated
        fixes.append(f"Declare read/write intent on {missing} tool(s) "
                     f"(readOnlyHint / destructiveHint) — one line each, hygiene {hygiene}% → up.")
    if total and cost < 75:
        heavy = sorted(m.tools, key=lambda t: t.tokens, reverse=True)[:3]
        names = ", ".join(f"{t.name} ({t.tokens} tok)" for t in heavy)
        fixes.append(f"Trim the heaviest schemas ({names}) — they drive the {tpt} tok/tool cost.")

    return Grade(letter=letter, score=overall, cost_score=cost, hygiene_score=hygiene,
                 tokens_per_tool=tpt, annotated=annotated, total=total, fixes=fixes)
