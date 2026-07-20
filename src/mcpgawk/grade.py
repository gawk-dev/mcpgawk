"""A transparent CRAFT grade for an MCP server.

Design (accuracy-critical, see docs/adoption-research-report-design.md):
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
    # Tools that can change data, take real parameters, and describe themselves in almost nothing.
    # Reported, never scored: adding it to the score would silently move every existing grade, and
    # a letter that changes because we improved our own analysis is indistinguishable from a server
    # that got worse — which is the one thing drift detection must never confuse.
    underdocumented: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)


def _cost_score(tpt: int) -> int:
    """tokens/tool -> 0-100. Piecewise-linear bands fit to the roster
    (Cloudflare 155≈A, Emergent 309≈B, Sarvam 358≈C, Firecrawl 740/Notion 1154≈F)."""
    if tpt <= 200:      s = 100 - (tpt - 100) * 0.10          # 100->100, 200->90
    elif tpt <= 350:    s = 90 - (tpt - 200) * (15 / 150)     # 200->90, 350->75
    elif tpt <= 550:    s = 75 - (tpt - 350) * (20 / 200)     # 350->75, 550->55
    else:               s = 55 - (tpt - 550) * (55 / 650)     # 550->55, 1200->~0
    return max(0, min(100, round(s)))


def _letter(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F"


#: Plain-English cost comparison for the narrative report. Derived from the SAME band function the
#: letter grade uses, so the sentence a user reads can never disagree with the grade — and there is
#: one place to change if the roster is refitted. "12,287 tokens" is meaningless on its own; whether
#: that is lean or extravagant for a server this size is the part that carries information.
_COST_PHRASE = {
    "A": "lean for a server this size",
    "B": "reasonable for a server this size",
    "C": "mid-range for a server this size",
    "D": "expensive for what it does",
    "F": "very expensive — among the heaviest we've measured",
}


def cost_phrase(tokens_per_tool: int) -> str:
    return _COST_PHRASE[_letter(_cost_score(tokens_per_tool))]


def _is_annotated(ann: dict) -> bool:
    # "annotated" = the tool declares its read/write intent (the trust-relevant hints).
    return bool(ann) and ("readOnlyHint" in ann or "destructiveHint" in ann)


#: A tool must take at least this many parameters before thin prose is worth raising — a
#: two-argument write needs little explaining, and flagging it would be noise.
_DOC_MIN_PARAMS = 4


def _is_underdocumented(t) -> bool:
    """Can it change data, does it take real arguments, and is it described in almost nothing?

    NOT a security signal — a terse tool is not an attack, and putting this in signals.py would have
    broken that module's 0-FP wall by mixing a judgement about prose into a layer that only fires on
    language aimed at the model. It is hygiene, next to "does this tool declare its intent".

    Found by comparing this scanner against a general-purpose agent (2026-07-21), on a real
    brokerage server: an order-placement tool — an irreversible real-money trade taking twelve
    parameters — documented in three words. An agent choosing that tool has nothing to go on,
    precisely where being wrong costs the most.
    """
    ann = t.annotations or {}
    if ann.get("readOnlyHint") is True:
        return False
    if not t.write:
        return False
    if t.param_count < _DOC_MIN_PARAMS:
        return False
    return t.description_words * 2 <= t.param_count


def grade(m: Measurement) -> Grade:
    total = m.tool_count
    tpt = round(m.total_tokens / total) if total else 0
    cost = _cost_score(tpt) if total else 100
    annotated = sum(1 for t in m.tools if _is_annotated(t.annotations or {}))
    hygiene = round(100 * annotated / total) if total else 100
    overall = round(W_COST * cost + W_HYGIENE * hygiene)
    letter = _letter(overall)

    underdocumented = [t.name for t in m.tools if _is_underdocumented(t)]

    fixes: list[str] = []
    if underdocumented:
        shown = ", ".join(underdocumented[:3]) + ("…" if len(underdocumented) > 3 else "")
        fixes.append(f"Describe what {shown} actually does — {'it' if len(underdocumented) == 1 else 'they'} "
                     f"can change data and take several arguments, but say almost nothing about it. "
                     f"An agent picks tools by reading this.")
    if total and hygiene < 90:
        missing = total - annotated
        fixes.append(f"Declare read/write intent on {missing} tool(s) "
                     f"(readOnlyHint / destructiveHint) — one line each, hygiene {hygiene}% → up.")
    if total and cost < 75:
        heavy = sorted(m.tools, key=lambda t: t.tokens, reverse=True)[:3]
        names = ", ".join(f"{t.name} ({t.tokens} tok)" for t in heavy)
        fixes.append(f"Trim the heaviest schemas ({names}) — they drive the {tpt} tok/tool cost.")

    return Grade(letter=letter, score=overall, cost_score=cost, hygiene_score=hygiene,
                 tokens_per_tool=tpt, annotated=annotated, total=total,
                 underdocumented=underdocumented, fixes=fixes)
