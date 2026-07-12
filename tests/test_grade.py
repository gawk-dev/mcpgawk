"""Grade is a transparent CRAFT composite (cost + hygiene), never a capability penalty."""
from __future__ import annotations

from mcpgawk.grade import grade
from mcpgawk.measure import Measurement, ToolMeasure


def _server(n_tools, total_tokens, annotated_frac, write_frac=0.0):
    tools = []
    for i in range(n_tools):
        ann = {}
        if i < round(n_tools * annotated_frac):
            ann = {"readOnlyHint": True}
        tools.append(ToolMeasure(name=f"t{i}", tokens=total_tokens // max(n_tools, 1),
                                 write=(i < round(n_tools * write_frac)), exfil_capable=False, annotations=ann))
    return Measurement(tokenizer="cl100k_base", total_tokens=total_tokens, tool_count=n_tools,
                       tools=tools, integrity_pin="x")


def test_lean_and_annotated_scores_high():
    g = grade(_server(8, 2472, 1.0))          # lean: 309 tok/tool, 100% annotated
    assert g.letter in ("A", "B") and g.hygiene_score == 100


def test_heavy_and_unannotated_fails():
    g = grade(_server(20, 23085, 0.0))         # heavy: 1154 tok/tool, 0% annotated
    assert g.letter == "F" and g.hygiene_score == 0 and g.cost_score < 30


def test_lean_but_unannotated_is_middling_not_top():
    g = grade(_server(8, 816, 0.0))            # Slack-ref-shape: lean (102/tool) but opaque
    assert g.cost_score >= 90 and g.hygiene_score == 0 and g.letter in ("C", "D")


def test_capability_is_not_penalised():
    # Same cost + hygiene, wildly different write surface -> identical grade.
    a = grade(_server(10, 3000, 0.8, write_frac=0.0))
    b = grade(_server(10, 3000, 0.8, write_frac=0.9))
    assert a.score == b.score and a.letter == b.letter


def test_fixes_are_actionable_and_only_when_needed():
    good = grade(_server(8, 1200, 1.0))        # lean + fully annotated -> no fixes
    assert good.fixes == []
    bad = grade(_server(30, 20000, 0.0))       # heavy + unannotated -> both fixes
    assert any("read/write intent" in f for f in bad.fixes)
    assert any("heaviest schemas" in f for f in bad.fixes)
