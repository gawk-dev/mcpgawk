"""The walls between layers, enforced by CI instead of by docstring.

Written 2026-07-21 after a real violation: a "thin description for blast radius" detector was added
to signals.py, where it did not belong. signals.py fires only on language aimed at the model and
holds a 0-false-positive wall; that detector keyed on CAPABILITY (is this a write? how many
parameters?) and on a judgement about prose. A terse tool is badly documented, not an attack, and
shipping it as a bounded signal would have inflated the meaning of every real signal beside it.

Nothing caught it. The signals canary checks that a registered kind has a fixture and a label lead
— that the detector is WIRED UP — but never that it BELONGS. The reviewer caught it, which is not a
mechanism. These tests are the mechanism.

Read this file as: what must remain true no matter who is editing, at 2am, mid-session.
"""
from __future__ import annotations

import inspect
import re

from mcpgawk import grade as grade_mod
from mcpgawk import measure as measure_mod
from mcpgawk import signals as signals_mod

#: Names that belong to the measurement/capability side. Their appearance in signals.py means a
#: fact has leaked into the heuristic layer, or a heuristic has started reading facts.
_MEASUREMENT_NAMES = [
    "ToolMeasure", "Measurement", "param_count", "description_words",
    "_is_write", "_exfil_capable", "total_tokens", "cost_index", "tokens_per_tool",
]


def _source(mod) -> str:
    return inspect.getsource(mod)


def test_signals_never_imports_the_measurement_layer():
    """An estimate must never be able to contaminate a fact, which is why these are separate
    modules at all. A local import inside a function counts — that is how the violation got in."""
    src = _source(signals_mod)
    assert not re.search(r"^\s*from\s+\.measure\s+import", src, re.M), \
        "signals.py imported measure — the heuristic layer is reading facts"
    assert not re.search(r"^\s*(from|import)\s+.*\bmeasure\b", src, re.M), \
        "signals.py imported measure (module-level or local) — the wall is breached"


def test_measure_never_imports_the_signals_layer():
    src = _source(measure_mod)
    assert not re.search(r"^\s*(from|import)\s+.*\bsignals\b", src, re.M), \
        "measure.py imported signals — a fact is now derived from a heuristic"


def test_signals_does_not_reason_about_capability_or_cost():
    src = _source(signals_mod)
    leaked = [n for n in _MEASUREMENT_NAMES if n in src]
    assert not leaked, (
        f"signals.py references measurement concepts {leaked}. A detector that keys on what a tool "
        f"CAN DO is not a signal about language — it belongs in measure.py (as a fact) or grade.py "
        f"(as hygiene). This is the exact mistake made on 2026-07-21."
    )


def test_every_registered_signal_kind_is_about_language_not_capability():
    """The families this layer is allowed to have. Adding one is a deliberate act: if a new family
    is not about text aimed at the model, it is in the wrong module, and this test is where you find
    that out rather than after it ships in a report."""
    allowed_families = {"injection", "dispatch", "shadowing", "servercard"}
    families = {k.split(":", 1)[0] for k in signals_mod.SIGNAL_KINDS}
    unexpected = families - allowed_families
    assert not unexpected, (
        f"new signal families {sorted(unexpected)} — if these describe capability or documentation "
        f"quality rather than model-facing language, move them out of signals.py and widen this set "
        f"only for genuine language detectors."
    )


def test_hygiene_judgements_live_in_grade_and_do_not_move_the_score():
    """grade.py may JUDGE — that is its job — but the score must stay a function of cost and hygiene
    alone. A letter that moves because we improved our own analysis is indistinguishable from a
    server that got worse, and drift detection cannot survive that ambiguity."""
    src = _source(grade_mod)
    assert "_is_underdocumented" in src, "the documentation judgement should live in grade.py"
    body = src[src.index("def grade("):]
    scoring_line = next(ln for ln in body.splitlines() if "overall = " in ln)
    assert "underdocumented" not in scoring_line, \
        "the score consulted `underdocumented` — every existing grade would silently shift"
