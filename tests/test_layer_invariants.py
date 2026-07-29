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
    # "obfuscation" added 2026-07-21, deliberately: invisible Unicode in a tool DESCRIPTION is
    # model-facing language, not a capability fact — the model reads the hidden characters and a
    # human reviewer cannot. It is kept a separate family from "injection" (matching Invariant's own
    # split, W021 vs E001) because hiding text and instructing the model are different findings: the
    # concealment is evidence of intent regardless of what is concealed, and the instruction it hides
    # is reported by its own detector.
    # "skill" added 2026-07-27, deliberately: a SKILL.md tree is model-facing language in its
    # purest form — the entire artefact is text loaded into the agent's context, and every skill:*
    # detector fires on language IN that text (a URL the text sends the agent to, an instruction
    # to emit credentials, a fetch-and-execute command, a secret pasted into the prose, or text
    # structured so its stated identity cannot be reviewed). None of them keys on what a tool CAN
    # DO — there are no tools; there is only language. Capability-flavoured skill checks
    # (financial execution, system-service modification — Invariant's W009/W013) are exactly why
    # this family is signal-grade-only: those need semantics, and skills.py declares them
    # not-checked rather than faking them here.
    allowed_families = {"injection", "dispatch", "shadowing", "servercard", "obfuscation", "skill"}
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


# --------------------------------------------------------------------- the history store's walls


def _free_and_paid_modules():
    """Every production module in both packages, parsed from source (not imported): AST-level
    invariants must hold for modules this suite never happens to import."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src"
    for pkg in ("mcpgawk", "gawk_platform"):
        yield from sorted((src / pkg).rglob("*.py"))


def test_only_history_py_derives_the_history_store_path():
    """`history.json` has ONE owner. This repo carried five readers of the store and was bitten by
    the drift between them (BUILD_PLAN task 4); after the collapse, only `history.py` may derive
    the store's path in code. `guard_hook.py` is the single pinned exception: it names the path to
    STAT it for projection freshness and to locate the sibling projection — the companion test
    below proves it never opens the store itself. Prose (docstrings, help text with spaces) is
    exempt; a path-shaped constant is not.
    """
    import ast

    offenders = []
    for path in _free_and_paid_modules():
        if path.name in ("history.py", "guard_hook.py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            s = node.value
            if ("history.json" in s and " " not in s) or s == "MCPGAWK_HISTORY":
                offenders.append(f"{path.name}:{node.lineno}: {s!r}")
    assert not offenders, (
        "these modules derive the history store's path themselves instead of going through "
        f"history.py/baseline.py — the five-readers drift class returning: {offenders}"
    )


def test_guard_hook_stats_the_history_store_but_never_opens_it():
    """The hook's freshness check may `os.stat` the store; it must never read or parse it — the
    projection generated by `history.save` is the only thing the hot path may enforce from. This
    is the AST pin for BUILD_PLAN task 3's 'retires the private re-read'."""
    import ast
    from pathlib import Path

    hook = Path(__file__).resolve().parents[1] / "src" / "mcpgawk" / "guard_hook.py"
    source = hook.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        is_open = isinstance(f, ast.Name) and f.id == "open"
        is_read = isinstance(f, ast.Attribute) and f.attr in ("read_text", "read_bytes", "load")
        if not (is_open or is_read):
            continue
        segment = (ast.get_source_segment(source, node) or "").lower()
        for marker in ("store", "history"):
            assert marker not in segment, (
                f"guard_hook.py:{node.lineno} looks like a direct read of the history store "
                f"({segment!r}) — the hook must consume the projection, never the store."
            )


# ------------------------------------------------------------------- the free/paid import wall


def _top_level_statements(tree):
    """Statements that execute at IMPORT time: module body, descending into top-level if/try/with
    and class bodies — but never into function bodies, which run only when called."""
    import ast

    stack = list(tree.body)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                stack.append(child)


def test_no_free_module_imports_the_paid_layer_at_top_level():
    """Package-wide, not per-module: a free install has no `gawk_platform` on disk (the wheel gate
    proves the artefact), so ANY top-level import of it in `mcpgawk/` breaks every free user at
    import time — and quietly couples the free engine to the paid one. `redact.py` and `runlog.py`
    have cited this test for weeks; now it exists.

    Mutation check (standing rule): add `import gawk_platform` to the top of spool.py → red here;
    revert → green. Verified 2026-07-28."""
    import ast
    from pathlib import Path

    free = Path(__file__).resolve().parents[1] / "src" / "mcpgawk"
    offenders = []
    for path in sorted(free.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in _top_level_statements(tree):
            roots = []
            if isinstance(node, ast.Import):
                roots = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                roots = [(node.module or "").split(".")[0]]
            if "gawk_platform" in roots:
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, (
        f"free modules import the paid layer at import time: {offenders} — a free install "
        f"(no gawk_platform on disk) would crash on import."
    )


def test_the_paid_imports_in_cli_stay_function_local():
    """cli.py is the deliberate seam: the licence gate hands over to `gawk_platform.cli` INSIDE
    the gated functions, so the import only happens once a paid capability is actually invoked.
    Pin that every gawk_platform import in cli.py sits inside a function, and that the two known
    hand-over points are still there — a new one appearing is a review event, not an error."""
    import ast
    from pathlib import Path

    cli = Path(__file__).resolve().parents[1] / "src" / "mcpgawk" / "cli.py"
    tree = ast.parse(cli.read_text(encoding="utf-8"))

    def _paid_imports(node):
        for n in ast.walk(node):
            if isinstance(n, ast.Import) and any(
                    a.name.split(".")[0] == "gawk_platform" for a in n.names):
                yield n
            elif isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "gawk_platform":
                yield n

    all_paid = list(_paid_imports(tree))
    in_functions = [n for f in ast.walk(tree)
                    if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                    for n in _paid_imports(f)]
    top_level = {n.lineno for n in all_paid} - {n.lineno for n in in_functions}
    assert not top_level, f"cli.py imports gawk_platform at module level (lines {sorted(top_level)})"
    imported = {getattr(a, "name", None) for n in in_functions for a in n.names}
    assert {"run_account", "run_pillar"} <= imported, (
        "the two deliberate licence-gate hand-overs (run_account, run_pillar) moved or vanished — "
        "re-read the gate before trusting this wall."
    )
