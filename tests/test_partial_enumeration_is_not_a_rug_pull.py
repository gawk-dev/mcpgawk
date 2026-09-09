"""A baseline nobody enumerated a kind on must not accuse the server of adding it.

WHY THIS FILE EXISTS. On 2026-09-09 a baseline was written by a client that called `tools/list`
and nothing else. It carried a MODERN `items` map with 70 `tool.*` keys and no `resource.*` keys —
which, to every reader, looked exactly like a server that exposes no resources. The next client
enumerated resources, `resource.dadan-video-card` appeared, and the decide screen announced it as
"did not exist when you approved this server": a rug-pull accusation against a server that had not
changed, aimed at the one reviewer who could disprove it on sight.

The root cause was a swallowed exception in `probe`: `resources/list` failing and `resources/list`
returning nothing produced the identical snapshot. The fix records which kinds were actually
enumerated, and `drift.comparable_kinds` is the ONE place that decides what may be diffed.
"""
from __future__ import annotations

from mcpgawk import drift, history


def _rec(items, *, enumerated=None, cost=100):
    r = {"items": dict(items), "cost_index": cost, "tokenizer": "cl100k",
         "measured_at": "2026-09-09T08:00:00Z", "pin": "p1", "pin_basis": drift.PIN_BASIS}
    if enumerated is not None:
        r["enumerated"] = list(enumerated)
    return r


def test_a_kind_the_baseline_never_enumerated_is_not_reported_as_added():
    """THE REPRODUCTION, with the real shape: tools-only baseline, resource appears next scan."""
    prev = _rec({"tool.a": "h1"}, enumerated=["tool"])   # what `wrap` now records: tools only
    curr = _rec({"tool.a": "h1", "resource.card": "h9"}, enumerated=["tool", "resource"])
    rep = drift.compare(prev, curr)
    assert rep.added == [], rep.added
    assert rep.baseline_extended is True, "the user must be told the kind's baseline starts now"


def test_a_server_that_really_did_enumerate_resources_still_reports_a_new_one():
    """NARROWNESS — the half that must not be lost. If the baseline PROVES it asked for resources
    and found none, a resource appearing afterwards is real drift and must still be reported."""
    prev = _rec({"tool.a": "h1"}, enumerated=["tool", "resource"])
    curr = _rec({"tool.a": "h1", "resource.card": "h9"}, enumerated=["tool", "resource"])
    rep = drift.compare(prev, curr)
    assert rep.added == ["resource.card"], rep.added
    assert rep.baseline_extended is False


def test_a_tool_is_always_comparable_even_with_no_enumerated_field():
    """`tools/list` is load-bearing in probe — a record exists only if it succeeded — so the
    fallback must never suppress a real tool addition, which is the whole product."""
    prev = _rec({"tool.a": "h1"})
    curr = _rec({"tool.a": "h1", "tool.exfiltrate": "h2"})
    rep = drift.compare(prev, curr)
    assert rep.added == ["tool.exfiltrate"]


def test_an_incomparable_kind_is_not_reported_as_removed_either():
    """Both directions. Filtering only the current side would turn the same unknown into a
    'removed' accusation the moment the enumerating client stopped asking."""
    prev = _rec({"tool.a": "h1", "resource.card": "h9"}, enumerated=["tool", "resource"])
    curr = _rec({"tool.a": "h1"}, enumerated=["tool"])
    rep = drift.compare(prev, curr)
    assert rep.removed == [], rep.removed


def test_the_decision_queue_does_not_hold_a_server_on_a_kind_it_cannot_diff():
    """`history.pending` ran its OWN comparison over the whole `items` map, so it queued a server
    that `drift.compare` then found nothing in — blocked, with an empty diff. One rule, imported."""
    store = {"servers": {"mcp:x": {
        "approved": _rec({"tool.a": "h1"}, enumerated=["tool"]),
        "history": [_rec({"tool.a": "h1", "resource.card": "h9"},
                         enumerated=["tool", "resource"])]}}}
    assert history.pending(store) == []


def test_the_queue_still_holds_a_server_whose_tools_really_changed():
    store = {"servers": {"mcp:x": {
        "approved": _rec({"tool.a": "h1"}),
        "history": [_rec({"tool.a": "h1", "tool.new": "h2"})]}}}
    assert history.pending(store) == ["mcp:x"]


def test_the_keyed_side_maps_are_filtered_by_the_same_rule():
    """`annotations`/`props`/`schemas` are keyed `{kind}.{name}` too. Filtering only `items` left
    the server queued on those instead — the same false block by another door."""
    prev = dict(_rec({"tool.a": "h1"}, enumerated=["tool"]), annotations={"tool.a": {}})
    curr = dict(_rec({"tool.a": "h1", "resource.card": "h9"}, enumerated=["tool", "resource"]),
                annotations={"tool.a": {}, "resource.card": {}})
    store = {"servers": {"mcp:x": {"approved": prev, "history": [curr]}}}
    assert history.pending(store) == []


# ---- the decide screen's own words -------------------------------------------------------------

def test_the_screen_does_not_claim_an_approval_that_never_happened():
    """`history.approved()` falls back to the OLDEST SIGHTING when a server was never approved —
    deliberately, so a diff has an anchor. The headline then asserted "changed since you approved
    it" about a server nobody had approved (dadan: `approved_at` was None on the same screen)."""
    from mcpgawk import panel
    store = {"mcp:x": {"aliases": ["x"],
                       "approved": {"items": {"tool.a": "h1"}, "measured_at": "2026-09-01T00:00:00Z",
                                    "pin": "p", "cost_index": 1},
                       "history": [{"items": {"tool.a": "h1", "tool.b": "h2"}, "seen": "2026-09-09T00:00:00Z",
                                    "measured_at": "2026-09-09T00:00:00Z", "pin": "p", "cost_index": 2}]}}
    html = panel.render_next({"store": {"servers": store}, "entries": {}, "monitor": {},
                              "verify_at": ""}, token="T")
    assert "nobody has approved this server yet" in html, html[:400]
    assert "changed since you approved it" not in html


def test_the_screen_names_the_kind_that_changed_not_always_tools():
    """The sub-line hardcoded "the tools it declares", so a resource change was announced as a
    tool change. Uses a baseline that DID enumerate resources, so the change is real drift."""
    from mcpgawk import panel
    base = {"items": {"tool.a": "h1"}, "enumerated": ["tool", "resource"],
            "measured_at": "2026-09-01T00:00:00Z", "pin": "p", "cost_index": 1}
    curr = {"items": {"tool.a": "h1", "resource.card": "h9"}, "enumerated": ["tool", "resource"],
            "seen": "2026-09-09T00:00:00Z", "measured_at": "2026-09-09T00:00:00Z",
            "pin": "p", "cost_index": 2}
    store = {"mcp:x": {"aliases": ["x"], "approved_at": "2026-09-01T10:00:00Z",
                       "approved": base, "history": [curr]}}
    html = panel.render_next({"store": {"servers": store}, "entries": {}, "monitor": {},
                              "verify_at": ""}, token="T")
    assert "change to the resources it declares" in html, html[:500]
    assert "to the tools it declares" not in html


# ---- the WRITE side: gate the record, not just the comparison ----------------------------------

def test_probe_records_which_kinds_it_actually_enumerated():
    """GATE THE WRITE. The compare-side fix rescues baselines that already exist; this stops new
    partial ones being written as though they were complete. A `resources/list` that FAILS must
    leave "resource" out of `enumerated` — previously the exception was swallowed and the empty
    list was indistinguishable from a server that has no resources.
    """
    import asyncio
    from mcpgawk import probe

    class _Res:
        def __init__(self, **kw): self.__dict__.update(kw)

    class _Session:
        async def initialize(self):
            return _Res(protocol_version="2025-06-18", server_info=None,
                        capabilities={"resources": {}, "tools": {"listChanged": True}})
        async def list_tools(self):  return _Res(tools=[])
        async def list_prompts(self): return _Res(prompts=[])
        async def list_resources(self): raise RuntimeError("boom")

    snap = asyncio.run(probe._snapshot(_Session(), "x", "http"))
    assert "tool" in snap.enumerated and "prompt" in snap.enumerated
    assert "resource" not in snap.enumerated, \
        "a failed resources/list must not be recorded as 'asked, none there'"
    assert snap.resources == [], "it still degrades — an optional surface never fails a scan"
    assert snap.capabilities.get("resources") == {}, \
        "the server's own declaration is kept: it is the evidence the record could not gather"
