"""The wrap baseline claimed to speak for kinds it never asked about.

WHY THIS FILE EXISTS. 0.1.40 fixed the partial-enumeration false rug-pull at the comparison:
`drift.comparable_kinds` restricts a diff to the kinds BOTH records actually enumerated. The fix
was verified against records written by `scan` and called done. It was not done.

`wrap._snapshot` builds a ServerSnapshot from what the wire said and never sets `enumerated`, so
every wrap baseline stores an EMPTY list. Empty is deliberately read as "no recorded fact, so do
not restrict" — the right reading for records written before the field existed, and exactly the
wrong one here, because wrap knows precisely what it saw: one `tools/list` and nothing else.

The result, reproduced on a live server the day after the first fix shipped: `wrap` recorded the
baseline, the very next scan enumerated resources as well, and the report said the server had
"changed since you approved it just now — resources added". Nothing on the server had moved. That
is a false rug-pull alarm on a first-party surface, and it is the eleventh instance of a rule
written in one file not being a rule: the comparison learned the rule, the second writer did not.

So this test drives `record_baseline` — the real writer — not `comparable_kinds`.
"""
from __future__ import annotations

from mcpgawk import drift
from mcpgawk.probe import ServerSnapshot

TOOL = {"name": "send", "description": "Send a thing.", "inputSchema": {"type": "object"}}


def _wrap_record():
    """What wrap stores, built through wrap's own snapshot so a change there is caught here."""
    from mcpgawk.measure import measure
    from mcpgawk.wrap import Session, _snapshot

    s = Session("dadan")
    s.tools = [TOOL]
    s.protocol_version = "2025-06-18"
    sn = _snapshot(s)
    return sn, drift.build_record(sn, measure(sn), measured_at="2026-09-10T00:00:00+00:00")


def test_the_wrap_baseline_records_that_it_only_saw_tools():
    sn, rec = _wrap_record()
    assert sn.enumerated == ["tool"], "wrap saw one tools/list; the record must say so"
    assert rec["enumerated"] == ["tool"]


def test_a_resource_the_wrap_baseline_never_asked_about_is_not_a_rug_pull():
    """THE REPRODUCTION. wrap first, then a full scan that also lists resources."""
    from mcpgawk.measure import measure

    _, prev = _wrap_record()
    full = ServerSnapshot(name="dadan", transport="stdio", protocol_version="2025-06-18",
                          tools=[TOOL], resources=[{"uri": "dadan-video-card", "name": "card"}])
    full.enumerated = ["tool", "resource"]
    curr = drift.build_record(full, measure(full), measured_at="2026-09-10T00:01:00+00:00")

    kinds = drift.comparable_kinds(prev, curr)
    assert kinds == {"tool"}, kinds

    d = drift.compare(prev, curr)
    added = [a for a in ((d.added if d else []) or []) if "dadan-video-card" in str(a)]
    assert not added, f"a first sighting is not an addition: {d.added}"


def test_a_tool_really_added_after_a_wrap_baseline_is_still_reported():
    """NARROWNESS. Restricting to `tool` must not blunt the surface wrap DID enumerate."""
    from mcpgawk.measure import measure

    _, prev = _wrap_record()
    worse = ServerSnapshot(name="dadan", transport="stdio", protocol_version="2025-06-18",
                           tools=[TOOL, {"name": "exfiltrate", "description": "New.",
                                         "inputSchema": {"type": "object"}}])
    worse.enumerated = ["tool"]
    curr = drift.build_record(worse, measure(worse), measured_at="2026-09-10T00:01:00+00:00")
    d = drift.compare(prev, curr)
    assert d is not None and any("exfiltrate" in str(a) for a in (d.added or [])), d
