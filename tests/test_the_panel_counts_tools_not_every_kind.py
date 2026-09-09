"""The panel called a resource a tool, and said so in six places at once.

WHY THIS FILE EXISTS. The measured store keys every item by kind — `tool.send`,
`prompt.summarise`, `resource.card`. `panel.server_detail` built `approved_tools` and
`current_tools` from `sorted(items)`, so both lists held EVERY kind while their names, and every
consumer, said "tools": the Servers table, the coverage bars, the "Tools now"/"Approved" stats,
the CSV `tools` column and the JSON `tools` field.

Found by the browser walk on 2026-09-10, on a live third-party server: the panel rendered
`0 of 71 exposed tools watched` while the SAME scan's footer said `70 tools, 0 prompts,
1 resources`. Two surfaces of one product disagreeing about one server, in front of the reviewer
who wrote it. Twelfth instance of "a rule in one file is not a rule", in its naming form — the
field was named for one kind and filled with all of them.

The quieter half is `declared_vs_observed`, which is not a count at all: it joins these keys
against the behaviour profile's wire names, so a resource arrived as a phantom row in a per-TOOL
table. Nobody would have noticed that from a screenshot.

So this test drives `panel.render` and `panel.state` — the surfaces a person and an agent
actually read — never `server_detail`'s dict alone. And it pins the other direction too:
filtering these lists must NOT narrow drift, because `history.pending` is what decides a server
"changed" and it reads the store's `items` map itself.
"""
from __future__ import annotations

import json
import re

from mcpgawk import panel

#: Two tools, one prompt, one resource. A store record's `items` values are opaque hashes.
_ITEMS = {
    "tool.send": "aaaa00000001",
    "tool.fetch": "aaaa00000002",
    "prompt.summarise": "bbbb00000001",
    "resource.card": "cccc00000001",
}
TOOL_COUNT = 2
KIND_COUNT = len(_ITEMS)


def _record(items: dict[str, str]) -> dict:
    return {
        "items": dict(items),
        "enumerated": ["tool", "prompt", "resource"],
        "texts": {}, "annotations": {}, "schemas": {},
        "transport": "stdio", "protocol_version": "2025-06-18",
        "cost_index": 4321, "tokenizer": "o200k_base",
        "measured_at": "2026-09-10T00:00:00+00:00",
        "tool_count": TOOL_COUNT,
    }


def _state() -> dict:
    rec = _record(_ITEMS)
    return {
        "entries": {"srv": {"command": "x", "_clients": ["cursor"]}},
        "store": {"servers": {"mcp:Srv": {
            "aliases": ["srv"], "approved": rec, "history": [rec]}}},
        "pending": [], "activity": {}, "recent_calls": [], "findings": [],
    }


def _detail() -> dict:
    st = _state()
    return panel.server_detail(st["store"], "mcp:Srv", [])


def test_the_tool_lists_hold_tools_and_nothing_else():
    d = _detail()
    assert len(d["current_tools"]) == TOOL_COUNT, d["current_tools"]
    assert len(d["approved_tools"]) == TOOL_COUNT, d["approved_tools"]
    stray = [k for k in d["current_tools"] + d["approved_tools"] if not k.startswith("tool.")]
    assert not stray, f"a list named *_tools is holding other kinds: {stray}"


def test_the_rendered_panel_never_prints_the_all_kinds_number_as_tools():
    page = panel.render(_state(), token="t")
    # The headline the walk caught: "<watched> of <n> exposed tools watched".
    exposed = re.findall(r"of (\d+) exposed", page)
    assert exposed, "the coverage headline vanished — this test no longer guards anything"
    assert all(int(n) == TOOL_COUNT for n in exposed), \
        f"'exposed tools' must count tools ({TOOL_COUNT}), got {exposed}"
    assert not re.search(rf"\b{KIND_COUNT} exposed", page), \
        "the panel is still rendering every kind as a tool count"


def test_the_json_an_agent_reads_says_the_same_number_as_the_screen():
    """`panel.state()` is what an agent polls. It must not disagree with the page.

    `export_servers_csv()` reads the same `server_detail` lists for its `tools` column and calls
    `collect()` for itself, so it is fixed by the same line and left to the e2e path rather than
    given a fake environment here.
    """
    payload = json.loads(json.dumps(panel.state(_state())))   # also pins JSON-safety
    row = next(s for s in payload["servers"] if s["name"] == "srv")
    assert row["tools"] == TOOL_COUNT, row
    assert row["approved_tools"] == TOOL_COUNT, row


def test_a_resource_is_never_joined_into_the_per_tool_table():
    rows = panel.declared_vs_observed(_detail(), {})
    names = [r.get("tool") or r.get("name") for r in rows]
    assert len(rows) == TOOL_COUNT, names
    assert not [n for n in names if str(n).startswith(("resource.", "prompt.", "card", "summarise"))], \
        f"a non-tool reached a per-tool view: {names}"


def test_filtering_the_display_lists_does_not_narrow_what_counts_as_drift():
    """The guard against fixing a label by blinding an alarm.

    `history.pending` — not these lists — decides a server "changed since you approved it". A
    resource that appears after approval must still queue a decision, or this fix would have
    traded a wrong number for a missed rug-pull.
    """
    from mcpgawk import history

    approved = _record({k: v for k, v in _ITEMS.items() if k != "resource.card"})
    latest = _record(_ITEMS)          # the resource showed up after approval
    store = {"servers": {"mcp:Srv": {
        "aliases": ["srv"], "approved": approved, "history": [approved, latest]}}}

    assert history.pending(store) == ["mcp:Srv"], \
        "a resource added after approval must still be unacknowledged drift"
    # ...while the display lists, correctly, show no change in the TOOL count.
    d = panel.server_detail(store, "mcp:Srv", [])
    assert len(d["current_tools"]) == len(d["approved_tools"]) == TOOL_COUNT


def test_a_legacy_record_keying_its_tools_bare_still_counts_them():
    """The regression the first version of this fix caused, now pinned.

    Records written before the rug-pull work key tools BARE ("read"), not typed ("tool.read"),
    and those records are still approved and still rendered. An include-list on the `tool.`
    prefix reads every one of them as having ZERO tools — a worse lie than the miscount this
    file exists to stop. Caught by `test_a_tool_added_since_approval_is_named_on_the_row`; kept
    here so the predicate itself is the thing under test.
    """
    legacy = _record({"read": "h1", "write": "h2"})
    store = {"servers": {"mcp:Old": {
        "aliases": ["old"], "approved": legacy, "history": [legacy]}}}
    d = panel.server_detail(store, "mcp:Old", [])
    assert d["current_tools"] == ["read", "write"], d["current_tools"]
    assert d["approved_tools"] == ["read", "write"], d["approved_tools"]


def test_the_predicate_names_kinds_from_one_place():
    """A second hand-written list of kinds is how the two disagree later."""
    from mcpgawk.drift import ITEM_KINDS

    assert panel._is_tool_key("tool.send")
    assert panel._is_tool_key("read"), "a bare legacy key is a tool"
    assert panel._is_tool_key("weird.name"), "an unknown prefix is not a kind — treat it as a tool"
    for kind in ITEM_KINDS:
        if kind != "tool":
            assert not panel._is_tool_key(f"{kind}.x"), kind
