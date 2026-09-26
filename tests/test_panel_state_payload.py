"""`panel.state()` — the whole-panel JSON payload — must actually build.

It did not. `_agent_rows` yields five values `(client, label, state, count, detail)` and the payload
unpacked four, so `state()` raised `ValueError: too many values to unpack` on any machine that has
an agent configured — which is every machine this payload exists for. Nothing calls it yet, so no
user hit it; it is shipped public code with a crash waiting on its first caller, and a type checker
saw it the moment the file was checked.

The test drives the real function against real discovered state rather than a hand-built dict:
the bug was in the JOIN between two real shapes, and a fixture that invents both cannot see it.
Since 2026-09-26 that state is a seeded config in the suite's temp home, read by the real
discovery code — not this machine's own agents.
"""
from __future__ import annotations

from mcpgawk import panel

#: What a consumer of this payload is entitled to. `client` is here on purpose: it is the key a
#: Protect action must send back, and dropping it would leave the UI with display labels only.
AGENT_KEYS = {"client", "label", "state", "servers", "detail"}


def test_the_payload_builds():
    """The whole point: it used to raise."""
    assert isinstance(panel.state(), dict)


def test_every_agent_row_carries_what_an_action_needs(seeded_fleet):
    # The suite runs on a temp home (public_conftest); seeded_fleet gives it an agent with servers,
    # so the join is exercised on every machine instead of skipping on an empty one.
    rows = panel.state()["agents"]
    assert rows, "the seeded fleet produced no agent row"
    for row in rows:
        assert set(row) == AGENT_KEYS, f"agent row shape drifted: {sorted(row)}"


def test_the_row_shape_matches_what_agent_rows_actually_yields(seeded_fleet):
    """Pins the JOIN, not either side. Both shapes were individually fine; the payload disagreed
    with the producer about how many values it hands back, and only checking them together sees it."""
    from mcpgawk.panel import _agent_rows, collect

    produced = _agent_rows(collect())
    assert produced, "the seeded fleet produced no agent row"
    assert len(produced[0]) == len(AGENT_KEYS), (
        "the producer's tuple width and the payload's field count must move together")
