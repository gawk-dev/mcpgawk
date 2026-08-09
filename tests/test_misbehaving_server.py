"""A server that runs and then fails is not the same as an address that answers nothing.

Both used to render identically — `UNREACHABLE · no MCP endpoint found` — for a crash, a missing
credential and a hang alike, and the narrative then advised checking whether the URL was really an
MCP endpoint and suggested `--stdio`, to someone whose stdio server had just launched and died.
The diagnosis was never missing: `probe_stdio` already captured the child's stderr. It was captured
and then thrown away at the two places a user looks.

These tests pin the distinction end to end: the typed kind, the fleet row a multi-server scan
shows by default, and the next-step hint in the narrative.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from mcpgawk import fleet, label
from mcpgawk.measure import measure
from mcpgawk.probe import probe_stdio

FIXTURE = Path(__file__).parent / "fixtures" / "misbehaving_mcp_server.py"


def _probe(mode: str):
    return asyncio.run(probe_stdio("broken", sys.executable, [str(FIXTURE), "--mode", mode],
                                   timeout=30))


@pytest.mark.parametrize("mode, expected_in_message", [
    ("crash", "ModuleNotFoundError"),
    ("missing-secret", "DEMO_API_TOKEN"),
])
def test_a_server_that_ran_and_died_is_typed_apart_from_silence(mode, expected_in_message):
    snap = _probe(mode)

    assert snap.error_kind == "server-failed", (
        f"a server that printed a reason must not be typed {snap.error_kind!r} — that is the "
        f"bucket for an address that answered nothing")
    assert expected_in_message in snap.error, f"the server's own words were lost: {snap.error}"


def _label_of(mode: str) -> dict:
    snap = _probe(mode)
    return label.build_label(snap, measure(snap))


def test_the_fleet_row_separates_it_from_no_endpoint_found():
    """The default view for a multi-server fleet. This is where all faults used to look alike."""
    state, reason = fleet.state_of(_label_of("crash"))

    assert state == "FAILED"
    assert "no MCP endpoint found" not in reason
    assert "started, then failed" in reason


def test_a_server_that_never_answers_is_TIMED_OUT_not_unreachable():
    """The beta page's "sits there doing nothing". A short budget keeps the test honest AND fast:
    the fixture holds the pipe open forever, so any pass here is a real give-up, not a lucky race."""
    snap = asyncio.run(probe_stdio("hangs", sys.executable, [str(FIXTURE), "--mode", "hang"],
                                   timeout=2))

    assert snap.error_kind == "timed-out", (
        f"a server that accepted the connection and went quiet must not read as "
        f"{snap.error_kind!r} — that sends the user to check an address that is correct")
    assert "no MCP response within" in snap.error

    state, reason = fleet.state_of(label.build_label(snap, measure(snap)))
    assert state == "TIMED-OUT"
    assert "no MCP endpoint found" not in reason

    text = label.render_cli(label.build_label(snap, measure(snap)))
    assert "A docs / repo / package URL is not one" not in text
    assert "never answered" in text
    assert "Check its own logs" in text


def test_the_next_step_hint_stops_pointing_at_urls():
    """The advice must match the KIND of failure: there is no URL here, and the server did run."""
    text = label.render_cli(_label_of("missing-secret"))

    assert "A docs / repo / package URL is not one" not in text
    assert "mcpgawk scan --stdio" not in text
    assert "The server started and then failed" in text
    # The cause itself still has to be right there, not one flag away, in the narrative view.
    assert "DEMO_API_TOKEN" in text
