"""Two gaps found by putting this scanner side by side with a general-purpose agent (2026-07-21).

The agent, given the same machine and forbidden from using mcpgawk, reported two risks the scanner
did not. Both matter more than the availability reporting the scanner already did well: a scanner
that says a server is reachable but under-states what it can do to you has failed at its own job.

  1. A real brokerage server's order-placement tool — an irreversible real-money trade with 12
     schema parameters, described in three words. The scanner said nothing, and worse, did not even
     count it as a tool that CHANGES data, because "place" was missing from the mutating-verb list.
  2. Three clients still pointing at the same deleted binary. Reported as plain UNREACHABLE, which
     reads as "dead, ignore it" — when a still-configured entry is a standing, pre-approved
     execution slot for whatever lands at that path next.
"""
from __future__ import annotations

import asyncio

from mcpgawk.fleet import state_of
from mcpgawk.measure import measure
from mcpgawk.probe import ServerSnapshot, _missing_program, probe
from mcpgawk.grade import grade
from mcpgawk.label import build_label


def _snap(tools: list[dict]) -> ServerSnapshot:
    return ServerSnapshot(name="s", transport="stdio", protocol_version="1", tools=tools)


def _tool(name: str, description: str, params: int, **ann) -> dict:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"properties": {f"p{i}": {"type": "string"} for i in range(params)}},
        **({"annotations": ann} if ann else {}),
    }


# --- The real case, reproduced exactly -------------------------------------------------------

def _graded(tools: list[dict]):
    return grade(measure(_snap(tools)))


def test_flags_the_order_placement_case():
    g = _graded([_tool("place_order", "Place an order", 12)])
    assert g.underdocumented == ["place_order"]
    assert any("place_order" in f for f in g.fixes)


def test_it_is_hygiene_not_a_security_signal():
    """It must NOT live in signals.py. That module fires only on language aimed at the model and
    holds a 0-false-positive wall; a terse tool is badly documented, not an attack, and reporting it
    as a bounded signal would inflate the meaning of every real signal beside it."""
    from mcpgawk import signals

    assert not hasattr(signals, "detect_thin_guidance")
    assert not any(k.startswith("guidance:") for k in signals.SIGNAL_KINDS)


def test_it_does_not_move_the_score():
    """Adding it to the grade would shift every existing letter, making "we improved our analysis"
    indistinguishable from "this server got worse" — the one confusion drift must never allow. So
    the score must remain a function of cost and hygiene ONLY, whatever this flags."""
    from mcpgawk.grade import W_COST, W_HYGIENE

    g = _graded([_tool("place_order", "Place an order", 12)])
    assert g.underdocumented == ["place_order"]
    assert g.score == round(W_COST * g.cost_score + W_HYGIENE * g.hygiene_score)


def test_a_money_moving_verb_counts_as_a_write_at_all():
    """The upstream bug. `place_order` was not classified as changing data, so a trading server's
    blast radius read smaller than it is — the scanner's central claim, wrong on a real server."""
    m = measure(_snap([_tool("place_order", "Place an order", 12)]))
    assert m.tools[0].write is True


def test_other_money_and_lifecycle_verbs_count_too():
    for verb, phrase in [("cancel_order", "Cancel an order"), ("transfer_funds", "Transfer funds"),
                         ("submit_claim", "Submit a claim"), ("rotate_key", "Rotate the key")]:
        m = measure(_snap([_tool(verb, phrase, 5)]))
        assert m.tools[0].write is True, f"{verb} should count as a write"


def test_the_facts_stay_on_the_measure_side_of_the_wall():
    m = measure(_snap([_tool("place_order", "Place an order", 12)]))
    assert m.tools[0].param_count == 12
    assert m.tools[0].description_words == 3


# --- Calibration: it must not cry wolf -------------------------------------------------------

def test_silent_on_a_read_only_tool_however_terse():
    assert _graded([_tool("get_margins", "Get margins", 8)]).underdocumented == []


def test_a_declared_read_only_tool_is_never_flagged():
    assert _graded([_tool("place_order", "Place an order", 12, readOnlyHint=True)]).underdocumented == []


def test_silent_when_the_tool_takes_few_parameters():
    assert _graded([_tool("delete_file", "Delete a file", 2)]).underdocumented == []


def test_silent_when_the_description_is_proportionate():
    tools = [_tool("create_invoice",
                   "Create an invoice for a customer, with line items, tax treatment, "
                   "due date and an optional purchase order reference.", 6)]
    assert _graded(tools).underdocumented == []


def test_a_declared_destructive_tool_with_no_description_is_flagged():
    assert _graded([_tool("purge", "", 5, destructiveHint=True)]).underdocumented == ["purge"]


# --- A configured entry whose program is gone -------------------------------------------------

def test_missing_program_detection():
    assert _missing_program("/Applications/Nope.app/Contents/MacOS/nope") is True
    assert _missing_program("/bin/sh") is False
    assert _missing_program("definitely-not-a-real-binary-xyz") is True
    assert _missing_program("") is False


def test_a_dangling_entry_is_not_launched_and_is_typed():
    snap = asyncio.run(probe({"command": "/Applications/Nope.app/Contents/MacOS/nope"}, "gone-server"))
    assert snap.error_kind == "command-missing"       # NOT the generic "unreachable"
    assert "does not exist" in (snap.error or "")


def test_the_report_says_it_is_still_configured_not_merely_dead():
    """'Dead' invites ignoring it. The entry is still approved in every client that lists it, so
    anything that later appears at that path runs without being asked about again."""
    snap = asyncio.run(probe({"command": "/Applications/Nope.app/Contents/MacOS/nope"}, "gone-server"))
    label = build_label(snap, measure(snap))
    state, detail = state_of(label)
    assert state == "UNREACHABLE"
    assert "still configured" in detail
    assert "would run" in detail


def test_a_dangling_entry_is_reported_even_when_local_scanning_was_DECLINED():
    """The case that matters most, and the one the first cut of this fix missed.

    Whether the program exists is a stat, not an execution — so it is answerable even when the user
    withheld consent to launch local servers. Putting the check only in probe() meant a dangling
    entry surfaced ONLY if you opted into running code, i.e. never in the default scan, i.e. hidden
    exactly where it was most likely to be found. Verified against a real config: an entry still
    listed by three clients, pointing at a deleted binary.
    """
    from mcpgawk.fleet import skipped_row

    row = skipped_row("gone-server", {"command": "/Applications/Nope.app/Contents/MacOS/gone",
                                 "_clients": ("codex", "gemini-cli", "kiro")})
    assert row.state == "UNREACHABLE"
    assert "no longer exists" in row.detail
    assert "would run" in row.detail
    assert len(row.clients) == 3          # still approved in all three

    alive = skipped_row("a-live-server", {"command": "/bin/sh"})
    assert alive.state == "SKIPPED"       # a real program is still just "not launched"
    assert "not launched" in alive.detail
