"""Where the gateway filter and the client hook DISAGREE — and whether the filter admits it.

Written after the filter shipped, because every test I had written until then used one call and
the declared tier only, and all of them passed while the filter handed out a clean bill on a
toxic flow the client hook denies. The gap was never in the code the tests covered; it was in the
tier the tests never exercised.

The rule this file enforces: the filter may be WEAKER than the client hook — it genuinely is,
because Obot hands a filter no session identity and the sequence check needs one — but it may
never be weaker SILENTLY. Every accept it issues on a call the hook would deny has to say which
check did not run.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpgawk import guard_hook, history, obot_filter, spool


@pytest.fixture()
def flow(tmp_path, monkeypatch):
    """A source and a sink, BOTH approved, plus the behavioural profile that classifies them.

    Both approved on purpose: the declared tier has no objection to either call, so anything that
    fires can only have come from the observed tier. That is what makes this the moat's test.
    """
    store = tmp_path / "history.json"
    history.save({"servers": {"toybox": {"approved": {
        "pin": "p", "measured_at": "2026-08-26T00:00:00Z",
        "tools": {"read_secrets": "h1", "send_out": "h2"}}}}}, str(store))
    profile = tmp_path / "behaviour.json"
    profile.write_text(json.dumps({"servers": {"toybox": {
        "read_secrets": {"source": True}, "send_out": {"sink": True}}}}), encoding="utf-8")
    monkeypatch.setenv("GAWK_BEHAVIOUR", str(profile))
    monkeypatch.setenv("MCPGAWK_HISTORY", str(store))
    monkeypatch.setenv("MCPGAWK_SPOOL", str(tmp_path / "calls.jsonl"))
    return store


def _hook_sequence(store: Path) -> bool:
    """Run source-then-sink through the CLIENT hook, recording session memory as the hook does.
    Returns whether the sink call was denied."""
    denied = False
    for tool in ("read_secrets", "send_out"):
        event = {"tool_name": f"mcp__toybox__{tool}", "tool_input": {}, "session_id": "sess-1"}
        out, _note, basis, _checked, _reason, _context = guard_hook._decide(event, store, "claude")
        denied = out is not None
        spool.record_decision(server="toybox", tool=tool, adapter="guard", session="sess-1",
                              decision="deny" if out else "defer", basis=basis)
    return denied


def _filter_sequence(store: Path) -> dict:
    """The same two calls through the gateway filter. Returns the sink call's verdict."""
    verdict = {}
    for tool in ("read_secrets", "send_out"):
        verdict = obot_filter.evaluate(
            {"message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": tool, "arguments": {}}}},
            server="toybox", store_path=store, record=False)
    return verdict


def test_the_client_hook_still_catches_the_toxic_flow(flow):
    """The baseline claim. If this ever goes false the divergence below is meaningless — and the
    product has a much bigger problem than its Obot adapter."""
    assert _hook_sequence(flow) is True, (
        "the client hook stopped denying source→sink; the behavioural tier is broken at the core, "
        "not in the adapter")


def test_the_gateway_filter_never_calls_a_toxic_flow_clean(flow):
    """THE REGRESSION THAT SHIPPED. The filter cannot see the sequence — that is a real and
    currently unavoidable limit — but it must not answer with the sentence it uses for a call it
    fully checked. 'no adverse finding' on a flow the hook denies is a false all-clear."""
    verdict = _filter_sequence(flow)
    assert verdict["accept"] is True          # honest: it cannot deny what it cannot see
    assert "no adverse finding" not in verdict["reason"], (
        "the filter issued its FULL clean bill on a call the client hook denies on the observed "
        "basis — the operator reads that as 'checked, safe'")
    assert "PARTIAL" in verdict["reason"]
    assert "sequence" in verdict["reason"].lower()
    assert "session identity" in verdict["reason"]


def test_a_call_the_sequence_check_cannot_concern_is_not_hedged(flow):
    """The hedge has to be earned. If every accept carried a warning the warning would be wallpaper
    — a source call is not a sink, and nothing about the sequence tier is missing for it."""
    verdict = obot_filter.evaluate(
        {"message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "read_secrets", "arguments": {}}}},
        server="toybox", store_path=flow, record=False)
    assert verdict["accept"] is True
    assert "PARTIAL" not in verdict["reason"]
    assert "no adverse finding" in verdict["reason"]


def test_a_host_with_no_behavioural_profile_says_so_rather_than_implying_depth(tmp_path,
                                                                              monkeypatch):
    """The containerised default: the filter is deployed with an approval store and no verify
    output. Only the tool LIST is being checked, and the accept has to admit that — otherwise the
    thinnest possible check reads exactly like the deepest one."""
    store = tmp_path / "history.json"
    history.save({"servers": {"toybox": {"approved": {
        "pin": "p", "measured_at": "2026-08-26T00:00:00Z",
        "tools": {"send_out": "h2"}}}}}, str(store))
    monkeypatch.setenv("GAWK_BEHAVIOUR", str(tmp_path / "absent.json"))

    verdict = obot_filter.evaluate(
        {"message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "send_out", "arguments": {}}}},
        server="toybox", store_path=store, record=False)
    assert verdict["accept"] is True
    assert "no adverse finding" not in verdict["reason"]
    assert "no behavioural profile" in verdict["reason"]
    assert "mcpgawk verify" in verdict["reason"]


def test_the_declared_tier_denies_identically_on_both_paths(flow):
    """Where the two paths DO agree, they must agree exactly — a tool outside the approved surface
    is refused by hook and filter alike, with the same sentence."""
    event = {"tool_name": "mcp__toybox__brand_new_tool", "tool_input": {}, "session_id": "s"}
    hook_out, _n, _b, _c, _r, _ctx = guard_hook._decide(event, flow, "claude")
    assert hook_out is not None

    verdict = obot_filter.evaluate(
        {"message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "brand_new_tool", "arguments": {}}}},
        server="toybox", store_path=flow, record=False)
    assert verdict["accept"] is False
    hook_text = hook_out["hookSpecificOutput"]["permissionDecisionReason"]
    assert hook_text.split("\n")[0] in verdict["reason"]
