"""The filter as Obot actually reaches it: a real process, over a real MCP client.

`obot_filter.evaluate` is unit-tested next door. This file exists because a correct verdict that
never reaches the gateway in a shape it can read is worth nothing, and every part of that trip —
the process starting at all, the tool being named what the operator registers, the response
carrying structuredContent — lives outside the function.

The response shape is the sharp one. Obot's hook runner reads `structuredContent`, else parses a
single text block as JSON, and if it can do neither it returns nil,nil and the call is passed
through UNJUDGED. A filter that answers in a shape they cannot parse does not fail loudly in
their gateway; it silently stops guarding. Nothing in Obot will tell us. These tests are the only
place that can.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcpgawk import history, obot_filter, obot_filter_server



@pytest.fixture(autouse=True)
def _isolate_behaviour_profile(tmp_path_factory, monkeypatch):
    """No test in this file may read the OPERATOR's real ~/.gawk/behaviour.json.

    Found 2026-08-26: the behavioural profile is looked up from the real home path unless
    GAWK_BEHAVIOUR is set, so these tests were quietly consulting whatever this machine happened
    to have verified. That makes a filter test pass or fail on the developer's own fleet — the
    exact shape of a green suite that proves nothing. Tests that WANT a profile set the variable
    themselves; everything else runs against a path that does not exist.
    """
    monkeypatch.setenv("GAWK_BEHAVIOUR", str(tmp_path_factory.mktemp("nb") / "absent.json"))

def _store(tmp_path: Path, servers: dict) -> Path:
    p = tmp_path / "history.json"
    history.save({"servers": servers}, str(p))
    return p


def _approved(tools: dict[str, str]) -> dict:
    return {"approved": {"pin": "abc123", "tools": tools, "measured_at": "2026-07-27T00:00:00Z"}}


def _params(store: Path, server: str | None, **env: str) -> StdioServerParameters:
    """Launch the module the way `uvx --from mcpgawk mcpgawk-obot-filter` would."""
    # GAWK_BEHAVIOUR travels into the child as well: the served filter runs in its OWN
    # process, and without this it reads the operator's real profile from home.
    base = {**os.environ, "MCPGAWK_HISTORY": str(store),
            "MCPGAWK_SPOOL": str(store.parent / "calls.jsonl"),
            "GAWK_BEHAVIOUR": str(store.parent / "behaviour-absent.json")}
    base.pop("MCPGAWK_SERVER", None)
    if server is not None:
        base["MCPGAWK_SERVER"] = server
    base.update(env)
    return StdioServerParameters(command=sys.executable,
                                 args=["-m", "mcpgawk.obot_filter_server"], env=base)


def _hook_input(tool: str) -> dict:
    return {"accept": True, "mutated": False,
            "message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": tool, "arguments": {}}}}


async def _filter(store: Path, server: str | None, tool: str, **env: str) -> dict:
    async with stdio_client(_params(store, server, **env)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return await s.call_tool(obot_filter.TOOL_NAME, _hook_input(tool))


@pytest.mark.asyncio
async def test_the_tool_is_named_what_the_operator_registers(tmp_path):
    """Obot is configured with a Filter Tool Name. If the served name and the documented name
    drift apart, every call reaches a tool that does not exist."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    async with stdio_client(_params(store, "figma")) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            listed = await s.list_tools()
    names = [t.name for t in listed.tools]
    assert names == [obot_filter.TOOL_NAME] == ["mcpgawk_guard"]


@pytest.mark.asyncio
async def test_a_deny_arrives_as_structured_content_the_gateway_can_read(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    res = await _filter(store, "figma", "delete_everything")

    assert res.structured_content is not None, (
        "no structuredContent: Obot falls back to parsing the text block, and if that fails it "
        "passes the call through unjudged — a deny would vanish silently")
    assert res.structured_content["accept"] is False
    assert "mcpgawk" in res.structured_content["reason"]

    # The fallback path must independently work, because it is what runs if structuredContent is
    # ever dropped: exactly ONE text block, and it must parse as a JSON object.
    texts = [c for c in res.content if getattr(c, "type", None) == "text"]
    assert len(texts) == 1
    assert json.loads(texts[0].text) == res.structured_content


@pytest.mark.asyncio
async def test_an_approved_call_passes_and_says_it_was_evaluated(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    res = await _filter(store, "figma", "get_file")
    assert res.structured_content["accept"] is True
    assert "approved baseline" in res.structured_content["reason"]
    assert "UNEVALUATED" not in res.structured_content["reason"]


@pytest.mark.asyncio
async def test_the_served_verdict_reaches_the_shared_decision_log(tmp_path):
    """The unit test proves evaluate() records. This proves the SERVED path does — a filter whose
    rulings never reach the trail leaves an operator with no evidence that it ever ruled."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    await _filter(store, "figma", "delete_everything")
    rows = [json.loads(line) for line
            in (store.parent / "calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()]
    assert [(r["decision"], r["adapter"], r["tool"]) for r in rows] == [
        ("deny", "obot-filter", "delete_everything")]


@pytest.mark.asyncio
async def test_an_unmapped_instance_passes_but_never_claims_to_have_checked(tmp_path):
    """The default deployment mistake: the filter is installed, MCPGAWK_SERVER is not set, and
    every call sails through. It must pass — blocking an unconfigured machine is worse — but it
    must never read as protection."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    res = await _filter(store, None, "get_file")
    assert res.structured_content["accept"] is True
    assert res.structured_content["reason"].startswith("UNEVALUATED by mcpgawk")


@pytest.mark.asyncio
async def test_fail_closed_reaches_the_served_verdict(tmp_path):
    """The switch is only real if it survives the trip through the process, not just the unit."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    res = await _filter(store, "stripe", "anything", MCPGAWK_FILTER_FAIL_CLOSED="1")
    assert res.structured_content["accept"] is False
    assert "UNEVALUATED" in res.structured_content["reason"]


@pytest.mark.asyncio
async def test_a_call_to_some_other_tool_name_is_answered_not_raised(tmp_path):
    """A raise reaches Obot as a filter error and blocks the message. Traffic that was never ours
    to judge must not become an outage."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    async with stdio_client(_params(store, "figma")) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool("not_our_tool", _hook_input("get_file"))
    assert res.structured_content["accept"] is True
    assert "not this filter's tool" in res.structured_content["reason"]


# ------------------------------------------------------------------ the coverage announcement

def test_coverage_says_guarding_nothing_when_nothing_is_approved(tmp_path, monkeypatch):
    """The trap this line exists for: a containerized filter with no store defers on everything,
    which maps to accept, and looks installed while guarding nothing."""
    store = _store(tmp_path, {})
    monkeypatch.setenv("MCPGAWK_SERVER", "figma")
    note = obot_filter_server.coverage_note(str(store))
    assert "approved NO servers" in note
    assert "guarding nothing" in note


def test_coverage_distinguishes_an_unreadable_store_from_an_empty_one(tmp_path, monkeypatch):
    """`load` degrades a corrupt store to an empty one. Announcing "nothing approved" for a store
    we could not READ is the false all-clear in miniature."""
    store = tmp_path / "history.json"
    store.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("MCPGAWK_SERVER", "figma")
    note = obot_filter_server.coverage_note(str(store))
    assert "UNREADABLE" in note


def test_coverage_names_the_guarded_server_when_it_is_really_covered(tmp_path, monkeypatch):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    monkeypatch.setenv("MCPGAWK_SERVER", "figma")
    note = obot_filter_server.coverage_note(str(store))
    assert "guarding 'figma'" in note
    assert "UNEVALUATED" in note          # still says what is NOT covered


def test_coverage_resolves_a_name_the_same_way_the_verdict_does(tmp_path, monkeypatch):
    """Caught by running `--coverage` on a real machine: every store key there is qualified
    (`mcp:vault-rag`), and the decision core resolves a bare `vault-rag` to it. A membership test
    against the raw key list announced "NO approved baseline" for servers the filter would in fact
    have guarded — the announcement and the enforcing path disagreeing, which is the defect the
    operator can least afford, because the announcement is all they read."""
    store = _store(tmp_path, {"mcp:vault-rag": _approved({"vault_search": "h1"})})
    monkeypatch.setenv("MCPGAWK_SERVER", "vault-rag")
    note = obot_filter_server.coverage_note(str(store))
    assert "NO approved baseline" not in note
    assert "guarding 'vault-rag'" in note

    # And the verdict path really does agree — the two are pinned to each other, not just asserted.
    hook_input = {"message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "not_approved", "arguments": {}}}}
    v = obot_filter.evaluate(hook_input, server="vault-rag", store_path=store, record=False)
    assert v["accept"] is False


def test_coverage_flags_a_server_it_has_no_baseline_for(tmp_path, monkeypatch):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    monkeypatch.setenv("MCPGAWK_SERVER", "stripe")
    note = obot_filter_server.coverage_note(str(store))
    assert "NO approved baseline" in note
