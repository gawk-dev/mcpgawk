"""What Obot's gateway would actually DO with our filter's answers.

The other two files check that we return the right verdict and that it survives the trip out of
the process. Neither answers the question the operator cares about: does the call get blocked?
That decision is made by Obot's code, not ours, and it has corners that punish a plausible-looking
response — an omitted `accept` REJECTS, an unparseable body silently ACCEPTS.

So this file replays Obot's decision logic against our real server. `_obot_would` below is a
REPLICA, transcribed from their Go source at main @ 8da1870 (pkg/mcp/hookrunner.go RunHook,
pkg/api/handlers/mcpgateway/proxy_hooks.go callAllHooks, pkg/mcp/hooks.go SessionMessageHook) —
it is not their binary, and it cannot prove their released build behaves this way. Running against
a real pinned Obot is slice 3 and remains the authoritative gate; this is the fast check that
catches a shape regression on every commit, everywhere, without a container runtime.

Transcribed rules, each mapped to the line it came from:
  * RunHook: no structuredContent AND (content count != 1 OR text is not a JSON object)
    -> return nil, nil                                   (hookrunner.go:67-78)
  * callAllHooks: output == nil -> continue, message passes UNCHANGED   (proxy_hooks.go:474-476)
  * tool transport error or IsError -> hook error -> blocked   (hookrunner.go:57-64)
  * decoded with Go zero values: absent `accept` is false -> rejected  (proxy_hooks.go:498-504)
  * empty reason on a reject -> 'hook %q did not provide a reason'     (proxy_hooks.go:498-504)
  * mutated && message != nil -> replace; else keep current            (proxy_hooks.go:505,524-526)
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcpgawk import history, obot_filter

BLOCKED = "BLOCKED"
FORWARDED = "FORWARDED"



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

def _obot_would(result) -> tuple[str, str | None]:
    """Obot's decision for one filter response. Returns (outcome, reason)."""
    if getattr(result, "isError", False) or getattr(result, "is_error", False):
        return BLOCKED, "hook returned an error result"

    structured = getattr(result, "structured_content", None)
    if structured is None:
        texts = [c for c in (result.content or []) if getattr(c, "type", None) == "text"]
        if len(texts) != 1 or not texts[0].text.strip():
            return FORWARDED, "unparseable hook response — passed through UNJUDGED"
        try:
            structured = json.loads(texts[0].text)
        except ValueError:
            return FORWARDED, "unparseable hook response — passed through UNJUDGED"
        if not isinstance(structured, dict):
            return FORWARDED, "unparseable hook response — passed through UNJUDGED"

    # Go zero values: a field the filter omitted decodes to false, not to "unset".
    accept = bool(structured.get("accept", False))
    reason = structured.get("reason") or "hook did not provide a reason"
    return (FORWARDED, reason) if accept else (BLOCKED, reason)


def _store(tmp_path: Path, servers: dict) -> Path:
    p = tmp_path / "history.json"
    history.save({"servers": servers}, str(p))
    return p


def _approved(tools: dict[str, str]) -> dict:
    return {"approved": {"pin": "abc123", "tools": tools, "measured_at": "2026-07-27T00:00:00Z"}}


def _params(store: Path, server: str | None, **env: str) -> StdioServerParameters:
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


async def _gateway(store: Path, server: str | None, message: dict, **env: str):
    """One trip through the filter, judged the way Obot judges it."""
    async with stdio_client(_params(store, server, **env)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(obot_filter.TOOL_NAME,
                                    {"accept": True, "mutated": False, "message": message})
    return _obot_would(res)


def _tools_call(tool: str) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}}


@pytest.mark.asyncio
async def test_a_tool_outside_the_baseline_is_actually_stopped(tmp_path):
    """The whole point, end to end: not 'we returned accept:false' but 'the gateway does not
    forward this call'."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    outcome, reason = await _gateway(store, "figma", _tools_call("delete_everything"))
    assert outcome == BLOCKED
    assert "not in the approved baseline" in reason


@pytest.mark.asyncio
async def test_an_approved_tool_still_reaches_the_server(tmp_path):
    """A filter that blocks the approved surface is an outage wearing a security badge."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    outcome, _ = await _gateway(store, "figma", _tools_call("get_file"))
    assert outcome == FORWARDED


@pytest.mark.asyncio
async def test_the_gateway_keeps_working_for_everything_we_do_not_judge(tmp_path):
    """tools/list and friends flow through a gateway constantly. Blocking them — or returning a
    shape that makes Obot block them — breaks every client on the fleet."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    for message in ({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {}},
                    {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}):
        outcome, _ = await _gateway(store, "figma", message)
        assert outcome == FORWARDED, message


@pytest.mark.asyncio
async def test_an_unconfigured_filter_does_not_take_the_fleet_down(tmp_path):
    """No baseline, no MCPGAWK_SERVER: the calls flow. Deliberate — see the fail-open decision —
    and this is the test that would catch it silently becoming fail-closed."""
    store = _store(tmp_path, {})
    outcome, reason = await _gateway(store, None, _tools_call("anything"))
    assert outcome == FORWARDED
    assert "UNEVALUATED" in reason


@pytest.mark.asyncio
async def test_fail_closed_really_stops_the_call_at_the_gateway(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    outcome, reason = await _gateway(store, "stripe", _tools_call("anything"),
                                     MCPGAWK_FILTER_FAIL_CLOSED="1")
    assert outcome == BLOCKED
    assert "UNEVALUATED" in reason


@pytest.mark.asyncio
async def test_no_answer_of_ours_ever_lands_in_the_silent_pass_through(tmp_path):
    """The corner that cannot be seen from inside Obot: a response it cannot parse is not an
    error there, it is an ACCEPT. If any of our paths ever produced one, the filter would stop
    guarding and nothing in their gateway would say so."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    messages = [
        _tools_call("delete_everything"), _tools_call("get_file"),
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}},          # no tool name
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "not-an-object"},
        {"jsonrpc": "2.0", "id": 1},                                                # no method
    ]
    for message in messages:
        _outcome, reason = await _gateway(store, "figma", message)
        assert reason != "unparseable hook response — passed through UNJUDGED", message


# --------------------------------------------------------------- the replica's own corners

def test_the_replica_reproduces_the_corners_it_exists_to_model():
    """A harness that does not itself reproduce Obot's two traps would quietly pass everything.
    Pinned with hand-built responses, since our server never emits these shapes."""
    class _R:
        def __init__(self, structured=None, content=(), is_error=False):
            self.structured_content = structured
            self.content = list(content)
            self.is_error = is_error

    class _T:
        type = "text"

        def __init__(self, text):
            self.text = text

    # An omitted `accept` is a REJECT, not a pass.
    assert _obot_would(_R(structured={"reason": "forgot the field"}))[0] == BLOCKED
    # An unparseable body is a PASS, not an error.
    assert _obot_would(_R(content=[_T("not json")]))[0] == FORWARDED
    assert _obot_would(_R(content=[_T("[]")]))[0] == FORWARDED          # JSON, but not an object
    assert _obot_would(_R(content=[_T("{}"), _T("{}")]))[0] == FORWARDED  # more than one block
    # An error result blocks.
    assert _obot_would(_R(structured={"accept": True}, is_error=True))[0] == BLOCKED
    # The text fallback is honoured when structuredContent is absent.
    assert _obot_would(_R(content=[_T('{"accept": false, "reason": "no"}')])) == (BLOCKED, "no")
