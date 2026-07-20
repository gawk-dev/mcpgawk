"""mcpgawk as an MCP server — the surface every agent (and Zed) reaches it through.

This module is unusual: it is a SECURITY tool that is itself an MCP server, driven by other agents.
So the tests here are mostly about restraint — what it must refuse to do when an agent asks.
"""
import json

import pytest

from mcpgawk import mcp_server
from mcpgawk.probe import ServerSnapshot


def _handler(server, kind):
    """Pull a registered handler out of the SDK's request map so the tools can be driven in-process,
    without spawning a subprocess for every assertion."""
    from mcp.types import CallToolRequest, ListToolsRequest

    want = {"list": ListToolsRequest, "call": CallToolRequest}[kind]
    return server.request_handlers[want]


@pytest.fixture
def server():
    return mcp_server.build_server()


async def _list_tools(server):
    from mcp.types import ListToolsRequest

    result = await _handler(server, "list")(ListToolsRequest(method="tools/list"))
    return result.root.tools


async def _call(server, name, args):
    from mcp.types import CallToolRequest, CallToolRequestParams

    req = CallToolRequest(method="tools/call", params=CallToolRequestParams(name=name, arguments=args))
    result = await _handler(server, "call")(req)
    return json.loads(result.root.content[0].text)


# --------------------------------------------------------------------------- #
# The tool surface
# --------------------------------------------------------------------------- #
async def test_exposes_exactly_the_two_intended_tools(server):
    names = {t.name for t in await _list_tools(server)}
    assert names == {"scan_mcp_fleet", "scan_mcp_server"}


async def test_every_tool_declares_its_intent(server):
    """We flag other servers for shipping tools with no annotations — our own scanner caught this
    server doing exactly that. It must not regress."""
    for tool in await _list_tools(server):
        assert tool.annotations is not None, f"{tool.name} declares no intent"
        assert tool.annotations.destructiveHint is False


async def test_no_tool_claims_read_only_while_it_can_execute_code(server):
    """The annotation must describe the WORST a tool can do, not its default.

    Both tools here start processes: scan_mcp_fleet spawns every configured local server when
    `launch_local` is set, and scan_mcp_server runs a supplied launch command. `launch_local` is
    chosen by the CALLING MODEL, not by a human.

    This shipped as readOnlyHint=True until 2026-07-21 — and THIS TEST ASSERTED IT, which is how it
    survived review. Scanning this very server with mcpgawk showed the cost: measure._is_write
    treats a declared readOnlyHint as authoritative, so mcpgawk reported mcpgawk's own tools as
    write=False, the clean bill of health this product exists to withhold from others. Worse, a
    client that auto-approves read-only tools would execute code on the strength of that claim,
    turning a design smell into an exploit path for any prompt injection reaching the model.
    """
    for tool in await _list_tools(server):
        assert tool.annotations.readOnlyHint is False, (
            f"{tool.name} declares readOnlyHint=True — it can start processes, and a client may "
            f"auto-approve it on that promise"
        )


async def test_our_own_scanner_sees_these_tools_as_writes(server):
    """The end-to-end version of the above: whatever we declare, mcpgawk's own measurement must not
    conclude that a process-spawning tool changes nothing. If this fails, we are once again handing
    ourselves a verdict we would not accept from anyone else."""
    from mcpgawk.measure import _is_write

    for tool in await _list_tools(server):
        as_wire = {"name": tool.name, "description": tool.description,
                   "annotations": tool.annotations.model_dump()}
        assert _is_write(as_wire, as_wire["annotations"]) is True, f"{tool.name} reads as read-only"


async def test_the_execution_consequence_is_stated_where_a_model_reads_it(server):
    """The description is the only thing a model consults when choosing a tool — and it is also what
    our own write-detection reads. Both must be able to see that a command gets run."""
    tools = {t.name: t.description.lower() for t in await _list_tools(server)}
    assert "run" in tools["scan_mcp_server"]
    assert "runs its code" in tools["scan_mcp_fleet"]


async def test_no_tool_description_would_trip_our_own_injection_detector(server):
    """Tool descriptions are model-visible text — the exact surface this product scans others for.
    A security tool whose own descriptions instruct the reading model would fail its own audit."""
    from mcpgawk.signals import detect

    tools = await _list_tools(server)
    snap = ServerSnapshot(
        name="self", transport="stdio", protocol_version="1",
        tools=[{"name": t.name, "description": t.description} for t in tools],
    )
    assert detect(snap) == []


# --------------------------------------------------------------------------- #
# Restraint — what it refuses to do when an agent asks
# --------------------------------------------------------------------------- #
async def test_fleet_scan_does_not_launch_local_servers_by_default(server, monkeypatch):
    """Spawning an MCP server RUNS ITS CODE. An agent must not be able to trigger that while
    'just having a look' — it takes an explicit flag in that call."""
    launched: list[str] = []

    async def fake_probe(entry, name):
        launched.append(name)
        return ServerSnapshot(name=name, transport="stdio", protocol_version="1")

    monkeypatch.setattr(mcp_server, "discover_servers", lambda: {
        "local": {"command": "npx", "args": ["-y", "x"]},
        "remote": {"url": "https://example.com/mcp"},
    })
    monkeypatch.setattr(mcp_server, "detect_unscannable", lambda: [])
    monkeypatch.setattr(mcp_server, "probe", fake_probe)

    payload = await _call(server, "scan_mcp_fleet", {})

    assert launched == ["remote"], "a local server was launched without being asked for"
    # …and the one we did not launch is still VISIBLE, never silently dropped.
    assert any(s["name"] == "local" and s["state"] == "SKIPPED" for s in payload["servers"])


async def test_fleet_scan_launches_locals_only_when_explicitly_asked(server, monkeypatch):
    launched: list[str] = []

    async def fake_probe(entry, name):
        launched.append(name)
        return ServerSnapshot(name=name, transport="stdio", protocol_version="1")

    monkeypatch.setattr(mcp_server, "discover_servers", lambda: {"local": {"command": "npx"}})
    monkeypatch.setattr(mcp_server, "detect_unscannable", lambda: [])
    monkeypatch.setattr(mcp_server, "probe", fake_probe)

    await _call(server, "scan_mcp_fleet", {"launch_local": True})

    assert launched == ["local"]


async def test_a_failure_is_reported_as_a_failure_not_an_empty_clean_result(server, monkeypatch):
    """The cardinal sin, restated for the agent-facing surface: an error must never be readable as
    'nothing found'."""
    def boom():
        raise RuntimeError("config unreadable")

    monkeypatch.setattr(mcp_server, "discover_servers", boom)

    payload = await _call(server, "scan_mcp_fleet", {})

    assert "error" in payload and "config unreadable" in payload["error"]
    assert "did NOT complete" in payload["note"]
    assert "servers" not in payload


async def test_an_unknown_tool_is_an_error_not_a_silent_success(server):
    payload = await _call(server, "scan_everything_please", {})
    assert "unknown tool" in payload["error"]


async def test_scanning_one_server_requires_a_target(server):
    payload = await _call(server, "scan_mcp_server", {})
    assert "error" in payload and "url" in payload["error"]


async def test_scan_one_returns_the_human_report_and_the_machine_label(server, monkeypatch):
    async def fake_probe_url(name, url, *a, **k):
        return ServerSnapshot(name=name, transport="http", protocol_version="1",
                              tools=[{"name": "ping", "description": "returns pong"}])

    monkeypatch.setattr(mcp_server, "probe_url", fake_probe_url)
    payload = await _call(server, "scan_mcp_server", {"url": "https://example.com/mcp"})

    assert "CLEAN" in payload["report"]
    assert payload["label"]["x-mcpgawk"]["tool_count"] == 1


def test_server_reports_its_own_version_not_the_sdks():
    """serverInfo must identify mcpgawk, not the `mcp` package it is built on.

    Observed live over stdio: the server announced "mcpgawk 1.28.1" — the SDK's version — because
    Server(name) was constructed without one. Every client that logs which mcpgawk it is talking to
    recorded a version that has never existed, which is precisely the sort of quiet inventory error
    this product exists to find in OTHER people's servers.
    """
    from mcpgawk import __version__
    from mcpgawk.mcp_server import build_server

    server = build_server()
    assert server.version == __version__
    assert server.version != "1.28.1"  # the mcp SDK version this used to report
