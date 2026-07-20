"""mcpgawk AS an MCP server — so any agent can audit the MCP servers it is sitting next to.

Why this exists: Zed's extension API (verified against zed_extension_api 0.7.0) has no panel, tree
or UI surface at all — language servers, slash commands, context servers, docs indexing, and
nothing else. A fleet dashboard cannot be drawn there by any extension. What Zed DOES support is
registering a context server, i.e. an MCP server its agent can call. So the way to reach Zed is to
become one.

That turns out to be the better artifact anyway: the same server works in Claude Code, Cursor,
Codex, Claude Desktop and anything else that speaks MCP, which is far more reach than one more
bespoke panel.

SAFETY, and it is not incidental — this server is itself an MCP server that other agents can drive:
  * READ-ONLY by construction. It reports what is configured and what was measured. It cannot edit
    a config, install anything, or write to disk.
  * It NEVER launches a local (stdio) server unless the CALLER explicitly asks in that invocation.
    Spawning an MCP server runs its code, and an agent must not be able to trigger that by accident
    while "just having a look".
  * It never returns environment VALUES. The fleet rows carry names and commands, never secrets.
  * Every tool description here is itself a model-visible surface — the exact thing this product
    scans other servers for. Kept plain and honest: no instructions to the reading model, no
    imperatives, nothing that would trip our own injection detector.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool, ToolAnnotations

from . import __version__, fleet
from .discover import detect_unscannable, discover_servers
from .label import build_label, render_cli
from .measure import measure
from .probe import probe, probe_stdio, probe_url
from .signals import as_dicts, detect, detect_card_mismatch, detect_dynamic_dispatch

SERVER_NAME = "mcpgawk"


def _label_of(snap) -> dict[str, Any]:
    sigs = (as_dicts(detect(snap)) + as_dicts(detect_card_mismatch(snap))
            + as_dicts(detect_dynamic_dispatch(snap)))
    return build_label(snap, measure(snap), bounded_signals=(sigs or None))


async def _scan_fleet(launch_local: bool) -> dict[str, Any]:
    """Discover and scan. Remote servers are always probed (nothing local runs); local ones only
    when the caller opted in for this call."""
    configured = discover_servers()
    targets = [(n, e) for n, e in configured.items() if launch_local or not e.get("command")]
    skipped = [(n, e) for n, e in configured.items() if not launch_local and e.get("command")]
    snaps = await asyncio.gather(*(probe(e, n) for n, e in targets)) if targets else []
    labels = [_label_of(s) for s in snaps]
    rows = fleet.build_rows(labels, dict(targets), skipped, detect_unscannable())
    return fleet.to_json(rows)


async def _scan_one(url: str | None, command: str | None) -> dict[str, Any]:
    if url:
        snap = await probe_url("requested", url)
    else:
        parts = (command or "").split()
        if not parts:
            raise ValueError("give either `url` or `command`")
        snap = await probe_stdio("requested", parts[0], parts[1:])
    label = _label_of(snap)
    return {"report": render_cli(label), "label": label}


def build_server() -> Server:
    # The version MUST be passed. Without it the SDK reports its OWN version in serverInfo, so this
    # server announced itself as "mcpgawk 1.28.1" — the `mcp` package's number. Every client that
    # logs which mcpgawk it is talking to recorded a version that does not exist, which is exactly
    # the kind of quiet inventory error this product exists to catch in other people's servers.
    server: Server = Server(SERVER_NAME, version=__version__)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="scan_mcp_fleet",
                # Plain description. This text is read by a model, and a security tool writing
                # imperative instructions into its own tool descriptions would fail its own scan.
                description=(
                    "Report every MCP server configured on this machine, grouped by the tool it is "
                    "configured in, with what each one can do and what it costs the context window. "
                    "Runs locally; no inventory is uploaded. Local servers are not started unless "
                    "launch_local is set, because starting one runs its code."
                ),
                # Declared intent, and it must be the TRUTH about the worst this tool can do —
                # not about its default. `launch_local` is chosen by the CALLING MODEL, and setting
                # it spawns every configured local server, i.e. runs their code. A tool that can do
                # that is not read-only, whatever it does when the flag is false.
                #
                # This was readOnlyHint=True until 2026-07-21, and scanning THIS server with our own
                # scanner proved why that is indefensible: `_is_write` treats a declared
                # readOnlyHint as authoritative, so mcpgawk reported mcpgawk's own tools as
                # write=False. We would have handed ourselves the clean bill of health this product
                # exists to withhold from others — and any client that auto-approves read-only tools
                # would have executed code on that promise.
                #
                # openWorld: it talks to remote servers. NOT idempotent: launching servers has
                # whatever side effects those servers have.
                annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                            idempotentHint=False, openWorldHint=True),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "launch_local": {
                            "type": "boolean",
                            "default": False,
                            "description": "Start local (stdio) servers in order to scan them. This runs their code.",
                        }
                    },
                },
            ),
            Tool(
                name="scan_mcp_server",
                description=(
                    "Scan one MCP server and return its full report: cost, which tools can change "
                    "data or reach the network, and any findings. Give either a remote url or a "
                    "local launch command. Supplying a command will run it, which starts that server "
                    "on this machine; a url is connected to and starts nothing."
                ),
                # `command` is a launch command this tool EXECUTES. Declaring that read-only is a
                # false statement in the manifest, and the client's approval prompt is exactly the
                # defence it would disable. destructiveHint is left False because scanning does not
                # itself destroy anything — but the caller must be asked, so readOnly must be False.
                annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                            idempotentHint=False, openWorldHint=True),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Remote MCP endpoint."},
                        "command": {"type": "string", "description": "Local launch command; running it starts the server."},
                    },
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
        args = arguments or {}
        try:
            if name == "scan_mcp_fleet":
                payload = await _scan_fleet(bool(args.get("launch_local")))
            elif name == "scan_mcp_server":
                payload = await _scan_one(args.get("url"), args.get("command"))
            else:
                raise ValueError(f"unknown tool: {name}")
        except Exception as exc:  # noqa: BLE001 — surface as data; never kill the session
            # An agent calling this must get a usable answer, not a dropped connection. And a
            # failure must never read as "nothing found" — that is the false all-clear this whole
            # product exists to prevent.
            payload = {"error": f"{type(exc).__name__}: {exc}",
                       "note": "This scan did NOT complete. Do not read it as a clean result."}
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

    return server


async def _serve() -> None:
    server = build_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main(argv: list[str] | None = None) -> int:
    """Entry point for `mcpgawk-mcp` (and `python -m mcpgawk.mcp_server`)."""
    asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
