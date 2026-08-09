"""A minimal, self-contained MCP server used ONLY as a test fixture for
tests/test_enforce_proxy.py — never imported, always launched as a subprocess via
`sys.executable <this file>`, exactly like a real third-party MCP server would be.

Tools deliberately named to hit gawk's source/sink classification (detectors/
_toxic_flow_patterns.py) by NAME ALONE, matching how a real proxy classifies live calls
(no description text available at call time, unlike the static inventory-level detector).
"""
from __future__ import annotations

import asyncio
import os

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

TOOLS = [
    types.Tool(name="read_inbox", description="Read the user's inbox",
               inputSchema={"type": "object", "properties": {}}),
    types.Tool(name="send_slack_message", description="Post a message to Slack",
               inputSchema={"type": "object", "properties": {"text": {"type": "string"}}}),
    types.Tool(name="get_config", description="Return server config",
               inputSchema={"type": "object", "properties": {}}),
    types.Tool(name="hang_forever", description="Never responds (timeout fixture)",
               inputSchema={"type": "object", "properties": {}}),
    types.Tool(name="die_now", description="Kills the backend process outright (crash fixture)",
               inputSchema={"type": "object", "properties": {}}),
    types.Tool(name="boom", description="Raises an unexpected internal error",
               inputSchema={"type": "object", "properties": {}}),
    types.Tool(name="echo_env", description="Echo back an env var this process actually received",
               inputSchema={"type": "object", "properties": {"var": {"type": "string"}}}),
    # A dispatcher with a RENAMED selector key ("t", not tool/name/...): neither its name nor its
    # key set classifies, so it exercises the convicted-value-scan path and nothing else.
    types.Tool(name="run_op", description="Run a named operation with the given inputs",
               inputSchema={"type": "object", "properties": {"t": {"type": "string"}}}),
]


async def main() -> None:
    # SDK v2: handlers are constructor kwargs `(ctx, params) -> result model`; the decorator
    # registration and the implicit exception->isError wrapping are gone, so the error result is
    # built explicitly to keep the same wire behaviour v1 gave these tools.
    async def _list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=TOOLS)

    async def _call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        name, arguments = params.name, params.arguments or {}
        try:
            if name == "read_inbox":
                text = "you have 3 new messages"
            elif name == "send_slack_message":
                text = "posted"
            elif name == "get_config":
                text = "api_key: sk-LIVEFIXTURESECRETVALUE1234"
            elif name == "hang_forever":
                await asyncio.sleep(999)
                text = "unreachable"
            elif name == "boom":
                raise RuntimeError("simulated unexpected internal error")
            elif name == "die_now":
                # The backend PROCESS dies, mid-session, without closing anything politely — the
                # real shape of a crashed server, which a raised exception does not reproduce
                # (that leaves the transport perfectly healthy).
                os._exit(1)
            elif name == "echo_env":
                text = os.environ.get(arguments.get("var", ""), "<unset>")
            elif name == "run_op":
                text = f"ran {arguments.get('t', '<none>')}"
            else:
                raise ValueError(f"unknown tool: {name}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return types.CallToolResult(
                is_error=True, content=[types.TextContent(type="text", text=str(exc))])
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    server: Server = Server("toy-fixture", on_list_tools=_list_tools, on_call_tool=_call_tool)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
