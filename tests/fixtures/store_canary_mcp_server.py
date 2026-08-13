"""A fixture server that puts a CREDENTIAL-SHAPED value in every server-controlled field that
reaches `~/.mcpgawk/history.json`, one distinct canary per field.

ADR-0012 says redaction happens at the persistence boundary. Only descriptions were ever passed
through `redact()` (drift.py `_item_texts`), so this fixture exists to measure the other fields
rather than reason about them: a resource URI and a tool name both become the fingerprint KEY, and
a key was never redacted.

Never imported — launched as a subprocess like a real third-party server.
"""
from __future__ import annotations

import asyncio

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

DESC_CANARY = "apiKey=CANARY_DESC_98765"          # control: drift.py already redacts descriptions
NAME_CANARY = "apiKey=CANARY_NAME_98765"          # becomes the fingerprint key
URI_CANARY = "apiKey=CANARY_URI_98765"            # becomes the fingerprint key
PROMPT_CANARY = "apiKey=CANARY_PROMPT_98765"
SCHEMA_CANARY = "apiKey=CANARY_SCHEMA_98765"      # an input-schema property description
ANNOT_CANARY = "apiKey=CANARY_ANNOT_98765"        # a tool annotation title

TOOLS = [
    types.Tool(name="ordinary_tool", description=f"Fetch with {DESC_CANARY} attached",
               inputSchema={"type": "object", "properties": {}}),
    types.Tool(name=f"fetch_{NAME_CANARY}", description="A tool whose NAME carries the secret",
               inputSchema={"type": "object", "properties": {}}),
    # A MUTATING verb, so verify SKIPS it — the skipped list is one of the two places a tool name
    # reaches behaviour.json and last-verify.json (the other is a finding).
    types.Tool(name=f"send_{NAME_CANARY}", description="Mutating, so it lands in the skipped list",
               inputSchema={"type": "object", "properties": {}}),
    types.Tool(name="schema_tool", description="A tool whose input SCHEMA carries the secret",
               inputSchema={"type": "object", "properties": {
                   "q": {"type": "string", "description": f"query, e.g. {SCHEMA_CANARY}"}}},
               annotations=types.ToolAnnotations(title=f"Titled {ANNOT_CANARY}")),
]
RESOURCES = [
    # NO `name`: `_item_texts` uses `name or uri`, so a named resource never exercises the URI
    # path at all. A URI-only resource is the ordinary shape, and it is the one that measures this.
    types.Resource(uri=f"https://host.invalid/doc?clientId=abc&{URI_CANARY}",
                   name="", description="A resource whose URI carries the secret"),
]
PROMPTS = [
    types.Prompt(name="summarise", description=f"Prompt text with {PROMPT_CANARY} in it"),
]


async def main() -> None:
    async def _list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=TOOLS)

    async def _list_resources(ctx, params) -> types.ListResourcesResult:
        return types.ListResourcesResult(resources=RESOURCES)

    async def _list_prompts(ctx, params) -> types.ListPromptsResult:
        return types.ListPromptsResult(prompts=PROMPTS)

    async def _call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    server: Server = Server("store-canary", on_list_tools=_list_tools, on_call_tool=_call_tool,
                            on_list_resources=_list_resources, on_list_prompts=_list_prompts)
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
