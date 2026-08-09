"""The SAME toy MCP server as toy_mcp_server.py, served over a REAL HTTP transport.

Launched as a subprocess by tests/test_enforce_remote.py, which then points `gawk-enforce serve
--http http://127.0.0.1:<port>/mcp` at it. Nothing is mocked: a genuine socket, a genuine
Streamable-HTTP (or SSE) transport, a genuine MCP handshake. The tool set is imported from the
stdio fixture rather than re-declared, so a local-vs-remote test can compare like with like and
the two fixtures cannot drift apart.

Usage:  python toy_http_mcp_server.py --port 8931 [--transport http|sse]
Prints "LISTENING <port>" on stdout once bound, so the test waits on a real readiness signal
instead of sleeping and hoping.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import sys
from pathlib import Path

import mcp.types as types
import uvicorn
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount, Route

sys.path.insert(0, str(Path(__file__).parent))
from toy_mcp_server import TOOLS  # noqa: E402 — path set above; one source of truth for the tools


def build_server(tools: "list[types.Tool] | None" = None) -> Server:
    # SDK v2: handlers are `(ctx, params) -> result model` constructor kwargs, so the tool list
    # is a parameter now instead of v1's decorator re-registration trick in build_app.
    serve_tools = tools if tools is not None else TOOLS

    async def _list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=serve_tools)

    async def _call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        # Same behaviours as the stdio fixture, so a test can assert the proxy treats a remote
        # backend identically: same redaction, same toxic-flow, same timeout handling.
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
            elif name == "echo_env":
                text = os.environ.get(arguments.get("var", ""), "<unset>")
            elif name == "echo_header":
                # Remote-only: proves a header actually crossed the wire to the backend.
                text = _LAST_HEADERS.get(arguments.get("name", "").lower(), "<absent>")
            else:
                raise ValueError(f"unknown tool: {name}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return types.CallToolResult(
                is_error=True, content=[types.TextContent(type="text", text=str(exc))])
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    return Server("toy-http-fixture", on_list_tools=_list_tools, on_call_tool=_call_tool)


#: Last request's headers, so `echo_header` can prove what the proxy actually sent upstream.
_LAST_HEADERS: dict[str, str] = {}
#: When set (--require-token), every request must carry exactly this bearer token or get a 401.
_REQUIRED_TOKEN: str | None = None

HTTP_TOOLS = [*TOOLS, types.Tool(
    name="echo_header", description="Echo a header this server actually received",
    inputSchema={"type": "object", "properties": {"name": {"type": "string"}}})]


def build_app(transport: str) -> Starlette:
    # Serve the extra remote-only tool as well.
    server = build_server(HTTP_TOOLS)

    if transport == "sse":
        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            _LAST_HEADERS.update({k.lower(): v for k, v in request.headers.items()})
            async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
                await server.run(streams[0], streams[1], server.create_initialization_options())
            from starlette.responses import Response
            return Response()

        return Starlette(routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ])

    manager = StreamableHTTPSessionManager(app=server, json_response=False, stateless=True)

    async def handle_http(scope, receive, send):
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        _LAST_HEADERS.update(headers)
        # Optional bearer gate, so a test can prove the OAuth-token path end to end without
        # depending on a third-party server and an interactive consent flow.
        if _REQUIRED_TOKEN is not None:
            if headers.get("authorization") != f"Bearer {_REQUIRED_TOKEN}":
                from starlette.responses import JSONResponse
                await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
                return
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with manager.run():
            yield

    return Starlette(routes=[Mount("/mcp", app=handle_http)], lifespan=lifespan)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--transport", choices=["http", "sse"], default="http")
    ap.add_argument("--require-token", default=None,
                    help="401 every request that does not carry exactly this bearer token")
    args = ap.parse_args()

    global _REQUIRED_TOKEN
    _REQUIRED_TOKEN = args.require_token

    app = build_app(args.transport)
    config = uvicorn.Config(app, host="127.0.0.1", port=args.port, log_level="error")
    server = uvicorn.Server(config)

    # Readiness signal: the test waits for this line rather than sleeping.
    async def _run() -> None:
        task = asyncio.create_task(server.serve())
        while not server.started:
            await asyncio.sleep(0.02)
        print(f"LISTENING {args.port}", flush=True)
        await task

    asyncio.run(_run())


if __name__ == "__main__":
    main()
