"""OBSERVE — connect to an MCP server via the official `mcp` SDK and snapshot it.

We use the maintained protocol client (`ClientSession` + the stdio/streamable-http/sse
transports). The SDK negotiates the protocol version and tracks the spec by definition, so
mcpgawk rides protocol evolution instead of owning a stale fork. We are a *one-shot client*,
not a man-in-the-middle proxy — that keeps us off the runtime-enforcement lane.

Egress note: the only network here is the SDK talking to the server being scanned. Nothing
about the captured inventory is sent anywhere else.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client

from .servercard import fetch_card


@dataclass
class ServerSnapshot:
    """Everything we captured from one server. Raw wire-shape tool dicts, so measurement
    sees exactly what a model's context would see."""
    name: str
    transport: str
    protocol_version: str | None
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)
    server_card: dict[str, Any] | None = None   # self-declared .well-known card (http/sse only)
    error: str | None = None


def _dump(items: list[Any]) -> list[dict[str, Any]]:
    """Pydantic model -> wire-shape dict (by_alias gives `inputSchema`, `readOnlyHint`, ...)."""
    out = []
    for it in items:
        if hasattr(it, "model_dump"):
            out.append(it.model_dump(by_alias=True, exclude_none=True, mode="json"))
        elif isinstance(it, dict):
            out.append(it)
    return out


async def _snapshot(session: ClientSession, name: str, transport: str) -> ServerSnapshot:
    init = await session.initialize()
    snap = ServerSnapshot(
        name=name,
        transport=transport,
        protocol_version=getattr(init, "protocolVersion", None),
        server_info=(init.serverInfo.model_dump(mode="json") if getattr(init, "serverInfo", None) else {}),
    )
    # tools/list is the load-bearing surface; prompts/resources are optional per server.
    snap.tools = _dump((await session.list_tools()).tools)
    for attr, method in (("prompts", "list_prompts"), ("resources", "list_resources")):
        try:
            res = await getattr(session, method)()
            setattr(snap, attr, _dump(getattr(res, attr)))
        except Exception:
            pass  # server doesn't advertise that capability — not an error for us
    return snap


# Per-server wall-clock bound. A hung / slow-loris server must degrade to ONE error row, never
# block the whole scan. Generous enough for a cold npx/uvx first-run install.
DEFAULT_TIMEOUT = 90.0


async def _bounded(coro_factory, name: str, transport: str, timeout: float) -> ServerSnapshot:
    try:
        return await asyncio.wait_for(coro_factory(), timeout)
    except Exception as e:  # noqa: BLE001 — incl. TimeoutError; surface, never crash the scan
        return ServerSnapshot(name=name, transport=transport, protocol_version=None,
                              error=f"{type(e).__name__}: {e}")


async def probe_stdio(name: str, command: str, args: list[str] | None = None,
                      env: dict[str, str] | None = None, timeout: float = DEFAULT_TIMEOUT) -> ServerSnapshot:
    async def _do():
        params = StdioServerParameters(command=command, args=args or [],
                                       env={**os.environ, **(env or {})})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                return await _snapshot(session, name, "stdio")
    return await _bounded(_do, name, "stdio", timeout)


async def probe_http(name: str, url: str, headers: dict[str, str] | None = None,
                     timeout: float = DEFAULT_TIMEOUT) -> ServerSnapshot:
    """Streamable-HTTP transport — for hosted MCPs. `headers` carries a user-supplied bearer/OAuth
    token for the MCP connection ONLY; the public Server Card fetch never sees it (see servercard.py)."""
    async def _do():
        async with streamablehttp_client(url, headers=headers or {}) as (read, write, _sid):
            async with ClientSession(read, write) as session:
                snap = await _snapshot(session, name, "http")
        snap.server_card = await fetch_card(url)   # public, unauthenticated; tolerant
        return snap
    return await _bounded(_do, name, "http", timeout)


async def probe_sse(name: str, url: str, headers: dict[str, str] | None = None,
                    timeout: float = DEFAULT_TIMEOUT) -> ServerSnapshot:
    async def _do():
        async with sse_client(url, headers=headers or {}) as (read, write):
            async with ClientSession(read, write) as session:
                snap = await _snapshot(session, name, "sse")
        snap.server_card = await fetch_card(url)
        return snap
    return await _bounded(_do, name, "sse", timeout)


async def probe(entry: dict[str, Any], name: str) -> ServerSnapshot:
    """Dispatch a config entry (mcp.json shape) to the right transport."""
    if entry.get("command"):
        return await probe_stdio(name, entry["command"], entry.get("args"), entry.get("env"))
    url = entry.get("url")
    if not url:
        return ServerSnapshot(name=name, transport="?", protocol_version=None,
                              error="entry has neither `command` (stdio) nor `url` (http/sse)")
    transport = entry.get("transport", "http")
    headers = entry.get("headers")
    return await (probe_sse if transport == "sse" else probe_http)(name, url, headers)
