"""A server that speaks ONLY the 2026-07-28 revision — the shape the ecosystem is upgrading to.

Hand-rolled JSON-RPC over stdio (same pattern as demo.py's fixture), because the SDK's Server
always negotiates down and the point of this fixture is a server that REFUSES to: the 2026-07-28
spec is backward-incompatible in both directions, so post-upgrade servers with this behaviour are
the case our tooling has to survive.
"""
from __future__ import annotations

import json
import sys

REVISION = "2026-07-28"
TOOLS = [{"name": "modern_tool", "description": "Only reachable over the 2026-07-28 revision",
          "inputSchema": {"type": "object", "properties": {}}}]


def send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    if "id" not in msg:
        continue
    mid, method = msg["id"], msg.get("method")
    if method == "server/discover":
        # The MODERN handshake (2026-07-28): one request, no session, the server states what it
        # supports and the client adopts. This is what a post-upgrade server answers.
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "supportedVersions": [REVISION],
            "capabilities": {"tools": {}},
            "resultType": "complete"}})
    elif method == "initialize":
        # A modern-only server: the LEGACY handshake is refused outright — the backward-
        # incompatible half of the spec, and the case our probe must survive by falling back
        # the other way (discover first, initialize only for legacy servers).
        send({"jsonrpc": "2.0", "id": mid,
              "error": {"code": -32601,
                        "message": f"initialize is not supported; use server/discover ({REVISION})"}})
    elif method == "tools/list":
        # 2026-07-28 list results are CACHEABLE and the client validates the envelope strictly.
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "tools": TOOLS, "resultType": "complete", "cacheScope": "private", "ttlMs": 0}})
    elif method == "tools/call":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": "ok"}], "isError": False}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    else:
        send({"jsonrpc": "2.0", "id": mid,
              "error": {"code": -32601, "message": "Method not found"}})
