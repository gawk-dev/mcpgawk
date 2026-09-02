"""`mcpgawk-obot-filter` — the verdict core (obot_filter.py) wearing an MCP server.

Obot registers a filter as an ordinary MCP server exposing ONE tool, and calls that tool before
forwarding each message. Deployment runtimes are remote URL / containerized / npx / uvx, so this
speaks stdio and is reachable as `uvx --from mcpgawk mcpgawk-obot-filter`.

Two things here are not decoration:

  * **structuredContent, always.** Obot's hook runner accepts `structuredContent`, and falls back
    to parsing a single text block as JSON. If it can do NEITHER it returns nil,nil and the call
    is passed through unjudged — their gateway is fail-closed on our errors but fail-OPEN on our
    unparseable answers. We emit both forms, every time.
  * **The startup coverage line.** A filter with no approved baselines defers on everything, which
    maps to accept: it would sit in the request path looking installed while guarding nothing.
    That is the exact shape of "availability yes, ambiguity no" — so this server states its
    coverage on stderr at startup, and every unevaluated verdict repeats it per call.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import (CallToolRequestParams, CallToolResult, ListToolsResult, TextContent, Tool,
                       ToolAnnotations)

from . import __version__, history, obot_filter

SERVER_NAME = "mcpgawk-obot-filter"


def _guarded_server() -> str | None:
    return (os.environ.get("MCPGAWK_SERVER") or "").strip() or None


def coverage_note(store_path: str | None = None) -> str:
    """What this instance can actually rule on, in one sentence, said before anything is served.

    Read from the same store the verdicts come from, so the announcement cannot claim a coverage
    the decision path does not have.
    """
    server = _guarded_server()
    try:
        # load_checked, not load: `load` degrades an unreadable store to an empty one, and
        # "nothing is approved" would then be indistinguishable from "the file holding every
        # approval could not be read" — the false all-clear this product exists to prevent.
        store, err = history.load_checked(store_path)
        if err:
            return (f"{SERVER_NAME}: the approval store is UNREADABLE ({err}). Every call will "
                    f"pass UNEVALUATED — this filter is not guarding anything.")
        servers = (store or {}).get("servers") or {}
        approved = sorted(k for k, v in servers.items()
                          if isinstance(v, dict) and isinstance(v.get("approved"), dict))
    except Exception as exc:                       # noqa: BLE001 - never fail to start over this
        return (f"{SERVER_NAME}: could NOT read the approval store ({type(exc).__name__}: {exc}). "
                f"Every call will pass UNEVALUATED — this filter is not guarding anything yet.")

    if not approved:
        return (f"{SERVER_NAME}: this machine has approved NO servers, so every call will pass "
                f"UNEVALUATED — the filter is installed but guarding nothing. Run `mcpgawk scan` "
                f"and approve a server, or mount the operator's ~/.mcpgawk into this environment.")
    if server is None:
        return (f"{SERVER_NAME}: MCPGAWK_SERVER is not set, so every call passes UNEVALUATED. "
                f"Obot does not tell a filter which server a call is headed for; set it to one of "
                f"the {len(approved)} approved baselines ({', '.join(approved)}) and attach this "
                f"instance to that server with a server-name selector.")
    # Resolved through the VERDICT path's own lookup, never by membership in the key list. Store
    # keys are qualified (`mcp:vault-rag`), and the decision core resolves a bare name through the
    # exact key, then the `mcp:` form, then aliases — so a naive `server in approved` announces
    # "not guarded" for servers it would in fact guard. An announcement that disagrees with the
    # enforcing path is the two-sources-of-truth defect, and the operator believes the announcement.
    from . import guard_hook

    store_file = Path(store_path) if store_path is not None else Path(history.default_path())
    if guard_hook.approved_for(server, store_file) is None:
        return (f"{SERVER_NAME}: guarding {server!r}, which has NO approved baseline here — every "
                f"call will pass UNEVALUATED. Approved on this machine: "
                f"{', '.join(approved) or 'nothing'}.")
    return (f"{SERVER_NAME} {__version__}: guarding {server!r} against its approved baseline. "
            f"{len(approved)} server(s) approved on this machine; anything else passes "
            f"UNEVALUATED.")


def build_server() -> Server:
    async def list_tools(ctx: Any, params: Any) -> ListToolsResult:
        return ListToolsResult(tools=[
            Tool(
                name=obot_filter.TOOL_NAME,
                # Read by Obot's operator, and by any model that lists this server. Plain
                # description: a security tool writing imperative instructions into its own tool
                # text would fail its own scan.
                description=(
                    "Rule on one MCP message for the Obot gateway. Returns "
                    "{accept, mutated, reason}: accept=false when mcpgawk's approved baseline for "
                    "this server denies the tool call, accept=true otherwise, with a reason that "
                    "says whether the call was evaluated or passed unevaluated."
                ),
                # It reads a local store and writes a decision record. It starts nothing, reaches
                # no network, and never modifies the message it is shown.
                annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False,
                                            idempotent_hint=True, open_world_hint=False),
                input_schema={
                    "type": "object",
                    "properties": {
                        "message": {"type": "object",
                                    "description": "The JSON-RPC message being filtered."},
                        "accept": {"type": "boolean"},
                        "mutated": {"type": "boolean"},
                        "reason": {"type": "string"},
                    },
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "accept": {"type": "boolean"},
                        "mutated": {"type": "boolean"},
                        "reason": {"type": "string"},
                    },
                    "required": ["accept", "mutated", "reason"],
                },
            ),
        ])

    async def call_tool(ctx: Any, params: CallToolRequestParams) -> CallToolResult:
        args = params.arguments or {}
        if params.name != obot_filter.TOOL_NAME:
            # Not a shape we can rule on. Answering in the verdict shape (rather than raising) is
            # deliberate: a raise reaches Obot as a filter error and blocks the call.
            verdict = {"accept": True, "mutated": False,
                       "reason": f"mcpgawk: {params.name!r} is not this filter's tool "
                                 f"({obot_filter.TOOL_NAME}) — passed unjudged"}
        else:
            # evaluate() is total: it answers in the shape on every path, including its own
            # failures, so there is nothing to catch here.
            verdict = obot_filter.evaluate(args)
        # BOTH forms, every time — see the module docstring.
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(verdict))],
            structured_content=verdict,
        )

    return Server(SERVER_NAME, version=__version__,
                  on_list_tools=list_tools, on_call_tool=call_tool)


async def _serve() -> None:
    server = build_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


#: The MCP path Obot is pointed at when this runs as a `remote` filter.
HTTP_PATH = "/mcp"


def _serve_http(host: str, port: int) -> int:
    """Streamable HTTP, for the deployment Obot actually uses in anger: it runs in a container and
    reaches the filter over a URL.

    uvicorn and starlette are NOT dependencies of the published mcpgawk wheel — it is a scanner,
    and a web stack is real weight for every user who will never serve anything. So this path is
    an OPTIONAL extra that says so plainly. The alternative (importing at module scope) would make
    `pip install mcpgawk` ship a server that cannot start, which is the same defect the package's
    own dependency list was once burned by: present on every dev machine, absent in the wheel.
    """
    try:
        import uvicorn
    except ModuleNotFoundError:
        print(f"{SERVER_NAME}: serving over HTTP needs the optional web stack. Install it with "
              f"`pip install 'mcpgawk[gateway]'` (or run this filter over stdio instead, which "
              f"needs nothing extra).", file=sys.stderr)
        return 2

    app = build_server().streamable_http_app(streamable_http_path=HTTP_PATH,
                                             stateless_http=True, host=host)
    print(f"{SERVER_NAME}: serving MCP on http://{host}:{port}{HTTP_PATH}", file=sys.stderr,
          flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        # Said on every start, not only when the flag was typed: this filter answers with verdicts
        # about somebody's fleet, and an operator reading logs later must see that it is reachable
        # off-box.
        print(f"{SERVER_NAME}: WARNING — bound to {host}, reachable beyond this machine.",
              file=sys.stderr, flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for `mcpgawk-obot-filter` (and `python -m mcpgawk.obot_filter_server`)."""
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        print("Usage:\n"
              "  mcpgawk.obot_filter_server                       serve over stdio (uvx/npx/\n"
              "                                                   containerized runtimes)\n"
              "  mcpgawk.obot_filter_server --http [--host H] [--port P]\n"
              "                                                   serve over streamable HTTP for\n"
              "                                                   Obot's `remote` runtime\n"
              "                                                   (needs mcpgawk[gateway])\n"
              "  mcpgawk.obot_filter_server --coverage            what this instance would guard\n")
        print("Environment:\n"
              "  MCPGAWK_SERVER               the baseline key this instance guards (required to\n"
              "                               evaluate anything — Obot never sends it)\n"
              "  MCPGAWK_FILTER_FAIL_CLOSED   reject calls this filter could not evaluate\n"
              "  MCPGAWK_HISTORY              path to the approval store (default ~/.mcpgawk)\n")
        return 0
    if argv and argv[0] == "--coverage":
        print(coverage_note())
        return 0
    if argv and argv[0] == "--http":
        host, port = "127.0.0.1", 8199
        rest = argv[1:]
        if rest and rest[0] == "--host":
            host, rest = rest[1], rest[2:]
        if rest and rest[0] == "--port":
            port = int(rest[1])
        print(coverage_note(), file=sys.stderr, flush=True)
        return _serve_http(host, port)
    # stderr, not stdout: stdout is the MCP transport.
    print(coverage_note(), file=sys.stderr, flush=True)
    asyncio.run(_serve())
    return 0


if __name__ == "__main__":                         # pragma: no cover
    raise SystemExit(main())
