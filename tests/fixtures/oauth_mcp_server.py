"""A real OAuth-protected MCP server: DCR + PKCE + authorization code, over a real socket.

The repo has no fixture like this. `toy_http_mcp_server.py` gates on a STATIC bearer token, and
`test_remote_login_verify.py` only checks that an already-stored token is replayed — so the actual
`mcpgawk scan --login` round-trip (discover the AS, register a client, PKCE, catch the redirect,
exchange the code) has never been driven against anything.

Everything here is the real protocol:
  GET  /mcp                                     -> 401 + WWW-Authenticate: Bearer resource_metadata=...
  GET  /.well-known/oauth-protected-resource    -> which AS guards this resource
  GET  /.well-known/oauth-authorization-server  -> AS metadata (also served under any suffix)
  POST /register                                -> dynamic client registration, returns client_id
  GET  /authorize                               -> 302 back to the client's loopback with ?code=
  POST /token                                   -> verifies S256 PKCE, returns an access token
  /mcp with that token                          -> a normal MCP server (two plausible tools)

The only part a test stubs is the human's click: `webbrowser.open` is replaced with a fetch of the
authorize URL that follows the 302. Registration, PKCE, the loopback callback and the
code-for-token exchange are all real traffic against this server.

Launched as a subprocess by tests/test_remote_oauth_login.py.

Usage: python oauth_mcp_server.py --port 8951
Prints "LISTENING <port>" once bound, so a test waits on a readiness signal instead of sleeping.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import secrets

import mcp.types as types
import uvicorn
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, Route

TOOLS = [
    types.Tool(name="list_repos", description="List the user's repositories",
               inputSchema={"type": "object", "properties": {}}),
    types.Tool(name="read_issue", description="Read one issue by number",
               inputSchema={"type": "object",
                            "properties": {"number": {"type": "integer"}}}),
]

BASE = ""                       # filled in once the port is known
CLIENTS: dict[str, dict] = {}   # client_id -> registration
CODES: dict[str, dict] = {}     # code -> {challenge, redirect_uri, client_id}
TOKENS: set[str] = set()        # issued access tokens
AUTHORIZE_HITS: list[str] = []  # every /authorize the "browser" actually reached


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


async def protected_resource(request):
    return JSONResponse({
        "resource": f"{BASE}/mcp",
        "authorization_servers": [BASE],
        "bearer_methods_supported": ["header"],
    })


async def as_metadata(request):
    return JSONResponse({
        "issuer": BASE,
        "authorization_endpoint": f"{BASE}/authorize",
        "token_endpoint": f"{BASE}/token",
        "registration_endpoint": f"{BASE}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["mcp:read"],
    })


async def register(request):
    """Dynamic client registration — the client has no pre-issued id, exactly like a real first run."""
    body = await request.json()
    client_id = "dcr-" + secrets.token_hex(8)
    CLIENTS[client_id] = body
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": 0,
        "redirect_uris": body.get("redirect_uris", []),
        "token_endpoint_auth_method": "none",
        **{k: v for k, v in body.items() if k in ("client_name", "grant_types", "response_types")},
    }, status_code=201)


async def authorize(request):
    """The page a human would see and approve. We approve immediately and bounce back with a code."""
    q = request.query_params
    AUTHORIZE_HITS.append(str(request.url))
    if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
        return JSONResponse({"error": "invalid_request", "detail": "PKCE S256 required"}, 400)
    if q.get("client_id") not in CLIENTS:
        return JSONResponse({"error": "unauthorized_client"}, 400)

    code = secrets.token_urlsafe(16)
    CODES[code] = {"challenge": q["code_challenge"], "client_id": q["client_id"],
                   "redirect_uri": q.get("redirect_uri", "")}
    sep = "&" if "?" in CODES[code]["redirect_uri"] else "?"
    back = f"{CODES[code]['redirect_uri']}{sep}code={code}"
    if q.get("state"):
        back += f"&state={q['state']}"
    return RedirectResponse(back, status_code=302)


async def token(request):
    form = await request.form()
    code = form.get("code", "")
    record = CODES.pop(code, None)
    if record is None:
        return JSONResponse({"error": "invalid_grant"}, 400)
    verifier = form.get("code_verifier", "")
    if not verifier or _s256(verifier) != record["challenge"]:
        return JSONResponse({"error": "invalid_grant", "detail": "PKCE verify failed"}, 400)

    access = "at-" + secrets.token_urlsafe(24)
    TOKENS.add(access)
    return JSONResponse({"access_token": access, "token_type": "Bearer",
                         "expires_in": 3600, "scope": "mcp:read"})


def build_app() -> Starlette:
    async def _list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=TOOLS)

    async def _call_tool(ctx, params) -> types.CallToolResult:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"ok:{params.name}")])

    server = Server("oauth-fixture", on_list_tools=_list_tools, on_call_tool=_call_tool)
    manager = StreamableHTTPSessionManager(app=server, json_response=False, stateless=True)

    async def handle_mcp(scope, receive, send):
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in TOKENS:
            # The challenge is the whole discovery entry point: it names where to find the AS.
            resp = JSONResponse({"error": "invalid_token"}, status_code=401, headers={
                "WWW-Authenticate": 'Bearer realm="mcp", error="invalid_token", '
                                    f'resource_metadata="{BASE}/.well-known/oauth-protected-resource"'})
            await resp(scope, receive, send)
            return
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with manager.run():
            yield

    # The SDK probes several well-known spellings; serve the AS metadata under any of them.
    return Starlette(routes=[
        Route("/.well-known/oauth-protected-resource", protected_resource),
        Route("/.well-known/oauth-protected-resource/{rest:path}", protected_resource),
        Route("/.well-known/oauth-authorization-server", as_metadata),
        Route("/.well-known/oauth-authorization-server/{rest:path}", as_metadata),
        Route("/.well-known/openid-configuration", as_metadata),
        Route("/register", register, methods=["POST"]),
        Route("/authorize", authorize, methods=["GET"]),
        Route("/token", token, methods=["POST"]),
        Route("/_hits", lambda r: JSONResponse(AUTHORIZE_HITS)),
        Mount("/mcp", app=handle_mcp),
    ], lifespan=lifespan)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()

    global BASE
    BASE = f"http://127.0.0.1:{args.port}"

    config = uvicorn.Config(build_app(), host="127.0.0.1", port=args.port, log_level="error")
    server = uvicorn.Server(config)

    import asyncio

    async def _run() -> None:
        task = asyncio.create_task(server.serve())
        while not server.started:
            await asyncio.sleep(0.02)
        print(f"LISTENING {args.port}", flush=True)
        await task

    asyncio.run(_run())


if __name__ == "__main__":
    main()
