"""D12 (docs/rca-report-defects-2026-09-25-failures.md#D12): agentic-news answers a sign-in-less
`initialize` with 401 + WWW-Authenticate, then answers our 2026-08-13 discover fallback with 400
"No valid session ID". The status hook kept only the LAST status, so the 401 was overwritten and a
live endpoint that wanted a sign-in read "UNREACHABLE — no MCP endpoint found". A loopback stub
reproduces the wire behaviour exactly."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mcpgawk import probe


class _TsExpressShape(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        if body.get("method") == "initialize":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource"')
            self.send_header("content-length", "0")
            self.end_headers()
            return
        out = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                          "error": {"code": -32000, "message": "Bad Request: No valid session ID or initialization request"}}).encode()
        self.send_response(400)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self.send_response(404)
        self.send_header("content-length", "0")
        self.end_headers()


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TsExpressShape)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_a_refused_initialize_stays_auth_required_after_the_fallback():
    srv = _serve()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/mcp"
        snap = asyncio.run(probe.probe_http("cli-http", url, timeout=20))
        assert snap.error_kind == "auth-required", snap.error
    finally:
        srv.shutdown()


def _response(code, headers=None):
    """A real response, as the transport hands the hook one: the POST it answers, and — for a 2xx —
    the JSON body type an MCP server sends. The hook reads both (T1/T2, 2026-09-25)."""
    import httpx2
    request = httpx2.Request("POST", "https://mcp.example.test/mcp")
    if headers is None:
        headers = {"content-type": "application/json"} if 200 <= code < 300 else {}
    return httpx2.Response(code, headers=headers, request=request)


def _replay(*codes):
    seen, hook = probe._status_recorder()
    for c in codes:
        asyncio.run(hook(c if not isinstance(c, int) else _response(c)))
    return seen["refused"] or seen["status"]


def test_a_refusal_outranks_a_later_web_page():
    """D12 order kept: a 401 on initialize, then a challenge-less 403 page from the fallback
    request, is still a sign-in wall — the not-MCP mark never outranks a recorded refusal."""
    seen, hook = probe._status_recorder()
    asyncio.run(hook(_response(401, {"www-authenticate": "Bearer"})))
    asyncio.run(hook(_response(403, {"content-type": "text/html"})))
    assert seen["refused"] == 401 and seen["not_mcp"] is True
    assert probe._not_mcp_signal(seen) is False          # probe_http's hint: stays auth-required
    seen, hook = probe._status_recorder()
    asyncio.run(hook(_response(403, {"content-type": "text/html"})))
    assert probe._not_mcp_signal(seen) is True           # the page alone: not an MCP endpoint


def test_what_proves_a_url_is_not_mcp():
    """The rule itself (`_not_mcp_answer`), each arm pinned — including what it must NOT read."""
    page = {"content-type": "text/html; charset=utf-8"}
    assert probe._not_mcp_answer(_response(403, page), credentialed=False)          # npmjs.com
    assert not probe._not_mcp_answer(_response(403, page), credentialed=True)       # Axiom
    assert not probe._not_mcp_answer(
        _response(403, {"www-authenticate": 'Bearer error="insufficient_scope"'}), False)
    assert probe._not_mcp_answer(_response(200, page), False)                        # pypi.org
    assert probe._not_mcp_answer(_response(404), False)                               # wrong path
    for ok in ({"content-type": "application/json"}, {"content-type": "text/event-stream"}, {}):
        assert not probe._not_mcp_answer(_response(200, ok), False), ok
    assert not probe._not_mcp_answer(_response(202, page), False)                    # notification
    expired = _response(404)
    expired.request.headers["mcp-session-id"] = "abc"
    assert not probe._not_mcp_answer(expired, False)                                  # expired session


def test_the_refusal_is_latched_until_a_success():
    assert _replay(401, 400) == 401            # agentic-news
    assert _replay(401) == 401                 # gitbook shape, unchanged
    assert _replay(401, 200, 502) == 502       # signed in, then an outage: never "auth-required"
    assert _replay(400) == 400
