"""A REAL 401, over a REAL transport, through the real prober.

Why this file exists even though `test_transport_permutation.py` already has three passing
"auth" tests: those hand `_aggregate_failure` a failure that is ALREADY tagged `auth-required`
(see its `_fail(..., "auth-required")` helper) or call `_kind_of` with a hand-built `httpx`
error. Both stub out the one step that was broken. The shipped scanner reported a live
auth-walled server as UNREACHABLE — "no MCP endpoint found … Is it a live MCP endpoint?" —
because SDK v2's transports raise `httpx2.HTTPStatusError`, whose `__name__` is also
"HTTPStatusError", while `_kind_of` only ever tested `isinstance(exc, httpx.HTTPStatusError)`.
Every real 401 fell through to "unreachable" and three green tests never noticed.

So this test drives the transport for real and asserts the two things the user actually gets:
the right verdict, and a ladder that STOPS — because continuing to permute after a 401 offers a
supplied bearer token to every other path on the host.
"""
from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcpgawk.probe import probe_url

FIXTURE = Path(__file__).parent / "fixtures" / "toy_http_mcp_server.py"
TOKEN = "SECRET-TEST-TOKEN"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def walled_url():
    """A real HTTP MCP server that 401s anything without the token. Readiness is the server's own
    LISTENING line, never a sleep."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(FIXTURE), "--port", str(port), "--require-token", TOKEN],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.stdout.readline().startswith("LISTENING"):
                break
            if proc.poll() is not None:
                raise RuntimeError(f"fixture died: {proc.stderr.read()[:400]}")
        else:
            raise RuntimeError("fixture never reported LISTENING")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


def _attempt_lines(snap) -> list[str]:
    return [ln for ln in snap.error.splitlines() if ln.strip().startswith("- ")
            and "not attempted" not in ln]


def test_kind_of_classifies_the_httpx2_error_the_sdk_actually_raises():
    """Pins the httpx2 arm DIRECTLY, because the end-to-end tests do not.

    A review found that reverting `_kind_of`'s httpx2 branch left the whole suite green: on the
    streamable-HTTP path the status-recorder fallback reaches the same verdict by another route, so
    the end-to-end assertions could not tell the two mechanisms apart. The SSE path has no recorder
    and depends on this branch alone, and `httpx2.HTTPStatusError` is NOT a subclass of the plain
    `httpx` one — same class name, different package, which is exactly why the bug survived review
    the first time.
    """
    import httpx2

    from mcpgawk.probe import _kind_of

    request = httpx2.Request("GET", "https://example.test/sse")
    for status, expected in ((401, "auth-required"), (403, "auth-required"),
                             (404, "not-an-mcp-endpoint")):
        err = httpx2.HTTPStatusError(
            f"Client error '{status}'", request=request,
            response=httpx2.Response(status, request=request))
        assert _kind_of(err) == expected, f"httpx2 {status} misread as {_kind_of(err)!r}"


def test_real_401_is_classified_auth_required(walled_url):
    """The verdict a user sees for a server that needs signing in to."""
    snap = asyncio.run(probe_url("walled", walled_url))

    assert snap.error_kind == "auth-required", (
        f"a live 401 must not read as {snap.error_kind!r} — that sends the user to check their "
        f"URL when the fix is a token. Got:\n{snap.error}")
    # The head line is the whole point of the classification: it names the two ways out.
    assert "authentication required" in snap.error
    assert "--login" in snap.error and "Authorization: Bearer" in snap.error


def test_ladder_stops_on_401_so_a_token_is_not_offered_around(walled_url):
    """A 401 ends the permutation. Continuing would hand a supplied credential to every other
    path on that host — observed live: one `--header` token reached /mcp, /, /sse and / again."""
    snap = asyncio.run(probe_url(
        "walled", walled_url, headers={"Authorization": f"Bearer {TOKEN}-WRONG"}))

    assert snap.error_kind == "auth-required"
    assert len(_attempt_lines(snap)) == 1, (
        "the ladder kept probing after a 401, replaying the credential:\n" + snap.error)


def test_a_good_token_still_scans(walled_url):
    """The negative control: classification changes nothing for a caller that IS allowed in."""
    snap = asyncio.run(probe_url(
        "walled", walled_url, headers={"Authorization": f"Bearer {TOKEN}"}))

    assert snap.error is None, f"authorised scan failed: {snap.error}"
    assert snap.tools, "authorised scan returned no tools"
