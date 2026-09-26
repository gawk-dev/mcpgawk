"""A URL whose host name does not resolve is a typo, a DNS problem or a missing VPN — say that.

Sweep of unseen servers, 2026-09-25 (docfork): every attempt failed with
`ConnectError: [Errno 8] nodename nor servname provided`, and the report headed it "no MCP
endpoint found" with the catch-all hint "A docs / repo / package URL is not one". Nothing was
contacted, so nothing can have answered as a docs page; the hint sent the reader to the wrong
fix. Typed by the `socket.gaierror` in the cause chain, never by the message text.

`.invalid` is reserved never to resolve (RFC 6761), so these tests need no live host.
"""
from __future__ import annotations

import asyncio
import socket

from mcpgawk import cli
from mcpgawk.fleet import state_of
from mcpgawk.label import build_label, render_cli
from mcpgawk.measure import measure
from mcpgawk.probe import ServerSnapshot, _aggregate_failure, _kind_of, probe

URL = "https://mcp-nothing-here.invalid/mcp"


def _dns_failure() -> BaseException:
    """The chain the SDK raises (measured): httpx2.ConnectError <- httpcore2.ConnectError <-
    socket.gaierror. The outer type is the same one a refused connection raises."""
    import httpx2
    inner = socket.gaierror(8, "nodename nor servname provided, or not known")
    outer = httpx2.ConnectError(str(inner))
    outer.__cause__ = inner
    return outer


def test_a_dns_failure_is_typed_by_its_cause_not_its_wording():
    assert _kind_of(_dns_failure(), transport="http") == "host-not-found"
    refused = __import__("httpx2").ConnectError("[Errno 61] Connection refused")
    refused.__cause__ = ConnectionRefusedError(61, "Connection refused")
    assert _kind_of(refused, transport="http") == "connect-failed", "a refusal is not a DNS miss"


def test_the_real_probe_names_the_host_that_does_not_resolve():
    snap = asyncio.run(probe({"url": URL}, "typo"))
    assert snap.is_failure
    assert snap.error_kind == "host-not-found", snap.error
    assert "mcp-nothing-here.invalid" in (snap.error or "")
    assert "no MCP endpoint found" not in (snap.error or "")


def test_the_row_and_the_report_point_at_the_name_not_at_a_docs_page():
    snap = asyncio.run(probe({"url": URL}, "typo"))
    label = build_label(snap, measure(snap))
    state, detail = state_of(label)
    assert state == "UNREACHABLE"            # an existing state: the IDE FleetState union is closed
    assert "does not resolve" in detail
    text = render_cli(label, verbose=False)
    assert "A docs / repo / package URL is not one" not in text
    assert "spelling" in text and "VPN" in text


def _attempt(label: str, kind: str) -> tuple[str, ServerSnapshot]:
    return label, ServerSnapshot(name="x", transport="http", protocol_version=None,
                                 error="ConnectError: ...", error_kind=kind)


def test_one_path_answering_outranks_the_name_not_resolving():
    """Only when EVERY attempt failed to resolve is the name the problem. The ladder tries one
    host, so a mix means something else answered; the other rules decide."""
    snap = _aggregate_failure("x", "http", [_attempt("http /mcp", "host-not-found"),
                                            _attempt("sse /sse", "timed-out")], [], url=URL)
    assert snap.error_kind == "timed-out"


def test_a_scan_of_a_mistyped_host_says_so(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MCPGAWK_NO_UPDATE_CHECK", "1")
    cli.main(["scan", "--http", URL, "--no-track"])
    out = capsys.readouterr()
    text = out.out + out.err
    assert "does not resolve" in text, text
    assert "Is it a live MCP endpoint?" not in text
