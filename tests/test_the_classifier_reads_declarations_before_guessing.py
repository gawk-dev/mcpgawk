"""Two classifier defects found by re-checking every number mcpgawk printed about a REAL server.

WHY THIS FILE EXISTS. On 2026-09-10 the scan of a reviewer's live MCP server (70 tools) was
re-verified claim by claim before the numbers went into a deck. Two of them did not survive.

  1. `_exfil_capable` never read `readOnlyHint`. `_is_write` has read it since it was written
     ("declared read-only wins over the verb heuristic") — the sibling classifier, in the same
     file, one function above, did not. So four tools whose product noun is "recording request"
     matched the bare word `request` in `_EXFIL_NAME` and were reported as leak paths; two of
     them were DECLARED readOnlyHint=true by the server. The headline read "7 of 70 tools can
     read your content AND reach the network" when the defensible figure was 3. A server that
     did the right thing and annotated its tools got punished for it.

  2. The verbose detail printed `read-only` whenever a tool had no tags. No tags means the write
     heuristic did not fire — NOT that the server declared the tool read-only. `restore_folder`,
     `restore_video` and `translate_video` declared no hint at all and none of "restore" or
     "translate" is a write verb, so all three rendered as "read-only" on the strength of our own
     silence. That is "availability yes, ambiguity no" inverted, on the safe-looking side: a
     mutating tool shown as harmless is the exact failure this product exists to prevent.

Both are the same root error — treating the absence of a signal as a positive finding — and both
are pinned here against the real tool shapes that exposed them.
"""
from __future__ import annotations

from mcpgawk import build_label, measure
from mcpgawk.label import render_cli
from mcpgawk.probe import ServerSnapshot


def _snap(tools):
    return ServerSnapshot(name="t", transport="stdio", protocol_version="x", tools=tools)


def _verbose(tools) -> str:
    snap = _snap(tools)
    return render_cli(build_label(snap, measure(snap)), verbose=True)


def test_a_declared_readonly_tool_is_not_a_leak_path():
    """The reproduction, with the real tool. `get_recording_request` is declared read-only and
    reaches nothing; it matched `_EXFIL_NAME` on the word "request" inside the product's own noun."""
    m = measure(_snap([{
        "name": "get_recording_request",
        "description": "Get a single recording request by id.",
        "annotations": {"readOnlyHint": True}}]))
    assert m.tools[0].exfil_capable is False, "a declared read-only tool cannot be the leak half"
    assert m.tools[0].write is False


def test_a_declared_readonly_tool_with_a_url_parameter_is_still_not_a_leak_path():
    """The parameter arm of the same function. A read-only tool that takes a `url` is fetching, and
    the declaration is the server's answer about what it does with what it reads."""
    m = measure(_snap([{
        "name": "get_page", "description": "Read a page.",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
        "annotations": {"readOnlyHint": True}}]))
    assert m.tools[0].exfil_capable is False


def test_an_undeclared_tool_that_reaches_the_network_still_flags():
    """NARROWNESS. The fix must not disarm the detector. `add_background_music` declares no hint and
    its description hands the server an http(s) URL to fetch — that one survived the recheck and
    must keep firing."""
    m = measure(_snap([{
        "name": "add_background_music",
        "description": "audio_url must be a PUBLIC http(s) URL; the editor downloads it."}]))
    assert m.tools[0].exfil_capable is True


def test_no_signal_is_never_rendered_as_read_only():
    """`restore_folder`: no annotations at all, and "restore" is in no verb list. Untagged is
    UNKNOWN, and the detail line must not upgrade our silence into the server's assurance."""
    # It DOES carry annotations — just not readOnlyHint — so the existing "no-annotation" tag
    # cannot rescue the line. Silence about the hint is the whole point of the case.
    out = _verbose([{"name": "restore_folder", "description": "Restore a folder.",
                     "annotations": {"title": "Restore folder"}}])
    assert "restore_folder" in out
    line = next(ln for ln in out.splitlines() if "restore_folder" in ln)
    assert "read-only" not in line, line
    assert "no signal" in line, line


def test_a_declared_read_only_tool_still_says_read_only():
    """The other half: when the server DID declare it, saying so is reporting a fact, not guessing."""
    out = _verbose([{"name": "get_profile", "description": "Fetch the profile.",
                     "annotations": {"readOnlyHint": True}}])
    line = next(ln for ln in out.splitlines() if "get_profile" in ln)
    assert "read-only (declared)" in line, line
