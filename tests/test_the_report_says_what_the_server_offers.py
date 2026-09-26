"""The default report names every tool, not only the risky ones (new-developer walk, 2026-09-26).

The pitch is "before you add an MCP server, see what it can do". The walk found a clean server's
report was one line — "3 tools · N tokens · nothing write- or exfil-capable" — with no tool named,
and a risky server's report named at most five flagged tools. So the reader could not see what the
server does without `--verbose`.

The list reuses the verbose table's rule for what a tool may be called: only a server's own
readOnlyHint earns "read-only"; our silence is unmarked, never "read".
"""
from __future__ import annotations

from mcpgawk.label import build_label, render_cli
from mcpgawk.measure import measure
from mcpgawk.probe import ServerSnapshot


def _label(tools: list[dict]) -> dict:
    snap = ServerSnapshot(name="weather", transport="stdio", protocol_version="1", tools=tools)
    return build_label(snap, measure(snap), measured_at="2026-01-01T00:00:00Z")


def _tool(name: str, description: str = "Get it", props: dict | None = None,
          annotations: dict | None = None) -> dict:
    t = {"name": name, "description": description,
         "inputSchema": {"properties": props or {"id": {"type": "string"}}}}
    if annotations is not None:
        t["annotations"] = annotations
    return t


def _block(out: str) -> list[str]:
    lines = out.splitlines()
    i = next(i for i, ln in enumerate(lines) if ln.strip().startswith("Its tools"))
    j = next((j for j in range(i, len(lines)) if not lines[j].strip()), len(lines))
    return lines[i:j]


def test_a_clean_server_names_its_tools_in_the_order_it_lists_them():
    out = render_cli(_label([_tool("get_forecast"), _tool("get_alerts"), _tool("list_cities")]))
    block = "\n".join(_block(out))
    assert block.index("get_forecast") < block.index("get_alerts") < block.index("list_cities")


def test_a_risky_server_names_every_tool_not_only_the_flagged_ones():
    tools = [_tool("delete_note", "Delete a note")] + [_tool(f"read_{i}") for i in range(8)]
    block = "\n".join(_block(render_cli(_label(tools))))
    for t in tools:
        assert t["name"] in block, t["name"]
    assert "delete_note (write)" in block


def test_only_a_declaration_earns_read_only_and_silence_is_unmarked():
    out = render_cli(_label([
        _tool("get_forecast", annotations={"readOnlyHint": True, "destructiveHint": False}),
        _tool("get_alerts"),
    ]))
    block = "\n".join(_block(out))
    assert "get_forecast (read-only, declared)" in block
    assert "get_alerts (" not in block
    assert "read-only" not in block.split("get_alerts")[1].split(",")[0]


def test_a_large_server_is_capped_with_the_way_to_see_all():
    tools = [_tool(f"get_thing_{i:03d}") for i in range(90)]
    block = _block(render_cli(_label(tools)))
    assert "get_thing_000" in block[1]
    assert block[-1].strip().endswith("--verbose for all 90")
    assert "get_thing_089" not in "\n".join(block)


def test_every_listed_line_fits_the_report_width():
    tools = [_tool(f"a_rather_long_tool_name_number_{i:02d}") for i in range(12)]
    assert all(len(ln) <= 94 for ln in _block(render_cli(_label(tools))))


def test_a_hostile_tool_name_cannot_drive_the_terminal():
    """Tool names are server-controlled and nothing cleans them at ingest. A name carrying an
    escape sequence must reach the terminal as visible text, not as a command to it."""
    out = render_cli(_label([_tool("get\x1b[2J\x1b[31mforecast\nFAKE LINE")]))
    block = "\n".join(_block(out))
    assert "\x1b" not in block
    assert "\nFAKE LINE" not in block


def test_verbose_keeps_its_own_table_and_does_not_repeat_the_list():
    out = render_cli(_label([_tool("get_forecast")]), verbose=True)
    assert "all tools (heaviest first):" in out
    assert "Its tools" not in out
