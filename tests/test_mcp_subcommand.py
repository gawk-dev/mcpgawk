"""`mcpgawk mcp` — the MCP server reached through the one binary.

`mcpgawk-mcp` has been the console script since the Zed context server (pyproject
`[project.scripts]`). A registry entry or a client config that can only name ONE package and a
subcommand (`uvx mcpgawk mcp`) needs the same server behind the main binary. This file proves the
two routes land on the same entry point, and that the old one is still wired.

The server ignores argv and blocks on stdin, so nothing here starts it: routing is proven by
replacing `mcp_server.main` and reading back what reached it.
"""
from __future__ import annotations

import importlib.metadata
import subprocess
import sys

from mcpgawk import cli


def test_parser_knows_mcp():
    args = cli.build_parser().parse_args(["mcp"])
    assert args.cmd == "mcp"


def test_mcp_help_exits_zero_and_names_stdio():
    """The doc build runs `<cmd> --help` for every listed command; this one must answer, not hang."""
    r = subprocess.run([sys.executable, "-m", "mcpgawk", "mcp", "--help"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "stdio" in r.stdout and "mcpgawk-mcp" in r.stdout


def test_mcp_routes_to_the_server_entry_point(monkeypatch):
    import mcpgawk.mcp_server as mcp_server

    seen: list[list[str]] = []

    def fake_main(argv=None):
        seen.append(list(argv or []))
        return 17

    monkeypatch.setattr(mcp_server, "main", fake_main)
    assert cli.main(["mcp"]) == 17
    assert seen == [[]], "the subcommand must hand the server entry an empty argv, as mcpgawk-mcp does"


def test_the_console_script_still_resolves():
    eps = {e.name: e.value for e in importlib.metadata.entry_points(group="console_scripts")
           if e.name.startswith("mcpgawk")}
    assert eps.get("mcpgawk-mcp") == "mcpgawk.mcp_server:main"
    assert eps.get("mcpgawk") == "mcpgawk.cli:main"
