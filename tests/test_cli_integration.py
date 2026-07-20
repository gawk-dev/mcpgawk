"""cli.main() integration: entry-threading for the opt-in checks (--supply-chain/--oauth-scopes
need the raw launch command/headers the core scan discards), with everything network/subprocess
mocked so this runs offline and fast."""
from __future__ import annotations

import json

from mcpgawk import cli
from mcpgawk.probe import ServerSnapshot
from mcpgawk.supplychain import SupplyChainFinding


def _fake_snapshot(name, transport):
    return ServerSnapshot(name=name, transport=transport, protocol_version="2025-11-25",
                          tools=[{"name": "a", "description": "read a thing"}])


async def _fake_probe_stdio(name, command, args=None, env=None, timeout=90.0):
    return _fake_snapshot(name, "stdio")


async def _fake_probe_url(name, url, headers=None, timeout=90.0, auth=None,
                          declared="http", permute=True):
    # The CLI's remote seam is now the permuting prober (transport permutation), not probe_http.
    return _fake_snapshot(name, "http")


def test_supply_chain_flag_reaches_the_launch_command(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_stdio", _fake_probe_stdio)
    seen = {}
    def fake_check(command, args):
        seen["command"], seen["args"] = command, args
        return SupplyChainFinding("npm", "request", "2.88.2", deprecated=True,
                                  detail="request has been deprecated")
    monkeypatch.setattr(cli, "check_supply_chain", fake_check)

    rc = cli.main(["scan", "--stdio", "npx -y request", "--supply-chain"])

    assert seen["command"] == "npx" and seen["args"] == ["-y", "request"]
    out = capsys.readouterr().out
    assert "DEPRECATED/YANKED" in out
    assert rc == 0


def test_oauth_scopes_flag_reaches_supplied_headers(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_url", _fake_probe_url)

    rc = cli.main(["scan", "--http", "https://example.com/mcp",
                   "--header", "Authorization: Bearer not-a-jwt", "--oauth-scopes"])

    out = capsys.readouterr().out
    assert "not locally inspectable" in out  # opaque token, honestly reported
    assert rc == 0


def test_opt_in_flags_absent_by_default(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_stdio", _fake_probe_stdio)
    cli.main(["scan", "--stdio", "npx -y request"])
    out = capsys.readouterr().out
    assert "supply-chain" not in out
    assert "oauth scopes" not in out


def test_json_output_carries_opt_in_fields_only_when_requested(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_stdio", _fake_probe_stdio)
    cli.main(["scan", "--stdio", "npx -y request", "--json"])
    labels = json.loads(capsys.readouterr().out)
    assert "supply_chain" not in labels[0]["x-mcpgawk"]
