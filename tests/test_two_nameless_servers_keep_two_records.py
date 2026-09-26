"""Two different servers scanned ad hoc must never share one record.

Found 2026-09-26 on live servers: `scan --http` bureau, then `scan --http` inference, in one home.
Neither asserts a name (both speak only the 2026-07-28 revision, whose `server/discover` carries no
serverInfo), so both keyed `http:cli-http`, the placeholder every ad-hoc `--http` scan shares. The
second scan reported DRIFT: bureau's 5 tools "removed", inference's 35 "added", and printed
`mcpgawk approve http:cli-http`, which would have approved one server's tools as the other's.
Every server that moves to the new revision becomes nameless, so this grows with the upgrade.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcpgawk import cli, history
from mcpgawk.probe import ServerSnapshot

FIXTURES = Path(__file__).parent / "fixtures"
CANARY = "CANARYnameless0123456789"


def _tool(name):
    return {"name": name, "description": f"Get {name}.", "inputSchema": {"type": "object"}}


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    monkeypatch.setenv("GAWK_BEHAVIOUR_PROFILE", str(tmp_path / "behaviour.json"))
    monkeypatch.setenv("MCPGAWK_NO_UPDATE_CHECK", "1")
    return tmp_path


@pytest.fixture()
def nameless_http(monkeypatch):
    """`probe_url` answering as a nameless server whose tools depend on the URL."""
    tools = {"https://bureau.example/mcp": ["bureau_get_case"],
             "https://inference.example/mcp": ["app_run", "task_get"]}

    async def fake_probe_url(name, url, headers, timeout, auth=None, **kw):
        base = url.split("?", 1)[0]
        return ServerSnapshot(name=name, transport="http", protocol_version="2026-07-28",
                              tools=[_tool(t) for t in tools.get(base, ["other"])],
                              server_info={})

    monkeypatch.setattr(cli, "probe_url", fake_probe_url)


def _scan(capsys, *argv):
    code = cli.main(["scan", *argv])
    out = capsys.readouterr()
    return code, out.out + out.err


def test_two_nameless_urls_keep_two_records_and_neither_drifts(home, nameless_http, capsys):
    _scan(capsys, "--http", "https://bureau.example/mcp")
    code, text = _scan(capsys, "--http", "https://inference.example/mcp")

    assert "DRIFT" not in text, f"the second server was diffed against the first:\n{text}"
    assert "first scan" in text
    # and the report names it by what was typed, not the placeholder both servers share
    assert "cli-http" not in text, text
    assert "● https://inference.example/mcp" in text, text
    store = history.load()
    assert "http:cli-http" not in store["servers"]
    a = history.resolve_all(store, "https://bureau.example/mcp")
    b = history.resolve_all(store, "https://inference.example/mcp")
    assert len(a) == 1 and len(b) == 1 and a != b, (a, b)


def test_a_rescan_of_the_same_nameless_url_still_finds_its_baseline(home, nameless_http, capsys):
    _scan(capsys, "--http", "https://bureau.example/mcp")
    _, text = _scan(capsys, "--http", "https://bureau.example/mcp")
    assert "first scan" not in text and "DRIFT" not in text
    assert len(history.load()["servers"]) == 1


def test_a_credential_in_the_url_reaches_neither_the_key_nor_the_alias(home, nameless_http,
                                                                       capsys):
    raw = f"https://bureau.example/mcp?apiKey={CANARY}"
    _, text = _scan(capsys, "--http", raw)
    assert CANARY not in text
    # every file the scan wrote (history, guard baseline, run log, …), not only the one we expect
    for f in Path(home).rglob("*"):
        if f.is_file():
            assert CANARY.encode() not in f.read_bytes(), f"the key is stored in {f.name}"
    store = history.load()
    assert len(history.resolve_all(store, raw)) == 1, "the URL as typed no longer resolves"


def test_the_printed_approve_command_survives_the_shell(home, monkeypatch, capsys):
    """A masked key carries `?` and `*`, which zsh globs: the printed line must quote it, and the
    word the shell hands `approve` must be the stored key."""
    import shlex
    tools = [["get_a"]]

    async def fake_probe_url(name, url, headers, timeout, auth=None, **kw):
        return ServerSnapshot(name=name, transport="http", protocol_version="2026-07-28",
                              tools=[_tool(t) for t in tools[0]], server_info={})

    monkeypatch.setattr(cli, "probe_url", fake_probe_url)
    raw = f"https://bureau.example/mcp?apiKey={CANARY}"
    _scan(capsys, "--http", raw)
    tools[0] = ["get_a", "get_b"]                       # the same server changes: drift
    _, text = _scan(capsys, "--http", raw)
    [line] = [ln for ln in text.splitlines() if "mcpgawk approve" in ln]
    argv = shlex.split(line.split("?", 1)[1])          # after "Reviewed it and it is fine?"
    key = argv[argv.index("approve") + 1]
    assert "*" in key and CANARY not in key
    assert key in history.load()["servers"], (key, line)
    # shlex.split does not glob, so check the quoting itself: unquoted, zsh expands the `*`
    assert line.rstrip().endswith(shlex.quote(key)) and shlex.quote(key) != key, line


ORDINARY_TARGETS = [
    "npx -y example-unknown@1.0.0",
    "npx -y @modelcontextprotocol/server-filesystem /tmp",
    "/opt/homebrew/opt/python@3.13/bin/python3 server.py",
    "uvx mcp-server-fetch",
    "npx mcp-remote@0.8.4 https://mcp.kite.trade/mcp",
    "docker run -i --rm ghcr.io/github/github-mcp-server",
    "https://thebureauoflostcontext.agency/mcp",
    "https://api.inference.sh/mcp",
    "https://mcp.example.com/@scope/server/mcp",
]


@pytest.mark.parametrize("target", ORDINARY_TARGETS)
def test_an_ordinary_target_is_its_own_key(target):
    """The key IS the masked target, so an over-eager masker merges servers: `redact()` once
    turned `npx -y a@1.0.0` and `npx -y b@2.0.0` into the same `npx -y [REDACTED]`."""
    assert history.adhoc_target(target) == target


def test_two_versions_of_one_package_are_two_keys():
    assert history.adhoc_target("npx -y a@1.0.0") != history.adhoc_target("npx -y b@2.0.0")


def _old_store(home, aliases):
    """A store written before the fix: every nameless --http target on `http:cli-http`."""
    rec = {"tools": {"old_tool": {"sha": "x"}}}
    Path(home / "history.json").write_text(json.dumps({"servers": {"http:cli-http": {
        "approved": rec, "approved_via": "first-sighting", "aliases": aliases,
        "history": [rec]}}}), encoding="utf-8")


def test_an_old_placeholder_record_of_one_server_carries_over(home, nameless_http, capsys):
    _old_store(home, ["https://bureau.example/mcp"])
    _, text = _scan(capsys, "--http", "https://bureau.example/mcp")
    store = history.load()
    assert "http:cli-http" not in store["servers"], "the server's own record was not reclaimed"
    assert "first scan" not in text, "the baseline was silently reset on upgrade"


def test_an_old_conflated_record_is_not_adopted_by_either_server(home, nameless_http, capsys):
    _old_store(home, ["https://bureau.example/mcp", "https://inference.example/mcp"])
    _, text = _scan(capsys, "--http", "https://inference.example/mcp")
    assert "DRIFT" not in text, f"adopted a record that holds another server's history:\n{text}"
    assert "first scan" in text
    assert "http:cli-http" in history.load()["servers"], "left in place, not deleted"


def test_two_real_modern_only_servers_over_stdio_keep_two_records(home, capsys):
    """The customer's path end to end: the real probe, a real server refusing `initialize`."""
    server = str(FIXTURES / "mcp2_only_server.py")
    one = f"{sys.executable} {server}"
    two = f"{sys.executable} {server} --second"      # a different target, same nameless server
    _scan(capsys, "--stdio", one)
    _, text = _scan(capsys, "--stdio", two)
    assert "DRIFT" not in text and "first scan" in text, text
    keys = [k for k in history.load()["servers"]]
    assert len(keys) == 2 and "stdio:cli-stdio" not in keys, keys
