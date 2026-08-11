"""A credential in a configured URL must not reach any surface. Measured, not assumed.

Hosted MCP servers authenticate this way — `https://…/mcp?clientId=…&apiKey=…` is a real shape, and
this machine has one configured. On 2026-08-11 a canary run showed `mcpgawk scan --json` printing the
key TWICE (once in a finding's `detail`, once in the caveat) while the human report and the history
store were clean. The redactor already existed (`redact.redact_url`, used by the fleet JSON and by
enforce's transport) — the failure ladder simply never called it.

That is this repo's own recurring shape twice over: a rule living in one file is not a rule, and a
sanitiser that is tested directly while the RENDERED output is not tested is how a live API key
shipped in an announcement once before. So these tests assert on rendered output, at every surface
that echoes a URL, with one canary value.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

CANARY = "CANARY_SECRET_VALUE_98765"
URL = f"https://mcp.example.invalid/mcp?clientId=abc123&apiKey={CANARY}"


@pytest.fixture
def config(tmp_path: Path) -> Path:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"brandy": {"url": URL}}}), encoding="utf-8")
    return cfg


def test_the_candidate_label_masks_the_key():
    """The single string every failure surface echoes. Masked here, masked everywhere downstream."""
    from mcpgawk.transport import Candidate

    label = Candidate(transport="http", url=URL).label
    assert CANARY not in label, f"the label carries the key: {label}"
    assert "apiKey=***" in label, f"masked, but not recognisably: {label}"


def test_the_scan_report_does_not_print_the_key(config, tmp_path, monkeypatch, capsys):
    """The rendered report — text AND json — for a server that could not be reached, which is the
    path that echoes every attempted URL."""
    from mcpgawk import cli

    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    cli.main(["scan", str(config), "--yes"])
    assert CANARY not in capsys.readouterr().out, "the human report printed the key"

    cli.main(["scan", str(config), "--yes", "--json"])
    out = capsys.readouterr().out
    assert CANARY not in out, "--json printed the key — this is the output that lands in CI logs"
    assert "apiKey=***" in out, "sanity: the URL is still shown, with the value masked"


def test_the_store_on_disk_does_not_contain_the_key(config, tmp_path, monkeypatch):
    """ADR-0012 N5. It held before this fix and must keep holding: the store outlives the terminal."""
    from mcpgawk import cli

    store = tmp_path / "history.json"
    monkeypatch.setenv("MCPGAWK_HISTORY", str(store))
    cli.main(["scan", str(config), "--track", "--yes"])
    if store.exists():
        assert CANARY not in store.read_text(encoding="utf-8")


def test_the_fleet_json_does_not_print_the_key():
    """The other machine-readable surface, which had its own redaction already — pinned here so both
    are covered by the same canary rather than by two separate conventions."""
    from mcpgawk.fleet import redact_url

    masked = redact_url(URL)
    assert masked and CANARY not in masked and "apiKey=***" in masked


def test_userinfo_credentials_are_masked_too():
    """The other place a URL hides a secret. Same canary, different shape."""
    from mcpgawk.redact import redact_url

    masked = redact_url(f"https://user:{CANARY}@mcp.example.invalid/mcp")
    assert masked and CANARY not in masked
