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
    # This asserted NOTHING until 2026-08-13: it was guarded by `if store.exists()`, and an
    # unreachable server records no baseline, so the guard was never true and the canary was never
    # checked — the same vacuous shape as two panel passes on 2026-08-11. The honest assertion is
    # the actual behaviour: a server we could not reach writes no record at all. If that ever
    # changes, this fails and the credential question has to be asked again rather than skipped.
    assert not store.exists(), ("an unreachable server now writes a record — re-check whether the "
                                "configured URL reaches disk")
    # Store coverage for a server that DOES answer lives in
    # tests/test_store_redacts_every_server_controlled_field.py, against a live fixture.


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


def test_the_panel_action_banner_masks_a_url_in_a_failure_message(tmp_path, monkeypatch):
    """The PANEL surface, driven through its real path — 2026-08-11, the second half of this hunt.

    `subprocess.TimeoutExpired` stringifies to the WHOLE command line, so a sign-in that times out
    put the configured URL — key and all — into the action banner, onto the rendered page and into
    `~/.gawk/last-action.json`. And a timeout is the EXPECTED case here: the OAuth flow waits 330s
    for a human who may simply walk away.

    Driven end to end (`_run_action_bg` → `_ACTION` → `render` → the file on disk) rather than by
    asserting on `run_login`'s return value: the scrub is a gate on the WRITE, so a test that never
    performs the write would pass with the gate removed.
    """
    import subprocess
    import sys
    import time

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / ".claude.json").write_text(
        json.dumps({"mcpServers": {"wrapped": {"command": "npx", "args": ["-y", "mcp-remote", URL]}}}),
        encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    from mcpgawk import panel

    def times_out(url: str, flag: str = "--http"):
        raise subprocess.TimeoutExpired(
            cmd=[sys.executable, "-m", "mcpgawk", "scan", flag, url, "--login"], timeout=330)

    monkeypatch.setattr(panel, "_run_login_cli", times_out)
    panel._ACTION.update(running=False, label="", message="", rows=[], at="")

    panel._run_action_bg("login", "wrapped")
    for _ in range(600):
        if not panel._ACTION["running"]:
            break
        time.sleep(0.05)
    assert not panel._ACTION["running"], "the action never finished"

    action = dict(panel._ACTION)
    message = action["message"]
    assert CANARY not in message, f"the banner carries the key: {message}"
    assert "apiKey=***" in message, f"masked, but not recognisably: {message}"
    assert "wrapped" in message, "over-masked: the operator can no longer tell WHICH server failed"

    page = panel.render(panel.collect(), token="t", action=action)
    assert CANARY not in page, "the rendered page printed the key"

    store = panel._action_store()
    assert store.is_file(), "sanity: the action was persisted, so the disk assert is not vacuous"
    assert CANARY not in store.read_text(encoding="utf-8"), "the key outlived the terminal"


def test_every_action_write_goes_through_the_scrubbing_gate():
    """A rot check that enumerates the WRITERS, not just the one in front of it.

    Thirteen call sites update the action state. The gate lives on `_ActionState`, so it covers
    them all — but only for as long as nobody swaps the state back to a plain dict or writes past
    it. This asserts the property that makes the gate hold, rather than re-testing one caller.
    """
    from mcpgawk import panel

    assert isinstance(panel._ACTION, panel._ActionState)
    probe = panel._ActionState()
    probe.update(message=f"failed: {URL}", label=f"login · {URL}",
                 rows=[{"detail": f"attempted {URL}"}])
    probe["message"] = f"assigned directly: {URL}"
    assert CANARY not in json.dumps(probe), f"a write path skipped the scrub: {probe}"
