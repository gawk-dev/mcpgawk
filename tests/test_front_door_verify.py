"""The front door runs behavioural verification by default — and degrades honestly.

Pins the four properties that make verify-in-the-default-flow safe to ship:
consent is respected (REMOTE_ONLY never launches a local server), the skip env
works, an unavailable engine never breaks protection, and an interrupted or
timed-out run is recorded INCOMPLETE — never as clean.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpgawk import cli, protect, runlog


@pytest.fixture(autouse=True)
def _no_real_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MCPGAWK_NO_VERIFY", raising=False)
    yield


def _capture_run(monkeypatch, rc: int):
    """Stub the engine; capture the synthesised config it was handed."""
    seen: dict = {}

    def fake_run(argv, timeout=None):
        seen["argv"] = argv
        seen["timeout"] = timeout
        seen["config"] = json.loads(Path(argv[0]).read_text())
        return rc

    monkeypatch.setattr("mcpgawk.verify.run", fake_run)
    monkeypatch.setattr("mcpgawk.verify.unavailable_reason", lambda: None)
    return seen


def test_no_verify_env_skips_entirely(monkeypatch, capsys):
    monkeypatch.setenv("MCPGAWK_NO_VERIFY", "1")
    called = []
    monkeypatch.setattr("mcpgawk.verify.unavailable_reason",
                        lambda: called.append(True) or None)
    cli._front_door_verify(protect.LAUNCH_ALL)
    assert not called, "MCPGAWK_NO_VERIFY=1 must short-circuit before any probe"
    assert "verif" not in capsys.readouterr().out.lower()


def test_remote_only_consent_never_launches_local_servers(monkeypatch):
    seen = _capture_run(monkeypatch, rc=0)
    monkeypatch.setattr("mcpgawk.discover.discover_servers", lambda **kw: {
        "local-npx": {"command": "npx", "args": ["-y", "x"], "env": {"K": "v"}},
        "remote": {"url": "https://mcp.example.com/mcp"},
    })
    cli._front_door_verify(protect.REMOTE_ONLY)
    servers = seen["config"]["mcpServers"]
    assert "remote" in servers
    assert "local-npx" not in servers, (
        "REMOTE_ONLY consent must never hand a local server to the engine — "
        "verify LAUNCHES what it is given")


def test_launch_all_includes_local_servers(monkeypatch):
    seen = _capture_run(monkeypatch, rc=0)
    monkeypatch.setattr("mcpgawk.discover.discover_servers", lambda **kw: {
        "local-npx": {"command": "npx", "args": ["-y", "x"]},
        "remote": {"url": "https://mcp.example.com/mcp"},
    })
    cli._front_door_verify(protect.LAUNCH_ALL)
    assert set(seen["config"]["mcpServers"]) == {"local-npx", "remote"}


def test_unavailable_engine_degrades_without_error(monkeypatch, capsys):
    monkeypatch.setattr("mcpgawk.verify.unavailable_reason", lambda: "Node is not installed")
    cli._front_door_verify(protect.LAUNCH_ALL)
    out = capsys.readouterr().out
    assert "skipped" in out and "Node" in out


@pytest.mark.parametrize("rc,status", [(0, runlog.OK), (1, runlog.FINDINGS),
                                       (4, runlog.INCOMPLETE), (130, runlog.INCOMPLETE),
                                       (3, runlog.ERROR)])
def test_run_outcome_is_recorded_with_its_real_status(monkeypatch, tmp_path, rc, status):
    _capture_run(monkeypatch, rc=rc)
    monkeypatch.setattr("mcpgawk.discover.discover_servers",
                        lambda **kw: {"remote": {"url": "https://mcp.example.com/mcp"}})
    finished: dict = {}
    monkeypatch.setattr("mcpgawk.runlog.start_run", lambda *a, **k: "rid-1")
    monkeypatch.setattr("mcpgawk.runlog.finish_run",
                        lambda rid, st, summary=None, **k: finished.update(rid=rid, status=st))
    cli._front_door_verify(protect.REMOTE_ONLY)
    assert finished["status"] == status, (
        f"engine rc {rc} must be recorded as {status}; an incomplete or failed run "
        "recorded as anything else would let a cut-off run read as clean")


def test_incomplete_never_claims_clean(monkeypatch, capsys):
    _capture_run(monkeypatch, rc=4)
    monkeypatch.setattr("mcpgawk.discover.discover_servers",
                        lambda **kw: {"remote": {"url": "https://mcp.example.com/mcp"}})
    cli._front_door_verify(protect.REMOTE_ONLY)
    out = capsys.readouterr().out
    assert "INCOMPLETE" in out
    assert "recorded — decisions now rest" not in out
