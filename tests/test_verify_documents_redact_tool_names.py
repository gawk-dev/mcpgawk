"""`last-verify.json`, the behaviour profile, and the skipped-tools line must not carry a
server-chosen tool name verbatim.

Seventh increment of the 2026-08-13 sweep, driven through the SHIPPED engine.

Two of the pre-registered predictions were WRONG, and both are recorded here because the reason
matters. `last-verify.json` does NOT embed tool output: a convicted `credential-exposure` finding
records the classification `{"leaked":"openai-key"}`, not the value. Neither does the behaviour
profile. What both DO record is tool NAMES — and a name is chosen by the server.

The first two attempts to measure that were VACUOUS and would have shipped as passes:

* with a clean run, neither file records a checked tool's name at all — names reach them only via
  a finding or the SKIPPED list, so a credential-named tool that verifies cleanly leaves no trace;
* so the fixture gained `send_apiKey=…` — a MUTATING verb, which makes verify skip it — and only
  then did the name reach `behaviour.json`\'s `skipped` list and the report\'s tool table.

The stdout line is included deliberately: it lands in CI logs, pasted issues and uploaded
artefacts, which is the same reason `scan --json` had to be masked.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "store_canary_mcp_server.py"
CANARY = "CANARY_NAME_98765"          # inside the fixture's `send_apiKey=…` tool name


@pytest.fixture(scope="module")
def run() -> dict[str, str]:
    from mcpgawk import verify as verify_mod

    if verify_mod.unavailable_reason() is not None:
        pytest.skip(f"verify unavailable here: {verify_mod.unavailable_reason()}")
    tmp = Path(tempfile.mkdtemp(prefix="verify-docs-"))
    cfg = tmp / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "canary": {"command": sys.executable, "args": [str(FIXTURE)]}}}), encoding="utf-8")
    profile, report = tmp / "behaviour.json", tmp / "last-verify.json"
    proc = subprocess.run(
        [sys.executable, "-m", "mcpgawk.cli", "verify", str(cfg),
         "--behaviour-profile", str(profile), "--out", str(report)],
        capture_output=True, text=True, timeout=300,
        cwd=str(Path(__file__).parent.parent), env={**__import__("os").environ,
                                                    "GAWK_BEHAVIOUR_PROFILE": str(profile)})
    assert profile.is_file() and report.is_file(), "the engine wrote neither document — vacuous"
    return {"profile": profile.read_text(encoding="utf-8"),
            "report": report.read_text(encoding="utf-8"),
            "stdout": proc.stdout + proc.stderr}


@pytest.mark.parametrize("surface", ["profile", "report", "stdout"])
def test_no_surface_carries_the_credential_shaped_tool_name(run: dict[str, str], surface: str):
    assert CANARY not in run[surface], f"{surface} carried a server-chosen credential"


@pytest.mark.parametrize("surface", ["profile", "report", "stdout"])
def test_the_skipped_list_is_still_there_to_read(run: dict[str, str], surface: str):
    """Non-vacuity, and the other half of the contract. If the skipped list vanished — or every
    name in it were masked — these assertions would pass while the feature was destroyed."""
    assert "ordinary_tool" in run[surface], f"{surface} lost the ordinary tool names"
    assert "[REDACTED]" in run[surface], f"{surface} shows no evidence the name was masked, not dropped"


@pytest.mark.parametrize("name", ["behaviour.json", "last-verify.json"])
def test_both_documents_are_owner_only(name: str, tmp_path: Path):
    """Same finding as `monitor.db` earlier the same day: `writeFileSync` creates 0644 under the
    default umask, while every sibling store is 0600. These two name every server on the machine
    and every tool they expose. `~/.gawk` is 0700, so the parent is today's protection — a mode on
    the file is what survives a copy, a tarball and a change to the parent."""
    import os
    import stat

    from mcpgawk import verify as verify_mod

    if verify_mod.unavailable_reason() is not None:
        pytest.skip("verify unavailable here")
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "canary": {"command": sys.executable, "args": [str(FIXTURE)]}}}), encoding="utf-8")
    profile, report = tmp_path / "behaviour.json", tmp_path / "last-verify.json"
    subprocess.run(
        [sys.executable, "-m", "mcpgawk.cli", "verify", str(cfg),
         "--behaviour-profile", str(profile), "--out", str(report)],
        capture_output=True, text=True, timeout=300,
        cwd=str(Path(__file__).parent.parent),
        env={**os.environ, "GAWK_BEHAVIOUR_PROFILE": str(profile)})
    target = tmp_path / name
    assert target.is_file(), f"{name} was not written — this assertion would be vacuous"
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
