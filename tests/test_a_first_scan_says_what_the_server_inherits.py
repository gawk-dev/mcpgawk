"""A first scan of a local server says what it inherits (new-developer walk, 2026-09-26).

`scan --stdio <cmd>` launches the server with the whole environment. The inherited-credentials
warning printed only when a scan failed or drifted, so the path a new developer takes most — one
successful first scan before adding a server — never showed it, including the variable names
0.1.62 added. A first sighting renders in full; so does this. An unchanged re-scan stays one line.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_SERVER = Path(__file__).parent / "fixtures" / "toy_mcp_server.py"


def _scan(tmp_path: Path) -> str:
    env = {**os.environ, "HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path / ".config"),
           "GAWK_OAUTH_KEY_BACKEND": "file", "MCPGAWK_NO_UPDATE_CHECK": "1",
           "GITHUB_TOKEN": "dummy-not-a-real-value"}
    env.pop("MCPGAWK_HISTORY", None)
    out = subprocess.run([sys.executable, "-m", "mcpgawk", "scan", "--stdio",
                          f"{sys.executable} {_SERVER}"],
                         env=env, cwd=tmp_path, capture_output=True, text=True, timeout=120)
    return out.stdout + out.stderr


def test_the_first_scan_names_what_it_inherits_and_a_quiet_rescan_does_not(tmp_path):
    first = _scan(tmp_path)
    assert "first scan — baseline recorded" in first, first[-2000:]
    assert "run as you, inheriting credentials" in first, first[-2000:]
    assert "GITHUB_TOKEN" in first
    assert "dummy-not-a-real-value" not in first

    again = _scan(tmp_path)
    assert "no change since your baseline" in again, again[-2000:]
    assert "inheriting credentials" not in again, again[-2000:]
