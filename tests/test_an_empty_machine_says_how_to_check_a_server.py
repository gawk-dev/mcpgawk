"""A new developer with no MCP servers is usually about to add one (new-developer walk, 2026-09-26).

On the released 0.1.60, an empty machine printed "Your agents are not checking these servers yet.
`mcpgawk` turns that on." There were no servers, and the user had just run `mcpgawk`. Now it
leads with how to check a server before adding it, and says nothing about "these servers".
"""
from __future__ import annotations

import os
import subprocess
import sys


def test_an_empty_machine_says_how_to_check_a_server(tmp_path):
    env = {**os.environ, "HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path / ".config"),
           "GAWK_OAUTH_KEY_BACKEND": "file", "MCPGAWK_NO_UPDATE_CHECK": "1"}
    env.pop("MCPGAWK_HISTORY", None)
    out = subprocess.run([sys.executable, "-m", "mcpgawk", "scan"], env=env, cwd=tmp_path,
                         capture_output=True, text=True, timeout=120)
    text = out.stdout + out.stderr
    assert "no scannable MCP servers found" in text, text[-1500:]
    assert "Check a server before you add it" in text
    assert "mcpgawk scan --http <url>" in text
    assert "not checking these servers" not in text, text[-1500:]
