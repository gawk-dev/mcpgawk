"""`--oauth-client-secret-env` naming an unset variable is a usage error, not a crash (2026-09-25).

Found by mypy (cli.py:213, return-value): `_run` returned the int 2 from inside its 3-tuple
contract, and `_dispatch` unpacks that tuple unconditionally — so the user got
`TypeError: cannot unpack non-iterable int object` after the helpful message. The same function
already documented the rule for `--only` ("RAISE, never `return 2`"); this path never followed it.
Driven through the real CLI with every store redirected; nothing is contacted (the check runs
before any sign-in starts).
"""
from __future__ import annotations

import os
import subprocess
import sys


def test_an_unset_secret_env_exits_2_with_the_reason_and_no_traceback(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "MCPGAWK_TEST_UNSET_SECRET"}
    env.update({"HOME": str(tmp_path), "GAWK_OAUTH_KEY_BACKEND": "file",
                "GAWK_OAUTH_STORE": str(tmp_path / "oauth"),
                "MCPGAWK_HISTORY": str(tmp_path / "history.json"),
                "MCPGAWK_RUNS": str(tmp_path / "runs.db"),
                "MCPGAWK_AUTH_NEEDED": str(tmp_path / "auth-needed.json"),
                "MCPGAWK_SIGNIN_ASIDE": str(tmp_path / "signin-aside.json"),
                "BROWSER": "true"})
    run = subprocess.run(
        [sys.executable, "-B", "-m", "mcpgawk", "scan", "--http", "https://mcp.example.invalid/mcp",
         "--login", "--oauth-client-id", "cid", "--oauth-client-secret-env",
         "MCPGAWK_TEST_UNSET_SECRET"],
        env=env, capture_output=True, text=True, timeout=60)
    out = run.stdout + run.stderr
    assert run.returncode == 2, out
    assert "MCPGAWK_TEST_UNSET_SECRET is not set in the environment" in out, out
    assert "Traceback" not in out and "cannot unpack" not in out, out
