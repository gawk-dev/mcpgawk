"""No test run may reach the macOS login Keychain (FOUNDER 2026-09-25).

A public-suite run with only HOME redirected let the OAuth tests call `security
add-generic-password` on the founder's Keychain: the public conftest never forced the file key
backend. The guard now lives in tests/public_conftest.py (shipped as the public conftest, imported
by the platform one). This file proves both layers are live, in BOTH suites — it is on the public
allow-list — and that the refusal is real, not assumed.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from mcpgawk import oauth_login


def test_the_file_key_backend_is_forced():
    assert os.environ.get("GAWK_OAUTH_KEY_BACKEND") == "file"


def test_security_on_path_is_the_refusing_shim():
    found = shutil.which("security")
    assert found and "no-keychain" in found, found
    assert found != "/usr/bin/security"


def test_a_keychain_attempt_is_refused_and_recorded(monkeypatch, tmp_path, _never_the_real_keychain):
    """Force the keychain backend the way a regression would: the shim refuses, the store falls back
    to its 0600 key file, and the call is recorded (then cleared, so the guard fixture passes)."""
    log = _never_the_real_keychain
    before = log.read_text()
    monkeypatch.setenv("GAWK_OAUTH_STORE", str(tmp_path / "oauth"))
    monkeypatch.setenv("GAWK_OAUTH_KEY_BACKEND", "keychain")
    oauth_login._reset_store_key_cache()
    try:
        key = oauth_login._store_key()
    finally:
        oauth_login._reset_store_key_cache()
    assert len(key) == 32                                    # the file fallback, never plaintext
    calls = log.read_text()[len(before):]
    assert "find-generic-password" in calls, calls           # it tried, and the shim took it
    log.write_text(before)


def test_a_subprocess_cli_inherits_the_guard(_never_the_real_keychain):
    """CLI subprocesses inherit PATH and the backend — the path most drives take."""
    log = _never_the_real_keychain
    before = log.read_text()
    out = subprocess.run(["security", "find-generic-password", "-s", "x"],
                         capture_output=True, text=True)
    assert out.returncode == 1 and "off limits" in out.stderr, out
    assert "find-generic-password -s x" in log.read_text()[len(before):]
    log.write_text(before)


def test_a_test_that_reaches_the_keychain_fails(tmp_path):
    """End to end, against the conftest exactly as it ships: a test that calls `security` must FAIL
    with the guard's message. The call is `security -h`, harmless even if the guard is broken."""
    import sys
    from pathlib import Path
    here = Path(__file__).parent
    src = here / "public_conftest.py"
    if not src.exists():                       # in the public repo it has already landed as conftest
        src = here / "conftest.py"
    (tmp_path / "conftest.py").write_text(src.read_text())
    (tmp_path / "test_reaches.py").write_text(
        "import subprocess\n"
        "def test_reaches():\n"
        # `-h` prints help and opens no Keychain: if the guard ever breaks, this test must fail
        # WITHOUT touching the real one — the thing it exists to prevent.
        "    subprocess.run(['security', '-h'], capture_output=True)\n")
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    env["PATH"] = os.environ["PATH"].split(os.pathsep, 1)[1]    # the inner run builds its own shim
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                          "-p", "no:randomly", str(tmp_path)],
                         cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    out = run.stdout + run.stderr
    assert run.returncode != 0, out
    assert "reached the macOS Keychain" in out and "`security -h`" in out, out


def test_only_the_two_public_trust_anchor_reads_are_answered(_never_the_real_keychain):
    """semgrep's CA loader gets public certificates WITHOUT any Keychain; a near miss is refused."""
    log = _never_the_real_keychain
    before = log.read_text()
    roots = subprocess.run(["security", "find-certificate", "-a", "-p",
                            "/System/Library/Keychains/SystemRootCertificates.keychain"],
                           capture_output=True, text=True)
    assert roots.returncode == 0 and "BEGIN CERTIFICATE" in roots.stdout
    store = subprocess.run(["security", "find-certificate", "-a", "-p",
                            "/Library/Keychains/System.keychain"], capture_output=True, text=True)
    assert store.returncode == 0 and store.stdout == ""
    assert log.read_text() == before                      # served, not recorded as a violation
    # Near misses name keychains that do not exist: if the guard ever broke, this check must still
    # never read a real one (FOUNDER 2026-09-25: extreme caution with the Keychain).
    for near_miss in (["find-certificate", "-a", "-p", "/nonexistent/mcpgawk-test.keychain"],
                      ["find-certificate", "-a", "-p",
                       "/System/Library/Keychains/SystemRootCertificates.keychain", "-c", "x"]):
        out = subprocess.run(["security", *near_miss], capture_output=True, text=True)
        assert out.returncode == 1 and "off limits" in out.stderr, near_miss
    assert log.read_text()[len(before):].count("find-certificate") == 2
    log.write_text(before)
