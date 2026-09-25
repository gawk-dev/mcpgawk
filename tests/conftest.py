"""CANONICAL SOURCE of the public repo's `tests/conftest.py`. Not used by this repo's own suite.

`scripts/public_sync.py` copies this file to `tests/conftest.py` in the public checkout. It is
named differently here for two reasons, both load-bearing:

  * this repo's real `tests/conftest.py` builds paid licence state and imports `gawk_platform`,
    which does not exist in the public repo and must NEVER be published into it;
  * `PUBLIC_TESTS` matches by filename, so a file that has to be RENAMED on the way out cannot
    travel by that route.

Why it exists at all. On 2026-08-06 a sync took the public suite from 1 failure to 9. None of the
eight was a regression: the canonical tests arrived without the conditions they were written
against, met the human-presence gate, and were correctly refused. `public_sync` had been copying
tests but not the conftest they depend on — the seventh instance of "a rule in one file is not a
rule". Syncing this file is the fix; hand-writing one in the public repo was not, because nothing
would have kept it alive.

The gate lives at the trust-store WRITES (`history.approve`, `baseline.publish`) rather than at the
commands, so every test that approves anything meets it. A pytest run has no TTY and is usually
launched from inside an agent session, which is exactly what the gate exists to stop.
`MCPGAWK_APPROVE_NONINTERACTIVE` is the documented CI hatch: it emulates "a human authorised this
pipeline", which is the true state of a CI run.

Set here once and visibly rather than sprinkled through twenty tests — and NOT a way of disabling
the gate. Any test asserting the REFUSAL clears this with monkeypatch first, and monkeypatch wins.
"""
from __future__ import annotations

import os
import stat

import pytest

#: FOUNDER 2026-09-25, "why my keychain is being accessed by you": a public-suite run with only HOME
#: redirected let the OAuth tests call `security add-generic-password` on the founder's login
#: Keychain — the platform conftest forced the file key backend, this one never did. Two layers:
#: the backend is forced to `file`, and a `security` that refuses and records sits first on PATH,
#: so ANY path to the Keychain — a new call site, a subprocess CLI, a reset backend — fails the test
#: that took it instead of touching the real one. The platform conftest imports these two fixtures.
KEYCHAIN_CALL_LOG = "keychain-calls.log"
_SYSTEM_ROOTS = "/System/Library/Keychains/SystemRootCertificates.keychain"
_SYSTEM_STORE = "/Library/Keychains/System.keychain"


@pytest.fixture(scope="session", autouse=True)
def _never_the_real_keychain(tmp_path_factory):
    shim = tmp_path_factory.mktemp("no-keychain")
    log = shim / KEYCHAIN_CALL_LOG
    log.write_text("")
    exe = shim / "security"
    # Two EXACT argv are answered without any Keychain: semgrep's CA loader (mirage/ca-certs) asks
    # for the public trust anchors in the two SYSTEM stores, and every run before this guard read
    # them. The root store is served from certifi's public CA bundle; the machine store answers
    # empty. Anything else — a certificate read from the login Keychain included — is refused.
    try:
        import certifi
        bundle = certifi.where()
    except ImportError:                                  # no bundle: refuse like everything else
        bundle = ""
    served = (f'  "find-certificate -a -p {_SYSTEM_ROOTS}") [ -n "{bundle}" ] && exec cat "{bundle}" ;;\n'
              f'  "find-certificate -a -p {_SYSTEM_STORE}") exit 0 ;;\n')
    exe.write_text('#!/bin/sh\ncase "$*" in\n' + served + 'esac\n'
                   f'printf "%s\\n" "$*" >> "{log}"\n'
                   'echo "mcpgawk test suite: the real Keychain is off limits" >&2\nexit 1\n')
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    prior = {k: os.environ.get(k) for k in ("GAWK_OAUTH_KEY_BACKEND", "PATH")}
    os.environ["GAWK_OAUTH_KEY_BACKEND"] = "file"
    os.environ["PATH"] = f"{shim}{os.pathsep}{prior['PATH'] or ''}"
    try:
        yield log
    finally:
        for k, v in prior.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.fixture(autouse=True)
def _a_keychain_call_fails_the_test(_never_the_real_keychain):
    log = _never_the_real_keychain
    before = log.read_text()
    yield
    new = log.read_text()[len(before):]
    assert not new, ("this test reached the macOS Keychain (`security " + new.strip() + "`) — the "
                     "suite refused it; force GAWK_OAUTH_KEY_BACKEND=file or fake subprocess.run")


@pytest.fixture(scope="session", autouse=True)
def _the_suite_is_the_documented_ci_override():
    prior = os.environ.get("MCPGAWK_APPROVE_NONINTERACTIVE")
    os.environ["MCPGAWK_APPROVE_NONINTERACTIVE"] = "1"
    try:
        yield
    finally:
        if prior is None:
            os.environ.pop("MCPGAWK_APPROVE_NONINTERACTIVE", None)
        else:
            os.environ["MCPGAWK_APPROVE_NONINTERACTIVE"] = prior


@pytest.fixture(autouse=True)
def _no_real_signin_child(monkeypatch):
    """Same guard as the platform conftest: no test may launch the panel's `scan --sign-in` child
    against a real fleet. A test that needs it patches `panel._run_signin_cli` with a fake."""
    try:
        from mcpgawk import panel
    except Exception:                              # noqa: BLE001
        return

    def _refuse(name):
        raise AssertionError(f"a test tried to launch the REAL sign-in child for {name!r} — "
                             f"patch panel._run_signin_cli with a fake")

    monkeypatch.setattr(panel, "_run_signin_cli", _refuse)
