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

import dataclasses
import json
import os
import stat
import sys
from pathlib import Path

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


@pytest.fixture(autouse=True)
def _never_the_real_agent_configs(request, tmp_path_factory):
    """No test reads the developer's real agent configs unless it says so (`@pytest.mark.real_home`).

    THE CLASS (2026-09-26o): the store redirects above cover mcpgawk's OWN files, not discovery.
    41 `panel.collect()` calls in 11 test files swept the real ~/.claude.json, Cursor, VS Code, Zed
    and Claude Desktop configs, so a test passed or failed by what the machine had installed — one
    read "no server named 'Revolut X'" from a queued action run against the real fleet.

    Two reach points, because HOME alone does not move all of them:
      * HOME (and USERPROFILE): every `Path.home()` / `expanduser` resolved at CALL time —
        discover_report, detect_unscannable, skills, ambient, wrap, the panel's config globs.
      * import-time constants: `agents.ADAPTERS[*].config` and `guard.CLAUDE_USER_SETTINGS` were
        fixed to the real home when the module loaded, and `collect()` reads the hook configs.

    NOT the working directory. discover_report also sweeps project-scope files (.mcp.json,
    .vscode/mcp.json, ...) under `Path.cwd()`, but moving the cwd of 4300 tests is a wider change
    than this class needs, and the repo root holds none today. Instead,
    test_a_test_never_reads_the_real_agent_configs fails if the working dir ever holds one.

    Function-scoped on purpose: the session tripwire snapshots the REAL ~/.gawk and ~/.mcpgawk
    before any of this applies, and a test that sets HOME itself still overrides it.

    Its OWN MonkeyPatch, not the test's `monkeypatch`: a test that calls `monkeypatch.undo()`
    mid-way (test_platform_credential_writers_are_owner_safe does) would otherwise put the real
    home back for the rest of that test.

    Yields the temp home (None when opted out) so the platform conftest can re-seed its
    home-bound licence cache there."""
    if request.node.get_closest_marker("real_home"):
        yield None
        return
    home = tmp_path_factory.mktemp("home")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("HOME", str(home))
        mp.setenv("USERPROFILE", str(home))
        _repoint_import_time_paths(mp, home)
        yield home


def _repoint_import_time_paths(mp: pytest.MonkeyPatch, home: Path) -> None:
    try:
        from mcpgawk import agents, guard
    except Exception:                              # noqa: BLE001 — a partial checkout may lack them
        return
    for key, adapter in agents.ADAPTERS.items():
        rel = _relative_to_real_home(adapter.config)
        if rel is not None:
            mp.setitem(agents.ADAPTERS, key, dataclasses.replace(adapter, config=home / rel))
    rel = _relative_to_real_home(guard.CLAUDE_USER_SETTINGS)
    if rel is not None:
        mp.setattr(guard, "CLAUDE_USER_SETTINGS", home / rel)


#: The home the suite started under, read at import — before any test redirects HOME.
_REAL_HOME = Path.home()


def _relative_to_real_home(path: Path) -> Path | None:
    try:
        return path.relative_to(_REAL_HOME)
    except ValueError:                             # already somewhere else (a test's own patch)
        return None


#: Where the fixture fleet lives, relative to the (temp) home — a Cursor config, the plainest shape.
SEEDED_FLEET_CONFIG = Path(".cursor") / "mcp.json"


@pytest.fixture
def seeded_fleet(request):
    """A small fleet in the temp home, for tests that used to read whatever THIS machine had.

    Before the redirect, test_panel_state_payload and two user-journey cases ran against the
    developer's real agent configs, and a real `mcpgawk scan` launched real servers; on an empty
    home they now skipped every time. Three entries cover the states they need: one launchable
    stdio server (our own fixture), one whose binary does not exist, one whose host cannot resolve.
    Returns the server names."""
    home = request.getfixturevalue("_never_the_real_agent_configs")
    assert home is not None, "seeded_fleet needs the temp home; do not combine it with real_home"
    assert not home.resolve().is_relative_to(_REAL_HOME.resolve()), "refusing to write the real home"
    here = Path(__file__).resolve().parent
    fleet = {
        "fleet-fixture": {"command": sys.executable,
                          "args": [str(here / "fixtures" / "annotated_mcp_server.py")]},
        "fleet-not-launched": {"command": "/nonexistent/fleet-binary", "args": []},
        "fleet-unresolvable": {"url": "https://mcp.example.invalid/mcp"},
    }
    cfg = home / SEEDED_FLEET_CONFIG
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"mcpServers": fleet}))
    return sorted(fleet)
