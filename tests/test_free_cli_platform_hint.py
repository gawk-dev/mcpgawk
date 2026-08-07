"""What a FREE install does when someone types a paid capability.

Public-safe by construction: this file must never import gawk_platform, because it is synced into
the public mcpgawk repo where the paid engine does not exist. It covers the path every free user
can hit — `mcpgawk verify ...` with nothing but the free scanner installed.

The shape it locks: ONE binary. `gawk` cannot be an executable name (it is GNU AWK, which owns
/usr/bin/gawk across the Debian family and supplies /usr/bin/awk there via the alternatives
system), and one-command-plus-licence-unlock is the convention for this product type — Semgrep,
Snyk, GitLab, Terraform all do it. So the paid capabilities live under `mcpgawk`, and a free user
must get ONE honest line, never an ImportError traceback and never a silent success.
"""
from __future__ import annotations

import builtins

import pytest

from mcpgawk import cli as free_cli


@pytest.fixture
def no_platform(monkeypatch):
    """Simulate a free-only install even when the paid engine happens to be importable."""
    real_import = builtins.__import__

    def _import(name, *a, **kw):
        if name.startswith("gawk_platform"):
            raise ImportError("No module named 'gawk_platform'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", _import)


def test_paid_capabilities_are_advertised_in_free_help():
    """A free user should SEE what the subscription adds without installing anything."""
    help_text = free_cli.build_parser().format_help()
    for capability in free_cli.PLATFORM_CAPABILITIES:
        assert capability in help_text
    assert "gawk Platform" in help_text
    assert "pricing" in help_text


# `verify` left the paid set on 2026-07-28 (BUILD_PLAN Task 0): behavioural
# verification is FREE. Kept out of this list deliberately — it used to be here, and a
# stale entry would re-assert a paywall the product no longer has.
@pytest.mark.parametrize("capability", ["enforce", "monitor", "build"])
def test_paid_capability_on_a_free_install_exits_3_with_one_actionable_line(
    capability, no_platform, capsys
):
    rc = free_cli.main([capability, "whatever.json"])

    assert rc == 3, "the same 'not available/not licensed' code every paid entry point returns"
    err = capsys.readouterr().err
    assert "gawk Platform" in err
    assert "pricing.html" in err
    assert "free" in err.lower(), "must reassure that the free scanner is unaffected"
    assert "Traceback" not in err


def test_the_hint_never_leaks_a_python_import_error(no_platform, capsys):
    """An ImportError reaching the user is the failure mode this replaced."""
    free_cli.main(["verify"])
    err = capsys.readouterr().err
    assert "ImportError" not in err
    assert "gawk_platform" not in err, "internal module names are not a customer-facing detail"


def test_free_scan_is_unaffected_by_the_paid_dispatch(no_platform):
    """The whole point of the free tier: scan needs no licence and no platform."""
    with pytest.raises(SystemExit) as exc:
        free_cli.main(["scan", "--help"])
    assert exc.value.code == 0


# `verify --audit-source` was SILENTLY IGNORED on a free install: the flags belong to the paid
# source auditor (Python), the engine is TS, and the free wrapper passed them straight through to
# an engine that had never heard of them. Worse than absence: `--source-dir <path>` made the PATH
# read as the positional config argument, so the run looked normal while auditing nothing.
@pytest.mark.parametrize("argv", [
    ["verify", "servers.json", "--audit-source"],
    ["verify", "--source-dir", "/tmp/src", "servers.json"],
    ["verify", "--source-dir=/tmp/src", "servers.json"],
])
def test_verify_audit_flags_on_a_free_install_exit_3_not_silently_ignored(
    argv, no_platform, capsys
):
    rc = free_cli.main(argv)

    assert rc == 3, "same 'not available' code as every other paid entry point"
    err = capsys.readouterr().err
    assert "gawk Platform" in err
    assert "pricing" in err
    assert "free" in err.lower(), "must say behavioural verify itself still works"
    assert "Traceback" not in err


def test_push_on_a_free_install_exits_3_with_one_actionable_line(no_platform, capsys):
    """`push` was stranded when the paid `gawk` binary was retired: pillars and account commands
    were carried into this dispatch, `push` was not, so NO install could run it."""
    rc = free_cli.main(["push"])

    assert rc == 3
    err = capsys.readouterr().err
    assert "gawk Platform" in err
    assert "Traceback" not in err


def test_push_is_advertised_in_free_help():
    help_text = free_cli.build_parser().format_help()
    assert "push" in help_text


def test_panel_help_admits_it_is_a_control_surface(capsys):
    """The help said 'Read-only — every action lives in `mcpgawk decide`' long after the panel
    grew re-scan/verify/sign-in/approve/protect. Same class as the beta page describing fixed
    things as broken: the words drifted from the running thing."""
    with pytest.raises(SystemExit) as exc:
        free_cli.main(["panel", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out.lower()
    assert "read-only — every action lives" not in out
    for word in ("re-scan", "verify", "approve", "token"):
        assert word in out, f"panel help should name its actions and the token model ({word})"
