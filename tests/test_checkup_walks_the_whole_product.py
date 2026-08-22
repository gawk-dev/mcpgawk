"""`mcpgawk checkup` — the walk must survive the machine it is most needed on.

A beta bundle is worth the most when something is already broken, so the properties that
matter are about failure, not success: a step that crashes must not end the walk, a tester
who declines to launch their servers must still get a complete bundle, and stopping
half-way must still produce a file. Everything else is detail.
"""

from __future__ import annotations

import json
import sys
import zipfile

import pytest

from mcpgawk import checkup


@pytest.fixture(autouse=True)
def _local_state(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".gawk").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GAWK_BEHAVIOUR_PROFILE", str(home / ".gawk" / "behaviour.json"))
    monkeypatch.setenv("MCPGAWK_SPOOL", str(home / ".mcpgawk" / "calls.jsonl"))
    monkeypatch.chdir(tmp_path)


def _fake_binary(script: str):
    """Stand in for the shipped binary so a unit test never launches a real MCP server."""
    return lambda: [sys.executable, "-c", script]


def _walkthrough(path):
    with zipfile.ZipFile(path) as archive:
        return json.loads(archive.read("walkthrough.json"))


def test_declining_to_launch_still_produces_a_complete_bundle(tmp_path, monkeypatch):
    """The answer a locked-down machine gives, and it must not be treated as a failure.

    A tester who cannot let us run their servers is not a broken run — they are most of the
    enterprise market, and their bundle still carries every other surface.
    """
    monkeypatch.setattr(checkup, "_binary", _fake_binary("print('ok')"))
    dest = tmp_path / "declined.zip"
    assert checkup.run(output=str(dest), assume_yes=False) == 0

    walk = _walkthrough(dest)
    assert walk["launched_local_servers"] is False
    by_name = {s["name"]: s for s in walk["steps"]}
    assert by_name["scan"]["outcome"] == checkup.DECLINED
    assert by_name["verify"]["outcome"] == checkup.DECLINED
    assert by_name["status-before"]["outcome"] == checkup.OK, "the rest of the walk must still run"
    assert "not a failure" in by_name["scan"]["detail"]


def test_a_step_that_fails_does_not_end_the_walk(tmp_path, monkeypatch):
    """The bundle from the machine where a step crashed is the one we most need."""
    monkeypatch.setattr(checkup, "_binary", _fake_binary("import sys; sys.exit(7)"))
    dest = tmp_path / "failed.zip"
    assert checkup.run(output=str(dest), assume_yes=True) == 0

    walk = _walkthrough(dest)
    outcomes = {s["name"]: s["outcome"] for s in walk["steps"]}
    assert outcomes["version"] == checkup.FAILED
    assert "panel" in outcomes, "the walk continued past a failing step to the end"
    assert all(s["exit_code"] == 7 for s in walk["steps"] if s["command"])


def test_a_nonzero_exit_is_a_failure_not_a_false_ok(tmp_path, monkeypatch):
    """A step exiting nonzero is a finding to surface, recorded as FAILED — never a false OK.

    The mapping used to record exit 1 as OK for EVERY step, on the theory that `scan` exits 1 on
    findings. But `scan --yes` (no --fail-on-findings, which checkup does not pass) exits 0 even
    WITH findings — they live in its output — and a nonzero `verify` means servers FAILED.
    Recording that as OK made the walk read all-green off a run whose flagship step failed.
    """
    monkeypatch.setattr(checkup, "_binary", _fake_binary("import sys; sys.exit(1)"))
    dest = tmp_path / "nonzero.zip"
    assert checkup.run(output=str(dest), assume_yes=True) == 0   # the walk still completes
    walk = _walkthrough(dest)
    cmd_steps = [s for s in walk["steps"] if s["command"]]
    assert cmd_steps and all(s["outcome"] == checkup.FAILED for s in cmd_steps), (
        "a nonzero exit must be FAILED, not a false OK")


def test_a_non_utf8_byte_does_not_abort_the_walk(tmp_path, monkeypatch):
    """A scanned server emitting one non-UTF-8 byte used to raise UnicodeDecodeError (a ValueError,
    past the OSError handler) and abort the whole walk with NO bundle — on the machine whose bundle
    is worth the most. Decoding must never end the walk."""
    monkeypatch.setattr(checkup, "_binary",
                        _fake_binary(r"import sys; sys.stdout.buffer.write(b'host \xff there')"))
    dest = tmp_path / "badbyte.zip"
    assert checkup.run(output=str(dest), assume_yes=True) == 0, "the walk did not complete"
    assert dest.exists(), "no bundle was written after a non-UTF-8 byte"
    walk = _walkthrough(dest)
    assert any(s["name"] == "panel" for s in walk["steps"]), "the walk reached the end"


def test_ctrl_c_during_the_panel_still_writes_the_bundle(tmp_path, monkeypatch):
    """The Ctrl-C guarantee covered only the step loop; a ^C during the panel or while gathering
    the rest died with a traceback and no file, right after the program promised one."""
    monkeypatch.setattr(checkup, "_binary", _fake_binary("print('ok')"))

    def _boom(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(checkup, "_panel_tabs", _boom)

    dest = tmp_path / "interrupted.zip"
    assert checkup.run(output=str(dest), assume_yes=True) == 0
    assert dest.exists(), "a ^C during the panel lost the whole bundle"
    walk = _walkthrough(dest)                     # the zip is valid and complete
    assert walk["stopped_early"] is True
    assert any(s["name"] == "scan" for s in walk["steps"]), "the earlier steps were still captured"


def test_the_panel_is_captured_once_with_every_tab_in_it(tmp_path, monkeypatch):
    """One render, not one per tab.

    The nav is CSS-only, so a single document already holds every tab. The first version
    wrote nine byte-identical 214 KB copies and its own step said 'ok'.
    """
    monkeypatch.setattr(checkup, "_binary", _fake_binary("print('ok')"))
    dest = tmp_path / "panel.zip"
    assert checkup.run(output=str(dest), assume_yes=True) == 0
    with zipfile.ZipFile(dest) as archive:
        pages = [n for n in archive.namelist() if n.startswith("panel/")]
    assert pages == ["panel/panel.html"], f"expected one panel document, got {pages}"


def test_the_walk_records_the_command_without_the_person_who_ran_it(tmp_path, monkeypatch):
    """`walkthrough.json` stores each command; the binary's path is under their home.

    Caught by grepping a real bundle: the raw list reached the file through asdict() while
    only the PRINTED copy was scrubbed. Scrub where it is stored, not where it is shown.
    """
    import getpass

    monkeypatch.setattr(checkup, "_binary", _fake_binary("print('ok')"))
    dest = tmp_path / "who.zip"
    assert checkup.run(output=str(dest), assume_yes=True) == 0
    with zipfile.ZipFile(dest) as archive:
        blob = "\n".join(archive.read(n).decode("utf-8", "replace") for n in archive.namelist())
    user = getpass.getuser()
    if len(user) >= 4:
        assert user not in blob, "the walk names the person who ran it"
