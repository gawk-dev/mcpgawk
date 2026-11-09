"""Signed approvals: the approval passphrase and the root-owned anchor (slice 1).

FOUNDER 2026-11-06 ("1. Yes 2. yes"), docs/design-approve-presence-2026-11-05.md §4.1. MEASURED the day
before: an agent moved a baseline three ways the signals never stopped (run 2: markers stripped + a
fake terminal; run 3: editing history.json; run 4: a double-fork that recorded `person_present: True`).
A signature only the passphrase can make, checked against a public key only root can place, is the
first control none of the three can satisfy.

THE CONSTRAINTS (design §4.1), pinned here before the feature:
  * no env var or flag names the anchor or carries the passphrase — tests patch module attributes;
  * the anchor is trusted only when root owns it and neither it nor its folder is writable by others;
  * in locked mode EVERY writer needs a signer that the anchor trusts — without one, it refuses;
  * a signature covers exactly what enforcement reads (`tools`, `props`, `approved_at`, the key);
  * in locked mode a baseline with no valid signature is named, never read as "you approved it".
"""
from __future__ import annotations

import ast
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from mcpgawk import approval_lock as al
from mcpgawk import history

PASS = "correct horse battery staple"
SIGHTING = {"pin": "p1", "tools": {"read": "aaaaaaaaaaaa"}, "items": {"tool.read": "aaaaaaaaaaaa"},
            "props": {"tool.read": ["path"]}, "tools_basis": 1,
            "measured_at": "2026-11-06T00:00:00+00:00"}


# ── fixtures: a fake root-owned anchor folder, by MODULE ATTRIBUTE, never by environment ──────────

@pytest.fixture
def person(monkeypatch):
    monkeypatch.setattr(history, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(history, "_process_ancestry", lambda: ["zsh", "login", "Terminal"])
    monkeypatch.delenv("MCPGAWK_APPROVE_NONINTERACTIVE", raising=False)
    for m in history.AGENT_ENV_MARKERS:
        monkeypatch.delenv(m, raising=False)


@pytest.fixture
def anchor_dir(tmp_path, monkeypatch):
    """A stand-in for /Library/Application Support/mcpgawk: the test user plays root."""
    d = tmp_path / "root-owned" / "mcpgawk"
    d.mkdir(parents=True)
    os.chmod(d, 0o755)
    os.chmod(d.parent, 0o755)
    monkeypatch.setattr(al, "ANCHOR_DIRS", {al._platform(): d})
    monkeypatch.setattr(al, "_root_owned", lambda st: st.st_uid == os.getuid())
    return d


@pytest.fixture
def store(tmp_path):
    path = str(tmp_path / "home" / ".mcpgawk" / "history.json")
    Path(path).parent.mkdir(parents=True)
    history.save({"servers": {"mcp:srv": {"aliases": ["srv"], "history": [dict(SIGHTING)]}}}, path)
    return path


def _lock(store, anchor_dir, passphrase=PASS):
    """Lock the scratch machine the way `approvals lock` does, minus sudo (the test user is 'root')."""
    doc, pub = al.create_key(passphrase)
    al.write_key(doc, al.key_path(store))
    al.write_anchor_unprivileged_for_tests(pub)
    return pub


# ── 1. nothing outside the person's own typing can unlock or relocate it ─────────────────────────

def test_the_lock_module_reads_no_environment():
    """An env var is exactly what an agent with a shell sets. The anchor path and the passphrase
    must come from nowhere it can write."""
    tree = ast.parse(Path(al.__file__).read_text(encoding="utf-8"))
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    calls = {n.func.attr for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "environ" not in names and "getenv" not in calls


def test_the_passphrase_is_read_from_the_terminal_only(monkeypatch):
    """No stdin fallback: getpass falls back to stdin when there is no /dev/tty; we refuse instead."""
    monkeypatch.setattr(al, "_open_tty", lambda: (_ for _ in ()).throw(OSError("no tty")))
    with pytest.raises(al.NoTerminal):
        al.read_passphrase("Approval passphrase: ")


def test_the_key_derivation_is_the_measured_strength():
    assert (al.SCRYPT_N, al.SCRYPT_R, al.SCRYPT_P) == (2 ** 17, 8, 1)
    assert al.MIN_PASSPHRASE >= 12


# ── 2. the anchor ────────────────────────────────────────────────────────────────────────────────

def test_no_anchor_means_unlocked(anchor_dir):
    a = al.read_anchor()
    assert a.status == "absent" and al.locked() is False


def test_a_root_owned_anchor_is_trusted(store, anchor_dir):
    pub = _lock(store, anchor_dir)
    a = al.read_anchor()
    assert a.status == "trusted" and a.public_key == pub and al.locked() is True


@pytest.mark.parametrize("break_it, said", [
    (lambda f: os.chmod(f, 0o666), "writable by group or others"),
    (lambda f: os.chmod(f.parent, 0o777), "folder is writable by group or others"),
])
def test_an_anchor_others_could_write_is_ignored_and_named(store, anchor_dir, break_it, said):
    _lock(store, anchor_dir)
    break_it(al.anchor_path())
    a = al.read_anchor()
    assert a.status == "untrusted" and said in a.why
    assert al.locked() is False


def test_an_anchor_not_owned_by_root_is_ignored_and_named(store, anchor_dir, monkeypatch):
    _lock(store, anchor_dir)
    monkeypatch.setattr(al, "_root_owned", lambda st: False)
    a = al.read_anchor()
    assert a.status == "untrusted" and "not owned by root" in a.why


# ── 3. locked: every writer needs a signer the anchor trusts ─────────────────────────────────────

def test_locked_approve_without_the_passphrase_is_refused(store, anchor_dir, person):
    _lock(store, anchor_dir)
    with pytest.raises(history.ApprovalBlocked) as refused:
        history.approve("mcp:srv", store)
    assert "passphrase" in refused.value.reason
    assert "approved_sig" not in history.load(store)["servers"]["mcp:srv"]


def test_locked_approve_through_the_ci_hatch_is_refused(store, anchor_dir, monkeypatch):
    _lock(store, anchor_dir)
    monkeypatch.setattr(history, "_stdin_is_tty", lambda: False)
    monkeypatch.setattr(history, "_process_ancestry", lambda: ["sh", "python"])
    monkeypatch.setenv("MCPGAWK_APPROVE_NONINTERACTIVE", "1")
    with pytest.raises(history.ApprovalBlocked):
        history.approve("mcp:srv", store)


def test_a_wrong_passphrase_unlocks_nothing(store, anchor_dir):
    _lock(store, anchor_dir)
    with pytest.raises(al.WrongPassphrase):
        al.unlock("not the passphrase at all", store)


def test_a_key_the_anchor_does_not_trust_cannot_sign(store, anchor_dir, person):
    """The agent's own fresh keypair, written where mcpgawk looks for the key."""
    _lock(store, anchor_dir)
    doc, _pub = al.create_key("an agent's own passphrase")
    al.write_key(doc, al.key_path(store))
    with pytest.raises(al.NotTheAnchoredKey):
        al.unlock("an agent's own passphrase", store)


def test_a_signed_approval_verifies_and_covers_what_enforcement_reads(store, anchor_dir, person):
    _lock(store, anchor_dir)
    signer = al.unlock(PASS, store)
    history.approve("mcp:srv", store, signer=signer)
    s = history.load(store)
    assert history.signature_state(s, "mcp:srv") == "valid"
    assert history.baseline_origin(s, "mcp:srv") == "approve"
    for field, value in (("tools", {"read": "bbbbbbbbbbbb"}), ("props", {"tool.read": ["path", "api_key"]})):
        tampered = json.loads(json.dumps(s))
        tampered["servers"]["mcp:srv"]["approved"][field] = value
        assert history.signature_state(tampered, "mcp:srv") == "invalid", field


def test_the_key_file_is_private(store, anchor_dir):
    _lock(store, anchor_dir)
    mode = stat.S_IMODE(al.key_path(store).stat().st_mode)
    assert mode & 0o077 == 0, oct(mode)


# ── 4. locked: a baseline with no valid signature is named, and waits for the person ─────────────

def test_a_hand_edited_approval_is_named_and_waits_for_a_signature(store, anchor_dir, person):
    """RUN 3, read back: the agent writes `approved` itself. Unlocked, `approve --list` said every
    server matched its baseline. Locked, the record has no valid signature: it is listed as needing
    the person, and no surface calls it the person's approval."""
    _lock(store, anchor_dir)
    s = history.load(store)
    e = s["servers"]["mcp:srv"]
    e.update({"approved": dict(SIGHTING), "approved_via": "approve",
              "approved_at": "2026-11-06T01:00:00+00:00"})
    history.save(s, store)
    s = history.load(store)
    assert history.needs_signature(s) == ["mcp:srv"]
    assert history.baseline_origin(s, "mcp:srv") == "unsigned"
    assert "you approved" not in history.changed_head("unsigned", None)
    assert "cannot verify" in history.changed_head("unsigned", None)


def test_unlocked_machines_behave_exactly_as_before(store, anchor_dir, person):
    """No anchor: nothing to sign, nothing named, the approval is the person's as today."""
    history.approve("mcp:srv", store)
    s = history.load(store)
    assert history.signature_state(s, "mcp:srv") is None
    assert history.needs_signature(s) == []
    assert history.baseline_origin(s, "mcp:srv") == "approve"


def test_signing_existing_approvals_needs_the_person_too(store, anchor_dir, person):
    history.approve("mcp:srv", store)          # before the lock
    _lock(store, anchor_dir)
    assert history.needs_signature(history.load(store)) == ["mcp:srv"]
    signer = al.unlock(PASS, store)
    assert history.sign_approvals(["mcp:srv"], signer, store) == ["mcp:srv"]
    s = history.load(store)
    assert history.signature_state(s, "mcp:srv") == "valid" and history.needs_signature(s) == []


# ── 5. the commands: approve on a locked machine reads the passphrase from the terminal only ─────

def _cli_approve(store, monkeypatch, *argv):
    from mcpgawk import cli
    monkeypatch.setattr(history, "default_path", lambda: store)
    return cli._dispatch(["approve", *argv])


def test_locked_cli_approve_with_no_terminal_refuses_and_moves_nothing(store, anchor_dir, person,
                                                                        monkeypatch, capsys):
    _lock(store, anchor_dir)
    monkeypatch.setenv("MCPGAWK_HISTORY", store)

    def no_tty():
        raise OSError("no tty")
    monkeypatch.setattr(al, "_open_tty", no_tty)
    assert _cli_approve(store, monkeypatch, "mcp:srv") == 4
    assert "no terminal" in capsys.readouterr().err
    assert not history.load(store)["servers"]["mcp:srv"].get("approved")


def test_locked_cli_approve_with_a_wrong_passphrase_refuses(store, anchor_dir, person, monkeypatch,
                                                            capsys):
    _lock(store, anchor_dir)
    monkeypatch.setenv("MCPGAWK_HISTORY", store)
    monkeypatch.setattr(al, "read_passphrase", lambda prompt: "an agent's best guess")
    assert _cli_approve(store, monkeypatch, "mcp:srv") == 4
    assert "does not unlock" in capsys.readouterr().err
    assert not history.load(store)["servers"]["mcp:srv"].get("approved")


def test_locked_cli_approve_with_the_passphrase_signs(store, anchor_dir, person, monkeypatch):
    _lock(store, anchor_dir)
    monkeypatch.setenv("MCPGAWK_HISTORY", store)
    monkeypatch.setattr(al, "read_passphrase", lambda prompt: PASS)
    assert _cli_approve(store, monkeypatch, "mcp:srv") == 0
    s = history.load(store)
    assert history.signature_state(s, "mcp:srv") == "valid" and history.needs_signature(s) == []


def test_an_untrusted_anchor_is_said_and_the_machine_stays_unlocked(store, anchor_dir, person):
    _lock(store, anchor_dir)
    os.chmod(al.anchor_path(), 0o666)                  # anyone could have written it
    signer, say, refused = al.signer_for(store)
    assert signer is None and refused is False
    assert any("ignoring the approval anchor" in line for line in say)


def _cli_lock(store, monkeypatch, answers):
    from mcpgawk import cli
    monkeypatch.setenv("MCPGAWK_HISTORY", store)
    monkeypatch.setattr(history, "default_path", lambda: store)
    monkeypatch.setattr(al, "install_anchor",
                        lambda pub: (al.write_anchor_unprivileged_for_tests(pub), al.read_anchor())[1])
    monkeypatch.setattr(al, "ask", lambda prompt: "y")
    typed = iter(answers)
    monkeypatch.setattr(al, "read_passphrase", lambda prompt: next(typed))
    return cli._dispatch(["approvals", "lock"])


def test_lock_offers_only_your_approvals_and_names_first_sightings(tmp_path, anchor_dir, person,
                                                                   monkeypatch, capsys):
    """MEASURED 2026-11-06, the founder's first lock: offered 17 for signing, signed 5, and said
    nothing about the 12 first sightings it could not sign. Offer what can be signed; name the rest
    with the command that approves them."""
    store = str(tmp_path / "home" / ".mcpgawk" / "history.json")
    Path(store).parent.mkdir(parents=True)
    history.save({"servers": {
        "mcp:mine": {"aliases": ["mine"], "history": [dict(SIGHTING)], "approved": dict(SIGHTING),
                     "approved_via": "approve", "approved_at": "2026-11-01T00:00:00+00:00"},
        "mcp:seen": {"aliases": ["seen"], "history": [dict(SIGHTING)], "approved": dict(SIGHTING),
                     "approved_via": "first-sighting"},
    }}, store)
    assert _cli_lock(store, monkeypatch, [PASS, PASS, PASS]) == 0
    out = capsys.readouterr().out
    never, offered = out.split("never approved")[1].split("you approved before the lock")
    assert "mcp:seen" in never and "mcp:mine" not in never
    assert "mcp:mine" in offered and "mcp:seen" not in offered
    assert "mcpgawk approve" in never
    assert "signed 1 approval." in out
    s = history.load(store)
    assert history.needs_signature(s) == ["mcp:seen"]


def test_a_short_passphrase_is_refused_before_asking_again(tmp_path, store, anchor_dir, person,
                                                           monkeypatch, capsys):
    asked = []
    from mcpgawk import cli
    monkeypatch.setenv("MCPGAWK_HISTORY", store)
    monkeypatch.setattr(history, "default_path", lambda: store)
    monkeypatch.setattr(al, "read_passphrase", lambda prompt: asked.append(prompt) or "short")
    assert cli._dispatch(["approvals", "lock"]) == 1
    assert len(asked) == 1 and "at least" in capsys.readouterr().err
    assert al.read_anchor().status != "trusted"


@pytest.mark.skipif(not hasattr(os, "fork") or sys.platform.startswith("win"), reason="POSIX pty")
def test_the_real_terminal_opens_and_answers():
    """MEASURED 2026-11-06: the founder's first `approvals lock` in their own terminal said "there is
    no terminal" — open("/dev/tty", "r+") raises "not seekable" on a real terminal and every test
    stubbed `_open_tty`. This one gives the child a real controlling terminal (pty.fork) and asks."""
    import pty
    import select
    import time as _t
    pid, master = pty.fork()
    if pid == 0:                                            # child: /dev/tty is the pty slave
        try:
            code = 0 if al.ask("answer? ") == "yes" else 3
        except BaseException:
            code = 2
        os._exit(code)
    buf, sent, status = b"", False, None
    try:
        deadline = _t.time() + 10
        while _t.time() < deadline and status is None:
            if select.select([master], [], [], 0.2)[0]:
                try:
                    buf += os.read(master, 1024)
                except OSError:
                    pass                                    # EIO once the child has gone
            if b"answer?" in buf and not sent:
                os.write(master, b"yes\n")
                sent = True
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                status = st
        if status is None:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    finally:
        os.close(master)
    assert status is not None, ("timed out", buf)
    assert os.WEXITSTATUS(status) == 0, (status, buf)
