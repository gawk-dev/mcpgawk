"""Slice 2 of the approval passphrase (docs/design-approve-presence-2026-11-05.md §4.1, FOUNDER 2026-11-06
"1 yes"): on a LOCKED machine the guard hook enforces only approvals whose signature verifies against the
root-owned anchor, and nothing defers.

Each test below is a way an agent moved a baseline on 2026-11-05 (runs 3 and 4) or a way to fake the
lock, replayed against the hook's own decision.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcpgawk import approval_lock as al
from mcpgawk import guard_hook, history

PASS = "correct horse battery staple"
SIGHTING = {"pin": "p1", "tools": {"read": "aaaaaaaaaaaa"}, "items": {"tool.read": "aaaaaaaaaaaa"},
            "props": {"tool.read": ["path"]}, "tools_basis": 1,
            "measured_at": "2026-11-06T00:00:00+00:00"}
EVENT = {"tool_name": "mcp__srv__read", "tool_input": {}}


@pytest.fixture
def person(monkeypatch):
    monkeypatch.setattr(history, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(history, "_process_ancestry", lambda: ["zsh", "login", "Terminal"])
    monkeypatch.delenv("MCPGAWK_APPROVE_NONINTERACTIVE", raising=False)
    for m in history.AGENT_ENV_MARKERS:
        monkeypatch.delenv(m, raising=False)


@pytest.fixture
def anchor_dir(tmp_path, monkeypatch):
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


_KEY: dict = {}


def _lock(store):
    """Lock the scratch machine. The key is derived ONCE per file: scrypt at the measured strength
    is deliberately slow, and re-deriving it per test pushed ./verify past its 100 s budget."""
    if "doc" not in _KEY:
        _KEY["doc"], _KEY["pub"] = al.create_key(PASS)
    al.write_key(_KEY["doc"], al.key_path(store))
    al.write_anchor_unprivileged_for_tests(_KEY["pub"])
    return _KEY["pub"]


def _signer(store):
    """The unlocked key, unlocked once (same reason). Signing needs no derivation."""
    if "signer" not in _KEY:
        _KEY["signer"] = al.unlock(PASS, store)
    return _KEY["signer"]


def _decide(store):
    out, _note = guard_hook.decide(dict(EVENT), Path(store))
    return out


def _denied(out) -> bool:
    return out is not None and out["hookSpecificOutput"]["permissionDecision"] == "deny"


def _signed_approval(store):
    _lock(store)
    history.approve("mcp:srv", store, signer=_signer(store))


# ── the writer and the reader agree on what is signed ─────────────────────────────────────────────

def test_a_signed_approval_verifies_from_the_projection_row_alone(store, anchor_dir, person):
    _signed_approval(store)
    row = json.loads(Path(history.projection_path(store)).read_text())["servers"]["mcp:srv"]
    assert row.get("sig"), "the projection must carry the signature"
    assert guard_hook._signed("mcp:srv", row, al.trusted_public_key()) is True
    assert not _denied(_decide(store))           # signed and unchanged: the call goes ahead


def test_the_fallback_anchor_path_is_the_lock_modules_own(real_anchor_paths):
    dirs, fallback = real_anchor_paths                # the shipped values, not the suite's stand-in
    assert set(dirs) == set(fallback) == {"darwin", "linux"}
    for plat, d in dirs.items():
        assert fallback[plat] == str(d / al.ANCHOR_FILE)


def test_no_test_reads_the_real_anchor():
    """CI has no anchor, so only this can fail there if the suite's redirect is removed."""
    assert not str(al.anchor_path()).startswith(("/Library", "/etc"))
    assert not any(p.startswith(("/Library", "/etc")) for p in guard_hook._ANCHOR_FALLBACK.values())


# ── locked: every way to an unsigned "approval" is refused ───────────────────────────────────────

def test_locked_a_never_approved_server_is_refused(store, anchor_dir, person):
    _lock(store)
    out = _decide(store)
    assert _denied(out)
    assert "locked" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_locked_an_approval_written_into_the_store_is_refused(store, anchor_dir, person):
    """RUN 3: the agent writes `approved` itself (through the canonical writer, so the projection is
    fresh and carries the row) — no signature, so no trust."""
    _lock(store)
    s = history.load(store)
    s["servers"]["mcp:srv"].update({"approved": dict(SIGHTING), "approved_via": "approve",
                                    "approved_at": "2026-11-06T01:00:00+00:00"})
    history.save(s, store)
    assert _denied(_decide(store))


def test_locked_an_approval_signed_by_another_key_is_refused(store, anchor_dir, person):
    _lock(store)
    doc2, _pub2 = al.create_key("an agent's own passphrase")
    other = tmp_key = Path(store).parent / "agent-key.json"
    al.write_key(doc2, tmp_key)
    s = history.load(store)
    e = s["servers"]["mcp:srv"]
    e.update({"approved": dict(SIGHTING), "approved_via": "approve",
              "approved_at": "2026-11-06T01:00:00+00:00"})
    # unlock(require_anchor=False) reads the key beside a store path: point it at the agent's key
    agent_store = str(other.parent / "x" / "history.json")
    Path(agent_store).parent.mkdir()
    al.write_key(doc2, al.key_path(agent_store))
    signer = al.unlock("an agent's own passphrase", agent_store, require_anchor=False)
    e["approved_sig"] = signer.sign(history.approval_payload("mcp:srv", e["approved"],
                                                             e["approved_at"]))
    history.save(s, store)
    assert _denied(_decide(store))


def test_locked_a_hand_edited_store_is_refused_not_deferred(store, anchor_dir, person):
    """The store written without the canonical writer: the projection is stale. Unlocked, the hook
    defers on that; locked, it refuses."""
    _signed_approval(store)
    p = Path(store)
    p.write_text(p.read_text() + "\n")           # any write that bypasses history.save
    out = _decide(store)
    assert _denied(out)


def test_locked_a_deleted_projection_is_refused(store, anchor_dir, person):
    _signed_approval(store)
    os.unlink(history.projection_path(store))
    assert _denied(_decide(store))


def test_locked_but_the_lock_code_cannot_load_refuses(store, anchor_dir, person, monkeypatch,
                                                      tmp_path):
    """Fail-closed: an anchor at the fixed path with the lock module unloadable is LOCKED and
    unverifiable — even a correctly signed approval is refused."""
    _signed_approval(store)
    marker = tmp_path / "fixed-anchor.json"
    marker.write_text("{}")
    monkeypatch.setattr(guard_hook, "_lock_module", lambda: None)
    monkeypatch.setattr(guard_hook, "_ANCHOR_FALLBACK", {al._platform(): str(marker)})
    assert guard_hook._lock_state() == b""
    assert _denied(_decide(store))


# ── not locked: exactly today's behaviour ─────────────────────────────────────────────────────────

def test_unlocked_a_never_approved_server_defers(store, anchor_dir, person):
    assert guard_hook._lock_state() is None
    assert not _denied(_decide(store))


def test_an_anchor_anyone_could_write_leaves_the_machine_unlocked(store, anchor_dir, person):
    _lock(store)
    os.chmod(al.anchor_path(), 0o666)
    assert guard_hook._lock_state() is None
    assert not _denied(_decide(store))           # old behaviour: never approved → defer


# ── the hook as it really runs: by file path, no package ─────────────────────────────────────────

def test_the_hook_loads_the_lock_code_without_the_package():
    """The installed hook runs guard_hook.py by path, with no parent package. If approval_lock
    stopped loading that way, `_lock_state` would fall back to the fixed path — this pins that the
    real module loads and answers."""
    hook = Path(guard_hook.__file__)
    code = ("import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('gh', {str(hook)!r})\n"
            "m = importlib.util.module_from_spec(spec); sys.modules['gh'] = m\n"
            "spec.loader.exec_module(m)\n"
            "mod = m._lock_module()\n"
            "assert mod is not None and 'mcpgawk' not in sys.modules, mod\n"
            "assert callable(mod.trusted_public_key) and callable(mod.payload)\n"
            "print('loaded', mod.__name__)\n")
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "loaded _mcpgawk_approval_lock" in r.stdout


# ── name-only approvals: a server mcpgawk has never seen (FOUNDER 2026-11-06) ─────────────────────
# MEASURED the same day: once locked, claude-in-chrome (built into the agent, in no config a scan
# reads) was refused with no way to approve it — `approve --list` silent, `approve` "no tracked
# server". A name-only approval is the person allowing it, unchecked, with the passphrase.

def _call(store, server):
    out, note = guard_hook.decide({"tool_name": f"mcp__{server}__tabs", "tool_input": {}},
                                  Path(store))
    return out, note


def _name_only(store, name):
    history.approve_name_only(name, _signer(store), store)


def test_a_name_only_approval_lets_that_name_through_and_says_it_is_unchecked(store, anchor_dir,
                                                                             person):
    _lock(store)
    assert _denied(_call(store, "chrome")[0])            # before: refused, as measured
    _name_only(store, "chrome")
    out, note = _call(store, "chrome")
    assert not _denied(out)
    assert note == guard_hook.NAME_ONLY_NOTE.format(server="chrome")
    assert "not checked" in note


def test_name_only_is_the_exact_name(store, anchor_dir, person):
    _lock(store)
    _name_only(store, "chrome")
    assert _denied(_call(store, "chrome2")[0])
    assert _denied(_call(store, "chrom")[0])


def test_a_forged_name_only_signature_is_refused(store, anchor_dir, person):
    _lock(store)
    s = history.load(store)
    s["name_only"] = {"chrome": {"approved_at": "2026-11-06T00:00:00+00:00", "sig": "AAAA"}}
    history.save(s, store)                                # canonical writer: projection fresh
    assert _denied(_call(store, "chrome")[0])


def test_a_signature_for_another_name_does_not_transfer(store, anchor_dir, person):
    _lock(store)
    _name_only(store, "other")
    s = history.load(store)
    s["name_only"]["chrome"] = dict(s["name_only"]["other"])
    history.save(s, store)
    assert _denied(_call(store, "chrome")[0])


def test_a_stale_store_refuses_even_a_valid_name_only(store, anchor_dir, person):
    _lock(store)
    _name_only(store, "chrome")
    p = Path(store)
    p.write_text(p.read_text() + "\n")                    # written behind the canonical writer
    assert _denied(_call(store, "chrome")[0])


def test_a_tracked_server_is_never_unblocked_by_name(store, anchor_dir, person):
    """`srv` is in the store (seen, never signed). A name-only approval for it — however made —
    must not let it through: a seen server is approved with its tools."""
    _lock(store)
    _name_only(store, "srv")
    assert _denied(_call(store, "srv")[0])


def test_a_name_only_signature_cannot_stand_in_for_a_server_row(store, anchor_dir, person):
    """Domain separation: the name-only signature pasted as a tracked row's `approved_sig` signs an
    EMPTY tool list under another key, so it verifies for nothing the hook would allow."""
    _lock(store)
    _name_only(store, "srv")
    s = history.load(store)
    e = s["servers"]["mcp:srv"]
    e.update({"approved": dict(SIGHTING), "approved_via": "approve",
              "approved_at": s["name_only"]["srv"]["approved_at"],
              "approved_sig": s["name_only"]["srv"]["sig"]})
    history.save(s, store)
    assert _denied(_decide(store))


def test_name_only_needs_the_passphrase(store, anchor_dir, person):
    _lock(store)
    with pytest.raises(history.ApprovalBlocked):
        history.approve_name_only("chrome", None, store)


# ── the command ─────────────────────────────────────────────────────────────────────────────────

def _cli(store, monkeypatch, *argv):
    from mcpgawk import cli
    monkeypatch.setenv("MCPGAWK_HISTORY", store)
    monkeypatch.setattr(history, "default_path", lambda: store)
    monkeypatch.setattr(al, "read_passphrase", lambda prompt: PASS)
    return cli._dispatch(["approve", *argv])


def test_cli_name_only_allows_an_unseen_server(store, anchor_dir, person, monkeypatch, capsys):
    _lock(store)
    assert _cli(store, monkeypatch, "chrome", "--name-only") == 0
    assert "by name only" in capsys.readouterr().out
    assert not _denied(_call(store, "chrome")[0])
    _cli(store, monkeypatch, "--list")
    assert "allowed by name only" in capsys.readouterr().out


def test_cli_refuses_name_only_for_a_server_it_has_seen(store, anchor_dir, person, monkeypatch,
                                                       capsys):
    _lock(store)
    assert _cli(store, monkeypatch, "srv", "--name-only") == 2
    assert "has seen" in capsys.readouterr().err
    assert "name_only" not in history.load(store)


def test_cli_name_only_on_an_unlocked_machine_changes_nothing(store, anchor_dir, person,
                                                             monkeypatch, capsys):
    assert _cli(store, monkeypatch, "chrome", "--name-only") == 2
    assert "not locked" in capsys.readouterr().err
    assert "name_only" not in history.load(store)


def test_an_unknown_name_on_a_locked_machine_points_at_name_only(store, anchor_dir, person,
                                                                 monkeypatch, capsys):
    _lock(store)
    assert _cli(store, monkeypatch, "chrome") == 2
    assert "--name-only" in capsys.readouterr().err
