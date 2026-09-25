"""When verify cannot complete a session-bound-auth server, it points at the OBSERVED alternative
if wrap has watched it, or at `wrap install` if it has not — without ever changing the exit code or
claiming reproduction. The follow-up logic is pure (observed_followup) so it is tested here directly.
"""
from __future__ import annotations

import json
import sys

from mcpgawk.verify import observed_followup


def _store() -> dict:
    return {"servers": {"kite": {"history": [
        {"tools": {"get_profile": "h1"}, "transport": "stdio",
         "measured_at": "2026-01-01T00:00:00Z", "enumerated": ["tool"]},
    ]}}}


def _spool(tmp_path, records) -> str:
    p = tmp_path / "calls.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return str(p)


def test_incomplete_server_wrap_observed_gets_the_observed_pointer(tmp_path):
    sp = _spool(tmp_path, [{"adapter": "wrap", "server": "kite", "tool": "get_profile", "decision": "allow"}])
    report = {"servers": [{"server": "kite", "status": "INCOMPLETE", "incompleteReasons": ["please sign in"]}]}
    lines = observed_followup(report, _store(), spool_path=sp)
    assert any("wrap has observed it" in ln for ln in lines)
    assert any("OBSERVED via wrap" in ln for ln in lines)
    assert any("not reproduction" in ln for ln in lines)  # honesty carried through


def test_incomplete_auth_server_without_wrap_data_gets_the_install_hint(tmp_path):
    sp = _spool(tmp_path, [])
    report = {"servers": [{"server": "kite", "status": "INCOMPLETE", "incompleteReasons": ["waiting for sign-in"]}]}
    lines = observed_followup(report, _store(), spool_path=sp)
    assert any("mcpgawk wrap install kite" in ln for ln in lines)


def test_a_completed_server_is_left_alone(tmp_path):
    sp = _spool(tmp_path, [{"adapter": "wrap", "server": "kite", "tool": "get_profile", "decision": "allow"}])
    report = {"servers": [{"server": "kite", "status": "CLEAN", "complete": True}]}
    assert observed_followup(report, _store(), spool_path=sp) == []


def test_incomplete_but_not_auth_and_no_wrap_data_says_nothing(tmp_path):
    # a dispatch/timeout INCOMPLETE with no wrap data and no auth reason must not misadvise `wrap`
    sp = _spool(tmp_path, [])
    report = {"servers": [{"server": "kite", "status": "INCOMPLETE", "incompleteReasons": ["dynamic dispatch"]}]}
    assert observed_followup(report, _store(), spool_path=sp) == []


def test_the_followup_never_corrupts_a_machine_readable_stdout(tmp_path, monkeypatch, capsys):
    """`--json` promises stdout IS the report. This follow-up is printed by the WRAPPER after the
    engine has finished, so until 2026-09-18 it landed inside that report: `mcpgawk verify --json |
    jq` died with "Invalid numeric literal", and `--json > report.json` wrote a file that is not
    JSON. The lines must still be shown — on stderr, where they cannot corrupt the stream.
    """
    from mcpgawk import history, verify

    # Redirect EVERY store this touches: the follow-up reads the real history and the real
    # last-verify.json otherwise, and a test must never read (or write) the operator's own.
    report = {"servers": [{"server": "kite", "status": "INCOMPLETE",
                           "incompleteReasons": ["please sign in"]}]}
    rep_path = tmp_path / "last-verify.json"
    rep_path.write_text(json.dumps(report), encoding="utf-8")
    sp = _spool(tmp_path, [{"adapter": "wrap", "server": "kite", "tool": "get_profile",
                            "decision": "allow"}])
    monkeypatch.setattr(verify, "_last_verify_path", lambda: rep_path)
    monkeypatch.setattr(history, "default_path", lambda: tmp_path / "history.json")
    monkeypatch.setattr(history, "load_checked", lambda _p: (_store(), None))
    monkeypatch.setattr(verify, "observed_followup",
                        lambda rep, store, **kw: observed_followup(rep, store, spool_path=sp))

    # The engine's half of a --json run: the report, and nothing else, on stdout.
    print(json.dumps({"schemaVersion": "1.2", "servers": []}))
    verify._print_observed_followup(sys.stderr)
    out, err = capsys.readouterr()

    json.loads(out)  # THE ASSERTION: stdout still parses. Bare print() here makes this raise.
    assert "wrap has observed" in err  # and the reader is not silently deprived of it


def test_a_human_run_still_gets_the_followup_on_stdout(tmp_path, monkeypatch, capsys):
    """The other half of the same rule: stdout is only sacred when it is a machine stream. In a
    normal run the engine's own prose goes to stdout, so these lines belong beside it."""
    from mcpgawk import history, verify

    report = {"servers": [{"server": "kite", "status": "INCOMPLETE",
                           "incompleteReasons": ["please sign in"]}]}
    rep_path = tmp_path / "last-verify.json"
    rep_path.write_text(json.dumps(report), encoding="utf-8")
    sp = _spool(tmp_path, [{"adapter": "wrap", "server": "kite", "tool": "get_profile",
                            "decision": "allow"}])
    monkeypatch.setattr(verify, "_last_verify_path", lambda: rep_path)
    monkeypatch.setattr(history, "default_path", lambda: tmp_path / "history.json")
    monkeypatch.setattr(history, "load_checked", lambda _p: (_store(), None))
    monkeypatch.setattr(verify, "observed_followup",
                        lambda rep, store, **kw: observed_followup(rep, store, spool_path=sp))

    verify._print_observed_followup(sys.stdout)
    out, _err = capsys.readouterr()
    assert "wrap has observed" in out
