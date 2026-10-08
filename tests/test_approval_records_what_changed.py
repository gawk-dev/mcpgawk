"""An approval records WHAT it accepted and, if given, WHY.

"Approved by me at 10:02" does not answer the first question a security team asks of a baseline:
what exactly did you accept? Each approval now stores the change it adopted (tools added and
removed, descriptions rewritten, inputs reshaped, permission growth) against the previous
approval, plus an optional `--reason`. Pattern from the Yashigani read
(docs/research-yashigani-2026-10-08.md, candidate 3).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcpgawk import drift, fingerprint, history
from mcpgawk.probe import ServerSnapshot


def _tool(name="send_note", desc="Return the note.", props=None, read_only=None):
    t = {"name": name, "description": desc,
         "inputSchema": {"type": "object", "properties": props or {"note": {"type": "string"}}}}
    if read_only is not None:
        t["annotations"] = {"readOnlyHint": read_only}
    return t


def _record(tools, at):
    snap = ServerSnapshot(name="notes", transport="stdio", protocol_version=None, tools=tools,
                          server_info={"name": "notes"}, enumerated=["tools"])
    m = SimpleNamespace(integrity_pin=fingerprint.surface_pin(tools), tool_count=len(tools),
                        total_tokens=0, tokenizer="x")
    return drift.build_record(snap, m, at)


@pytest.fixture(autouse=True)
def person(monkeypatch):
    monkeypatch.setattr(history, "require_human_approval", lambda: None)
    monkeypatch.setattr(history, "approval_evidence", lambda source="cli": {
        "source": source, "terminal": True, "agent_markers": [], "agent_process": None,
        "hatch": False, "person_present": True})


def _store(tmp_path, approved, later):
    path = str(tmp_path / "history.json")
    entry = {"aliases": ["notes"], "history": [approved, later]}
    if approved is not None:
        entry.update(approved=approved, approved_at="2026-10-01T00:00:00+00:00",
                     approved_via="approve")
    history.save({"servers": {"mcp:notes": entry}}, path)
    return path


def _entry(path):
    return history.load(path)["servers"]["mcp:notes"]


def test_an_approval_records_the_change_it_accepted_and_the_reason(tmp_path):
    a = _record([_tool()], "2026-10-01T00:00:00+00:00")
    b = _record([_tool(desc="Return the note, trimmed."),
                 _tool(name="forward_note", props={"note": {"type": "string"}})],
                "2026-10-02T00:00:00+00:00")
    path = _store(tmp_path, a, b)
    history.approve("mcp:notes", path=path, reason="vendor release 2.4, reviewed the diff")
    e = _entry(path)
    change = e["approved_change"]
    assert change["tools_added"] == ["forward_note"]
    assert change["descriptions_changed"] == ["send_note"]
    assert change["tools_removed"] == []
    assert e["approved_reason"] == "vendor release 2.4, reviewed the diff"


def test_permission_growth_is_named_in_the_record(tmp_path):
    a = _record([_tool(read_only=True)], "2026-10-01T00:00:00+00:00")
    b = _record([_tool(read_only=False)], "2026-10-02T00:00:00+00:00")
    path = _store(tmp_path, a, b)
    history.approve("mcp:notes", path=path)
    growth = _entry(path)["approved_change"]["permission_growth"]
    assert growth == {"send_note": ["lost readOnlyHint"]}


def test_a_first_approval_says_so_and_a_missing_reason_is_absent(tmp_path):
    later = _record([_tool()], "2026-10-02T00:00:00+00:00")
    path = _store(tmp_path, None, later)
    history.approve("mcp:notes", path=path)
    e = _entry(path)
    assert e["approved_change"] == {"first_approval": True, "tools": 1}
    assert "approved_reason" not in e


def test_a_reason_is_bounded(tmp_path):
    a = _record([_tool()], "2026-10-01T00:00:00+00:00")
    path = _store(tmp_path, a, a)
    history.approve("mcp:notes", path=path, reason="x" * 5000)
    assert len(_entry(path)["approved_reason"]) == history.APPROVAL_REASON_MAX


def test_the_cli_passes_the_reason_and_the_listing_shows_both(tmp_path, monkeypatch, capsys):
    from mcpgawk import cli
    a = _record([_tool()], "2026-10-01T00:00:00+00:00")
    b = _record([_tool(), _tool(name="forward_note")], "2026-10-02T00:00:00+00:00")
    path = _store(tmp_path, a, b)
    monkeypatch.setattr(history, "default_path", lambda: path)
    assert cli.main(["approve", "notes", "--reason", "needed forward_note"]) == 0
    assert _entry(path)["approved_reason"] == "needed forward_note"
    capsys.readouterr()
    cli._baseline(SimpleNamespace(history=path, json=False, server=None))
    out = capsys.readouterr().out
    assert "+1 tool (forward_note)" in out, out
    assert "reason     needed forward_note" in out, out
