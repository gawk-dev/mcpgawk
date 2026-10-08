"""THE ORIGINAL BASELINE: what a server has become since it was first trusted, not only since the
last approval.

Each approval moves `approved`, so `approved_change` only ever shows one step. A server widened in
steps that each look small ("salami": +1 tool, then a dropped readOnlyHint) never shows the total.
The first approved record is now kept on the entry (`original_approved`) and never moved; approve,
decide and `baseline` show the change since it. Enforcement is unchanged: the guard still compares
against `approved`. Pattern from the Yashigani read (docs/research-yashigani-2026-10-08.md, item 1).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcpgawk import decide, drift, fingerprint, history
from mcpgawk.probe import ServerSnapshot

KEY = "mcp:notes"


def _tool(name="send_note", desc="Send the note.", read_only=True):
    return {"name": name, "description": desc,
            "inputSchema": {"type": "object", "properties": {"note": {"type": "string"}}},
            "annotations": {"readOnlyHint": read_only}}


def _record(tools, at):
    snap = ServerSnapshot(name="notes", transport="stdio", protocol_version=None, tools=tools,
                          server_info={"name": "notes"}, enumerated=["tools"])
    m = SimpleNamespace(integrity_pin=fingerprint.surface_pin(tools), tool_count=len(tools),
                        total_tokens=0, tokenizer="x")
    return drift.build_record(snap, m, at)


A = [_tool()]
B = [_tool(), _tool("forward_note", "Forward the note.")]          # step 1: +1 tool
C = [_tool(read_only=False), _tool("forward_note", "Forward the note.")]   # step 2: lost readOnlyHint


@pytest.fixture(autouse=True)
def person(monkeypatch):
    monkeypatch.setattr(history, "require_human_approval", lambda: None)
    monkeypatch.setattr(history, "approval_evidence", lambda source="cli": {
        "source": source, "terminal": True, "agent_markers": [], "agent_process": None,
        "hatch": False, "person_present": True})


@pytest.fixture
def path(tmp_path):
    return str(tmp_path / "history.json")


def _see(path, tools, at):
    history.record(KEY, _record(tools, at), path=path, alias="notes")


def _entry(path):
    return history.load(path)["servers"][KEY]


def _salami(path):
    _see(path, A, "2026-10-01T00:00:00+00:00")
    history.approve(KEY, path=path)
    _see(path, B, "2026-10-02T00:00:00+00:00")
    history.approve(KEY, path=path)
    _see(path, C, "2026-10-03T00:00:00+00:00")


def test_the_first_approval_is_kept_and_never_moves(path):
    _salami(path)
    e = _entry(path)
    assert e["original_approved"]["pin"] == _record(A, "x")["pin"]
    assert e["original_via"] in ("first-sighting", "approve")
    history.approve(KEY, path=path)
    assert _entry(path)["original_approved"]["pin"] == _record(A, "x")["pin"], "an approval moved it"


def test_decide_shows_the_step_and_the_total(path):
    _salami(path)
    [d] = decide.pending_decisions(history.load(path))
    step, total = d["since_last"], d["since_original"]
    assert step["tools_added"] == [] and "send_note" in step["permission_growth"], step
    assert total["tools_added"] == ["forward_note"], total
    assert "send_note" in total["permission_growth"], total


def test_the_approval_record_carries_the_total(path):
    _salami(path)
    history.approve(KEY, path=path)
    change = _entry(path)["approved_change"]
    total = change["since_original"]
    assert total["tools_added"] == ["forward_note"] and "send_note" in total["permission_growth"]
    words = history.change_words(change)
    assert "since first" in words and "+1 tool (forward_note)" in words, words


def test_the_second_approval_does_not_repeat_the_same_diff_twice(path):
    _see(path, A, "2026-10-01T00:00:00+00:00")
    history.approve(KEY, path=path)
    _see(path, B, "2026-10-02T00:00:00+00:00")
    history.approve(KEY, path=path)
    change = _entry(path)["approved_change"]
    assert "since_original" not in change, "the original IS the approval just replaced: one diff"


def test_a_store_from_before_this_keeps_the_earliest_known_and_says_so(path):
    _see(path, A, "2026-10-01T00:00:00+00:00")
    history.approve(KEY, path=path)
    store = history.load(path)
    for k in ("original_approved", "original_approved_at", "original_via"):
        store["servers"][KEY].pop(k, None)                    # an older mcpgawk wrote this store
    history.save(store, path)
    _see(path, B, "2026-10-02T00:00:00+00:00")
    history.approve(KEY, path=path)
    e = _entry(path)
    assert e["original_via"] == "earliest-known", e.get("original_via")
    assert e["original_approved"]["pin"] == _record(A, "x")["pin"]
    _see(path, C, "2026-10-03T00:00:00+00:00")
    history.approve(KEY, path=path)
    words = history.change_words(_entry(path)["approved_change"])
    assert "since the earliest approval on record" in words, words


def test_the_guard_still_enforces_the_latest_approval_not_the_original(path):
    _salami(path)
    history.approve(KEY, path=path)
    import json
    proj = json.loads(open(history.projection_path(path), encoding="utf-8").read())
    assert set(proj["servers"][KEY]["tools"]) == {"send_note", "forward_note"}


def test_the_baseline_listing_prints_the_total(path, monkeypatch, capsys):
    from mcpgawk import cli
    _salami(path)
    history.approve(KEY, path=path)
    capsys.readouterr()
    cli._baseline(SimpleNamespace(history=path, json=False, server=None))
    out = capsys.readouterr().out
    assert "since first" in out and "forward_note" in out, out


def test_the_decide_page_shows_the_total_under_the_step(path):
    _salami(path)
    page = decide.render_page(decide.pending_decisions(history.load(path)), token="T")
    assert "In total</b>, since first seen 2026-10-01: +1 tool (forward_note)" in page, page[-1500:]


@pytest.mark.parametrize("field", ["original_approved", "changed_since_approval"])
def test_a_credential_in_a_kept_record_is_masked_on_save(path, field):
    """Both copies the entry keeps (the original baseline, the latched sighting) reach disk through
    `save` like every other record, and are masked there (history.entry_records)."""
    import copy
    _see(path, A, "2026-10-01T00:00:00+00:00")
    store = history.load(path)
    rec = copy.deepcopy(store["servers"][KEY]["approved"])
    rec.pop("_redacted", None)
    rec.setdefault("texts", {})["tool.send_note"] = "Send it with apiKey=CANARY_KEPT_4242"
    store["servers"][KEY][field] = rec
    history.save(store, path)
    assert "CANARY_KEPT_4242" not in open(path, encoding="utf-8").read()
