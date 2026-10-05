"""The guard refuses a tool whose PERMISSIONS grew after approval, not only one whose description
changed. Other schema changes keep waiting for sign-off, as decided on 2026-08-15.

MEASURED 2026-10-06 (HANDOFF): after approval, dropping `readOnlyHint` or adding a `forward_to`
URL parameter was reported by scan ("CAPABILITY ESCALATION", "gained parameter(s): forward_to")
and ALLOWED by the installed hook in normal and strict mode, while the launch article said a
changed tool is blocked. FOUNDER 2026-10-06 ("Block permission growth"): refuse on a description
change (as before), an annotation escalation, and a new parameter that names a destination.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcpgawk import decision, drift, fingerprint, guard_hook, history
from mcpgawk.probe import ServerSnapshot

AT0 = "2026-10-01T00:00:00+00:00"
AT1 = "2026-10-02T00:00:00+00:00"
DATA = Path(__file__).resolve().parent.parent / "docs" / "research-data" / "live-probe-churn-2026-10-04.json"


def _tool(*, read_only=None, props=None, desc="Return the note."):
    t = {"name": "send_note", "description": desc,
         "inputSchema": {"type": "object", "properties": props or {"note": {"type": "string"}}}}
    if read_only is not None:
        t["annotations"] = {"readOnlyHint": read_only}
    return t


def _record(tool: dict, at: str) -> dict:
    snap = ServerSnapshot(name="notes", transport="stdio", protocol_version=None, tools=[tool],
                          server_info={"name": "notes"}, enumerated=["tools"])
    m = SimpleNamespace(integrity_pin=fingerprint.surface_pin([tool]), tool_count=1,
                        total_tokens=0, tokenizer="x")
    return drift.build_record(snap, m, at)


@pytest.fixture(autouse=True)
def _no_behaviour(tmp_path, monkeypatch):
    monkeypatch.setenv("GAWK_BEHAVIOUR", str(tmp_path / "absent-behaviour.json"))


def _store(tmp_path, approved_tool: dict, later_tool: dict, *, strict: bool) -> Path:
    approved = _record(approved_tool, AT0)
    store = {"servers": {"mcp:notes": {"aliases": ["notes"], "approved": approved,
                                       "approved_at": AT0, "approved_via": "approve",
                                       "history": [approved, _record(later_tool, AT1)]}}}
    if strict:
        store["guard"] = {"strict": True}
    path = tmp_path / "history.json"
    history.save(store, str(path))
    return path


def _call(path):
    output, _note = guard_hook.decide({"tool_name": "mcp__notes__send_note", "tool_input": {}}, path)
    return output


@pytest.mark.parametrize("strict", [False, True])
def test_a_tool_that_stops_declaring_read_only_is_refused(tmp_path, strict):
    path = _store(tmp_path, _tool(read_only=True), _tool(read_only=False), strict=strict)
    output = _call(path)
    assert output is not None, "a tool that lost readOnlyHint after approval was allowed"
    reason = output["hookSpecificOutput"]["permissionDecisionReason"]
    assert "readOnlyHint" in reason, reason
    assert decision.reason_code(reason) == decision.REASON_TOOL_CHANGED


@pytest.mark.parametrize("strict", [False, True])
def test_a_new_destination_parameter_is_refused(tmp_path, strict):
    later = _tool(props={"note": {"type": "string"},
                         "forward_to": {"type": "string", "description": "URL to send the note to"}})
    path = _store(tmp_path, _tool(), later, strict=strict)
    output = _call(path)
    assert output is not None, "a tool that gained a destination parameter was allowed"
    assert "forward_to" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_an_ordinary_schema_change_still_waits_for_sign_off_and_is_not_refused(tmp_path):
    """FOUNDER 2026-08-15, kept: a widened schema alone does not break the agent."""
    later = _tool(props={"note": {"type": "string"}, "pageId": {"type": "string"}})
    path = _store(tmp_path, _tool(), later, strict=False)
    assert _call(path) is None


@pytest.mark.skipif(not DATA.exists(), reason="the live-probe data set lives in the canonical repo only")
def test_the_destination_rule_on_86_real_releases_flags_only_new_capability():
    """Every parameter the top servers really added between 10 Mar and 9 Sep (live probe, 4 Oct).
    The rule must flag the four that add a place to send or write to, and nothing else: a detector
    that fires on honest updates gets switched off."""
    data = json.loads(DATA.read_text(encoding="utf-8"))
    flagged = []
    for pkg, p in data["packages"].items():
        vers = p["versions"]
        ok = [v for v in p["order"] if vers.get(v, {}).get("status") == "ok"]
        for a, b in zip(ok, ok[1:]):
            before = {t["name"]: t for t in vers[a]["tools"]}
            for t in vers[b]["tools"]:
                if t["name"] not in before:
                    continue
                old = (before[t["name"]].get("inputSchema") or {}).get("properties") or {}
                new = (t.get("inputSchema") or {}).get("properties") or {}
                flagged += [f"{t['name']}.{p_}" for p_ in new
                            if p_ not in old and drift.destination_param(p_)]
    assert sorted(flagged) == sorted(["browser_tabs.url", "evaluate_script.filePath",
                                      "emulate.extraHttpHeaders", "upload_file.filePaths"])


@pytest.mark.parametrize("name, expected", [
    ("forward_to", True), ("webhook_url", True), ("cc", True), ("targetUrl", True),
    ("outputFormat", False), ("pageId", False), ("target", False), ("connectionId", False),
    ("context", False), ("query", False)])
def test_what_counts_as_a_destination(name, expected):
    assert drift.destination_param(name) is expected


def test_the_panel_says_blocked_for_permission_growth_and_names_it():
    """The Decisions chip said "NOT blocked — schema/annotations only, calls still pass" for every
    schema/annotation drift. It must now agree with the guard: permission growth IS blocked."""
    import re
    from mcpgawk import panel
    approved = _record(_tool(read_only=True), AT0)
    grown = _record(_tool(read_only=False), AT1)
    plain = _record(_tool(props={"note": {"type": "string"}, "pageId": {"type": "string"}}), AT1)
    store = {"servers": {
        "mcp:grew": {"aliases": ["grew"], "approved": approved, "history": [approved, grown]},
        "mcp:widened": {"aliases": ["widened"], "approved": _record(_tool(), AT0),
                        "history": [_record(_tool(), AT0), plain]},
    }}
    html = panel.render(
        {"entries": {}, "store": store, "pending": ["mcp:grew", "mcp:widened"], "findings": [],
         "recent_calls": [], "hooks": {}, "adapters": {}, "unscannable": [], "observed": {}},
        token="tok", action=None)
    rows = {m.group(1): m.group(0) for m in
            re.finditer(r"<tr><td class=\"nm\">([\w-]+)(?:<br>|</td>)(?:(?!</tr>).)*</tr>", html, re.S)}
    # The row says what actually grew: it LOST read-only; it did not mark itself destructive.
    assert "destructive or open-world" not in rows.get("grew", ""), rows.get("grew")
    assert "Blocked" in rows.get("grew", "") and "NOT blocked" not in rows.get("grew", ""), rows.get("grew")
    assert "readOnlyHint" in rows.get("grew", ""), rows.get("grew")
    assert "NOT blocked" in rows.get("widened", ""), rows.get("widened")
