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


@pytest.mark.parametrize("before, after, named", [
    # exa-mcp-server 3.4.0 -> 3.4.1 (live probe, 2026-10-07): only openWorldHint moved, false -> true.
    ({"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
     {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
     "openWorldHint"),
    ({"readOnlyHint": False, "destructiveHint": False}, {"readOnlyHint": False, "destructiveHint": True},
     "destructiveHint"),
    ({"idempotentHint": True}, {"idempotentHint": False}, "idempotentHint"),
])
def test_every_annotation_escalation_the_docs_name_is_refused(tmp_path, before, after, named):
    """docs/rugpull.html names four annotation escalations the call-time check refuses; each one is
    exercised here through the real hook, not only the comparison."""
    a, b = _tool(), _tool()
    a["annotations"], b["annotations"] = before, after
    output = _call(_store(tmp_path, a, b, strict=False))
    assert output is not None, f"a tool whose {named} escalated after approval was allowed"
    assert named in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_an_annotation_that_narrows_is_not_refused(tmp_path):
    """The reverse direction (openWorldHint true -> false) asks for less; refusing it would be noise."""
    a, b = _tool(), _tool()
    a["annotations"], b["annotations"] = {"openWorldHint": True}, {"openWorldHint": False}
    assert _call(_store(tmp_path, a, b, strict=False)) is None


def test_an_ordinary_schema_change_still_waits_for_sign_off_and_is_not_refused(tmp_path):
    """FOUNDER 2026-08-15, kept: a widened schema alone does not break the agent."""
    later = _tool(props={"note": {"type": "string"}, "pageId": {"type": "string"}})
    path = _store(tmp_path, _tool(), later, strict=False)
    assert _call(path) is None


@pytest.mark.skipif(not DATA.exists(), reason="the live-probe data set lives in the canonical repo only")
def test_the_destination_rule_on_real_releases_flags_only_new_capability():
    """Every parameter the top servers really added between 10 Mar and 9 Sep (live probe: 86 transitions on
    4 Oct, 107 once all 30 packages completed on 7 Oct; the new ones added no destination parameter).
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


@pytest.mark.parametrize("param", ["command", "sql", "shellScript", "exec_args"])
def test_a_new_execution_parameter_is_refused(tmp_path, param):
    """A tool that gains a parameter naming code to run (command, sql, shell, exec) asks for more
    power than was approved — the same class as a new destination. Driven through the real hook."""
    later = _tool(props={"note": {"type": "string"}, param: {"type": "string"}})
    output = _call(_store(tmp_path, _tool(), later, strict=False))
    assert output is not None, f"a tool that gained the execution parameter {param} was allowed"
    assert param in output["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("name, expected", [
    ("command", True), ("sql", True), ("shellScript", True), ("cmd", True),
    ("query", False), ("code", False), ("queryString", False), ("language", False),
    ("commandId", False), ("scriptName", False), ("runCommand", True)])
def test_what_counts_as_an_execution_parameter(name, expected):
    assert drift.execution_param(name) is expected


@pytest.mark.skipif(not DATA.exists(), reason="the live-probe data set lives in the canonical repo only")
def test_the_execution_rule_on_real_releases_flags_nothing():
    """Measured 2026-10-08: none of the parameters the top servers added in 107 real updates names
    code to execute, so the rule adds no false refusals on honest releases."""
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
                flagged += [f"{t['name']}.{q}" for q in new if q not in old and drift.execution_param(q)]
    assert flagged == []
