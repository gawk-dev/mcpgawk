"""Every denial words WHO SET THE BASELINE the way the scan does — "you approved it" only when a
person did.

FOUND 2026-11-06 (tests/test_demo.py, the agent-run demo): the guard's denial said "has CHANGED
since you approved it" and "after they approved it" of a first-sighting baseline nobody approved,
while the scan printed just above it said "you have not approved this server yet". The rule
(`history.changed_head`, 2026-10-09: notion and brandfetch) had reached the scan, /next and
`baseline`, but not the decision core, which may not import it (stdlib only, loaded by path). So
the core carries the same words keyed by `history.baseline_origin`'s values, the projection carries
the origin to the hook, and THIS file pins that the two agree and that the decision never moves.

FOUNDER 2026-11-06: "leave you approved it" — a person's approval keeps its words exactly.
"""
from __future__ import annotations

import json

import pytest

from mcpgawk import decision, history
from mcpgawk.guard_hook import decide, projection_path

ORIGINS = ("approve", "fleet", "first-sighting", "unattended", "unsigned", "unknown", None)
APPROVAL_WORDS = ("you approved", "they approved", "user approved", "you never approved")


def _texts(origin):
    """Every denial and person line the core can emit for a baseline with this origin."""
    return {
        "changed": decision.changed_reason("srv", "t", "aaa", "bbb", "2026-11-06T00:00:00Z", origin),
        "permission": decision.permission_changed_reason("srv", "t", ["now writes"], None, origin),
        "reverted": decision.reverted_reason("srv", "t", "2026-11-01T00:00:00Z", origin),
        "added": decision.deny_reason("srv", "t", origin),
        "smuggled": decision.declared_verdict("srv", "t", {"t": "h"}, None,
                                              args={"api_key": "x"}, approved_props=[],
                                              origin=origin)[2],
        **{f"line:{code}": decision.human_line("srv", "t", code, origin=origin)
           for code in (decision.REASON_TOOL_ADDED, decision.REASON_TOOL_CHANGED,
                        decision.REASON_CREDENTIAL_SMUGGLED, None)},
    }


@pytest.mark.parametrize("origin", ORIGINS)
def test_approval_words_appear_only_when_a_person_approved(origin):
    for name, text in _texts(origin).items():
        assert text, name
        said = [w for w in APPROVAL_WORDS if w in text]
        if origin == "approve":
            continue
        assert not said, f"{origin!r} {name} claims an approval nobody made: {said}\n{text}"


def test_a_persons_approval_keeps_its_exact_words():
    """The pre-2026-11-06 wording, unchanged for origin "approve"."""
    t = _texts("approve")
    assert "has CHANGED since you approved it — same name, different content (approved aaa" \
        in t["changed"] and "a tool you trusted" in t["changed"]
    assert "changed the tool 't' after they approved it, mcpgawk blocked" in t["changed"]
    assert "has CHANGED since you approved it — it can now do more than was approved" \
        in t["permission"]
    assert "after they approved it and changed it back" in t["reverted"]
    assert ("'t' is not in the approved baseline for MCP server 'srv'. A tool that appeared "
            "after this server was approved") in t["added"]
    assert "added a tool called 't' since they approved it, mcpgawk blocked" in t["added"]
    assert "were not part of the tool when the user approved it" in t["smuggled"]
    assert "A parameter that appears after approval" in t["smuggled"]
    assert t[f"line:{decision.REASON_TOOL_CHANGED}"].endswith(
        "its content changed since you approved it. Review it with `mcpgawk decide` in your own "
        "terminal.")


@pytest.mark.parametrize("origin, phrase", [
    ("approve", "you approved it"),
    ("fleet", "your fleet approval accepted"),
    ("first-sighting", "you have not approved this server yet"),
    ("unattended", "without a person present"),
    ("unknown", "who approved it is not on record"),
    ("unsigned", "this machine cannot verify who approved it"),
])
def test_the_guard_says_what_the_scan_says(origin, phrase):
    """ONE RULE: the distinguishing words of `history.changed_head` for this origin are in the
    denial's first line — the scan, /next, `baseline` and the guard cannot disagree."""
    assert phrase in history.changed_head(origin, None)
    first_line = _texts(origin)["changed"].splitlines()[0]
    assert phrase in first_line, first_line


def test_a_caller_that_does_not_say_claims_nothing():
    """None = the caller never looked; it must not even claim the record is silent."""
    t = _texts(None)
    assert "has CHANGED since its baseline —" in t["changed"]
    assert "not on record" not in t["changed"] and "not approved" not in t["changed"]


@pytest.mark.parametrize("origin", ORIGINS)
def test_the_wording_never_changes_the_code_or_the_decision(origin):
    t = _texts(origin)
    for name in ("changed", "permission", "reverted"):
        assert decision.reason_code(t[name]) == decision.REASON_TOOL_CHANGED, (origin, name)
    assert decision.reason_code(t["added"]) == decision.REASON_TOOL_ADDED, origin
    assert decision.reason_code(t["smuggled"]) == decision.REASON_CREDENTIAL_SMUGGLED, origin
    # The decision is the same whatever the words.
    assert decision.declared_verdict("s", "new", {"t": "h"}, origin=origin)[0] == decision.DENY
    assert decision.declared_verdict("s", "t", {"t": "h"}, "h2", origin=origin)[0] == decision.DENY
    assert decision.declared_verdict("s", "t", {"t": "h"}, "h", origin=origin)[0] == decision.DEFER


def test_texts_written_before_the_change_still_classify():
    """Spool rows and logs keep their old prose; the classifier must still read them."""
    old_changed = ("SECURITY BLOCK (mcpgawk). 't' on MCP server 's' has CHANGED since you "
                   "approved it — same name")
    old_added = "SECURITY BLOCK (mcpgawk). 't' is not in the approved baseline for MCP server 's'."
    assert decision.reason_code(old_changed) == decision.REASON_TOOL_CHANGED
    assert decision.reason_code(old_added) == decision.REASON_TOOL_ADDED


# ----------------------------------------------------------------------------- end to end

SEEN_AT = "2026-11-06T06:00:00+00:00"


def _store(tmp_path, entry):
    p = tmp_path / "history.json"
    history.save({"servers": {"mcp:srv": entry}}, str(p))
    return p


def _rec(tools, at):
    return {"pin": at, "tools": tools, "measured_at": at}


def _first_sighting_then_drift():
    first = _rec({"t": "h1"}, "2026-11-05T00:00:00+00:00")
    return {"aliases": ["srv"], "approved": dict(first), "approved_via": "first-sighting",
            "history": [dict(first), _rec({"t": "h2", "new": "h3"}, SEEN_AT)]}


def _person_approved_then_drift():
    e = _first_sighting_then_drift()
    e.update({"approved_via": "approve", "approved_at": "2026-11-05T01:00:00+00:00",
              "approved_evidence": {"source": "cli", "terminal": True, "agent_markers": [],
                                    "agent_process": None, "hatch": False,
                                    "person_present": True}})
    return e


def test_the_projection_carries_who_set_each_baseline(tmp_path):
    store = _store(tmp_path, _first_sighting_then_drift())
    row = json.loads(projection_path(store).read_text())["servers"]["mcp:srv"]
    assert row["origin"] == "first-sighting"
    store = _store(tmp_path, _person_approved_then_drift())
    row = json.loads(projection_path(store).read_text())["servers"]["mcp:srv"]
    assert row["origin"] == "approve"


@pytest.mark.parametrize("entry, says, never", [
    (_first_sighting_then_drift, "you have not approved this server yet", "you approved"),
    (_person_approved_then_drift, "since you approved it", "not approved this server"),
])
def test_the_installed_hook_words_its_denials_from_the_projection(tmp_path, entry, says, never):
    store = _store(tmp_path, entry())
    for tool in ("t", "new"):
        out, _ = decide({"tool_name": f"mcp__srv__{tool}"}, store)
        hso = out["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny", tool
        reason = hso["permissionDecisionReason"]
        human = out.get("systemMessage") or ""
        if tool == "t":
            assert says in reason, reason
        assert never not in reason, reason
        assert never not in human, human


# ── the CONTEXT line on an allowed call words who set the baseline too (audit 2026-11-10, B) ────
# `_confidence_line` never read `origin`: a first-sighting row printed "at your baseline" to the
# agent, the same defect the denials had on 2026-11-06, one line over.
from mcpgawk.guard_hook import _confidence_line  # noqa: E402

_ROW = {"tools": {"t": "aaa"}, "approved_at": "2026-11-06T00:00:00Z"}


@pytest.mark.parametrize("origin", [o for o in ORIGINS if o != "approve"])
def test_the_context_line_claims_no_approval_nobody_gave(origin):
    row = dict(_ROW, **({"origin": origin} if origin else {}))
    line = _confidence_line("srv", "t", row, row["tools"], "2026-11-07T00:00:00Z", None, True, None)
    assert "your baseline" not in line, line
    for w in APPROVAL_WORDS:
        assert w not in line, line


def test_the_context_line_keeps_approved_for_a_person_approval():
    row = dict(_ROW, origin="approve")
    line = _confidence_line("srv", "t", row, row["tools"], "2026-11-07T00:00:00Z", None, True, None)
    assert "at your baseline" in line and "approved 2026-11-06" in line, line


def test_the_context_line_says_first_seen_is_not_approved():
    row = dict(_ROW, origin="first-sighting")
    line = _confidence_line("srv", "t", row, row["tools"], None, None, True, None)
    assert "not approved this server yet" in line, line


# ── a content check that stood down is not "not re-scanned" (audit 2026-11-10, C) ─────────────
def test_the_context_line_names_a_stood_down_content_check():
    row = dict(_ROW, origin="approve", seen_not_compared="its approved per-tool hashes were "
               "written by a different mcpgawk component … Run `mcpgawk approve srv` …")
    line = _confidence_line("srv", "t", row, row["tools"], None, None, True, None)
    assert "not re-scanned" not in line, line
    assert "content check" in line and "not run" in line, line
    assert "mcpgawk approve" not in line, "the agent's line must never carry an approval command"


# ── the person's line names WHICH kind of change (audit 2026-11-10, item F) ──────────────────────
# Permission growth and a change-and-revert both read "its content changed since you approved it":
# for permission growth the description did NOT change, and a revert is back to its approved form.
from mcpgawk import guard_hook  # noqa: E402


def test_the_person_line_names_permission_growth():
    reason = decision.permission_changed_reason("srv", "t", ["lost readOnlyHint"], None, "approve")
    line = guard_hook._human(decision, "srv", "t", reason, "approve")
    assert "can now do more" in line and "lost readOnlyHint" in line, line
    assert "its content changed" not in line, line


def test_the_person_line_names_a_change_that_reverted():
    reason = decision.reverted_reason("srv", "t", "2026-11-05T00:00:00Z", "approve")
    line = guard_hook._human(decision, "srv", "t", reason, "approve")
    assert "changed back" in line, line


def test_the_codes_stay_stable_for_every_consumer():
    """The spool, the plugin hook and the differential corpus key on these codes."""
    for reason in (decision.permission_changed_reason("s", "t", ["x"]),
                   decision.reverted_reason("s", "t")):
        assert decision.reason_code(reason) == decision.REASON_TOOL_CHANGED


# ── the person is sent where the change is visible (audit 2026-11-10, item G) ────────────────────
# A tool-added or smuggled-credential deny is made from the projection with no scan; `decide`
# lists only changes a scan has queued and could answer "Nothing is waiting on you".
@pytest.mark.parametrize("code", [decision.REASON_TOOL_ADDED, decision.REASON_CREDENTIAL_SMUGGLED,
                                  decision.REASON_NO_BASELINE_STRICT])
def test_a_deny_no_scan_has_queued_sends_the_person_to_scan(code):
    line = decision.human_line("srv", "t", code, "approve")
    assert "`mcpgawk scan`" in line and "`mcpgawk decide`" not in line, line


def test_a_changed_tool_still_goes_to_decide():
    assert "`mcpgawk decide`" in decision.human_line("srv", "t", decision.REASON_TOOL_CHANGED, "approve")
