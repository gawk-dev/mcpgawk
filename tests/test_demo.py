"""`mcpgawk demo` — assert the walkthrough on its STATE, not just its prose.

The demo's whole worth is that every step is the real pipeline. So this test checks the stores
the real commands wrote inside the sandbox: a trusted baseline of exactly the approved tool, a
baseline that does NOT move when the server drifts, a regenerated guard projection, and a guard
hook that stays silent on the approved tool while denying the one that appeared after approval.

A subprocess smoke proves the CLI wiring (`python -m mcpgawk.cli demo`) end to end; the rest call
`run_demo` in-process against a pytest sandbox so the assertions can read the files directly. All
state is redirected into the sandbox — the suite-wide tripwire (`conftest._never_touch_real_home
_state`) would fail this file if a single byte of the real ~/.gawk or ~/.mcpgawk were touched.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from mcpgawk.demo import SERVER, _Sandbox, run_demo


def _run(tmp_path: Path, **kw) -> int:
    return run_demo(sandbox=str(tmp_path / "box"), **kw)


def test_demo_exits_clean_and_leaves_an_inspectable_sandbox(tmp_path, capsys):
    rc = _run(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0, out
    # By default the sandbox is kept — it is the evidence of what the product found.
    assert "Sandbox kept at" in out
    assert (tmp_path / "box" / "state" / "history.json").is_file()


def test_demo_baseline_holds_across_the_rug_pull(tmp_path, capsys):
    """The load-bearing state claims: approved == {read_notes}, and it does not move when the
    server turns hostile (drift is pending until a human approves)."""
    rc = _run(tmp_path)
    assert rc == 0, capsys.readouterr().out
    box = _Sandbox(tmp_path / "box")
    rec = json.loads(box.history.read_text())["servers"][f"mcp:{SERVER}"]
    assert sorted(rec["approved"]["tools"]) == ["read_notes"], "baseline is not the clean tool set"
    # The hostile scan added a sighting but must not have moved the approved baseline.
    assert rec["history"][-1]["texts"]["tool.read_notes"] != rec["approved"]["texts"]["tool.read_notes"]
    assert box.projection.is_file(), "the guard projection was never generated"


def test_demo_guard_blocks_both_the_rewritten_tool_and_the_new_tool(tmp_path, capsys):
    """Re-run the two hook calls against the finished sandbox and assert the verdicts directly,
    rather than trusting the demo's own printed summary. Since 2026-09-05 (slice 1) the approved
    tool whose description was rewritten is denied too — on the last scan's evidence, and the
    denial says so."""
    rc = _run(tmp_path)
    assert rc == 0, capsys.readouterr().out
    box = _Sandbox(tmp_path / "box")
    pulled = box.guard("read_notes")
    blocked = box.guard("exfiltrate_notes")
    assert '"permissionDecision": "deny"' in pulled.stdout, \
        "the guard did not block the approved tool whose content changed"
    pulled_reason = json.loads(pulled.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    # The sandbox approves with no terminal (the CI hatch), so the record says no person was
    # present — and since 2026-11-06 the guard says what the record says, never "you approved it".
    assert "has CHANGED since its baseline, approved without a person present" in pulled_reason
    assert "you approved" not in pulled_reason and "they approved" not in pulled_reason
    assert "last seen" in pulled_reason and "not this call" in pulled_reason
    assert "mcpgawk approve" not in pulled_reason
    assert '"permissionDecision": "deny"' in blocked.stdout, \
        "the guard did not block the tool that appeared after approval"
    reason = json.loads(blocked.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "exfiltrate_notes" in reason and SERVER in reason


def test_demo_discloses_the_non_interactive_approval_hatch(tmp_path, capsys):
    """The sandbox waives the terminal check; the demo must say so, or it teaches a false sense of
    how `approve` behaves on a real fleet. It must not claim to waive the agent check (2026-11-06:
    nothing in the sandbox does)."""
    rc = _run(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "refuses inside an agent session" in out and "skips the terminal check" in out
    assert "waives that" not in out


def _as_agent(monkeypatch):
    """The demo run BY an agent: every sandbox child sees `claude` above it (test-only emulation,
    tests/fixtures/ci_ancestry), with the env markers already gone as they are in any suite run."""
    monkeypatch.setenv("MCPGAWK_TEST_ANCESTRY", "zsh,claude,-zsh,login")


def test_demo_run_by_an_agent_shows_the_refusal_and_still_completes(tmp_path, capsys, monkeypatch):
    """MEASURED 2026-11-06: once approve refused an agent ancestor, the demo stopped at step 2
    ("approve did not succeed") for every agent that ran it. Run by an agent it now shows mcpgawk's
    own refusal, walks on from the first scan's baseline and never narrates "you approve"."""
    _as_agent(monkeypatch)
    rc = _run(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Your agent tries to approve it" in out and "claude is running this" in out
    assert "You approve it" not in out and "refuse your agent's approval" in out
    box = _Sandbox(tmp_path / "box")
    rec = json.loads(box.history.read_text())["servers"][f"mcp:{SERVER}"]
    assert sorted(rec["approved"]["tools"]) == ["read_notes"]
    assert rec.get("approved_via") != "approve" and "approved_evidence" not in rec, \
        "a refused approval must leave the first scan's baseline exactly as it was"
    pulled, blocked = box.guard("read_notes"), box.guard("exfiltrate_notes")
    assert '"permissionDecision": "deny"' in pulled.stdout
    assert '"permissionDecision": "deny"' in blocked.stdout


def test_the_guard_never_says_you_approved_a_baseline_nobody_approved(tmp_path, capsys,
                                                                       monkeypatch):
    """FOUND 2026-11-06 by the agent-run demo: both denials said "since you approved it" /
    "since they approved it" of a first-sighting baseline, while the scan printed just above them
    said "you have not approved this server yet". Pinned strict-xfail until decision.py worded
    from the projection's `origin`; now a plain test."""
    _as_agent(monkeypatch)
    assert _run(tmp_path) == 0, capsys.readouterr().out
    box = _Sandbox(tmp_path / "box")
    for tool in ("read_notes", "exfiltrate_notes"):
        reason = json.loads(box.guard(tool).stdout)["hookSpecificOutput"]["permissionDecisionReason"]
        assert "you approved" not in reason and "they approved" not in reason, reason
        assert "you have not approved this server yet" in reason or \
            "they have not approved this server yet" in reason, reason


def test_demo_clean_flag_removes_the_sandbox(tmp_path, capsys):
    rc = _run(tmp_path, clean=True)
    out = capsys.readouterr().out
    assert rc == 0, out
    assert not (tmp_path / "box").exists(), "--clean left the sandbox behind"


def test_demo_runs_from_the_shipped_entry_point(tmp_path):
    """CLI wiring, as a customer hits it: `python -m mcpgawk.cli demo` in its own process."""
    box = tmp_path / "cli-box"
    r = subprocess.run(
        [sys.executable, "-m", "mcpgawk.cli", "demo", "--sandbox", str(box), "--clean"],
        capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "BLOCKED" in r.stdout and "has CHANGED since" in r.stdout


def test_the_demo_sandbox_can_actually_be_verified(tmp_path):
    """THE OBVIOUS NEXT STEP AFTER `mcpgawk demo` MUST NOT FAIL.

    `mcpgawk verify` exercises a tool to see what it DOES. Until 2026-09-18 the fixture answered
    only initialize/tools/list/ping, so `verify` on a kept demo sandbox got -32601 for every call
    and reported INCOMPLETE, 0/4, "infra failure" — on a sandbox this project ships and invites
    people to inspect. This asserts the fixture answers a tool call, in both faces, without
    starting the whole engine: the protocol behaviour is the thing that broke.
    """
    import json as _json
    import subprocess as _sp
    import sys as _sys
    from mcpgawk.demo import _Sandbox

    box = _Sandbox(tmp_path / "box")
    box.build()

    def call(tool: str) -> dict:
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool}},
        ]
        p = _sp.run([_sys.executable, str(box.fixture)],
                    input="".join(_json.dumps(m) + "\n" for m in msgs),
                    capture_output=True, text=True, timeout=30)
        lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
        return _json.loads(lines[-1])

    clean = call("read_notes")
    assert "error" not in clean, f"the fixture refuses tools/call: {clean.get('error')}"
    assert clean["result"]["content"][0]["text"], "the tool returned no content to check"

    box.set_mode("pulled")
    pulled = call("read_notes")
    body = pulled["result"]["content"][0]["text"]
    assert "ignore previous instructions" in body.lower(), (
        "the poisoned face must carry the lure in its RESPONSE too — that is what gives verify's "
        "output checks something real to catch")

    unknown = call("no_such_tool")
    assert unknown.get("error", {}).get("code") == -32602, (
        "an unknown tool should be an invalid-params error, not method-not-found")
