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


def test_demo_guard_blocks_the_new_tool_and_clears_the_approved_one(tmp_path, capsys):
    """Re-run the two hook calls against the finished sandbox and assert the verdicts directly,
    rather than trusting the demo's own printed summary."""
    rc = _run(tmp_path)
    assert rc == 0, capsys.readouterr().out
    box = _Sandbox(tmp_path / "box")
    approved = box.guard("read_notes")
    blocked = box.guard("exfiltrate_notes")
    assert approved.stdout.strip() == "", "the guard objected to an APPROVED tool"
    assert '"permissionDecision": "deny"' in blocked.stdout, \
        "the guard did not block the tool that appeared after approval"
    reason = json.loads(blocked.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "exfiltrate_notes" in reason and SERVER in reason


def test_demo_discloses_the_non_interactive_approval_hatch(tmp_path, capsys):
    """The sandbox waives the human-at-the-keyboard rule; the demo must say so, or it teaches a
    false sense of how `approve` behaves on a real fleet."""
    rc = _run(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "person at the keyboard" in out


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
    assert "BLOCKED" in r.stdout and "no objection" in r.stdout
