"""The runtime decision log must not write a credential, and must not go silent to avoid one.

`spool.jsonl` records every MCP call the guard checks: `{ts, session, server, tool, decision,
basis, adapter}`. `server` and `tool` come straight off the agent's hook event
(`mcp__<server>__<tool>`), so they are SERVER-CONTROLLED — the same class as the item keys that
were writing credentials into `history.json` until 2026-08-13.

Measured, at the real entry point (the hook, driven on stdin), not reasoned about:

* a credential-shaped TOOL name was written verbatim — predicted, and confirmed
* the SERVER name was too — predicted CLEAN on the theory that the name is normalised. It is not.
  The hook copies what the event carries. The wrong prediction is recorded here on purpose.

The first attempt at the gate then broke the log entirely: `spool` is imported BY PATH with no
parent package (see `guard_hook._load_sibling` — done so a PreToolUse hook never imports the MCP
SDK), so `from .redact import …` raised, the hook swallowed it, and nothing was recorded at all.
That is the exact failure `_load_sibling`'s docstring already recorded for `runlog`. Hence
`test_the_spool_still_writes_without_a_package_context`, which is the one that would have caught it.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TOOL_CANARY = "CANARY_TOOLNAME_98765"
SRV_CANARY = "CANARY_SERVER_98765"


def _run_hook(tool_name: str, tmp_path: Path) -> Path:
    spool = tmp_path / "spool.jsonl"
    env = {**os.environ, "MCPGAWK_SPOOL": str(spool), "HOME": str(tmp_path)}
    event = {"hook_event_name": "PreToolUse", "tool_name": tool_name,
             "tool_input": {"q": "x"}, "session_id": "sess-1"}
    subprocess.run([sys.executable, "-m", "mcpgawk.guard_hook"], input=json.dumps(event),
                   capture_output=True, text=True, timeout=60, env=env, cwd=str(tmp_path))
    # ASSERTED, never `if exists`. "The hook wrote nothing" is a FAILURE here, not a skip — it is
    # how the first version of this gate presented, and a silent recorder is its own defect.
    assert spool.is_file(), "the hook recorded nothing — the spool went silent"
    return spool


def test_a_credential_shaped_name_is_not_written_to_the_decision_log(tmp_path: Path):
    text = _run_hook(f"mcp__srv_apiKey={SRV_CANARY}__fetch_apiKey={TOOL_CANARY}", tmp_path
                     ).read_text(encoding="utf-8")
    assert TOOL_CANARY not in text, "the tool name carried a credential to disk"
    assert SRV_CANARY not in text, "the server name carried a credential to disk"
    assert '"decision":' in text, "sanity: a real record was written, not an empty file"


@pytest.mark.parametrize("tool_name,server,tool", [
    ("mcp__github__create_api_key", "github", "create_api_key"),
    ("mcp__aws__get_secret_value", "aws", "get_secret_value"),
    ("mcp__vault-rag__vault_search", "vault-rag", "vault_search"),
])
def test_ordinary_names_are_not_mangled(tmp_path: Path, tool_name: str, server: str, tool: str):
    """Over-redaction would be its own defect: a decision log nobody can read does not tell an
    operator which tool was blocked. These names CONTAIN credential nouns and must survive whole —
    the prose redactor needs an assignment shape to fire, and this is what pins that."""
    rec = json.loads(_run_hook(tool_name, tmp_path).read_text(encoding="utf-8").splitlines()[0])
    assert (rec["server"], rec["tool"]) == (server, tool)


def test_the_spool_still_writes_without_a_package_context(tmp_path: Path):
    """The regression the gate itself introduced. `guard_hook` loads this module by absolute path
    with NO parent package; a relative import in the write path raises there and the hook swallows
    it, so the log silently stops. Load it the same way the hook does and prove it still writes —
    and still redacts."""
    import importlib.util

    path = Path(__file__).parent.parent / "src" / "mcpgawk" / "spool.py"
    spec = importlib.util.spec_from_file_location("_bare_spool", path)
    assert spec and spec.loader
    bare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bare)
    assert "mcpgawk" not in getattr(bare, "__package__", "") or not bare.__package__, \
        "loaded WITH a package context — this test would not exercise the hook's path"

    target = tmp_path / "bare.jsonl"
    assert bare.append({"ts": "2026-01-01T00:00:00Z", "server": "srv",
                        "tool": f"fetch_apiKey={TOOL_CANARY}", "decision": "deny",
                        "basis": "declared", "adapter": "claude-code"}, path=str(target)) is True
    written = target.read_text(encoding="utf-8")
    assert TOOL_CANARY not in written, "no package context: the record was written unredacted"
    assert '"decision":"deny"' in written, "no package context: the record was lost"


def test_the_recorders_own_failure_note_is_redacted(tmp_path: Path):
    from mcpgawk import spool

    target = tmp_path / "s.jsonl"
    spool.note_failure(f"OSError: could not write https://h.invalid/x?apiKey={TOOL_CANARY}",
                       path=str(target))
    note = Path(str(target) + spool.ERR_SUFFIX)
    assert note.is_file(), "the failure note was not written"
    assert TOOL_CANARY not in note.read_text(encoding="utf-8")


def test_the_gate_is_on_append_so_every_writer_inherits_it():
    """A rot check on the property, not on one caller: `append` is the single write path (the only
    caller today is `guard_hook`, via `record_decision`), so anything added later is covered."""
    from mcpgawk import spool

    masked = spool._redacted({"ts": "t", "decision": "allow", "basis": "declared",
                              "adapter": "claude-code", "server": f"s_apiKey={SRV_CANARY}",
                              "tool": f"t_apiKey={TOOL_CANARY}",
                              "reason": f"blocked apiKey={TOOL_CANARY}"})
    assert TOOL_CANARY not in json.dumps(masked) and SRV_CANARY not in json.dumps(masked)
    assert masked["decision"] == "allow" and masked["adapter"] == "claude-code", \
        "closed-vocabulary fields must never be rewritten"
