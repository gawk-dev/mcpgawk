"""Every server-controlled field that reaches `history.json` is masked — measured, at the real
entry point, one canary per field.

ADR-0012 says redaction happens at the persistence boundary. Until 2026-08-13 it did not: the only
`redact()` call lived in `drift._item_texts`, one caller, covering DESCRIPTIONS alone. A canary run
through `mcpgawk scan --track` found three fields writing a credential to disk verbatim:

* a tool **name** — it becomes the item key, so it landed in `texts`, `items`, `tools`, `schemas`,
  `props` and `annotations` at once (12 occurrences of one canary)
* a resource **URI** — `_item_texts` keys on `name or uri`, so the ordinary URI-only resource shape
  (`https://host/doc?apiKey=…`) put the key on disk (10 occurrences)
* **annotation values** — `{"title": "…"}` stored as measured

Seventh instance of this repo's most repeated defect: a rule living in one file instead of on the
write. The gate now sits in `history.save` (every writer) and at `record()` ingress (so the object
that gets COMPARED is the object that gets STORED — masking only on the way out would diff a raw
`current` against a masked baseline and invent a rename on every scan).

The first version of this measurement was VACUOUS and nearly shipped as a pass: the fixture's
resource had a `name`, and `name or uri` meant the URI path was never exercised at all. The fixture
now uses a URI-only resource for that reason. Read `tests/fixtures/store_canary_mcp_server.py`
before changing it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "store_canary_mcp_server.py"

#: One canary per server-controlled field, so a failure names the field rather than "something leaked".
CANARIES = {
    "tool description": "CANARY_DESC_98765",
    "tool name": "CANARY_NAME_98765",
    "resource uri": "CANARY_URI_98765",
    "prompt description": "CANARY_PROMPT_98765",
    "schema property description": "CANARY_SCHEMA_98765",
    "annotation value": "CANARY_ANNOT_98765",
}


@pytest.fixture
def scanned(tmp_path: Path) -> str:
    """The store on disk after a real `scan --track` against the canary server."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "canary": {"command": sys.executable, "args": [str(FIXTURE)]}}}), encoding="utf-8")
    store = tmp_path / "history.json"
    env = {**__import__("os").environ, "MCPGAWK_HISTORY": str(store), "HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-m", "mcpgawk.cli", "scan", str(cfg), "--track", "--yes"],
                   capture_output=True, text=True, timeout=180, env=env, cwd=str(tmp_path))
    # ASSERTED, not `if store.exists()`. A conditional guard here would turn "the scan never ran"
    # into a silent pass — the exact shape that made two earlier canary passes vacuous.
    assert store.is_file(), "no store was written — every assertion below would be vacuous"
    text = store.read_text(encoding="utf-8")
    assert "mcp:store-canary" in text, "the server was not recorded — the canary never reached disk"
    return text


@pytest.mark.parametrize("field,canary", sorted(CANARIES.items()))
def test_no_server_controlled_field_reaches_the_store_verbatim(scanned: str, field: str, canary: str):
    assert canary not in scanned, f"{field} wrote a credential to history.json"


def test_the_masked_forms_still_identify_what_changed(scanned: str):
    """Masked, not destroyed. Over-redaction would break the feature the store exists for: a drift
    report has to be able to say WHICH resource changed, which needs the host and parameter names."""
    store = json.loads(scanned)
    rec = store["servers"]["mcp:store-canary"]["approved"]
    keys = list(rec["texts"])
    assert any(k.startswith("resource.https://host.invalid/doc?") and "apiKey=***" in k for k in keys), \
        f"the resource is no longer identifiable: {keys}"
    assert "tool.ordinary_tool" in keys, "an ordinary tool name was mangled by the redactor"
    assert "tool.schema_tool" in keys, "an ordinary tool name was mangled by the redactor"


def test_masking_an_item_key_does_not_invent_drift(tmp_path: Path):
    """The risk this fix introduces: the item key IS the identity drift compares on, so a store
    written BEFORE the gate holds raw keys. The second scan must be quiet, and the raw value must be
    gone from disk once it has been rewritten."""
    import os
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "canary": {"command": sys.executable, "args": [str(FIXTURE)]}}}), encoding="utf-8")
    store = tmp_path / "history.json"
    env = {**os.environ, "MCPGAWK_HISTORY": str(store), "HOME": str(tmp_path)}
    run = lambda: subprocess.run(                                              # noqa: E731
        [sys.executable, "-m", "mcpgawk.cli", "scan", str(cfg), "--track", "--yes"],
        capture_output=True, text=True, timeout=180, env=env, cwd=str(tmp_path))
    run()
    raw_name = "fetch_apiKey=CANARY_NAME_98765"
    doc = json.loads(store.read_text(encoding="utf-8"))
    rewritten = json.dumps(doc).replace("[REDACTED]", raw_name)   # the pre-gate shape
    store.write_text(rewritten, encoding="utf-8")
    assert "CANARY_NAME_98765" in store.read_text(encoding="utf-8"), "sanity: the raw baseline is in place"

    proc = run()
    out = (proc.stdout + proc.stderr).lower()
    assert "drift" not in out, "masking an existing baseline's key reported drift that never happened"
    assert "CANARY_NAME_98765" not in store.read_text(encoding="utf-8"), \
        "the pre-gate credential survived a rewrite of the store"


def test_the_gate_is_on_the_write_not_on_a_caller():
    """A rot check that enumerates the property, not one caller: `save` is the boundary every
    writer reaches (`record`, `approve`, `baseline`), so the masking has to be reachable from it."""
    from mcpgawk import history

    rec = {"texts": {"tool.fetch_apiKey=SECRETVALUE123": "desc with apiKey=SECRETVALUE123"},
           "tools": {"fetch_apiKey=SECRETVALUE123": "abc123"},
           "annotations": {"tool.x": {"title": "apiKey=SECRETVALUE123"}},
           "props": {"tool.x": ["apiKey=SECRETVALUE123"]},
           "pin": "deadbeef"}
    history.redact_record(rec)
    assert "SECRETVALUE123" not in json.dumps(rec), f"a field skipped the gate: {rec}"
    assert rec["pin"] == "deadbeef", "identity fields must survive untouched"
