"""`compared` in `--json`: a refused baseline must not read as "checked and clean".

Shipped 2026-08-09 (`bd5dac5`) with its own test gap written into the commit message: the behaviour
was verified by a direct check and never pinned. This is that pin.

Why the field exists: when a baseline is REFUSED — written by a newer mcpgawk than the one reading
it — every diff list stays deliberately empty, because nothing was compared and nothing may be
claimed. `rug_pull` serialises `false` and `hostile` an empty list — exactly what a clean comparison looks
like. The exit code says otherwise, but a CI gate keyed on those two fields reads
green on a server that was never checked. `compared` is what lets a consumer tell the difference.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from mcpgawk import cli, history

FIXTURE = str(Path(__file__).parent / "fixtures" / "toy_mcp_server.py")   # asserts "toy-fixture"


def _config(tmp_path: Path) -> Path:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "toy": {"command": sys.executable, "args": [FIXTURE]}}}))
    return cfg


def _drift_block(out: str) -> dict:
    """The drift block for our one server, out of the report a consumer actually parses."""
    labels = json.loads(out[out.index("["):])
    toy = [lab for lab in labels if lab.get("name") == "toy"]
    assert toy, f"the scanned server is missing from the JSON: {out[:400]}"
    return toy[0]["x-mcpgawk"].get("drift") or {}


def _seed(store: Path, record: dict) -> None:
    history.record("mcp:toy-fixture", record, path=str(store), alias="toy")


def _baseline(schema: int | None, tools: dict[str, str]) -> dict:
    rec: dict = {"pin": "seeded", "tools": tools, "measured_at": "2026-08-10T00:00:00Z"}
    if schema is not None:
        rec["schema_version"] = schema
    return rec


def test_a_refused_baseline_says_nothing_was_compared(tmp_path, monkeypatch, capsys):
    """A baseline from a NEWER build. Empty diff lists are correct — the claim must be withheld —
    but they must not be readable as a clean result."""
    from mcpgawk.drift import RECORD_SCHEMA

    store = tmp_path / "history.json"
    monkeypatch.setenv("MCPGAWK_HISTORY", str(store))
    _seed(store, _baseline(RECORD_SCHEMA + 1, {"read_inbox": "h1"}))

    cli.main(["scan", str(_config(tmp_path)), "--track", "--yes", "--json"])
    drift = _drift_block(capsys.readouterr().out)

    assert drift.get("unreadable"), "sanity: this baseline should have been REFUSED, not diffed"
    assert not drift["rug_pull"] and not drift["hostile"], (
        "sanity: the calm-looking pair is exactly why `compared` has to exist")
    assert drift["compared"] is False, (
        "nothing was compared, so a CI gate keyed on rug_pull/hostile must be able to tell")


def test_a_real_comparison_says_it_compared(tmp_path, monkeypatch, capsys):
    """The other direction, so the field is not just a constant `false`: a readable baseline that
    genuinely differs from the live server reports the drift AND that a comparison happened."""
    store = tmp_path / "history.json"
    monkeypatch.setenv("MCPGAWK_HISTORY", str(store))
    _seed(store, _baseline(None, {"read_inbox": "a-different-hash"}))

    cli.main(["scan", str(_config(tmp_path)), "--track", "--yes", "--json"])
    drift = _drift_block(capsys.readouterr().out)

    assert not drift.get("unreadable"), "sanity: this baseline is readable"
    assert drift["compared"] is True
    assert drift["changed"] or drift["added"] or drift["removed"], (
        "sanity: the seeded baseline does differ from the live server")
