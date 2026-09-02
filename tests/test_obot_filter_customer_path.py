"""The filter against a baseline the PRODUCT produced, not one a test hand-wrote.

Every other filter test builds its store with `history.save({...})` and invented hashes. That
proves the adapter reads the shape those tests write — which is not the question. The question is
whether it reads what `mcpgawk scan` and `mcpgawk approve` actually leave on a customer's disk:
real key naming, real content hashes, real recorded parameter lists, real projection.

A unit test that supplies its own inputs cannot detect that nothing supplies them in production,
so this file supplies none of them. It runs the real commands against a real MCP server over a
real stdio transport, and only then asks the filter for a verdict.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcpgawk import baseline, cli, history, obot_filter

FIXTURE = str(Path(__file__).parent / "fixtures" / "mutable_mcp_server.py")


@pytest.fixture()
def real_store(tmp_path, monkeypatch):
    """A store produced by `mcpgawk scan` + `mcpgawk approve`, exactly as an operator makes one."""
    store = tmp_path / "history.json"
    monkeypatch.setenv("MCPGAWK_HISTORY", str(store))
    monkeypatch.setenv("MCPGAWK_SPOOL", str(tmp_path / "calls.jsonl"))
    monkeypatch.setenv("GAWK_BEHAVIOUR", str(tmp_path / "absent.json"))

    # The human gate is real and correct: an agent session may not approve. A test is not a human,
    # so it uses the same deliberate override a CI pipeline would — never by weakening the gate.
    for marker in baseline.AGENT_ENV_MARKERS:
        monkeypatch.delenv(marker, raising=False)
    monkeypatch.setenv(baseline.APPROVE_OVERRIDE_ENV, "1")

    assert cli.main(["scan", "--stdio", f"{sys.executable} {FIXTURE}", "--yes"]) in (0, 1)
    tracked = list((history.load(str(store)) or {}).get("servers", {}))
    assert tracked, "scan recorded no server — the rest of this file would be testing nothing"
    key = tracked[0]
    assert cli.main(["approve", key]) == 0
    return store, key


def _call(tool: str, args: dict | None = None) -> dict:
    return {"accept": True, "mutated": False,
            "message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": tool, "arguments": args or {}}}}


def test_the_filter_reads_a_baseline_the_product_actually_wrote(real_store):
    """The whole point: no hand-built fixture anywhere between `scan` and the verdict."""
    store, key = real_store
    approved = (history.load(str(store)) or {})["servers"][key]["approved"]
    real_tool = sorted(approved["tools"])[0]

    verdict = obot_filter.evaluate(_call(real_tool), server=key, store_path=store, record=False)
    assert verdict["accept"] is True
    assert "UNEVALUATED" not in verdict["reason"], (
        "the filter could not evaluate against a baseline this product just wrote — the store key "
        f"{key!r} did not resolve, and every hand-built test would still be green")
    assert "approved baseline" in verdict["reason"]


def test_a_tool_that_appears_after_a_real_approve_is_denied(real_store):
    """The rug-pull, through the real pipeline: the server grows a tool the operator never saw."""
    store, key = real_store
    verdict = obot_filter.evaluate(_call("tool_that_was_never_approved"), server=key,
                                   store_path=store, record=False)
    assert verdict["accept"] is False
    assert "not in the approved baseline" in verdict["reason"]


def test_the_real_store_key_is_usable_as_MCPGAWK_SERVER_verbatim(real_store):
    """What the operator is TOLD to do: take the key the product prints and set it as the env var.
    Real keys are qualified and can carry colons, spaces and '#', and the pair is round-tripped
    through an agent-shaped tool name on every call — so the key the product emits has to survive
    that trip, or the documented setup silently guards nothing."""
    store, key = real_store
    approved = (history.load(str(store)) or {})["servers"][key]["approved"]
    real_tool = sorted(approved["tools"])[0]

    verdict = obot_filter.evaluate(_call(real_tool), server=key, store_path=store, record=False)
    assert "cannot be expressed unambiguously" not in verdict["reason"]
    assert "UNEVALUATED" not in verdict["reason"]


def test_the_recorded_ruling_names_the_real_server_key(real_store):
    """The trail has to be joinable to the fleet the operator sees in `mcpgawk scan`. A ruling
    filed under a name that appears nowhere else is evidence of nothing."""
    store, key = real_store
    spool_path = str(store.parent / "calls.jsonl")
    Path(spool_path).write_text("", encoding="utf-8")

    obot_filter.evaluate(_call("tool_that_was_never_approved"), server=key, store_path=store,
                         spool_path=spool_path)
    rows = [json.loads(line) for line in Path(spool_path).read_text(encoding="utf-8").splitlines()
            if line.strip()]
    assert [r["server"] for r in rows] == [key]
    assert [r["decision"] for r in rows] == ["deny"]
