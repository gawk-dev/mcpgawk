"""The Obot filter adapter — mcpgawk's verdict inside somebody else's gateway.

This file IS the architectural constraint test for S1 (docs/design-s1-obot-filter-2026-08-26.md).
It exists before the adapter is trusted anywhere, because three of its constraints are the kind
that fail silently in production and look fine in review:

  * Obot treats a response it cannot parse as an ACCEPT (hookrunner.go returns nil,nil when there
    is no structuredContent and the text is not a JSON object). So a malformed verdict of ours
    does not fail loudly in their gateway — it waves the call through. Our own suite is the only
    place that can catch it, which is why C2 pins the SHAPE of every path including our crashes.
  * mcpgawk's free core never says "allow" — it denies or defers — and a defer on a server with
    no baseline is indistinguishable, in shape, from a defer on a server that was checked and
    found clean. Obot needs an explicit boolean either way, so the honesty has to live in the
    reason string (C4), or an operator reads "accepted" as "guarded".
  * The verdict is keyed server+tool, and Obot deliberately does NOT tell a filter which server
    it is attached to. A wrong or missing server name produces a SILENT DEFER in the core, so C4
    also covers the unmapped-name case.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcpgawk import obot_filter



@pytest.fixture(autouse=True)
def _isolate_behaviour_profile(tmp_path_factory, monkeypatch):
    """No test in this file may read the OPERATOR's real ~/.gawk/behaviour.json.

    Found 2026-08-26: the behavioural profile is looked up from the real home path unless
    GAWK_BEHAVIOUR is set, so these tests were quietly consulting whatever this machine happened
    to have verified. That makes a filter test pass or fail on the developer's own fleet — the
    exact shape of a green suite that proves nothing. Tests that WANT a profile set the variable
    themselves; everything else runs against a path that does not exist.
    """
    monkeypatch.setenv("GAWK_BEHAVIOUR", str(tmp_path_factory.mktemp("nb") / "absent.json"))

def _store(tmp_path: Path, servers: dict) -> Path:
    """Through the canonical writer, which also regenerates the projection the hook reads — a
    hand-written history.json is a store the decision core must refuse to enforce from."""
    from mcpgawk import history

    p = tmp_path / "history.json"
    history.save({"servers": servers}, str(p))
    return p


def _approved(tools: dict[str, str]) -> dict:
    return {"approved": {"pin": "abc123", "tools": tools,
                         "measured_at": "2026-07-27T00:00:00Z"}}


def _call(tool: str, args: dict | None = None) -> dict:
    """The hook input Obot actually sends: one SessionMessageHook whose message is the raw
    JSON-RPC envelope. No server identity — that absence is the point (backend.go: 'The target
    MCP server itself is intentionally absent')."""
    return {"accept": True, "mutated": False,
            "message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": tool, "arguments": args or {}}}}


# --------------------------------------------------------------- C1: paid never ships public

def test_C1_the_filter_never_reaches_into_the_paid_engine():
    """The filter ships in the PUBLIC wheel. If it imports gawk_platform, publishing it publishes
    the paid engine — the one mistake that cannot be walked back once it is on PyPI."""
    src = Path(obot_filter.__file__).read_text(encoding="utf-8")
    assert "gawk_platform" not in src

    # Not just absent from the source: absent from the import GRAPH, so a sibling that pulls it in
    # transitively is caught too.
    probe = ("import sys; import mcpgawk.obot_filter; "
             "print([m for m in sys.modules if m.startswith('gawk_platform')])")
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]", out.stdout


# ------------------------------------------------------- C2: every path answers in Obot's shape

def test_C2_every_verdict_is_serialisable_and_states_accept_explicitly(tmp_path):
    """`accept` omitted decodes to Go's zero value (false) and REJECTS; an unparseable body
    silently ACCEPTS. Both failure modes start with us not returning the shape."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    cases = [
        _call("get_file"), _call("delete_everything"),
        {"message": {"jsonrpc": "2.0", "method": "resources/read", "params": {}}},
        {"message": "not-an-object"}, {}, {"message": {"method": "tools/call"}},
    ]
    for hook_input in cases:
        v = obot_filter.evaluate(hook_input, server="figma", store_path=store, record=False)
        assert isinstance(v.get("accept"), bool), v
        assert isinstance(v.get("reason"), str) and v["reason"], v
        json.dumps(v)  # must survive the wire


def test_C2_an_internal_error_still_answers_in_the_shape(tmp_path, monkeypatch):
    """A raise inside the handler is not ours to leak: Obot blocks the whole call on a filter
    error, and a half-written response hits the fail-open corner. We answer, and we SAY we
    failed."""
    def boom(*a, **k):
        raise RuntimeError("core exploded")

    monkeypatch.setattr(obot_filter.guard_hook, "_decide", boom)
    v = obot_filter.evaluate(_call("get_file"), server="figma",
                             store_path=tmp_path / "absent.json", record=False)
    assert isinstance(v["accept"], bool)
    assert "mcpgawk filter failed" in v["reason"]
    assert "core exploded" in v["reason"]
    json.dumps(v)


# ------------------------------------------------------------------------ C3: a deny is a deny

def test_C3_a_denied_tool_is_rejected_carrying_the_reason(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    v = obot_filter.evaluate(_call("delete_everything"), server="figma",
                             store_path=store, record=False)
    assert v["accept"] is False
    assert "mcpgawk" in v["reason"]
    assert "delete_everything" in v["reason"]


def test_C3_the_deny_tells_the_reader_where_the_store_actually_IS(tmp_path):
    """The core's block text was written for the client-side hook, where the approval store sits
    on the caller's own machine, and it ends by telling the agent's user to run `mcpgawk scan`.
    Through a gateway that is wrong advice at the worst moment: the store is on the gateway host,
    and neither the agent nor its user can act on it. The finding must survive verbatim; only the
    remedy is corrected."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    v = obot_filter.evaluate(_call("delete_everything"), server="figma",
                             store_path=store, record=False)
    assert v["accept"] is False
    assert "delete_everything" in v["reason"]        # the specific finding, untouched
    assert "GATEWAY host" in v["reason"]
    assert "Running mcpgawk locally changes nothing here" in v["reason"]


# ----------------------------------------- C4: "checked and clean" never reads like "not looked"

def test_C4_evaluated_clean_and_unevaluated_are_different_sentences(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})

    clean = obot_filter.evaluate(_call("get_file"), server="figma", store_path=store, record=False)
    assert clean["accept"] is True
    assert "UNEVALUATED" not in clean["reason"]
    # It claims a real check against the baseline. Which TIERS it rests on is pinned separately in
    # test_obot_filter_parity.py — this assertion is only that "checked" and "not looked at" are
    # never the same sentence.
    assert "approved baseline" in clean["reason"]

    # Same store, a server it holds no baseline for: the core defers, exactly as it does for the
    # approved-and-clean case. Only the reason can tell the operator these are different events.
    blind = obot_filter.evaluate(_call("anything"), server="stripe", store_path=store, record=False)
    assert blind["accept"] is True
    assert blind["reason"].startswith("UNEVALUATED by mcpgawk")
    assert "stripe" in blind["reason"]


def test_C4_an_unmapped_server_name_is_labelled_not_waved_through(tmp_path):
    """Obot never sends the target server. If the operator did not map this instance to a baseline
    key, we do not guess and we do not pretend to have checked."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    v = obot_filter.evaluate(_call("get_file"), server=None, store_path=store, record=False)
    assert v["accept"] is True
    assert v["reason"].startswith("UNEVALUATED by mcpgawk")
    assert "MCPGAWK_SERVER" in v["reason"]


def test_C4_a_loud_stand_down_from_the_core_is_carried_into_the_reason(tmp_path):
    """The core refuses to enforce a baseline written by a build it cannot interpret, and says so.
    That sentence is the operator's only signal, so it must survive the trip through the adapter.

    Triggered the way it really happens — a record whose schema_version is newer than this build
    reads — because the marker is generated by the projection writer, not stored in history.json.
    """
    rec = _approved({"get_file": "h1"})
    rec["approved"]["schema_version"] = 9999
    store = _store(tmp_path, {"figma": rec})
    v = obot_filter.evaluate(_call("get_file"), server="figma", store_path=store, record=False)
    assert v["accept"] is True
    assert v["reason"].startswith("UNEVALUATED by mcpgawk")
    assert "newer mcpgawk" in v["reason"]


def test_C4_the_real_store_key_shapes_survive_the_round_trip(tmp_path):
    """The operator is TOLD to set MCPGAWK_SERVER to a store key, and real keys are qualified and
    untidy — `mcp:vault-rag`, `mcp:BrowserStack MCP Server#3cb4da84649c`, `stdio:local`. The pair
    is encoded into an agent-shaped tool name and parsed straight back out, so every shape the
    operator is handed has to survive that trip or their filter guards nothing while claiming a
    missing baseline."""
    keys = ["mcp:vault-rag", "mcp:BrowserStack MCP Server#3cb4da84649c", "stdio:local",
            "http:cli-http", "plain"]
    store = _store(tmp_path, {k: _approved({"ok_tool": "h1"}) for k in keys})
    for key in keys:
        allowed = obot_filter.evaluate(_call("ok_tool"), server=key, store_path=store, record=False)
        assert allowed["accept"] is True, key
        assert "approved baseline" in allowed["reason"], key
        assert "UNEVALUATED" not in allowed["reason"], key
        denied = obot_filter.evaluate(_call("nope"), server=key, store_path=store, record=False)
        assert denied["accept"] is False, key


def test_C4_a_name_that_cannot_round_trip_says_so_instead_of_blaming_the_baseline(tmp_path):
    """'__' is the separator: server 'a__b' calling 'c' re-reads as server 'a', tool 'b__c'. That
    consults some OTHER server's baseline and then reports 'no approved baseline' — false, and it
    sends the operator to `mcpgawk scan`, which cannot fix it."""
    store = _store(tmp_path, {"a": _approved({"anything": "h1"}),
                              "a__b": _approved({"c": "h1"})})
    v = obot_filter.evaluate(_call("c"), server="a__b", store_path=store, record=False)
    assert v["accept"] is True
    assert v["reason"].startswith("UNEVALUATED by mcpgawk")
    assert "cannot be expressed unambiguously" in v["reason"]
    assert "no approved baseline" not in v["reason"]


# ------------------------------------------------------------------- C5: out of scope, and says so

def test_C5_traffic_we_do_not_judge_passes_and_names_itself(tmp_path):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    not_ours = [
        {"message": {"jsonrpc": "2.0", "method": "tools/list", "params": {}}},
        {"message": {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}},   # response direction
        {"message": "not-an-object"},
        {},
    ]
    for hook_input in not_ours:
        v = obot_filter.evaluate(hook_input, server="figma", store_path=store, record=False)
        assert v["accept"] is True, hook_input
        assert "out of scope" in v["reason"], hook_input


# --------------------------------------------------------------------- C6: the fail-closed switch

def test_C6_fail_closed_turns_every_unproven_call_into_a_rejection(tmp_path, monkeypatch):
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})

    blind = obot_filter.evaluate(_call("anything"), server="stripe", store_path=store,
                                 record=False, fail_closed=True)
    assert blind["accept"] is False
    assert "UNEVALUATED" in blind["reason"]

    def boom(*a, **k):
        raise RuntimeError("core exploded")

    monkeypatch.setattr(obot_filter.guard_hook, "_decide", boom)
    broken = obot_filter.evaluate(_call("get_file"), server="figma", store_path=store,
                                  record=False, fail_closed=True)
    assert broken["accept"] is False

    # Fail-closed is about OUR uncertainty, not about traffic that was never ours to judge.
    # Blocking tools/list would break the gateway for every client with no security gained.
    other = obot_filter.evaluate({"message": {"jsonrpc": "2.0", "method": "tools/list"}},
                                 server="figma", store_path=store, record=False, fail_closed=True)
    assert other["accept"] is True


# ------------------------------------------------------------- C7: accepts stay cheap and inert

def test_C7_a_plain_accept_never_mutates_or_echoes_the_payload(tmp_path):
    """Obot discards `message` unless `mutated` is true and passes the original bytes through.
    Echoing a payload back on every accept buys nothing and costs up to the 10 MB cap."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    v = obot_filter.evaluate(_call("get_file", {"blob": "x" * 4096}), server="figma",
                             store_path=store, record=False)
    assert v["mutated"] is False
    assert "message" not in v


# ------------------------------------------------------------------ C8: one record shape, shared

def test_C8_judged_calls_land_in_the_spool_as_this_adapter(tmp_path):
    """`record_decision` is the one shape the hook, the proxy and anything added later all write,
    so the same event cannot be described two ways. The deny/allow/defer split is what keeps
    `status` from counting declines as enforcement."""
    store = _store(tmp_path, {"figma": _approved({"get_file": "h1"})})
    spool = str(tmp_path / "calls.jsonl")

    obot_filter.evaluate(_call("delete_everything"), server="figma", store_path=store,
                         spool_path=spool)
    obot_filter.evaluate(_call("get_file"), server="figma", store_path=store, spool_path=spool)
    obot_filter.evaluate(_call("anything"), server="stripe", store_path=store, spool_path=spool)
    # Never judged, never recorded: a gateway sees every method, and logging them all would bury
    # the calls we actually ruled on.
    obot_filter.evaluate({"message": {"jsonrpc": "2.0", "method": "tools/list"}}, server="figma",
                         store_path=store, spool_path=spool)

    rows = [json.loads(line) for line in Path(spool).read_text(encoding="utf-8").splitlines()
            if line.strip()]
    assert [r["decision"] for r in rows] == ["deny", "allow", "defer"]
    assert {r["adapter"] for r in rows} == {"obot-filter"}
    assert [r["server"] for r in rows] == ["figma", "figma", "stripe"]
    assert [r["tool"] for r in rows] == ["delete_everything", "get_file", "anything"]
