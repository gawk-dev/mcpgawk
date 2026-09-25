"""Advice a report gives must follow what the scan actually knows (T4, T6 — 2026-09-25).

The hosted test server pins the customer-visible cases (tests/test_testserver_scenarios.py). This
file pins the arms those scenarios never reach: every way a credential can ride along keeps the
token advice, and a dispatcher verify CAN drive keeps the pointer to verify.
"""
from mcpgawk import label
from mcpgawk.probe import _anonymous

AC = {"annotated": 1, "read_only": 0, "destructive": 1}
TOKEN_ADVICE = "If you don't need write access, connect with a read-only token instead."


def test_only_a_provably_bare_connection_is_anonymous():
    assert _anonymous("https://mcp.example.test/mcp", {}, None) is True
    assert _anonymous("https://mcp.example.test/mcp", None, None) is True
    # Never False: a header we cannot classify is not proof a token exists either.
    assert _anonymous("https://mcp.example.test/mcp", {"Authorization": "Bearer x"}, None) is None
    assert _anonymous("https://mcp.example.test/mcp", {"X-Api-Key": "x"}, None) is None
    assert _anonymous("https://mcp.example.test/mcp", {}, object()) is None          # a sign-in
    assert _anonymous("https://mcp.example.test/mcp?api_key=x", {}, None) is None    # key in URL


def test_the_token_advice_needs_a_token_to_be_possible():
    tools = [{"name": "execute", "write_capable": True, "tokens": 10}]
    assert TOKEN_ADVICE not in label._actions(0, 1, AC, False, tools, 10, anonymous=True)
    for unknown in (None, False):     # stdio, any header, an old stored label
        assert TOKEN_ADVICE in label._actions(0, 1, AC, False, tools, 10, anonymous=unknown)
    assert TOKEN_ADVICE not in label._actions(0, 0, AC, False, tools, 10, anonymous=None)  # D7


def _exfil_body(undriven):
    tool = {"name": "exec", "exfil_capable": True, "exfil_basis": "wording:request", "tokens": 10}
    out = label._concerns(1, 10, 0, 0, AC, [tool], False, [], False, None, undriven)
    return " ".join(line for _, body in out for line in body)


def test_verify_is_offered_only_where_it_can_drive():
    assert "does not drive this dispatcher shape" in _exfil_body(frozenset({"exec"}))
    assert "runs the tools in a sandbox" not in _exfil_body(frozenset({"exec"}))
    assert "runs the tools in a sandbox" in _exfil_body(frozenset())        # an ordinary tool


def test_a_drivable_dispatcher_pair_is_not_undriven():
    """Sentry's discover/execute pair is the shape verify drives: the narrative keeps verify."""
    snap_label = {"x-mcpgawk": {
        "trust_surface": {"write_count": 0, "exfil_count": 0},
        "annotation_completeness": AC, "tool_count": 2, "cost_index_tokens": 20,
        "tools": [{"name": "use_sentry", "exfil_capable": True, "exfil_basis": "wording:request",
                   "tokens": 10}, {"name": "search_tools", "tokens": 10}],
        "bounded_signals": [{"kind": "dispatch:dynamic-tool-catalog",
                             "tool": "search_tools, use_sentry"}]},
        "name": "s", "transport": "http"}
    nar = label.build_narrative(snap_label)
    text = " ".join(line for c in nar["concerns"] for line in c["body"])
    assert "runs the tools in a sandbox" in text, text
