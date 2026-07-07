"""Server Card reader: URL derivation, tolerant parse, card-vs-reality, under-declaration signal."""
from __future__ import annotations

from mcpgawk.probe import ServerSnapshot
from mcpgawk.servercard import _looks_like_card, card_url_for, compare_to_reality
from mcpgawk.signals import detect_card_mismatch


def test_well_known_url_derivation():
    assert card_url_for("https://host.example/mcp?a=1") == "https://host.example/.well-known/mcp/server-card.json"
    assert card_url_for("https://h:8443/sse") == "https://h:8443/.well-known/mcp/server-card.json"


def test_tolerant_parse_accepts_card_rejects_junk():
    assert _looks_like_card({"protocolVersion": "2025-11-25", "serverInfo": {"name": "x"}})
    assert _looks_like_card({"name": "x", "$schema": "..."})
    assert not _looks_like_card({"random": "html page"})
    assert not _looks_like_card("<html>404</html>")
    assert not _looks_like_card(["a", "b"])


def test_compare_matches_reality():
    card = {"version": "1.0", "tools": [{"name": "a"}, {"name": "b"}]}
    c = compare_to_reality(card, ["a", "b"])
    assert c["matches_reality"] is True and not c["undeclared_tools"] and not c["phantom_tools"]


def test_compare_detects_under_declaration_and_phantom():
    card = {"tools": [{"name": "a"}, {"name": "ghost"}]}
    c = compare_to_reality(card, ["a", "b"])           # 'b' hidden from card; 'ghost' claimed but absent
    assert c["undeclared_tools"] == ["b"]
    assert c["phantom_tools"] == ["ghost"]
    assert c["matches_reality"] is False


def test_card_without_tools_list_is_tolerated():
    c = compare_to_reality({"version": "2", "protocolVersion": "2025-11-25"}, ["a"])
    assert c["present"] and "undeclared_tools" not in c   # no tool list -> nothing to compare, no crash


def _snap(card, tools):
    return ServerSnapshot(name="s", transport="http", protocol_version="x",
                          tools=[{"name": t, "description": ""} for t in tools], server_card=card)


def test_mismatch_signal_fires_on_under_declaration():
    f = detect_card_mismatch(_snap({"tools": [{"name": "public"}]}, ["public", "hidden_admin"]))
    assert f and f[0].kind == "servercard:undeclared-tools" and "hidden_admin" in f[0].evidence


def test_mismatch_signal_silent_when_card_matches_or_absent():
    assert detect_card_mismatch(_snap({"tools": [{"name": "a"}]}, ["a"])) == []
    assert detect_card_mismatch(_snap(None, ["a"])) == []


async def test_card_fetch_sends_no_auth_and_no_redirect(monkeypatch):
    """SECURITY: the public card fetch must never carry the user's bearer, and must not follow a
    redirect (either would let a .well-known 3xx exfiltrate the credential cross-origin)."""
    import httpx

    from mcpgawk.servercard import fetch_card

    seen: dict = {}

    class FakeResp:
        status_code = 200
        def json(self):
            return {"protocolVersion": "2025-11-25", "serverInfo": {"name": "s"}}

    class FakeClient:
        def __init__(self, **kw):
            seen["client_kwargs"] = kw
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def get(self, url, **kw):
            seen["url"] = url
            seen["get_kwargs"] = kw
            return FakeResp()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    card = await fetch_card("https://host.example/mcp")
    assert card is not None
    assert seen["client_kwargs"].get("follow_redirects") is False           # no redirect chase
    assert not seen["get_kwargs"].get("headers")                            # no auth header sent
    assert seen["url"].endswith("/.well-known/mcp/server-card.json")
