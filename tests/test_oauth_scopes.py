"""OAuth-scopes opt-in check — pure local decode, no network, no signature verification."""
from __future__ import annotations

import base64
import json

from mcpgawk.oauth_scopes import inspect


def _jwt(payload: dict) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256'})}.{seg(payload)}.sig"


def test_no_headers_returns_none():
    assert inspect(None) is None
    assert inspect({}) is None


def test_no_bearer_scheme_returns_none():
    assert inspect({"Authorization": "Basic dXNlcjpwYXNz"}) is None


def test_jwt_scope_claim_decoded():
    token = _jwt({"scope": "read write admin", "aud": "mcp-test", "exp": 9999999999})
    result = inspect({"Authorization": f"Bearer {token}"})
    assert result["token_type"] == "jwt"
    assert result["scopes"] == ["read", "write", "admin"]
    assert result["aud"] == "mcp-test"


def test_jwt_scp_claim_fallback():
    token = _jwt({"scp": ["read", "write"]})
    result = inspect({"Authorization": f"Bearer {token}"})
    assert result["scopes"] == ["read", "write"]


def test_jwt_no_scope_claim_at_all():
    token = _jwt({"aud": "mcp-test"})
    result = inspect({"Authorization": f"Bearer {token}"})
    assert result["scopes"] is None


def test_opaque_token_not_guessed_at():
    result = inspect({"Authorization": "Bearer sk-live-opaque-token-12345"})
    assert result["token_type"] == "opaque"
    assert result["scopes"] is None


def test_malformed_jwt_payload_never_crashes():
    result = inspect({"Authorization": "Bearer not-base64!!.not-base64!!.sig"})
    assert result["token_type"] == "jwt"
    assert result["scopes"] is None
    assert result["error"]


def test_header_key_case_insensitive():
    token = _jwt({"scope": "read"})
    result = inspect({"authorization": f"bearer {token}"})
    assert result["scopes"] == ["read"]
