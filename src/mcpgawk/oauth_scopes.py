"""OAUTH SCOPES — opt-in, local-only inspection of a user-supplied bearer token.

Decodes the `Authorization: Bearer <token>` header (if present) the user already gave us for
the MCP connection. No network call: if the token is a JWT we base64-decode its payload
locally to read the `scope`/`scp` claim — the signature is never verified (we don't have the
issuer's key, and don't need to; we're reading a declaration, not authenticating). Opaque
(non-JWT) tokens are reported as not locally inspectable. Gated behind `--oauth-scopes`
because it surfaces claims from a credential the user typed in, even though nothing leaves
the machine.
"""
from __future__ import annotations

import base64
import json
from typing import Any


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _bearer_token(headers: dict[str, str] | None) -> str | None:
    for k, v in (headers or {}).items():
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            return v[7:].strip()
    return None


def inspect(headers: dict[str, str] | None) -> dict[str, Any] | None:
    """None if there's no bearer token to inspect at all."""
    token = _bearer_token(headers)
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return {"token_type": "opaque", "scopes": None,
                "note": "not a JWT — scope not locally inspectable without server-side introspection"}
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:  # noqa: BLE001 — malformed token, never crash the scan
        return {"token_type": "jwt", "scopes": None, "error": f"undecodable payload: {type(e).__name__}: {e}"}
    scope_claim = payload.get("scope") or payload.get("scp")
    scopes = scope_claim.split() if isinstance(scope_claim, str) else scope_claim
    return {"token_type": "jwt", "scopes": scopes, "aud": payload.get("aud"), "exp": payload.get("exp")}
