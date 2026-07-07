"""Server Card reader — read a server's self-declaration and check it against reality.

SEP-1649 / SEP-2127: an HTTP MCP server MAY publish `/.well-known/mcp/server-card.json` describing
itself for pre-connection discovery. mcpgawk reads it when present, but does NOT trust it: we still
live-connect and MEASURE, then compare. A card that *under-declares* (hides tools it actually
exposes) is a trust signal — exactly the independent-measurement value mcpgawk exists for.

Tolerant by design: any fetch/parse failure -> no card -> fall back to live measurement. The card
fetch is to the server being scanned (the one allowed network touch), same as connecting. Applies to
HTTP/SSE servers only (stdio has no well-known URL).
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

WELL_KNOWN = "/.well-known/mcp/server-card.json"


def card_url_for(server_url: str) -> str:
    p = urlsplit(server_url)
    return urlunsplit((p.scheme, p.netloc, WELL_KNOWN, "", ""))


def _looks_like_card(d: Any) -> bool:
    return isinstance(d, dict) and bool(
        d.get("serverInfo") or d.get("name") or d.get("protocolVersion") or "$schema" in d)


async def fetch_card(server_url: str, timeout: float = 8.0) -> dict[str, Any] | None:
    """GET the well-known card. Returns the parsed card, or None on any failure (tolerant).

    SECURITY: Server Cards are PUBLIC pre-connection discovery, so we send NO auth headers and
    do NOT follow redirects — otherwise a `.well-known` endpoint could 3xx to an attacker host and
    (if we forwarded the user's bearer) leak their credential cross-origin. Neither is negotiable.
    """
    import httpx
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as c:
            r = await c.get(card_url_for(server_url))   # no headers — public, unauthenticated
        if r.status_code != 200:
            return None
        data = r.json()
        return data if _looks_like_card(data) else None
    except Exception:  # noqa: BLE001 — a missing/broken card must never break a scan
        return None


def compare_to_reality(card: dict[str, Any], measured_tool_names: list[str]) -> dict[str, Any]:
    """What the card declares vs what we actually measured."""
    out: dict[str, Any] = {
        "present": True,
        "declared_version": card.get("version"),
        "declared_protocol": card.get("protocolVersion"),
    }
    ct = card.get("tools")
    if isinstance(ct, list):
        declared = sorted({t.get("name") for t in ct if isinstance(t, dict) and t.get("name")})
        real = sorted(set(measured_tool_names))
        undeclared = sorted(set(real) - set(declared))   # present but hidden from the card
        phantom = sorted(set(declared) - set(real))       # claimed but not actually present
        out.update({
            "declared_tool_count": len(declared),
            "measured_tool_count": len(real),
            "undeclared_tools": undeclared,   # the trust-relevant case
            "phantom_tools": phantom,
            "matches_reality": not (undeclared or phantom),
        })
    return out
