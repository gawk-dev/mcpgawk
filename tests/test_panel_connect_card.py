"""The one-paste enrolment card (founder, 2026-08-07 — Natoma's Get Config, applied local-first).

The card must exist on the hub, name the REAL shipped binary (`mcpgawk-mcp` is a console script in
every install), give a block for each named client, and say honestly that it enforces nothing —
per the design-integrity rule, a card that read as protection would be a lie.

Public-safe: imports only mcpgawk.
"""
from __future__ import annotations

import inspect

from mcpgawk import panel


CARD = panel._connect_card()


def test_the_card_names_the_real_binary_not_an_aspiration():
    assert "mcpgawk-mcp" in CARD
    assert "scan_mcp_fleet" in CARD and "scan_mcp_server" in CARD


def test_every_named_client_gets_a_block():
    for client in ("Claude Code", "Claude Desktop", "Cursor", "VS Code"):
        assert client in CARD, f"{client} lost its config block"
    assert "claude mcp add mcpgawk -- mcpgawk-mcp" in CARD


def test_the_card_admits_it_enforces_nothing():
    """Connecting the scanner's answers is not protection; the hook is. The card says so."""
    assert "does <b>not</b> block anything by itself" in CARD


def test_the_card_is_static_and_token_free():
    """It must be safe on the read-only view: no token, no form, no POST."""
    assert "<form" not in CARD and "?t=" not in CARD


def test_render_actually_places_the_card_on_the_hub():
    """A card that exists but is never rendered is the dead-code pattern; pin the call site."""
    assert "_connect_card()" in inspect.getsource(panel.render)


def test_the_setup_prompt_lets_the_agent_do_the_plumbing():
    """The Kerno-pattern paste-to-your-agent prompt: it must name the real binary and the real
    tool, and ask for a summary — value on the first call, not just registration."""
    assert "paste this prompt" in CARD
    assert 'command "mcpgawk-mcp", stdio transport' in CARD
    assert "scan_mcp_fleet" in CARD
