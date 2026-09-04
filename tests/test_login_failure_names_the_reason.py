"""A failed sign-in must say WHY — on the terminal and on the panel — never the footer, never a
circle.

Founder's panel, 2026-09-03 20:12Z, "Sign in now" on figma:
    "sign-in for figma did not complete — Scanned locally — your server inventory never left
     this machine."
The child printed the reason ("OAuthRegistrationError: Registration failed: 403 Forbidden") five
lines above its footer; the panel took the last line. And the child itself advised "retry with
`--login`" from inside the login flow — `_signin_failure_line` fixed that on 2026-08-14 for the
FLEET path only; the single-URL path the button runs never called it.
"""
from __future__ import annotations

import inspect
from pathlib import Path

from mcpgawk import cli, panel

FIXTURE = Path(__file__).parent / "fixtures" / "figma-login-refused-2026-09-03.txt"
REAL = FIXTURE.read_text(encoding="utf-8")            # the child's stdout, verbatim
FOOTER = "never left this machine"


def test_the_fixture_is_the_real_refusal():
    assert "Registration failed: 403 Forbidden" in REAL and FOOTER in REAL
    assert "retry with `--login`" in REAL, "the circle the CLI printed before the fix"


# --- the panel ------------------------------------------------------------------------------ #

def test_panel_detail_is_the_refusal_and_the_way_through_not_the_footer():
    detail = panel._login_failure_detail("figma", "https://mcp.figma.com/mcp", REAL)
    assert "refuses automatic client registration" in detail
    assert "403" in detail, "the server's own refusal must be quoted"
    assert "--oauth-client-id" in detail, "the way through must be named"
    assert FOOTER not in detail
    assert "retry with `--login`" not in detail


def test_panel_detail_prefers_the_attempt_line_for_an_ordinary_failure():
    out = ("● cli-http   [http]   UNREACHABLE\n"
           "    ✗ could not scan — no answer within the time budget:\n"
           "  - http https://x.example/mcp: ReadTimeout: timed out after 12s\n"
           "────\n1 server · 0 tools\nScanned locally — your server inventory never left this machine.\n")
    detail = panel._login_failure_detail("x", "https://x.example/mcp", out)
    assert detail.startswith("- http https://x.example/mcp: ReadTimeout")
    assert FOOTER not in detail


def test_panel_detail_for_no_output_sends_you_to_the_terminal():
    detail = panel._login_failure_detail("x", "https://x.example/mcp", "\n  \n")
    assert "printed nothing" in detail and "mcpgawk scan --http https://x.example/mcp --login" in detail


def test_panel_run_login_uses_the_detail_helper():
    assert "_login_failure_detail(" in inspect.getsource(panel.run_login)


# --- the terminal --------------------------------------------------------------------------- #

def test_single_url_login_error_names_the_way_through_and_keeps_the_ladder():
    snap_error = ("authentication required — the endpoint is live but refused this scan; "
                  "retry with `--login` or `--header \"Authorization: Bearer …\"`:\n"
                  "  - http https://mcp.figma.com/mcp: OAuthRegistrationError: Registration failed: "
                  "403 Forbidden. This did NOT pass; it was not measured.")
    text = cli._honest_login_error("https://mcp.figma.com/mcp", snap_error,
                                   "Registration failed: 403 Forbidden")
    assert "retry with `--login`" not in text, "advice to run the flow that just ran is a circle"
    assert "authentication required" in text and "403 Forbidden" in text, "the ladder stays"
    assert "--oauth-client-id" in text and "developer console" in text


def test_single_url_login_error_for_an_ordinary_failure_only_cuts_the_circle():
    snap_error = ("authentication required — the endpoint is live but refused this scan; "
                  "retry with `--login` or `--header \"Authorization: Bearer …\"`:\n"
                  "  - http https://x.example/mcp: HTTPStatusError: 401")
    text = cli._honest_login_error("https://x.example/mcp", snap_error, None)
    assert "retry with `--login`" not in text and "HTTPStatusError: 401" in text
    assert "--oauth-client-id" not in text, "no registration refusal, no BYO advice"


def test_the_single_url_login_path_is_wired_to_it():
    src = inspect.getsource(cli._run)
    assert "_honest_login_error(" in src, "the fleet path had the honest line; the panel's path must too"


# --- the path production takes AFTER the fix ------------------------------------------------ #

AFTER = (Path(__file__).parent / "fixtures" / "figma-login-refused-after-fix-2026-09-03.txt"
         ).read_text(encoding="utf-8")            # the fixed child's stdout, verbatim


def test_panel_detail_on_the_fixed_childs_output_is_the_way_through_once():
    """After the CLI fix the child ALREADY prints the honest line, so the panel takes the first
    branch, not the compose-from-refusal branch the pre-fix fixture exercises. Both fixtures are
    real captures; this is the one a customer's panel will see."""
    assert "refuses automatic client registration" in AFTER and FOOTER in AFTER
    detail = panel._login_failure_detail("figma", "https://mcp.figma.com/mcp", AFTER)
    assert "--oauth-client-id" in detail and "403" in detail
    assert FOOTER not in detail and "retry with `--login`" not in detail
    assert detail.count("mcp.figma.com:") == 1, "the host is named once, not twice"
