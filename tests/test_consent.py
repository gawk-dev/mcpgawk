"""SCAN / Consent — default-deny before LAUNCHING a discovered/configured stdio server.

Zero-config discovery auto-finds local servers, and scanning a stdio server RUNS its code. These lock
the gate: remote servers always pass (no code runs), local servers launch only with --yes or an
interactive 'y' and never by default, non-interactive fails closed, env VALUES are never shown, and
explicit --stdio is never gated (it's your own typed command).
"""
from __future__ import annotations

import io

import mcpgawk.cli as cli
from mcpgawk.consent import gate_stdio_consent
from mcpgawk.probe import ServerSnapshot

STDIO = ("local", {"command": "evil-mcp", "args": ["--run"], "env": {"API_KEY": "sekret-value"}})
REMOTE = ("notion", {"url": "https://mcp.notion.com/mcp"})


def _gate(targets, **kw):
    err = io.StringIO()
    approved = gate_stdio_consent(targets, err=err, **kw)
    return approved, err.getvalue()


# ---- the gate ---------------------------------------------------------------

def test_remote_only_needs_no_consent():
    approved, err = _gate([REMOTE])
    assert approved == [REMOTE]
    assert err == ""  # nothing to spawn, nothing to ask


def test_assume_yes_launches_everything():
    approved, err = _gate([STDIO, REMOTE], assume_yes=True)
    assert approved == [STDIO, REMOTE]
    assert "--yes" in err


def test_non_interactive_defaults_to_deny_stdio_keeps_remote():
    approved, err = _gate([STDIO, REMOTE], assume_yes=False, stdin_isatty=False)
    assert approved == [REMOTE]  # local server NOT launched; remote still scanned
    assert "NOT launched" in err


def test_interactive_yes_launches():
    approved, _ = _gate([STDIO, REMOTE], stdin_isatty=True, ask=lambda: "y")
    assert approved == [STDIO, REMOTE]


def test_interactive_no_or_empty_denies_stdio():
    for reply in ("n", "", "no", "garbage"):
        approved, _ = _gate([STDIO], stdin_isatty=True, ask=lambda r=reply: r)
        assert approved == []  # default-deny on anything but an explicit yes


def test_env_values_are_never_shown_keys_are():
    _, err = _gate([STDIO], stdin_isatty=False)
    assert "API_KEY" in err            # which env vars are passed IS shown
    assert "sekret-value" not in err   # their VALUES are not
    assert "evil-mcp --run" in err     # the launch command is shown


# ---- wired into the scan flow (discovery path) ------------------------------

def _run_scan(monkeypatch, argv, servers):
    monkeypatch.setattr(cli, "discover_report", lambda: (dict(servers), []))
    probed: list[str] = []

    async def fake_probe(entry, name):
        probed.append(name)
        return ServerSnapshot(name=name, transport="stdio", protocol_version="1")

    monkeypatch.setattr(cli, "probe", fake_probe)
    cli.main(argv)
    return probed


def test_discovered_stdio_is_denied_by_default(monkeypatch, capsys):
    # pytest runs non-interactively (stdin not a tty) → default-deny.
    probed = _run_scan(monkeypatch, ["scan"], [("local", {"command": "evil-mcp"})])
    assert probed == []  # never launched
    assert "would be LAUNCHED" in capsys.readouterr().err


def test_discovered_stdio_launched_with_yes(monkeypatch, capsys):
    probed = _run_scan(monkeypatch, ["scan", "--yes"], [("local", {"command": "evil-mcp"})])
    assert probed == ["local"]


def test_discovered_remote_scanned_without_prompt(monkeypatch, capsys):
    probed = _run_scan(monkeypatch, ["scan"], [("notion", {"url": "https://x/mcp"})])
    assert probed == ["notion"]  # remote runs no local code → never gated


def test_consent_agents_reads_the_key_discovery_actually_emits():
    """Regression: this read `_client` (singular) for weeks while discovery emits `_clients`
    (a list) — the consent prompt's "which of your tools" detail rendered empty on every real
    machine, with every test green, because tests supplied inputs production never did."""
    entries = {
        "fs": {"command": "npx", "_clients": ["claude-code", "cursor"]},
        "notion": {"url": "https://mcp.notion.com/mcp", "_clients": ["cursor"]},
        "odd": {"command": "x"},                     # no attribution at all — must not crash
    }
    assert cli._consent_agents(entries) == ["claude-code", "cursor"]
    assert cli._consent_agents({}) == []
    assert cli._consent_agents(None) == []


def test_discovery_problems_name_the_silent_failures():
    from mcpgawk.discover import ABSENT, OK, UNPARSABLE
    sources = [
        {"client": "cursor", "path": ".cursor/mcp.json", "status": UNPARSABLE,
         "servers": 0, "disabled": [], "unrecognised": []},
        {"client": "windsurf", "path": ".codeium/windsurf/mcp_config.json", "status": OK,
         "servers": 1, "disabled": [], "unrecognised": ["mystery"]},
        {"client": "kimi", "path": ".kimi/mcp.json", "status": ABSENT,
         "servers": 0, "disabled": [], "unrecognised": []},
    ]
    lines = cli._discovery_problems(sources)
    assert any("cursor" in ln and "unparsable" in ln for ln in lines), \
        "an existing-but-unparsable config must be named, not folded into silence"
    assert any("mystery" in ln for ln in lines)
    assert not any("kimi" in ln for ln in lines), "a missing file is not a problem to report"
