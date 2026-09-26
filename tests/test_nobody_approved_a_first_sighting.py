"""New-developer walk, 2026-09-26, on the released 0.1.60.

1. A first scan silently became the baseline, and the next scan's drift said "changed since you
   approved it just now". Nobody had approved anything.
2. `status` and `approve --list` said "Accept: mcpgawk approve <name>", but the name shown for an
   ad-hoc server was a whole command line, and the same server went by three names. Now each
   pending server gets its exact command, by key, shell-quoted.
"""
from __future__ import annotations

import shlex

from mcpgawk import drift, history, status


def _report(origin):
    r = drift.DriftReport(pin_changed=True, added=["tool.b"], removed=[], changed=[],
                          token_delta=10, prev_at=None)
    r.baseline_origin = origin
    return r


def test_a_first_sighting_baseline_is_not_called_an_approval():
    out = drift.render("tiny", _report("first-sighting"))
    assert "changed since first seen" in out
    assert "you have not approved this server yet" in out
    assert "you approved it" not in out


def test_a_real_approval_still_says_so():
    assert "after you approved it" in drift.render("tiny", _report("approve"))


def test_an_unknown_origin_keeps_the_old_wording():
    # A baseline older than the field: its origin is unknown and is not guessed either way.
    assert "you approved it" in drift.render("tiny", _report(None))


def test_the_scan_path_sets_the_origin(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "h.json"))
    rec = {"pin": "a", "tools": {"x": "1"}, "measured_at": "2026-09-26T00:00:00+00:00"}
    assert history.record("mcp:tiny", rec) is None
    assert history.baseline_origin(history.load(), "mcp:tiny") == "first-sighting"


def test_status_prints_the_exact_command_per_pending_server():
    key = "mcp:Kite MCP Server"
    out = status.render(hook_health={}, guard_path=None, agents={}, baseline_total=0,
                        pending=["npx -y kite"], pending_keys=[key], behaviour_tools=None,
                        enforce_available=False, last_activity=None, activity=None)
    assert f"mcpgawk approve {shlex.quote(key)}" in out
    assert "approve <name>" not in out
    assert "changed since you approved them" not in out


def test_approve_list_prints_the_exact_command_per_server(tmp_path, monkeypatch, capsys):
    from mcpgawk import cli
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "h.json"))
    key = "mcp:tiny weather"
    history.record(key, {"pin": "a", "tools": {"x": "1"}, "items": {"tool.x": "1"},
                         "measured_at": "2026-09-26T00:00:00+00:00"},
                   alias="python server.py --port 1")
    history.record(key, {"pin": "b", "tools": {"x": "2"}, "items": {"tool.x": "2"},
                         "measured_at": "2026-09-26T00:01:00+00:00"})
    cli.main(["approve", "--list"])
    out = capsys.readouterr().out
    assert "changed since their baseline" in out
    assert f"mcpgawk approve {shlex.quote(key)}" in out, out
    assert "approve <name>" not in out


def test_an_adhoc_server_is_shown_by_the_name_it_asserts():
    # Re-walk, 2026-09-26: the report said "cli-stdio" (which approve refuses) and status showed a
    # whole temp-path command line. Both now show the server's own name, which approve resolves.
    from mcpgawk.label import display_name as label_name
    lab = {"name": "cli-stdio", "serverInfo": {"name": "tiny-weather"}}
    assert label_name(lab) == "tiny-weather"
    assert label_name({"name": "cli-stdio", "serverInfo": None}) == "cli-stdio"
    assert label_name({"name": "notes", "serverInfo": {"name": "other"}}) == "notes"
    store = {"servers": {
        "mcp:tiny-weather": {"aliases": ["/tmp/x/venv/bin/python /tmp/x/tiny/server.py"]},
        "mcp:docs": {"aliases": ["https://mcp.example.com/mcp"]},
        "mcp:notes-pro": {"aliases": ["notes"]},
        "mcp:bare": {"aliases": ["/opt/bin/bare-server"]},
    }}
    assert history.display_name(store, "mcp:tiny-weather") == "tiny-weather"
    assert history.display_name(store, "mcp:docs") == "docs"
    assert history.display_name(store, "mcp:notes-pro") == "notes"      # a config name stays
    assert history.display_name(store, "mcp:bare") == "bare"
    assert history.resolve(store, "tiny-weather") == "mcp:tiny-weather"
