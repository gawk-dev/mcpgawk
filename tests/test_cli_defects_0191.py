"""Defects found walking 0.1.90 as a fresh user (2026-11-16), one test per defect."""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"


def test_every_pricing_link_names_the_page_that_exists():
    """Defect 5: the lapsed-subscription lines linked https://mcp.gawk.dev/pricing, a path the site
    only redirects. Every product link names pricing.html."""
    bad = []
    for p in SRC.rglob("*.py"):
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"mcp\.gawk\.dev/pricing(?!\.html)", line):
                bad.append(f"{p.relative_to(SRC)}:{n}")
    assert not bad, bad


# ── Defect 4: help text and exit codes ───────────────────────────────────────────────────────────
import builtins  # noqa: E402
from types import SimpleNamespace  # noqa: E402

import pytest  # noqa: E402

from mcpgawk import cli, drift, fingerprint, history  # noqa: E402
from mcpgawk.probe import ServerSnapshot  # noqa: E402


@pytest.fixture
def no_platform(monkeypatch):
    """A free-only install, even where the paid engine happens to be importable."""
    real_import = builtins.__import__

    def _import(name, *a, **kw):
        if name.startswith("gawk_platform"):
            raise ImportError("No module named 'gawk_platform'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", _import)


@pytest.mark.parametrize("cmd", ["logout", "push", "enforce", "monitor"])
@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_on_a_free_install_prints_usage_and_exits_0(cmd, flag, no_platform, capsys):
    """`logout --help` and `push --help` printed the not-installed refusal and exited 3. Help is
    help: usage on stdout, exit 0, and it still says the command is not installed here."""
    rc = cli.main([cmd, flag])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert out.startswith(f"usage: mcpgawk {cmd}"), out
    assert "isn't installed" in out or "not in this environment" in out, out


@pytest.mark.parametrize("cmd", ["logout", "push", "enforce"])
def test_a_real_invocation_on_a_free_install_still_refuses(cmd, no_platform, capsys):
    assert cli.main([cmd]) == 3


def test_top_level_help_tells_the_free_guard_from_paid_enforce():
    """The epilog listed `enforce  guard a live server, call by call` under Platform and then said
    "the runtime guard stay free" — two guards, one paid, one free, named alike."""
    text = " ".join(cli.build_parser().format_help().split())
    free, _, paid = text.partition("mcpgawk Platform —")
    assert "guard" in free and "hook" in free, free
    assert "guard a live server" not in paid, paid
    assert "gateway" in paid, paid
    assert "runtime guard stay free" not in text


def test_runs_help_does_not_put_verify_behind_platform():
    sub = cli.build_parser()._subparsers._group_actions[0].choices["runs"]
    text = " ".join(sub.format_help().split())
    assert "Platform) verify" not in text, text
    assert "verify" in text


def _rec(desc: str, at: str) -> dict:
    tools = [{"name": "read", "description": desc, "inputSchema": {"type": "object"}}]
    snap = ServerSnapshot(name="srv", transport="http", protocol_version="2025-06-18",
                          tools=tools, server_info={"name": "srv"}, enumerated=["tool"])
    m = SimpleNamespace(integrity_pin=fingerprint.surface_pin(tools), tool_count=1,
                        total_tokens=0, tokenizer="x")
    return drift.build_record(snap, m, at)


def _pending_store(p: str) -> None:
    history.record("mcp:srv", _rec("Read notes", "2026-11-01T00:00:00+00:00"), path=p, alias="srv")
    history.approve("mcp:srv", path=p)
    history.record("mcp:srv", _rec("Read notes, and more", "2026-11-02T00:00:00+00:00"), path=p,
                   alias="srv")


def test_status_says_held_only_once_a_guard_hook_is_installed(tmp_path, monkeypatch):
    """Defect 1, end to end as the shipped CLI in a scratch HOME: `status` said "blocked until you
    decide" with no guard hook installed. No hook: not held. After `guard install` (Claude Code's
    hook) on a machine whose only agent is Cursor: STILL not held — the hook is on an agent that
    reaches nothing here. Add a Claude Code server: held where the hook is installed."""
    import json
    import os
    import subprocess
    import sys
    monkeypatch.setattr(history, "require_human_approval", lambda signer=None: None)
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps(
        {"mcpServers": {"srv": {"command": "definitely-not-launched-mcp"}}}))
    store = str(tmp_path / "history.json")
    _pending_store(store)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GAWK_")}
    env.update(HOME=str(home), MCPGAWK_HISTORY=store, MCPGAWK_SPOOL=str(tmp_path / "c.jsonl"),
               MCPGAWK_RUNS=str(tmp_path / "runs.db"), MCPGAWK_NO_UPDATE_CHECK="1")

    def run(*a):
        return subprocess.run([sys.executable, "-m", "mcpgawk", *a], env=env, cwd=tmp_path,
                              capture_output=True, text=True, timeout=120,
                              stdin=subprocess.DEVNULL)

    before = " ".join(run("status").stdout.split())
    assert "changed since their baseline" in before, before
    assert "blocked until" not in before and "held by" not in before, before
    assert "not held: no guard hook is installed here" in before, before

    assert run("guard", "install").returncode == 0
    assert (home / ".claude" / "settings.json").is_file()
    cursor_only = " ".join(run("status").stdout.split())
    assert "not held: no guard hook is installed here" in cursor_only, cursor_only

    (home / ".claude.json").write_text(json.dumps(
        {"mcpServers": {"srv": {"command": "definitely-not-launched-mcp"}}}))
    both = " ".join(run("status").stdout.split())
    assert "held where the guard hook is installed, until you decide" in both, both
    assert "not held" not in both, both


def test_approve_and_decide_help_say_held_where_the_hook_is():
    subs = cli.build_parser()._subparsers._group_actions[0].choices
    for name in ("approve", "decide"):
        text = " ".join(subs[name].format_help().split())
        assert "held where the guard hook is installed" in text, text
        assert "calls are blocked" not in text and "keep blocking" not in text, text


@pytest.mark.parametrize("state", ["all", "some", "none"])
def test_unsigned_and_held_change_words_follow_the_hook(state, monkeypatch):
    from mcpgawk import status
    monkeypatch.setattr(status, "hold_state_here", lambda: state)
    refuse, hold = cli._refuse_words(), cli._hold_words()
    if state == "none":
        assert "no guard hook is installed here to refuse calls" in refuse
        assert hold.startswith("not held")
    else:
        assert "guard hook refuses" in refuse and "held" in hold and "not held" not in hold
    assert "agent hook refuses" not in refuse and "blocked" not in hold


@pytest.mark.parametrize("state, want", [("none", "are not held: no guard hook is installed"),
                                          ("all", "are held by the guard hook until you approve")])
def test_a_change_that_changed_back_says_who_holds_it(state, want, monkeypatch, capsys):
    """scan's "changed on <day> and changed back" line said "stay blocked until you approve"."""
    from mcpgawk import status
    monkeypatch.setattr(status, "hold_state_here", lambda: state)
    report = drift.compare(_rec("Read notes", "2026-11-01T00:00:00+00:00"),
                           _rec("Read notes, and more", "2026-11-02T00:00:00+00:00"))
    cli._print_held_change("srv", "mcp:srv", {"measured_at": "2026-11-02"}, report)
    out = " ".join(capsys.readouterr().out.split())
    assert want in out and "stay blocked" not in out, out


def test_hold_state_is_judged_over_the_agents_present():
    from mcpgawk.status import hold_state
    assert hold_state({"claude-code": "ok", "cursor": "absent"}, ["cursor"]) == "none"
    assert hold_state({"claude-code": "ok", "cursor": "absent"}, ["cursor", "claude-code"]) == "some"
    assert hold_state({"claude-code": "ok"}, ["claude-code"]) == "all"
    assert hold_state({"claude-code": "ok"}, []) == "all"
    assert hold_state({"claude-code": "broken"}, ["claude-code"]) == "none"
    assert hold_state({}, ["claude-code"]) == "some"
    assert hold_state({"claude-code": "ok"}, None) == "some"


def test_bare_approve_lists_and_exits_like_approve_list(tmp_path, monkeypatch, capsys):
    """Bare `approve` "lists what is waiting" (its help) and exited 1 where `approve --list`
    printed the same and exited 0. Listing is not a failure."""
    monkeypatch.setattr(history, "require_human_approval", lambda signer=None: None)
    p = str(tmp_path / "history.json")
    monkeypatch.setenv("MCPGAWK_HISTORY", p)
    history.record("mcp:srv", _rec("Read notes", "2026-11-01T00:00:00+00:00"), path=p, alias="srv")
    history.approve("mcp:srv", path=p)
    history.record("mcp:srv", _rec("Read notes, and more", "2026-11-02T00:00:00+00:00"), path=p,
                   alias="srv")
    assert history.pending(history.load(p)) == ["mcp:srv"]
    rc_list = cli.main(["approve", "--list"])
    out_list = capsys.readouterr().out
    rc_bare = cli.main(["approve"])
    out_bare = capsys.readouterr().out
    assert out_bare == out_list and "mcp:srv" in out_bare
    assert rc_bare == rc_list == 0
