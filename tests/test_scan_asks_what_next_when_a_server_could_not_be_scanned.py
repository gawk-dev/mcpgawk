"""When `scan` could not finish a server and a person is at the terminal, it asks what to do next.

FOUNDER DECISION 2026-11-16. The prompt:

    notes   could not scan — no answer within 20s

    What next?
      [r] try again
      [s] skip it and finish the scan
      [d] show why it failed
    >

[r] scans that server again with the same options; [s] keeps it as could-not-scan (exit 1, never
a pass); [d] prints what is already known, redacted, and asks again. EOF and Ctrl-C are [s].

Nobody to ask means no prompt and today's behaviour exactly: stdin or stderr not a terminal,
`--json`, `--fleet-json`, `--yes`, or an agent session (markers or an agent process above us).
The prompt goes to STDERR; stdout is the same whether a person was asked or not.
"""
from __future__ import annotations

import builtins
import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from mcpgawk import cli, history
from mcpgawk.probe import ServerSnapshot

FIXTURE = Path(__file__).parent / "fixtures" / "toy_http_mcp_server.py"
QUIET = ServerSnapshot(name="notes", transport="http", protocol_version=None,
                       error="no MCP response within 20s: TimeoutError", error_kind="timed-out")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    monkeypatch.setenv("GAWK_BEHAVIOUR_PROFILE", str(tmp_path / "behaviour.json"))
    monkeypatch.setenv("MCPGAWK_NO_UPDATE_CHECK", "1")
    (tmp_path / "home").mkdir()
    # A person's shell, not this suite's real parent: it is often run from inside an agent.
    for marker in history.AGENT_ENV_MARKERS:
        monkeypatch.delenv(marker, raising=False)
    monkeypatch.setattr(history, "_process_ancestry", lambda: ["zsh", "login", "Terminal"])
    return tmp_path


def _config(home, url="http://127.0.0.1:9/mcp") -> str:
    cfg = home / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"notes": {"url": url}}}))
    return str(cfg)


def _terminal(monkeypatch, stdin=True, stderr=True):
    monkeypatch.setattr("sys.stdin.isatty", lambda: stdin)
    monkeypatch.setattr("sys.stderr.isatty", lambda: stderr)


def _answers(monkeypatch, *replies):
    """Feed the prompt. A reply that is an exception class is raised; past the end is EOF."""
    asked = []
    queue = list(replies)

    def fake_input(prompt=""):
        asked.append(prompt)
        if not queue:
            raise EOFError
        r = queue.pop(0)
        if isinstance(r, type) and issubclass(r, BaseException):
            raise r
        return r

    monkeypatch.setattr(builtins, "input", fake_input)
    return asked


def _probe(monkeypatch, answers_on=()):
    """`cli.probe` that times out, except on the attempt numbers in `answers_on` (1-based)."""
    calls = []

    async def fake_probe(entry, name):
        calls.append((name, dict(entry)))
        if len(calls) in answers_on:
            return ServerSnapshot(name=name, transport="http", protocol_version="2025-06-18")
        return ServerSnapshot(name=QUIET.name if name == "notes" else name, transport="http",
                              protocol_version=None, error=QUIET.error,
                              error_kind=QUIET.error_kind)

    monkeypatch.setattr(cli, "probe", fake_probe)
    return calls


# ── a person at the terminal is asked ────────────────────────────────────────────────────────────

def test_a_person_at_the_terminal_is_asked_what_next(home, capsys, monkeypatch):
    calls = _probe(monkeypatch)
    _terminal(monkeypatch)
    _answers(monkeypatch, "s")

    rc = cli.main(["scan", _config(home)])

    out, err = capsys.readouterr()
    assert "notes   could not scan — no answer within 20s" in err
    for line in ("What next?", "[r] try again", "[s] skip it and finish the scan",
                 "[d] show why it failed"):
        assert line in err, line
    assert "What next" not in out, "the prompt belongs on stderr; stdout is the scan's output"
    assert len(calls) == 1
    assert rc == 1, "a skipped server is could-not-scan: exit 1, never a pass and never 4"


def test_skip_keeps_the_server_as_not_scanned(home, capsys, monkeypatch):
    _probe(monkeypatch)
    _terminal(monkeypatch)
    _answers(monkeypatch, "s")

    rc = cli.main(["scan", _config(home)])

    out = capsys.readouterr().out
    assert "notes" in out and "could not scan" in out, "the skipped server must stay listed"
    assert "This did NOT pass" in out
    assert "CLEAN" not in out.upper()
    assert rc == 1


def test_try_again_picks_up_a_server_that_answers_the_second_time(home, capsys, monkeypatch):
    calls = _probe(monkeypatch, answers_on=(2,))
    _terminal(monkeypatch)
    asked = _answers(monkeypatch, "r")

    rc = cli.main(["scan", _config(home)])

    out, err = capsys.readouterr()
    assert len(calls) == 2, "[r] scans the same server again"
    assert calls[0] == calls[1], "same server, same entry: the same options"
    assert len(asked) == 1, "it answered on the second try, so nothing more is asked"
    assert "TIMED-OUT" not in out.upper() and "could not scan" not in out
    assert rc == 0


def test_try_again_can_fail_again_and_ask_again(home, capsys, monkeypatch):
    calls = _probe(monkeypatch)
    _terminal(monkeypatch)
    asked = _answers(monkeypatch, "r", "s")

    rc = cli.main(["scan", _config(home)])

    err = capsys.readouterr().err
    assert len(calls) == 2
    assert len(asked) == 2 and err.count("What next?") == 2
    assert rc == 1


def test_details_prints_the_reason_redacted_and_asks_again(home, capsys, monkeypatch):
    url = "http://127.0.0.1:9/mcp?apiKey=sk-live-0123456789abcdef"

    async def fake_probe(entry, name):
        return ServerSnapshot(name=name, transport="http", protocol_version=None,
                              error=f"no MCP response within 20s: TimeoutError at {url}",
                              error_kind="timed-out")

    monkeypatch.setattr(cli, "probe", fake_probe)
    _terminal(monkeypatch)
    asked = _answers(monkeypatch, "d", "s")

    rc = cli.main(["scan", _config(home, url)])

    out, err = capsys.readouterr()
    assert len(asked) == 2, "[d] asks again afterwards"
    assert "TimeoutError" in err and "timed-out" in err
    assert "http" in err and "127.0.0.1:9/mcp" in err
    # stdout is the scan's own report, unchanged by this feature; the prompt's lines are ours.
    assert "sk-live-0123456789abcdef" not in err, "details go through the redactor"
    assert "apiKey=***" in err
    assert rc == 1


def test_details_for_a_local_server_show_the_command_without_its_secrets(home, capsys,
                                                                       monkeypatch):
    async def fake_probe(entry, name):
        return ServerSnapshot(name=name, transport="stdio", protocol_version=None,
                              error="it started, then failed", error_kind="server-failed")

    monkeypatch.setattr(cli, "probe", fake_probe)
    monkeypatch.setattr(cli, "gate_stdio_consent", lambda targets, assume_yes=False: targets)
    _terminal(monkeypatch)
    _answers(monkeypatch, "d", "s")
    cfg = home / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"notes": {
        "command": "npx", "args": ["-y", "notes-mcp", "--token", "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"],
        "env": {"NOTES_KEY": "envsecretvalue123"}}}}))

    rc = cli.main(["scan", str(cfg)])

    out, err = capsys.readouterr()
    assert "npx -y notes-mcp" in err
    assert "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB" not in err + out
    assert "envsecretvalue123" not in err + out
    assert rc == 1


@pytest.mark.parametrize("ending", [EOFError, KeyboardInterrupt])
def test_eof_and_ctrl_c_are_skip(home, capsys, monkeypatch, ending):
    calls = _probe(monkeypatch)
    _terminal(monkeypatch)
    _answers(monkeypatch, ending)

    rc = cli.main(["scan", _config(home)])

    out = capsys.readouterr().out
    assert len(calls) == 1
    assert "notes" in out
    assert rc == 1


def test_ctrl_c_while_trying_again_is_skip(home, capsys, monkeypatch):
    """A retry can wait 20-90s; that is when a person presses Ctrl-C. It must not crash the scan
    or lose the report: the server stays could-not-scan and the scan finishes with exit 1."""
    calls = []

    async def fake_probe(entry, name):
        calls.append(name)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return QUIET

    monkeypatch.setattr(cli, "probe", fake_probe)
    _terminal(monkeypatch)
    _answers(monkeypatch, "r")

    rc = cli.main(["scan", _config(home)])

    out = capsys.readouterr().out
    assert len(calls) == 2
    assert "notes" in out and "could not scan" in out
    assert rc == 1


def test_unknown_input_asks_again(home, capsys, monkeypatch):
    _probe(monkeypatch)
    _terminal(monkeypatch)
    asked = _answers(monkeypatch, "maybe", "", "s")

    rc = cli.main(["scan", _config(home)])

    assert len(asked) == 3
    assert capsys.readouterr().err.count("What next?") == 3
    assert rc == 1


def test_stdout_is_the_same_whether_a_person_was_asked_or_not(home, capsys, monkeypatch):
    _probe(monkeypatch)
    _terminal(monkeypatch, stdin=False)
    cli.main(["scan", "--no-track", _config(home)])
    unasked = capsys.readouterr().out

    _terminal(monkeypatch)
    _answers(monkeypatch, "d", "s")
    cli.main(["scan", "--no-track", _config(home)])
    asked = capsys.readouterr().out

    assert asked == unasked


# ── nobody to ask: no prompt, exactly as today ───────────────────────────────────────────────────

NOBODY = {
    "stdin is not a terminal": dict(stdin=False),
    "stderr is not a terminal": dict(stderr=False),
    "--json": dict(argv=["--json"]),
    "--fleet-json": dict(argv=["--fleet-json"]),
    "--yes": dict(argv=["--yes"]),
    "CLAUDECODE set": dict(env={"CLAUDECODE": "1"}),
    "AI_AGENT set": dict(env={"AI_AGENT": "codex"}),
    "an agent process above us": dict(ancestry=["zsh", "claude", "-zsh", "login"]),
}


@pytest.mark.parametrize("case", list(NOBODY), ids=list(NOBODY))
def test_nobody_to_ask_means_no_prompt(home, capsys, monkeypatch, case):
    c = NOBODY[case]
    calls = _probe(monkeypatch)
    _terminal(monkeypatch, stdin=c.get("stdin", True), stderr=c.get("stderr", True))
    for k, v in (c.get("env") or {}).items():
        monkeypatch.setenv(k, v)
    if "ancestry" in c:
        monkeypatch.setattr(history, "_process_ancestry", lambda: list(c["ancestry"]))

    def never(prompt=""):
        raise AssertionError("asked a question with nobody there to answer it")

    monkeypatch.setattr(builtins, "input", never)

    rc = cli.main(["scan", *c.get("argv", []), _config(home)])

    out, err = capsys.readouterr()
    assert "What next?" not in err + out
    assert len(calls) == 1
    assert rc == 1, "a server that could not be scanned still exits 1"


def test_a_sign_in_wall_is_not_offered_a_retry(home, capsys, monkeypatch):
    """Trying again cannot fix a 401; the sign-in offer is what asks about those."""
    async def fake_probe(entry, name):
        return ServerSnapshot(name=name, transport="http", protocol_version=None,
                              error="authentication required", error_kind="auth-required")

    monkeypatch.setattr(cli, "probe", fake_probe)
    monkeypatch.setattr(cli, "_offer_batched_auth", lambda *a, **k: {})
    _terminal(monkeypatch)
    _answers(monkeypatch)

    cli.main(["scan", _config(home)])

    assert "What next?" not in capsys.readouterr().err


# ── the real path: real sockets, a real terminal ─────────────────────────────────────────────────

def _child_env(home) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in history.AGENT_ENV_MARKERS}
    env.update(HOME=str(home / "home"), MCPGAWK_NO_UPDATE_CHECK="1",
               MCPGAWK_HISTORY=str(home / "history.json"), MCPGAWK_TEST_ANCESTRY="")
    return env


def test_a_closed_port_with_no_terminal_exits_1_without_asking(home):
    url = f"http://127.0.0.1:{_free_port()}/mcp"
    r = subprocess.run([sys.executable, "-m", "mcpgawk", "scan", "--http", url],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                       env=_child_env(home))
    assert "What next?" not in r.stdout + r.stderr
    assert "nothing is listening" in r.stdout + r.stderr
    assert r.returncode == 1


def test_a_closed_port_in_a_real_terminal_asks_and_skip_exits_1(home):
    pty = pytest.importorskip("pty")      # POSIX only; a missing module must not stop collection
    url = f"http://127.0.0.1:{_free_port()}/mcp"
    master, slave = pty.openpty()
    proc = subprocess.Popen([sys.executable, "-m", "mcpgawk", "scan", "--no-track", "--http", url],
                            stdin=slave, stderr=slave, stdout=subprocess.PIPE,
                            env=_child_env(home), close_fds=True)
    os.close(slave)
    seen = b""

    def wait_for(token: bytes, times: int = 1, budget: float = 30) -> None:
        nonlocal seen
        end = time.time() + budget
        while seen.count(token) < times and time.time() < end:
            ready, _, _ = select.select([master], [], [], 0.5)
            if ready:
                try:
                    seen += os.read(master, 4096)
                except OSError:
                    break
        assert seen.count(token) >= times, seen.decode(errors="replace")

    try:
        wait_for(b"> ")
        assert b"could not scan" in seen and b"What next?" in seen
        assert url.encode() in seen, "an ad-hoc server is named by what was typed"
        os.write(master, b"d\n")
        wait_for(b"kind:")
        assert b"nothing-listening" in seen and b"error:" in seen
        wait_for(b"> ", times=2)
        os.write(master, b"s\n")
        out = proc.stdout.read().decode()
        rc = proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)
    assert "What next?" not in out, "the prompt went to the terminal on stderr, not stdout"
    assert rc == 1

    plain = subprocess.run([sys.executable, "-m", "mcpgawk", "scan", "--no-track", "--http", url],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                           env=_child_env(home))
    assert plain.stdout == out, "stdout must not change because a person was asked"


def test_try_again_reaches_a_real_server_that_started_in_between(home, capsys, monkeypatch):
    """The target changes between attempts: nothing listens on the first, a real MCP server
    answers on the second. Same command, same options — `--http` at the same URL."""
    port = _free_port()
    url = f"http://127.0.0.1:{port}/mcp"
    _terminal(monkeypatch)
    started: list[subprocess.Popen] = []

    def start_then_retry(prompt=""):
        if started:
            raise EOFError
        proc = subprocess.Popen([sys.executable, str(FIXTURE), "--port", str(port)],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        started.append(proc)
        ready = threading.Event()

        def read():
            for line in proc.stdout:
                if line.startswith("LISTENING"):
                    ready.set()
                    return

        threading.Thread(target=read, daemon=True).start()
        assert ready.wait(30), "fixture never reported LISTENING"
        return "r"

    monkeypatch.setattr(builtins, "input", start_then_retry)
    try:
        rc = cli.main(["scan", "--no-track", "--http", url])
    finally:
        for p in started:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    out, err = capsys.readouterr()
    assert started, "the first attempt must fail and ask"
    assert err.count("What next?") == 1
    assert "nothing is listening" not in out
    assert rc != 4
    assert "could not scan" not in out
