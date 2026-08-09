"""The first sixty seconds — what a brand-new user sees.

Written after running the actual new-user path on a clean machine (fresh install, empty HOME, two
MCP servers configured in an agent config) rather than reasoning about it. Two things that would
put a first-time user off turned up immediately, and neither was visible from any existing test:

  * the SERVER's stderr flooded the report — npm deprecation warnings and a "new version of npm
    available" notice in the middle of a security tool's output, which reads as broken;
  * the front door asked the launch question, the user answered, and then the scan underneath
    re-announced the same warning — which reads as though the answer was ignored, and undermines
    the "asked once, then remembered" promise the prompt makes.
"""
from __future__ import annotations

import asyncio

from mcpgawk import consent
from mcpgawk.probe import _stderr_tail, probe_stdio


class _Err:
    def __init__(self) -> None:
        self.text = ""

    def write(self, s: str) -> None:
        self.text += s

    def flush(self) -> None:
        pass


# --- the server's noise stays out of our report ------------------------------------------------ #

def test_a_healthy_servers_chatter_never_reaches_the_user(capfd):
    """A server that starts fine but prints to stderr (npm does, constantly) must not appear in
    our output. Asserted on the REAL captured streams, since the leak was through the child
    process rather than through anything Python printed."""
    snap = asyncio.run(probe_stdio(
        "noisy", "sh", ["-c", "echo 'npm warn deprecated glob@10.5.0' >&2; sleep 0.2"], timeout=10))
    out, err = capfd.readouterr()
    assert "npm warn" not in out and "npm warn" not in err, (
        "the server's stderr reached the user's terminal")
    assert snap.error, "this fixture is not an MCP server; it should still fail cleanly"


def test_the_failure_reason_is_captured_even_though_it_is_not_yet_displayed(tmp_path):
    """probe captures what the server said, so a config pointing at a deleted file has a real
    diagnosis available. Displaying it is deliberately NOT done yet (see fleet.state_of): redact()
    mangles ordinary paths. This pins the capture so that work has something to build on."""
    snap = asyncio.run(probe_stdio("gone", "python3", ["/nonexistent/server.py"], timeout=10))
    assert snap.error
    assert "the server said:" in snap.error, "the server's own explanation was discarded"


def test_stderr_tail_drops_package_manager_notices():
    import tempfile

    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as fh:
        fh.write("npm notice New minor version of npm available!\nreal failure here\n"
                 "npm notice To update run: npm install -g npm\n")
        assert _stderr_tail(fh) == "real failure here"


def test_stderr_tail_is_empty_when_the_server_said_nothing():
    import tempfile

    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as fh:
        fh.write("\n   \n")
        assert _stderr_tail(fh) == ""


# --- asked once means asked once ---------------------------------------------------------------- #

def test_the_scan_does_not_re_ask_after_the_front_door_asked(monkeypatch):
    """The front door asks with fuller disclosure and remembers. Re-announcing underneath made a
    first run ask, get an answer, and immediately restate the warning."""
    monkeypatch.setenv(consent.CONSENT_GIVEN_ENV, "1")
    err = _Err()
    targets = [("local", {"command": "npx", "args": ["-y", "srv"]})]
    approved = consent.gate_stdio_consent(targets, assume_yes=True, err=err)
    assert len(approved) == 1, "consent already given must still launch"
    assert err.text == "", f"the scan re-announced after the front door asked: {err.text!r}"


def test_without_that_signal_the_scan_still_announces(monkeypatch):
    """The suppression must never become a silent way to launch code unannounced."""
    monkeypatch.delenv(consent.CONSENT_GIVEN_ENV, raising=False)
    err = _Err()
    consent.gate_stdio_consent([("local", {"command": "npx", "args": ["-y", "srv"]})],
                               assume_yes=True, err=err)
    assert "would be LAUNCHED" in err.text


def test_the_signal_alone_never_authorises_a_launch(monkeypatch):
    """It is honoured only TOGETHER with an explicit yes. On its own it must not turn a
    default-deny run into a launching one — otherwise a stray env var silently grants consent."""
    monkeypatch.setenv(consent.CONSENT_GIVEN_ENV, "1")
    err = _Err()
    approved = consent.gate_stdio_consent(
        [("local", {"command": "npx", "args": ["-y", "srv"]}),
         ("remote", {"url": "https://example.com/mcp"})],
        assume_yes=False, stdin_isatty=False, err=err)
    assert [n for n, _ in approved] == ["remote"], "a local server was launched without consent"


# --- B5: honest degradation when the machine cannot run behavioural checking ------------------- #
#
# The same failure class as the Windsurf adapter that installed cleanly and checked nothing:
# a machine without Node or Docker CANNOT run the free behavioural tier, and quietly falling back
# to name-only checks would let the narrower guarantee wear the stronger one's clothes. These pin
# that the degradation is said out loud, names the missing dependency, and never offers a dead
# command.

def _no_node(monkeypatch):
    import shutil as _sh

    from mcpgawk import capability

    real_which = _sh.which
    monkeypatch.setattr(capability.shutil, "which",
                        lambda name: None if name in ("node", "docker") else real_which(name))


def test_degraded_machine_status_says_behavioural_checking_is_unavailable(monkeypatch, tmp_path):
    from mcpgawk.status import collect_and_render

    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    _no_node(monkeypatch)
    out = collect_and_render()
    assert "UNAVAILABLE" in out
    assert "Node.js" in out and "container runtime" in out, "the WHY must be named"
    assert "DECLARED surface only" in out, "the weaker remaining guarantee must be stated"
    assert "mcpgawk verify" not in out, \
        "a dead command was offered — verify cannot run on this machine"


def test_degraded_machine_scan_carries_the_same_line(monkeypatch, tmp_path, capsys):
    from mcpgawk import cli
    from mcpgawk.probe import ServerSnapshot

    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    _no_node(monkeypatch)

    async def fake_probe(name, command, args=None, env=None, timeout=90.0):
        return ServerSnapshot(name="notes", transport="stdio", protocol_version="2025-06-18",
                              tools=[{"name": "read_note", "description": "reads a note"}])

    monkeypatch.setattr(cli, "probe_stdio", fake_probe)
    cli.main(["scan", "--stdio", "python fake"])
    out = capsys.readouterr().out
    assert "UNAVAILABLE" in out and "Node.js" in out


def test_degradation_never_reads_as_a_silent_name_only_fallback(monkeypatch, tmp_path):
    """THE pin. Wherever the degraded machine's status describes name-only checking, the
    unavailability is stated FIRST — the narrow posture must never appear as if it were the
    product working as designed."""
    from mcpgawk.status import collect_and_render

    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    _no_node(monkeypatch)
    out = collect_and_render()
    name_only_at = out.find("NAME only")
    unavailable_at = out.find("UNAVAILABLE")
    assert unavailable_at != -1
    assert name_only_at == -1 or unavailable_at < name_only_at


def test_a_capable_machine_is_not_nagged_about_degradation(monkeypatch, tmp_path):
    import shutil as _sh

    from mcpgawk import capability
    from mcpgawk.status import collect_and_render

    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    real_which = _sh.which
    monkeypatch.setattr(capability.shutil, "which",
                        lambda name: "/usr/bin/fake" if name in ("node", "docker")
                        else real_which(name))
    out = collect_and_render()
    assert "UNAVAILABLE" not in out
