"""`mcpgawk` (bare) — the front door, and the consent decision behind it.

The consent logic decides whether this tool LAUNCHES other people's code on the user's machine, so
it is security-relevant in the strict sense and gets the same treatment as a gate:

  * a non-interactive run never INVENTS a decision in either direction;
  * an unrecognised answer is never treated as agreement;
  * a stored answer only carries forward while it answers the SAME question (versioned), because
    silently reusing consent given on narrower terms is the quiet scope creep this product exists
    to catch elsewhere;
  * the prompt discloses every file that changes and names the undo BEFORE asking (rustup-init).
"""
from __future__ import annotations

import json

from mcpgawk import protect


# --- what the user is told before being asked ------------------------------------------------- #

def test_the_prompt_discloses_what_changes_and_how_to_undo_it():
    text = protect.consent_prompt(8, ["Claude Code", "Cursor"])
    assert "~/.mcpgawk/" in text and "agent settings" in text, "files being changed are not named"
    assert "mcpgawk guard uninstall" in text, "the undo command is not offered before consenting"
    assert "8" in text, "the number of servers affected is not stated"


def test_the_prompt_states_the_honest_reason_scanning_is_not_new_exposure():
    """The framing IS the argument: these servers are already in the agent's config, so the agent
    starts them every session. Default-denying them protected nobody and returned a wall of
    SKIPPED instead of findings."""
    # Normalised: the property is what the sentence SAYS, not where the line happens to wrap.
    text = " ".join(protect.consent_prompt(3, ["Claude Code"]).split())
    assert "already starts it every session" in text
    assert "not new exposure" in text


# --- the decision ------------------------------------------------------------------------------ #

def test_a_non_interactive_run_never_invents_a_decision():
    """Returning None (not a default) is the point: the caller then degrades to remote-only and
    SAYS so, which is a stated limitation rather than a silent one."""
    assert protect.ask_consent(4, [], stdin_isatty=False, ask=lambda: "1") is None


def test_enter_takes_the_recommended_option_the_prompt_marks():
    assert protect.ask_consent(4, [], stdin_isatty=True, ask=lambda: "") == protect.LAUNCH_ALL
    assert protect.ask_consent(4, [], stdin_isatty=True, ask=lambda: "1") == protect.LAUNCH_ALL


def test_declining_is_honoured():
    assert protect.ask_consent(4, [], stdin_isatty=True, ask=lambda: "2") == protect.REMOTE_ONLY
    assert protect.ask_consent(4, [], stdin_isatty=True, ask=lambda: "n") == protect.REMOTE_ONLY


def test_an_unrecognised_answer_is_not_agreement():
    """Anything we cannot read must not authorise launching code. The same default-deny rule the
    batched-auth prompt already follows."""
    for reply in ("maybe", "3", "yes please", "¯\\_(ツ)_/¯"):
        assert protect.ask_consent(4, [], stdin_isatty=True, ask=lambda r=reply: r) is None


def test_eof_or_interrupt_is_not_agreement():
    def boom():
        raise EOFError

    assert protect.ask_consent(4, [], stdin_isatty=True, ask=boom) is None


# --- remembering it ----------------------------------------------------------------------------- #

def test_a_saved_answer_is_remembered(tmp_path, monkeypatch):
    monkeypatch.setattr(protect, "CONSENT_PATH", tmp_path / "consent.json")
    protect.save_consent(protect.LAUNCH_ALL)
    assert protect.load_consent() == protect.LAUNCH_ALL


def test_an_answer_to_a_DIFFERENT_question_is_not_reused(tmp_path, monkeypatch):
    """Bumping CONSENT_VERSION must invalidate stored consent. A tool that carries forward an old
    'yes' after materially changing what it asks for is doing the thing we warn users about."""
    path = tmp_path / "consent.json"
    monkeypatch.setattr(protect, "CONSENT_PATH", path)
    path.write_text(json.dumps({"version": protect.CONSENT_VERSION - 1,
                                "scan_local": protect.LAUNCH_ALL}), encoding="utf-8")
    assert protect.load_consent() is None


def test_a_corrupt_or_unknown_consent_file_reads_as_never_asked(tmp_path, monkeypatch):
    path = tmp_path / "consent.json"
    monkeypatch.setattr(protect, "CONSENT_PATH", path)
    for content in ("{not json", json.dumps({"version": protect.CONSENT_VERSION,
                                             "scan_local": "something-else"}), "[]"):
        path.write_text(content, encoding="utf-8")
        assert protect.load_consent() is None, f"{content!r} was accepted as a decision"


def test_the_consent_file_is_owner_only(tmp_path, monkeypatch):
    path = tmp_path / "consent.json"
    monkeypatch.setattr(protect, "CONSENT_PATH", path)
    protect.save_consent(protect.REMOTE_ONLY)
    assert (path.stat().st_mode & 0o077) == 0, "consent state is readable by other local accounts"


# --- the report -------------------------------------------------------------------------------- #

def test_unchecked_servers_are_never_omitted_from_the_report():
    """Absence of a finding must never read as a clean bill of health."""
    out = protect.protection_report({"servers": {}}, "guard on",
                                    unchecked=[("figma", "needs credentials")])
    assert "Not checked" in out and "figma" in out and "needs credentials" in out


def test_servers_awaiting_a_decision_are_reported_first():
    store = {"servers": {"a": {"approved": {}}, "b": {"approved": {}, "latest": {"x": 1}}}}
    out = protect.protection_report(store, "guard on", unchecked=[])
    assert "Protected:" in out
