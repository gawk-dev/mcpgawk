"""`mcpgawk` with no arguments — the whole journey, one command.

WHY THIS EXISTS. Every protection in this product worked and none of them were ON. The author's
own machine, 2026-07-27: eleven MCP servers across six agents, the guard hook not installed, and
`mcpgawk scan` returning a wall of SKIPPED with zero findings. The capabilities were never the
problem; the user having to know `scan` then `approve` then `guard install` was.

So the front door does the whole thing: find the fleet, ask once, scan, let the baseline settle,
turn runtime checking on, and say plainly what is covered and what is not.

THREE RULES, each one a correction of something this product got wrong:

1. **Ask once, remember.** The consent decision is stored (`~/.mcpgawk/consent.json`, 0600). A
   security tool that re-interrogates you every run trains you to stop reading it.

2. **Say what will change BEFORE asking, and name the undo.** The rustup-init pattern. Modifying
   config that is not ours without disclosure is the thing clig.dev tells you not to do.

3. **Never let absence read as safety.** Servers that could not be checked are named with the
   reason, every run, beneath the findings — never folded into a coverage percentage and never
   silently dropped. "Nothing was found" and "nothing was looked at" must never render alike.

Idempotent by construction: re-running is how you check on things. The second run reports what
changed, not the whole world again.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from . import history, state

#: Where the fleet-launch decision is remembered. Beside the other local state, owner-only.
CONSENT_PATH = Path.home() / ".mcpgawk" / "consent.json"

#: Bumped when the QUESTION changes materially. A stored answer only carries forward while it is
#: an answer to the same question — silently reusing consent given for narrower terms would be
#: exactly the kind of quiet scope creep this product exists to catch elsewhere.
CONSENT_VERSION = 1

LAUNCH_ALL = "launch"
REMOTE_ONLY = "remote-only"


def load_consent() -> str | None:
    """The remembered fleet-launch decision, or None if never asked (or asked differently)."""
    try:
        data = json.loads(CONSENT_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != CONSENT_VERSION:
        return None
    choice = data.get("scan_local")
    return choice if choice in (LAUNCH_ALL, REMOTE_ONLY) else None


def save_consent(choice: str) -> None:
    """Remember the decision. A failure here is reported, never fatal: not being able to REMEMBER
    an answer must not stop us acting on the answer we were just given."""
    try:
        state.secure_dir(CONSENT_PATH.parent)
        CONSENT_PATH.write_text(
            json.dumps({"version": CONSENT_VERSION, "scan_local": choice}, indent=2),
            encoding="utf-8")
        state.harden(str(CONSENT_PATH))
    except OSError as exc:
        print(f"mcpgawk: couldn't save your choice ({exc}) — you'll be asked again next time.",
              file=sys.stderr)


def consent_prompt(local_count: int, agents: list[str]) -> str:
    """The one question, with full disclosure of what changes and how to undo it.

    The framing matters and is the honest one: these servers are ALREADY in your agent's config,
    which means that agent starts them every session. Scanning them runs the same code that
    already runs — it is not new exposure. Default-denying them (the old behaviour) protected
    nobody from anything and returned a wall of SKIPPED instead of findings.
    """
    where = ", ".join(agents) if agents else "your agents"
    return (
        f"\n  To check a local server I have to start it — the same way {where} already\n"
        f"  starts it every session. Scanning {local_count} of them runs code that already runs\n"
        f"  on this machine; it is not new exposure.\n"
        f"\n  What I will change:\n"
        f"    ~/.mcpgawk/            your approved baseline and this answer\n"
        f"    your agent settings    one hook that checks each MCP call (existing hooks kept)\n"
        f"  Undo any time:  mcpgawk guard uninstall\n"
        f"\n    [1] Check everything          (recommended — asked once, then remembered)\n"
        f"    [2] Remote servers only        (local servers stay unchecked)\n"
        f"\n  > "
    )


def ask_consent(local_count: int, agents: list[str], *,
                stdin_isatty: bool | None = None, ask=input, err=None) -> str | None:
    """Ask the one question. Returns the choice, or None when we cannot ask (non-interactive).

    Returning None rather than defaulting is deliberate: a non-interactive run must not INVENT a
    consent decision in either direction. The caller degrades to remote-only and says so, which is
    a stated limitation rather than a silent one.
    """
    err = sys.stderr if err is None else err
    isatty = sys.stdin.isatty() if stdin_isatty is None else stdin_isatty
    if not isatty:
        return None
    err.write(consent_prompt(local_count, agents))
    err.flush()
    try:
        reply = (ask() or "").strip().lower()
    except (EOFError, KeyboardInterrupt):
        err.write("\n")
        return None
    # Default (bare Enter) is the recommended option, matching what the prompt marks. Anything
    # unrecognised is NOT treated as agreement.
    if reply in ("", "1", "y", "yes"):
        return LAUNCH_ALL
    if reply in ("2", "n", "no"):
        return REMOTE_ONLY
    return None


def protection_report(store: dict[str, Any], guard_line: str,
                      unchecked: list[tuple[str, str]]) -> str:
    """What the user is left with: what is covered, what needs them, what was not checked.

    Ordered by what the reader must DO — a change waiting on a decision first, because that is the
    only part that is blocking, then the state of protection, then the honest coverage gaps. The
    'not checked' block is never omitted and never summarised into a number."""
    servers = store.get("servers") or {}
    waiting = history.pending(store)
    covered = [k for k in servers if k not in waiting]

    out: list[str] = [""]
    if waiting:
        out.append(f"  {len(waiting)} server(s) changed since you approved them — your agents are")
        out.append("  blocked from calling them until you decide:")
        for key in waiting:
            out.append(f"      {history.display_name(store, key)}")
        out.append("    See what moved:  mcpgawk scan")
        out.append("    Accept it:       mcpgawk approve <name>")
        out.append("")

    out.append(f"  Protected: {len(covered)} server(s) at their approved baseline.")
    out.append(f"  {guard_line}")

    if unchecked:
        out.append("")
        out.append(f"  Not checked ({len(unchecked)}) — absence of a finding here is not a clean bill:")
        for name, why in unchecked:
            out.append(f"      {name:<28} {why}")
    return "\n".join(out) + "\n"
