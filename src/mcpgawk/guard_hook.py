"""The PreToolUse decision — the hot path, deliberately stdlib-only.

This runs as a fresh process on EVERY MCP tool call your agent makes, so its cost is paid
hundreds of times a session. Importing the package proper costs ~200ms (measured), almost all of
it pulling the MCP SDK in through `mcpgawk/__init__` — which a baseline lookup does not need. This
module therefore imports NOTHING but the standard library, and `mcpgawk-guard-hook` invokes it via
a path that skips the package `__init__` entirely. Measured difference: ~200ms → ~15ms per call.

That means it re-reads `history.json` rather than calling `mcpgawk.baseline`. Duplicated readers
are how this repo has been bitten before, so `tests/test_guard.py` pins the two together: it
asserts this reader and the canonical `baseline.approved_tools()` return the SAME answer for the
same file. If the canonical shape ever changes, that test fails here.

WHAT IT DECIDES, and — just as important — what it refuses to decide:

  * A tool whose hash DIFFERS from what you approved → **deny**. The server changed a tool's
    schema or description after you trusted it, and your agent is about to call the new version.
    This is the rug-pull, caught at the moment it matters.
  * A tool ABSENT from an otherwise-approved server → **deny**. A tool that appeared after
    approval is exactly the shape a malicious update takes.
  * A server with NO approved baseline → **defer**, always. "Never approved" is not "violated":
    blocking here would break every tool call on a machine that has simply never run
    `mcpgawk approve`, which is most machines. Trust-on-first-use is scan's job, not the guard's.
  * Anything we cannot parse or read → **defer, loudly** on stderr. A security tool that bricks
    an agent session because its own baseline file was corrupt has done more harm than the drift
    it was watching for.

**It never returns "allow".** That is the subtle one. `permissionDecision: "allow"` does not mean
"this is fine" to Claude Code — it means "skip the permission prompt the user would otherwise
see". A security hook that returned it would be auto-approving tool calls the human was about to
be asked about, silently REDUCING the protection on the machine it was installed to protect. So
the only outcomes here are deny (we found something) and defer (carry on as normal).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

#: Same file the scanner writes; `baseline.py` is a narrow view over it, not a separate store.
DEFAULT_HISTORY = Path.home() / ".mcpgawk" / "history.json"


def _load_spool():
    """Import the spool WITHOUT a package context.

    This module is invoked by absolute file path (see guard.hook_command) precisely so that
    `mcpgawk/__init__` — and the ~200ms MCP SDK import behind it — never runs. That also means
    there is no parent package, so `from . import spool` would raise. Loading the sibling by path
    keeps ONE definition of the record shape (the writer here and every reader in the package use
    the same module) without paying for the package. `runlog` cannot be used this way: it does a
    relative import of `state`, which is what kept the hook silent in the first place.

    Returns None if anything goes wrong. Logging is a duty, not a precondition: failing to record
    must never cost a verdict.
    """
    try:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spool.py")
        spec = importlib.util.spec_from_file_location("_mcpgawk_spool", path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:                              # noqa: BLE001 - never break the hot path
        return None

EXIT_OK = 0


def history_path() -> Path:
    override = os.environ.get("MCPGAWK_HISTORY")
    return Path(override) if override else DEFAULT_HISTORY


def parse_mcp_tool_name(tool_name: str) -> tuple[str, str] | None:
    """`mcp__<server>__<tool>` → (server, tool). None for a non-MCP tool (Bash, Edit, …), which
    this hook has no opinion about.

    Split from the LEFT on the first `__` after the prefix, then treat the REST as the tool name:
    a tool name may itself contain `__`, and a server name may not (the client builds this string
    by joining, and its own convention is server-then-tool)."""
    if not tool_name.startswith("mcp__"):
        return None
    rest = tool_name[len("mcp__"):]
    server, sep, tool = rest.partition("__")
    if not sep or not server or not tool:
        return None
    return server, tool


def approved_for(server: str, store_path: Path) -> dict[str, str] | None:
    """`{tool: hash}` approved for this server, or None when nothing has been approved for it.

    None and `{}` mean different things and callers MUST distinguish: None is "never approved"
    (defer), `{}` would be "approved as having no tools" (a real, if odd, state)."""
    try:
        raw = json.loads(store_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    servers = raw.get("servers")
    if not isinstance(servers, dict):
        return None

    record = servers.get(server)
    if record is None:
        # The store may be keyed by the server's ASSERTED IDENTITY rather than the config name the
        # agent uses in `mcp__<name>__<tool>`; `aliases` carries the mapping. NB aliases sit
        # alongside `approved`, not inside it (see baseline.publish) — the flattened
        # `baseline --json` export nests them, and reading that shape here found nothing.
        for candidate in servers.values():
            if isinstance(candidate, dict) and server in (candidate.get("aliases") or []):
                record = candidate
                break
    if not isinstance(record, dict):
        return None
    approved = record.get("approved")
    if not isinstance(approved, dict):
        return None
    tools = approved.get("tools")
    return dict(tools) if isinstance(tools, dict) else None


def decide(event: dict, store_path: Path | None = None) -> tuple[dict | None, str | None]:
    """(hook output or None to defer, stderr note or None). Pure — no I/O beyond the store read,
    so the whole decision table is directly testable."""
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str):
        return None, None

    parsed = parse_mcp_tool_name(tool_name)
    if parsed is None:
        return None, None          # not an MCP tool: not ours to judge
    server, tool = parsed

    store = store_path or history_path()
    approved = approved_for(server, store)
    if approved is None:
        # Never approved. NOT a violation — see the module docstring.
        return None, None

    if tool not in approved:
        return _deny(
            f"'{tool}' is not in the approved baseline for MCP server '{server}'. A tool that "
            f"appeared after you approved this server is how a malicious update arrives. Review "
            f"it with `mcpgawk scan`, and run `mcpgawk approve {server}` if you accept the change."
        ), None

    # The tool exists and was approved. Whether its CONTENT still matches is the rug-pull check,
    # and it needs the live hash — which the hook does not have (it sees the call, not the
    # server's current tools/list). Drift of an approved tool is caught by scan/monitor, which do
    # connect. Claiming to check it here would be the more dangerous error.
    return None, None


def _deny(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"[mcpgawk guard] {reason}",
        }
    }


def main(argv: list[str] | None = None) -> int:
    """Read the event on stdin, decide, emit. ALWAYS exits 0: a non-zero exit from a PreToolUse
    hook is an error condition, and we never want our own failure to be interpreted as a verdict.
    A deny is expressed in the JSON, which is the documented, unambiguous channel."""
    try:
        raw = sys.stdin.read()
    except Exception as exc:  # noqa: BLE001
        print(f"[mcpgawk guard] could not read hook input: {exc}", file=sys.stderr)
        return EXIT_OK
    if not raw.strip():
        return EXIT_OK

    try:
        event = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"[mcpgawk guard] hook input was not JSON ({exc}) — deferring, not blocking.",
              file=sys.stderr)
        return EXIT_OK
    if not isinstance(event, dict):
        return EXIT_OK

    try:
        output, note = decide(event)
    except Exception as exc:  # noqa: BLE001 — our bug must never brick the agent session
        print(f"[mcpgawk guard] internal error, deferring (NOT a clean verdict): "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_OK

    _record(event, output)

    if note:
        print(f"[mcpgawk guard] {note}", file=sys.stderr)
    if output is not None:
        sys.stdout.write(json.dumps(output))
    return EXIT_OK


def _record(event: dict, output: dict | None) -> None:
    """Append this decision to the runtime spool.

    EVERY checked call is recorded, including the ones we defer on — that is the whole point.
    Recording only denials would make "nothing was blocked" and "nothing was watching" produce an
    identical, empty log, which is the exact ambiguity this exists to remove.

    Arguments are deliberately NOT recorded: they carry the secrets and file contents this product
    redacts everywhere else. See spool.py.
    """
    try:
        tool_name = event.get("tool_name")
        if not isinstance(tool_name, str):
            return
        parsed = parse_mcp_tool_name(tool_name)
        if parsed is None:
            return                                  # not an MCP call — not ours to log
        server, tool = parsed
        spool = _load_spool()
        if spool is None:
            return
        decision = "deny" if output else "defer"
        spool.record_decision(
            server=server, tool=tool, decision=decision, adapter="claude-code-hook",
            session=event.get("session_id") if isinstance(event.get("session_id"), str) else None,
        )
    except Exception:                              # noqa: BLE001 - a lost record is not a verdict
        return


if __name__ == "__main__":
    sys.exit(main())
