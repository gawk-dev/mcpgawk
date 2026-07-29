"""The PreToolUse decision — the hot path, deliberately stdlib-only.

This runs as a fresh process on EVERY MCP tool call your agent makes, so its cost is paid
hundreds of times a session. Importing the package proper costs ~200ms (measured), almost all of
it pulling the MCP SDK in through `mcpgawk/__init__` — which a baseline lookup does not need. This
module therefore imports NOTHING but the standard library, and `mcpgawk-guard-hook` invokes it via
a path that skips the package `__init__` entirely. Measured difference: ~200ms → ~15ms per call.

That means it cannot call `mcpgawk.baseline`. Instead of holding a second reader of
`history.json` (duplicated readers are how this repo has been bitten before), it reads the flat
PROJECTION (`guard-baseline.json`) that `history.save` — the canonical writer — regenerates on
every store write. The projection carries the stat of the store it was derived from; if the two
disagree the projection is stale and this hook DEFERS, loudly, rather than enforce a surface that
may no longer be the approved one (see `_approved_from_projection`).

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


def _load_sibling(name: str):
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
        cached = sys.modules.get(f"_mcpgawk_{name}")
        if cached is not None:
            return cached
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{name}.py")
        spec = importlib.util.spec_from_file_location(f"_mcpgawk_{name}", path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        # REGISTER BEFORE EXEC. A @dataclass resolves its annotations through
        # sys.modules[cls.__module__]; if the module is not registered that lookup returns None and
        # exec_module dies with a bare AttributeError. The spool loader survived without this only
        # because it declares no dataclass — so the omission was invisible until agents.py did.
        # Caught by running the real hook per format, not by importing the package in a test.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    except Exception:                              # noqa: BLE001 - never break the hot path
        return None

EXIT_OK = 0
#: Agents where a non-zero exit MEANS deny. Deliberately NOT Claude Code: there a non-zero exit is
#: an ERROR condition, and this hook's founding rule is that our own failure must never be read as
#: a verdict. Cursor is the opposite case — it ALLOWS the call when a hook errors (unless
#: failClosed), so for Cursor a hard exit-2 alongside the JSON is the safer belt-and-braces.
EXIT_DENY = 2
DENY_BY_EXIT = {"cursor", "codex", "kimi", "gemini", "windsurf"}


def history_path() -> Path:
    override = os.environ.get("MCPGAWK_HISTORY")
    return Path(override) if override else DEFAULT_HISTORY


#: The behavioural profile verify writes — the SAME shared path the TS producer and the paid
#: gateway use (pinned by tests/test_behaviour_default.py). Free since Task 0's answer.
DEFAULT_BEHAVIOUR = Path.home() / ".gawk" / "behaviour.json"


def behaviour_path() -> Path:
    override = os.environ.get("GAWK_BEHAVIOUR")
    return Path(override) if override else DEFAULT_BEHAVIOUR


def _load_behaviour() -> dict | None:
    """`{server: {tool: {"source"?, "sink"?}}}` or None when no profile exists or it is
    unreadable. None means the behavioural TIER is absent — never that anything is safe; the
    verdict then rests on the declared basis alone, and B5 makes the absence loud elsewhere."""
    try:
        raw = json.loads(behaviour_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    servers = raw.get("servers") if isinstance(raw, dict) else None
    return servers if isinstance(servers, dict) else None


def _session_sources(session: str | None, behaviour: dict) -> tuple[tuple[str, str], ...]:
    """`(server, tool)` calls recorded EARLIER THIS SESSION whose own observations classify them
    as sources — the spool is the hook's session memory. Chronological order; empty on any
    failure (a lost memory weakens the behavioural tier, it never invents a deny)."""
    if not session:
        return ()
    spool = _load_sibling("spool")
    if spool is None:
        return ()
    try:
        # Session-SCOPED read: a global row budget would let a busy parallel session evict this
        # session's earlier source calls and the sequence check would fade out under load.
        # hasattr because the hook loads spool by file path — pair mismatches must degrade, not die.
        if hasattr(spool, "read_session"):
            rows = spool.read_session(session)       # most recent first, session-bounded
        else:
            rows = spool.read()                      # most recent first, globally bounded
    except Exception:  # noqa: BLE001 — never break the hot path over its own memory
        return ()
    out: list[tuple[str, str]] = []
    for row in reversed(rows):
        if not isinstance(row, dict) or row.get("session") != session:
            continue
        srv, tool = row.get("server"), row.get("tool")
        if not isinstance(srv, str) or not isinstance(tool, str):
            continue
        if (behaviour.get(srv) or {}).get(tool, {}).get("source") is True:
            out.append((srv, tool))
    return tuple(out)


def _session_id(event: dict) -> str | None:
    """The session identity, tolerantly. Every hooked agent puts `session_id` at top level today,
    but session memory silently dying because one agent renames or camel-cases the key is the
    kind of quiet failure this hook is not allowed to have — so the common variants are accepted,
    and a missing identity stays None (counted and reported by `status`, never guessed)."""
    for key in ("session_id", "sessionId"):
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    return None


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


#: Kept in lockstep with history.PROJECTION_NAME — this module cannot import the package (see the
#: module docstring), so the name is repeated here and pinned by tests/test_guard.py.
PROJECTION_NAME = "guard-baseline.json"


def projection_path(store_path: Path) -> Path:
    """The projection always sits BESIDE the history file it was derived from, so an
    MCPGAWK_HISTORY override relocates both together."""
    return store_path.parent / PROJECTION_NAME


def approved_for(server: str, store_path: Path) -> dict[str, str] | None:
    """`{tool: hash}` approved for this server, or None when nothing has been approved for it.

    None and `{}` mean different things and callers MUST distinguish: None is "never approved"
    (defer), `{}` would be "approved as having no tools" (a real, if odd, state)."""
    approved, _note = _approved_from_projection(server, store_path)
    return approved


def _approved_from_projection(server: str,
                              store_path: Path) -> tuple[dict[str, str] | None, str | None]:
    """Read the approved surface from the PROJECTION the canonical writer generated — never from
    `history.json` itself. This hook used to hold its own second reader of the store, kept honest
    only by a test; now it consumes an artefact `history.save` produced, so the two cannot drift.

    Returns `(approved, note)`. A missing, unreadable or STALE projection yields `(None, note)` —
    the hook DEFERS, never enforces yesterday's baseline, and the note goes to stderr so the
    degraded state is loud rather than silently unprotected. Silent None (no note) only when the
    history store does not exist either: that is a fresh machine, not a failure."""
    proj = projection_path(store_path)
    try:
        history_stat = os.stat(store_path)
    except OSError:
        history_stat = None

    try:
        raw = json.loads(proj.read_text(encoding="utf-8"))
    except OSError:
        if history_stat is None:
            return None, None                       # fresh machine: nothing approved, nothing odd
        return None, ("no guard projection found beside the baseline store — deferring (not "
                      "enforcing). Run `mcpgawk scan` to regenerate it.")
    except (json.JSONDecodeError, ValueError):
        return None, ("the guard projection is not readable JSON — deferring (not enforcing). "
                      "Run `mcpgawk scan` to regenerate it.")
    if not isinstance(raw, dict):
        return None, ("the guard projection has an unexpected shape — deferring (not enforcing). "
                      "Run `mcpgawk scan` to regenerate it.")

    # THE STALENESS CHECK. The projection carries the stat of the history file it was derived
    # from; a mismatch means the store was written by something that did not regenerate the
    # projection, and enforcing a surface that may no longer be the approved one is the more
    # dangerous error. Defer, loudly — never allow, never enforce stale state.
    source = raw.get("source")
    fresh = (history_stat is not None and isinstance(source, dict)
             and source.get("mtime_ns") == history_stat.st_mtime_ns
             and source.get("size") == history_stat.st_size)
    if not fresh:
        return None, ("the guard projection is STALE (the baseline store changed without "
                      "regenerating it) — deferring (not enforcing). Run `mcpgawk scan` to "
                      "regenerate it.")

    servers = raw.get("servers")
    if not isinstance(servers, dict):
        return None, None
    record = servers.get(server)
    if record is None:
        # The projection may be keyed by the server's ASSERTED IDENTITY rather than the config
        # name the agent uses in `mcp__<name>__<tool>`; `aliases` carries the mapping.
        for candidate in servers.values():
            if isinstance(candidate, dict) and server in (candidate.get("aliases") or []):
                record = candidate
                break
    if not isinstance(record, dict):
        return None, None
    tools = record.get("tools")
    return (dict(tools) if isinstance(tools, dict) else None), None


def decide(event: dict, store_path: Path | None = None,
           fmt: str = "claude") -> tuple[dict | None, str | None]:
    """(hook output or None to defer, stderr note or None)."""
    output, note, _basis = _decide(event, store_path, fmt)
    return output, note


def _decide(event: dict, store_path: Path | None,
            fmt: str) -> tuple[dict | None, str | None, str]:
    """The full decision including WHICH BASIS produced it, so the record carries the evidence
    tier (declared vs observed) — an operator cannot calibrate trust in a deny without it."""
    tool_name, _args = _read_event(fmt, event)
    if not isinstance(tool_name, str):
        return None, None, "declared"

    parsed = parse_mcp_tool_name(tool_name)
    if parsed is None:
        return None, None, "declared"   # not an MCP tool: not ours to judge
    server, tool = parsed

    store = store_path or history_path()
    approved, note = _approved_from_projection(server, store)

    # The verdict itself comes from the shared decision core — the paid gateway evaluates the SAME
    # functions, so the paths cannot drift apart. If the core cannot be loaded we cannot compute a
    # verdict, and "we found nothing" is defer, not deny.
    core = _load_sibling("decision")
    if core is None:
        return None, note, "declared"

    # The behavioural tier (free since Task 0): observations verify recorded for THIS server,
    # plus this session's earlier observed-source calls from the spool. Both are gathered only
    # when they can matter — an observed sink is what makes the sequence check worth reading the
    # session memory for.
    behaviour = _load_behaviour()
    observations = behaviour.get(server) if behaviour else None
    if not isinstance(observations, dict):
        observations = None
    sources: tuple[tuple[str, str], ...] = ()
    if behaviour and observations and (observations.get(tool) or {}).get("sink") is True:
        sources = _session_sources(_session_id(event), behaviour)

    verdict, basis, reason = core.verdict(server, tool, approved, observations, sources)
    if verdict == core.DENY:
        return _deny(fmt, reason), note, basis
    return None, note, basis


def _read_event(fmt: str, event: dict) -> tuple[str | None, dict]:
    """Pull (tool name, arguments) out of whichever agent's payload this is. Loaded the same
    package-free way as the spool: this file runs by absolute path with no parent package."""
    mod = _load_sibling("agents")
    if mod is None:
        name = event.get("tool_name")
        return (name if isinstance(name, str) else None), {}
    return mod.parse_event(fmt, event)


def _deny(fmt: str, reason: str) -> dict:
    """This agent's own deny shape. Claude Code and Codex take `permissionDecision`; Cursor takes
    `{"permission": "deny"}` with snake_case messages. Emitting the wrong one reads as a
    MALFORMED hook, and on Cursor a malformed hook ALLOWS the call unless failClosed is set — so
    getting this right per agent is a security property, not formatting."""
    text = f"[mcpgawk guard] {reason}"
    mod = _load_sibling("agents")
    if mod is None:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "permissionDecision": "deny",
                                       "permissionDecisionReason": text}}
    return mod.deny_payload(fmt, text)


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

    # Which agent are we speaking to? Passed by the installed command, defaulting to Claude Code
    # so an older config that predates --format keeps working unchanged.
    argv = list(sys.argv[1:] if argv is None else argv)
    fmt = "claude"
    if "--format" in argv:
        i = argv.index("--format")
        if i + 1 < len(argv):
            fmt = argv[i + 1]

    try:
        output, note, basis = _decide(event, None, fmt)
    except Exception as exc:  # noqa: BLE001 — our bug must never brick the agent session
        print(f"[mcpgawk guard] internal error, deferring (NOT a clean verdict): "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_OK

    _record(event, output, fmt, basis)

    if note:
        print(f"[mcpgawk guard] {note}", file=sys.stderr)
    if output is not None:
        sys.stdout.write(json.dumps(output))
        return EXIT_DENY if fmt in DENY_BY_EXIT else EXIT_OK
    return EXIT_OK


def _record(event: dict, output: dict | None, fmt: str = "claude",
            basis: str = "declared") -> None:
    """Append this decision to the runtime spool.

    EVERY checked call is recorded, including the ones we defer on — that is the whole point.
    Recording only denials would make "nothing was blocked" and "nothing was watching" produce an
    identical, empty log, which is the exact ambiguity this exists to remove.

    The event is read through the SAME adapter `decide` used — the log must name the agent that
    made the call, and a Cursor payload read as if it were Claude Code records the wrong thing.

    Arguments are deliberately NOT recorded: they carry the secrets and file contents this product
    redacts everywhere else. See spool.py.
    """
    try:
        agents = _load_sibling("agents")
        if agents is not None:
            tool_name, _args = agents.parse_event(fmt, event)
            adapter = next((a.key for a in agents.ADAPTERS.values() if a.fmt == fmt), fmt)
        else:
            raw = event.get("tool_name")
            tool_name = raw if isinstance(raw, str) else None
            adapter = fmt
        if not isinstance(tool_name, str):
            return
        parsed = parse_mcp_tool_name(tool_name)
        if parsed is None:
            return                                  # not an MCP call — not ours to log
        server, tool = parsed
        spool = _load_sibling("spool")
        if spool is None:
            return
        decision = "deny" if output else "defer"
        spool.record_decision(
            server=server, tool=tool, decision=decision, adapter=adapter, basis=basis,
            session=_session_id(event),
        )
    except Exception:                              # noqa: BLE001 - a lost record is not a verdict
        return


if __name__ == "__main__":
    sys.exit(main())
