"""The runtime evidence spool — every decision the agent hook makes, appended.

WHY. The hook inspects EVERY MCP tool call a developer's agent makes, and recorded none of them:
it wrote the verdict back to the agent and forgot. So the two questions a monitored system must
answer — "what did my agent do today" and "was anything denied while I wasn't watching" — had no
source of truth, and *"nothing was blocked" was indistinguishable from "nothing was watching"*.
Runtime verification without logging is half a control.

THREE CONSTRAINTS, all load-bearing:

1. **Stdlib only, no relative imports.** The hook is invoked by absolute FILE PATH so it never
   executes `mcpgawk/__init__` (which pulls the MCP SDK: ~200ms, versus a ~17ms budget for the
   whole call). A module with `from . import x` cannot be loaded that way at all — which is
   exactly why the hook could not use `runlog`. This file is importable BOTH ways: normally by the
   package, and by path from the hook.

2. **Append, never a database.** Measured on this machine: JSONL append 0.027 ms; sqlite
   connect+insert+close 0.306 ms plus a 1.19 ms import, plus write serialisation between parallel
   agent sessions. An `O_APPEND` write of a record this size is atomic on POSIX (far below
   PIPE_BUF), so concurrent agents interleave lines safely with no locking.

3. **Metadata, never payloads.** Tool ARGUMENTS are not written here. They routinely contain the
   secrets, file contents and personal data this product redacts everywhere else; a security tool
   whose own log becomes the richest target on the machine has failed at its own premise. We
   record which tool was called and what was decided — enough to answer both questions above, and
   enough for session-scoped sequence checks, without becoming a payload archive.

WHAT THIS IS NOT: tamper-evident. An append-only file with no chain is a RECORD, not evidence — a
local user can rewrite it. Only the portion folded into the hash-chained audit log (enforce's
`audit.py`) may be described as evidence, and only up to its last off-box anchor.
"""
from __future__ import annotations

import json
import os
import time

#: Beside the other local state. Overridable for tests and for users who relocate their state.
DEFAULT_SPOOL = os.path.join(os.path.expanduser("~"), ".mcpgawk", "calls.jsonl")

#: Rotate at ~5 MB (roughly 50k calls). Checked with a single `stat` on append — microseconds
#: against a 17 ms budget — because a spool that grows without bound eventually fills a laptop, and
#: discovering that during an incident is the worst possible time.
MAX_BYTES = 5 * 1024 * 1024

SPOOL_ENV = "MCPGAWK_SPOOL"

#: Fields whose values we choose from a closed vocabulary, so no server can reach them.
_VERBATIM_FIELDS = frozenset({"ts", "decision", "basis", "adapter"})

#: Cached (redact, redact_ident). See `_redactor`.
_REDACTOR: tuple | None = None


def spool_path() -> str:
    return os.environ.get(SPOOL_ENV) or DEFAULT_SPOOL


def _rotate_if_large(path: str) -> None:
    """Keep one previous generation. Best-effort: rotation failing must never cost a record."""
    try:
        if os.path.getsize(path) < MAX_BYTES:
            return
        os.replace(path, path + ".1")
    except OSError:
        pass


def _redactor():
    """The redaction functions, loadable BOTH as a package module and as a bare file.

    `guard_hook` imports this module by absolute path with no parent package (so that importing
    `mcpgawk/__init__` — and the MCP SDK behind it — never happens in a PreToolUse hook). In that
    context `from .redact import …` raises ImportError, the hook swallows it, and the spool goes
    silent: exactly the failure `_load_sibling`'s own docstring records for `runlog`, and exactly
    what this gate did on its first attempt before it was driven through the real hook.

    So: relative import when there is a package, sibling-by-path when there is not. Cached, because
    a PreToolUse hook runs on every single tool call.
    """
    global _REDACTOR
    if _REDACTOR is not None:
        return _REDACTOR
    try:
        from .redact import redact, redact_ident
    except ImportError:                            # no package context — the hook's path
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_mcpgawk_redact", os.path.join(os.path.dirname(os.path.abspath(__file__)), "redact.py"))
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        redact, redact_ident = module.redact, module.redact_ident
    _REDACTOR = (redact, redact_ident)
    return _REDACTOR


def _redacted(record: dict) -> dict:
    """Mask credential shapes in one spool record, on the way to disk. Returns a NEW dict.

    The spool's `server` and `tool` come straight off the agent's hook event — `mcp__<server>__<tool>`
    — so they are SERVER-CONTROLLED, exactly like the item keys that were writing credentials into
    `history.json` until 2026-08-13. Measured here rather than assumed: driving the real hook with
    a credential-shaped tool name wrote it to `spool.jsonl` verbatim, and so did the server name,
    which had been predicted clean on the theory that the name is normalised. It is not; the hook
    copies what the event carries.

    `redact_ident` needs an assignment shape to fire, so ordinary names (`create_api_key`,
    `get_token_count`) are untouched — the log stays readable, which is the point of a log. The
    closed-vocabulary fields (`decision`, `basis`, `adapter`, `ts`) are never rewritten.

    A NEW dict, not in place: the caller may still be using the record (the hook logs its own
    decision after building it), and a logger must not mutate its caller's data.
    """
    loaded = _redactor()
    if loaded is None:
        # Neither write the raw value (that is the leak) nor drop the record (that would make
        # "nothing was watching" indistinguishable from "nothing was blocked" — the ambiguity this
        # spool exists to remove). Keep the event, lose only the fields we cannot vouch for.
        return {k: (v if k in _VERBATIM_FIELDS or not isinstance(v, str) else "[unredactable]")
                for k, v in record.items()}
    redact, redact_ident = loaded
    out = {}
    for key, value in record.items():
        if not isinstance(value, str) or key in _VERBATIM_FIELDS:
            out[key] = value
        elif key == "reason":
            out[key] = redact(value) or value      # free prose, written by us but not fixed text
        else:
            out[key] = redact_ident(value)
    return out


def append(record: dict, path: str | None = None) -> bool:
    """Append one decision. Returns True if written.

    NEVER raises. This runs inside a PreToolUse hook: an exception here would surface as a broken
    hook on a developer's tool call, and a security tool that breaks the agent session it is
    protecting has done more harm than the drift it was watching for. The same rule the hook's own
    decision path already follows.
    """
    target = path or spool_path()
    try:
        directory = os.path.dirname(target)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        _rotate_if_large(target)
        line = json.dumps(_redacted(record), separators=(",", ":"), default=str) + "\n"
        # O_APPEND makes the write atomic for a record this size, so two agent sessions writing
        # concurrently interleave whole lines rather than corrupting each other. Opened per call
        # on purpose: the hook is a fresh process, so there is no handle worth keeping.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
        return True
    except Exception as exc:                       # noqa: BLE001 - see docstring: never raise
        # Recorder self-evidence: a spool that drops records silently makes an internal-error
        # storm indistinguishable from an idle machine — the exact confusion this file's own
        # docstring exists to prevent, applied to the recorder itself. Best-effort by nature:
        # if even the sidecar cannot be written, the failure really is environmental.
        note_failure(f"{type(exc).__name__}: {exc}", path=target)
        return False


#: Sidecar beside the spool: the recorder's own last failure. One line, overwritten — this is a
#: health signal ("the row count may be incomplete since <ts>"), not a second log to rotate.
ERR_SUFFIX = ".err"


def _redact_text(value: str) -> str:
    """Prose redaction for the recorder's own failure note. Same dual-context loader as above —
    this runs on the path where something has ALREADY gone wrong, so it must not add a second
    failure."""
    loaded = _redactor()
    return (loaded[0](value) or value) if loaded else "[unredactable]"


def note_failure(reason: str, path: str | None = None) -> None:
    """Record that the recorder itself failed. NEVER raises; overwrites (last failure wins)."""
    target = (path or spool_path()) + ERR_SUFFIX
    try:
        directory = os.path.dirname(target)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        line = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            # An exception message can carry a path, a URL or the value that failed to serialise.
            "reason": (_redact_text(str(reason)) or str(reason))[:300],
        }, separators=(",", ":")) + "\n"
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:                              # noqa: BLE001 - best-effort by design
        pass


def recorder_health(path: str | None = None) -> dict | None:
    """The last recorded recorder failure, or None when none is recorded.

    None means "no failure NOTED", not "no failure happened" — the same absence-is-not-evidence
    rule as everywhere else, which is why callers should render a returned failure loudly and
    render None as nothing at all.
    """
    target = (path or spool_path()) + ERR_SUFFIX
    try:
        with open(target, encoding="utf-8", errors="replace") as fh:
            item = json.loads(fh.readline().strip() or "null")
        return item if isinstance(item, dict) else None
    except (OSError, ValueError):
        return None


def record_decision(*, server: str, tool: str, decision: str, adapter: str,
                    session: str | None = None, reason: str | None = None,
                    basis: str = "declared", path: str | None = None) -> bool:
    """The one record shape every enforcement adapter writes, so the hook, the proxy and anything
    added later cannot describe the same event differently.

    `decision` is the verdict as the adapter applied it (`deny` / `defer` / `allow`). `basis` says
    WHAT justified it — `declared` (the approved surface) or `observed` (what verify saw the tool
    do) — because a block from a name match and a block from evidence are very different claims and
    an operator cannot calibrate trust without knowing which they got.
    """
    return append({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        "session": session,
        "server": server,
        "tool": tool,
        "decision": decision,
        "basis": basis,
        "adapter": adapter,
        **({"reason": reason} if reason else {}),
    }, path=path)


def read(limit: int = 500, path: str | None = None) -> list[dict]:
    """Most recent first. A malformed line is SKIPPED, never fatal: the spool is written by a hot
    path that can be killed mid-write, and one torn line must not hide every good record behind it.
    """
    target = path or spool_path()
    try:
        with open(target, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: list[dict] = []
    for line in reversed(lines):
        if len(out) >= limit:
            break
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def read_session(session: str, limit: int = 500, scan: int = 8000,
                 path: str | None = None) -> list[dict]:
    """Rows for ONE session, most recent first. Session memory must be read session-scoped:
    a global row budget lets a busy PARALLEL session evict this one's earlier calls, and the
    sequence check silently stops firing — the worst failure mode for a control is fading out
    under load. Bounded by `scan` lines total, and the previous rotation generation (`.1`) is
    consulted when the live file does not exhaust the budget, so rotating mid-session no longer
    wipes the session's memory."""
    target = path or spool_path()
    out: list[dict] = []
    budget = scan
    for candidate in (target, target + ".1"):
        if len(out) >= limit or budget <= 0:
            break
        try:
            with open(candidate, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for line in reversed(lines):
            if len(out) >= limit or budget <= 0:
                break
            budget -= 1
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and item.get("session") == session:
                out.append(item)
    return out


def summarise(limit: int = 5000, path: str | None = None) -> dict:
    """Counts a human actually wants: how many calls were checked, how many denied, over how many
    sessions, and when we last saw anything. Used by `mcpgawk status` so 'is anything watching'
    can be answered with observed activity rather than with configuration."""
    rows = read(limit=limit, path=path)
    denied = sum(1 for r in rows if r.get("decision") == "deny")
    # A `defer` is a call we DECLINED to check. Counting it as checked is how a machine with 801
    # declines and zero enforcements reported "802 MCP call(s) checked". `calls` stays the total
    # seen — the two answer different questions and both have to be available to say either.
    deferred = sum(1 for r in rows if r.get("decision") == "defer")
    checked = sum(1 for r in rows if r.get("decision") in ("allow", "deny"))
    sessions = {r.get("session") for r in rows if r.get("session")}
    servers = {r.get("server") for r in rows if r.get("server")}
    return {
        "calls": len(rows),
        "checked": checked,
        "deferred": deferred,
        "denied": denied,
        "sessions": len(sessions),
        "servers": len(servers),
        "last_seen": rows[0].get("ts") if rows else None,
        # Calls that arrived with no session identity: the sequence check cannot protect those,
        # and that gap must be countable rather than a silent null in each row.
        "no_session": sum(1 for r in rows if not r.get("session")),
    }
