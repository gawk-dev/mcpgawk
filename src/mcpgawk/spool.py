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
        line = json.dumps(record, separators=(",", ":"), default=str) + "\n"
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


def note_failure(reason: str, path: str | None = None) -> None:
    """Record that the recorder itself failed. NEVER raises; overwrites (last failure wins)."""
    target = (path or spool_path()) + ERR_SUFFIX
    try:
        directory = os.path.dirname(target)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        line = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            "reason": str(reason)[:300],
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
