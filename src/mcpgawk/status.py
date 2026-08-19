"""`mcpgawk status` — one answer to "is anything watching, and what is it watching against?"

WHY. The answer used to be spread across three commands a user had to know existed and then
correlate themselves (`guard status`, `enforce status`, `monitor status`). On the author's own
machine the true answer was "nothing is watching", and nobody knew — because finding out required
already suspecting it.

THE RULE THIS FILE EXISTS TO KEEP: **coverage is stated per agent, never in aggregate.** The guard
hook installs into Claude Code's settings only. A user running Cursor or Codex who sees a cheerful
"Protected ✓" would be actively misled — the most dangerous output this product could produce,
because it converts a gap into a belief of safety. So every agent found on this machine is listed
with its own state, and an agent we cannot cover says so.

Read-only by construction: it opens stores, never writes them, and never starts anything.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

#: Agents whose MCP calls the guard hook can currently intercept. Claude Code exposes PreToolUse
#: hooks; the others have no equivalent interception point wired yet, so they are covered only by
#: the enforce proxy (which routes the server itself, not the agent).
def _hook_capable() -> set[str]:
    """Sourced from the adapter registry, never a hand-kept list — adding an agent must not
    require remembering to update the thing that reports coverage."""
    try:
        from .agents import ADAPTERS
        return set(ADAPTERS)
    except Exception:                              # noqa: BLE001
        return {"claude-code"}


HOOK_CAPABLE = _hook_capable()

#: Display names for the client ids `discover` attributes servers to.
CLIENT_LABELS = {
    "antigravity": "Antigravity",
    "claude-code": "Claude Code",
    "claude-desktop": "Claude Desktop",
    "claude-desktop-extension": "Claude Desktop extension",
    "cursor": "Cursor",
    "codex": "Codex",
    "gemini-cli": "Gemini CLI",
    "kimi": "Kimi CLI",
    "kiro": "Kiro",
    "windsurf": "Windsurf",
    "zed": "Zed",
    "vscode": "VS Code",
    "amp": "Amp",
    "cline": "Cline",
    "continue": "Continue",
    "goose": "Goose",
    "junie": "Junie",
    "lmstudio": "LM Studio",
    "opencode": "opencode",
    "roo": "Roo Code",
    "warp": "Warp",
}


def _label(client: str) -> str:
    return CLIENT_LABELS.get(client, client)


def agents_on_this_machine(entries: dict[str, Any] | None) -> dict[str, int]:
    """{client_id: server_count} across everything discovery found."""
    counts: dict[str, int] = {}
    for entry in (entries or {}).values():
        if not isinstance(entry, dict):
            continue
        for client in entry.get("_clients") or []:
            counts[str(client)] = counts.get(str(client), 0) + 1
    return counts


def hook_health_by_client() -> dict[str, str]:
    """{client id: "absent"|"broken"|"ok"} — asked of EACH agent's own config.

    One global "the guard is installed" boolean used to be applied to every hook-capable client, so
    installing into Claude Code alone printed Cursor and Gemini CLI as ON — "every MCP call
    checked" — for agents that had never been wired. Protection is per-agent because the config
    file is per-agent; there is no machine-wide answer to give.
    """
    try:
        from . import guard
        from .agents import ADAPTERS
    except Exception:                              # noqa: BLE001
        return {}
    out: dict[str, str] = {}
    for key, adapter in ADAPTERS.items():
        try:
            out[key] = guard.hook_health_for(adapter)
        except Exception:                          # noqa: BLE001
            # An unreadable config is not "protected". Degrade THAT agent, never the whole answer.
            out[key] = "absent"
    return out


def render(*, hook_health: dict[str, str], guard_path: Path | None,
           agents: dict[str, int], baseline_total: int, pending: list[str],
           behaviour_tools: int | None, enforce_available: bool,
           last_activity: str | None, activity: dict | None = None,
           muted_total: int = 0, behavioural_unavailable: str | None = None,
           monitor_open: int | None = None, baseline_error: str | None = None,
           agents_error: str | None = None) -> str:
    """The whole picture, ordered by what the reader must act on.

    `behaviour_tools is None` means "no profile" — distinct from 0, which would mean a profile that
    observed nothing. The two justify very different levels of confidence and must not render the
    same way.
    """
    out: list[str] = ["", "  RUNTIME CHECKING"]

    if not agents:
        if agents_error:
            out.append(f"      Agent discovery FAILED ({agents_error}) — whether anything on this")
            out.append("      machine calls MCP servers is UNKNOWN, not none.")
        else:
            out.append("      No MCP-using agents found on this machine.")
    # Width from the longest label present, so a long client id cannot shunt the state column out
    # of alignment — the state is the part being scanned for.
    width = max((len(_label(c)) for c in agents), default=0)
    for client, count in sorted(agents.items(), key=lambda kv: -kv[1]):
        name = _label(client)
        health = hook_health.get(client, "absent")
        if client in HOOK_CAPABLE and health == "ok":
            # Since B4 the hook checks the DECLARED surface and, where verify has recorded
            # observations, OBSERVED behaviour — say both, or the stronger free tier reads as
            # if it did not exist (the old wording pre-dated Task 0's answer).
            out.append(f"      {name:<{width}}  ON   every MCP call checked against your baseline "
                       f"+ observed behaviour (where recorded)")
        elif client in HOOK_CAPABLE and health == "broken":
            # Configured but unrunnable. This must NOT read as ON (nothing is checked) and must
            # NOT read as OFF (the user did install it, and `run mcpgawk` is not the fix).
            out.append(f"      {name:<{width}}  BROKEN  hook installed but cannot run — "
                       f"{count} server(s) going UNCHECKED; `mcpgawk guard install` repairs it")
        elif client in HOOK_CAPABLE:
            out.append(f"      {name:<{width}}  OFF  {count} server(s) unchecked — run `mcpgawk`")
        else:
            # The honest one. Saying nothing here is how a gap becomes a belief of safety.
            out.append(f"      {name:<{width}}  --   no hook point; {count} server(s) reachable "
                       f"without a check")
    if any(h != "absent" for h in hook_health.values()) and guard_path:
        out.append(f"      hook: {guard_path}")

    out += ["", "  EXPECTED BEHAVIOUR"]
    if baseline_error:
        # Say it INSTEAD of the count, not beside it: printing "0 server(s)" next to a warning
        # still invites the reader to take the 0 at face value, and 0 is not what we know.
        out.append(f"      ⚠ could not read your approved baseline ({baseline_error}) — the "
                   f"number of approved servers is UNKNOWN, not zero.")
    else:
        out.append(f"      {baseline_total} server(s) at an approved baseline (what they may expose)")
    if behavioural_unavailable:
        # B5 — never a silent fallback: the missing dependency is named BEFORE any name-only
        # posture is described, and no dead command (`mcpgawk verify` cannot run here) is offered.
        out.append(f"      ⚠ {behavioural_unavailable}")
        if behaviour_tools:
            out.append(f"      ({behaviour_tools} tool(s) have recorded observations from an "
                       f"earlier verify; new observations cannot be made until the above is fixed)")
    elif behaviour_tools is None:
        out.append("      no observed-behaviour profile — checks are by NAME only, which the")
        out.append("      server author chooses.            mcpgawk verify  (records what they DO)")
    else:
        out.append(f"      {behaviour_tools} tool(s) with observed behaviour from verify")
    if muted_total:
        # Suppression must stay a countable, visible decision — a mute the user forgot about is a
        # blind spot they chose once and inherit forever unless something keeps saying so.
        out.append(f"      {muted_total} finding(s) muted by you as false positives "
                   f"(mcpgawk wrong — still listed on scans, never hidden)")
    if pending:
        out.append("")
        out.append(f"      {len(pending)} server(s) changed since you approved them — blocked until")
        out.append("      you decide:")
        for name in pending[:10]:
            out.append(f"          {name}")
        out.append("      Review: mcpgawk scan     Accept: mcpgawk approve <name>")

    out += ["", "  DEEP MONITORING (arguments, responses, toxic flow, tamper-evident log)"]
    if enforce_available:
        out.append("      available — mcpgawk enforce install")
    else:
        out.append("      not installed in this environment (part of mcpgawk Platform)")
    # Monitor de-duplicates alerts, so "0 new" is not "nothing wrong". An UNACKNOWLEDGED alert is
    # an open question about a server you trusted, and it belongs on the screen that answers
    # "am I protected?" — this surface did not read monitor at all.
    if monitor_open is None:
        if enforce_available:
            out.append("      monitor: no record on this machine — nothing is re-checking your "
                       "servers between scans")
    elif monitor_open:
        out.append(f"      ⚠ {monitor_open} OPEN monitor alert(s) — a watched server changed or "
                   f"stopped answering and nobody has accepted it")
        out.append("        `mcpgawk monitor status` lists them")
    else:
        out.append("      monitor: no open alerts")

    out += ["", "  WHAT IT HAS ACTUALLY SEEN"]
    if activity and activity.get("calls"):
        # SEEN and CHECKED are different numbers. Reporting the total as "checked" is what let a
        # machine with 801 declines and one deny announce "802 MCP call(s) checked" at exit 0.
        # `checked` is absent from rows written before the distinction existed — say so rather
        # than inferring it, since inferring it either way restates the same false claim.
        checked = activity.get("checked")
        deferred = activity.get("deferred") or 0
        out.append(f"      {activity['calls']} MCP call(s) seen across "
                   f"{activity['sessions']} agent session(s), {activity['servers']} server(s)")
        if checked is None:
            out.append("      how many were actually CHECKED is not recorded in this log "
                       "(written before the distinction existed)")
        else:
            out.append(f"      {checked} actually checked against an approved baseline")
        if deferred:
            out.append(f"      ⚠ {deferred} call(s) NOT checked — the guard declined (no or stale "
                       f"baseline projection) and let them through. Run `mcpgawk scan`.")
        denied = activity.get("denied") or 0
        out.append(f"      {denied} denied" if denied else "      none denied")
        no_session = activity.get("no_session") or 0
        if no_session:
            out.append(f"      {no_session} call(s) carried no session identity — the"
                       " session-sequence check cannot protect those")
        out.append(f"      last: {activity.get('last_seen')}                 mcpgawk runs")
    else:
        # The distinction that motivates the whole spool: configuration is not observation.
        out.append("      nothing recorded yet — so 'nothing was blocked' cannot yet be")
        out.append("      distinguished from 'nothing was watched'. Use your agent once.")
    try:
        from . import spool as _spool
        recorder = _spool.recorder_health()
    except Exception:                              # noqa: BLE001 - status must always render
        recorder = None
    if recorder:
        # The recorder's own honesty: a failure note means the counts above may be incomplete,
        # and an absence of rows may be the recorder failing rather than a quiet machine.
        out.append(f"      ⚠ RECORDER FAILURE at {recorder.get('ts')}: {recorder.get('reason')}")
        out.append("        the counts above may be incomplete — absence of rows is not quiet")

    out += ["", f"  Last run: {last_activity or 'nothing recorded yet'}", ""]
    return "\n".join(out)


def collect_and_render() -> str:
    """Gather from every store and render. Each probe is independently guarded: one unreadable
    store must degrade THAT LINE, never blank the whole answer — a status command that dies is a
    status command that gets replaced by guessing."""
    from . import history

    try:
        from .guard import CLAUDE_USER_SETTINGS
        # Per-agent, and asked of each agent's own config — not one boolean sniffed out of the
        # prose of `guard status` ("NOT installed" not in text), which could not distinguish a
        # broken hook from a working one and knew nothing about any agent but Claude Code.
        hook_health = hook_health_by_client()
        guard_path: Path | None = CLAUDE_USER_SETTINGS
    except Exception:                              # noqa: BLE001
        hook_health, guard_path = {}, None

    try:
        from .discover import discover_servers
        found = discover_servers()
        entries = found[0] if isinstance(found, tuple) else found
        agents = agents_on_this_machine(entries)
    except Exception as exc:                       # noqa: BLE001
        # NOT `agents = {}`. Discovery failing and this machine having no agents produced the same
        # value, and therefore the same sentence — "No MCP-using agents found on this machine." —
        # on the one screen that answers "am I protected?". The marker travels with the result so
        # the renderer can tell the two apart, the same fix `load_checked` made for the store.
        agents, agents_error = {}, f"{type(exc).__name__}: {exc}"
    else:
        agents_error = None

    try:
        # load_checked, not load: `load` degrades an unreadable store to {"servers": {}}, which is
        # byte-for-byte the answer a fresh machine gives — so a CORRUPT trust store rendered as a
        # calm "0 server(s) at an approved baseline" while status still reported protection ON.
        # Nothing raised, so the except below never fired either. Eval Tier 4; the panel's copy of
        # this defect was fixed separately, and this is the same store read from the other surface.
        store, baseline_error = history.load_checked(history.default_path())
        servers = store.get("servers") or {}
        pending_keys = history.pending(store)
        baseline_total = len([k for k in servers if k not in pending_keys])
        # Resolve to what the USER calls each server, not our internal identity key.
        pending = [history.display_name(store, k) for k in pending_keys]
        muted_total = history.muted_total(store)
    except Exception as exc:                       # noqa: BLE001
        pending, baseline_total, muted_total = [], 0, 0
        baseline_error = f"{type(exc).__name__}: {exc}"

    behaviour_tools: int | None = None
    try:
        profile = Path.home() / ".gawk" / "behaviour.json"
        if profile.is_file():
            import json
            data = json.loads(profile.read_text(encoding="utf-8"))
            behaviour_tools = sum(len(v) for v in (data.get("servers") or {}).values()
                                  if isinstance(v, dict))
    except Exception:                              # noqa: BLE001
        behaviour_tools = None

    try:
        import importlib.util
        enforce_available = importlib.util.find_spec("gawk_platform") is not None
    except Exception:                              # noqa: BLE001
        enforce_available = False

    # OPEN alerts, not new ones. Monitor de-duplicates, so a permanently dead or drifted server
    # raises its alert once and reports "0 new" for ever after; `mcpgawk status` did not read
    # monitor at all, so an unacknowledged alert was invisible on the one screen that claims to
    # answer "am I protected?". None = we could not look (monitor absent or unreadable), which is
    # rendered differently from zero.
    monitor_open: int | None = None
    try:
        from pathlib import Path as _P

        import sqlite3
        db = os.environ.get("GAWK_MONITOR_DB") or str(_P.home() / ".gawk" / "monitor.db")
        if _P(db).is_file():
            # READ-ONLY, deliberately, and NOT through SqliteMonitorStore. This module's contract
            # is that it opens stores and never writes them; the store class applies schema
            # migrations and enables WAL on open, which would have `mcpgawk status` — a query —
            # modifying the operator's monitoring database as a side effect of being run.
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            try:
                row = conn.execute("SELECT COUNT(*) FROM open_alerts").fetchone()
                monitor_open = int(row[0]) if row else 0
            finally:
                conn.close()
    except Exception:                              # noqa: BLE001
        monitor_open = None

    last_activity = None
    try:
        from . import runlog
        rows = runlog.list_runs(limit=1)
        if rows:
            r = rows[0]
            last_activity = f"{r.kind} — {r.status} at {r.started_at}"
    except Exception:                              # noqa: BLE001
        last_activity = None

    try:
        from . import spool
        activity = spool.summarise()
    except Exception:                              # noqa: BLE001
        activity = None

    try:
        from .capability import unavailable_line
        behavioural_unavailable = unavailable_line()
    except Exception:                              # noqa: BLE001
        behavioural_unavailable = None

    return render(hook_health=hook_health, guard_path=guard_path, agents=agents,
                  agents_error=agents_error,
                  baseline_total=baseline_total, pending=pending,
                  baseline_error=baseline_error,
                  behaviour_tools=behaviour_tools, enforce_available=enforce_available,
                  last_activity=last_activity, activity=activity, muted_total=muted_total,
                  behavioural_unavailable=behavioural_unavailable,
                  monitor_open=monitor_open)
