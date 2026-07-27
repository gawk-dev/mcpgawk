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

from pathlib import Path
from typing import Any

#: Agents whose MCP calls the guard hook can currently intercept. Claude Code exposes PreToolUse
#: hooks; the others have no equivalent interception point wired yet, so they are covered only by
#: the enforce proxy (which routes the server itself, not the agent).
HOOK_CAPABLE = {"claude-code"}

#: Display names for the client ids `discover` attributes servers to.
CLIENT_LABELS = {
    "claude-code": "Claude Code",
    "claude-desktop": "Claude Desktop",
    "cursor": "Cursor",
    "codex": "Codex",
    "gemini-cli": "Gemini CLI",
    "kiro": "Kiro",
    "windsurf": "Windsurf",
    "zed": "Zed",
    "vscode": "VS Code",
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


def render(*, guard_installed: bool, guard_path: Path | None,
           agents: dict[str, int], baseline_total: int, pending: list[str],
           behaviour_tools: int | None, enforce_available: bool,
           last_activity: str | None, activity: dict | None = None) -> str:
    """The whole picture, ordered by what the reader must act on.

    `behaviour_tools is None` means "no profile" — distinct from 0, which would mean a profile that
    observed nothing. The two justify very different levels of confidence and must not render the
    same way.
    """
    out: list[str] = ["", "  RUNTIME CHECKING"]

    if not agents:
        out.append("      No MCP-using agents found on this machine.")
    # Width from the longest label present, so a long client id cannot shunt the state column out
    # of alignment — the state is the part being scanned for.
    width = max((len(_label(c)) for c in agents), default=0)
    for client, count in sorted(agents.items(), key=lambda kv: -kv[1]):
        name = _label(client)
        if client in HOOK_CAPABLE and guard_installed:
            out.append(f"      {name:<{width}}  ON   every MCP call checked against your baseline")
        elif client in HOOK_CAPABLE:
            out.append(f"      {name:<{width}}  OFF  {count} server(s) unchecked — run `mcpgawk`")
        else:
            # The honest one. Saying nothing here is how a gap becomes a belief of safety.
            out.append(f"      {name:<{width}}  --   no hook point; {count} server(s) reachable "
                       f"without a check")
    if guard_installed and guard_path:
        out.append(f"      hook: {guard_path}")

    out += ["", "  EXPECTED BEHAVIOUR"]
    out.append(f"      {baseline_total} server(s) at an approved baseline (what they may expose)")
    if behaviour_tools is None:
        out.append("      no observed-behaviour profile — checks are by NAME only, which the")
        out.append("      server author chooses.            mcpgawk verify  (records what they DO)")
    else:
        out.append(f"      {behaviour_tools} tool(s) with observed behaviour from verify")
    if pending:
        out.append("")
        out.append(f"      {len(pending)} server(s) changed since you approved them — blocked until")
        out.append("      you decide:")
        for key in pending[:10]:
            out.append(f"          {key}")
        out.append("      Review: mcpgawk scan     Accept: mcpgawk approve <name>")

    out += ["", "  DEEP MONITORING (arguments, responses, toxic flow, tamper-evident log)"]
    if enforce_available:
        out.append("      available — mcpgawk enforce install")
    else:
        out.append("      not installed in this environment (part of gawk Platform)")

    out += ["", "  WHAT IT HAS ACTUALLY SEEN"]
    if activity and activity.get("calls"):
        out.append(f"      {activity['calls']} MCP call(s) checked across "
                   f"{activity['sessions']} agent session(s), {activity['servers']} server(s)")
        denied = activity.get("denied") or 0
        out.append(f"      {denied} denied" if denied else "      none denied")
        out.append(f"      last: {activity.get('last_seen')}                 mcpgawk runs")
    else:
        # The distinction that motivates the whole spool: configuration is not observation.
        out.append("      nothing recorded yet — so 'nothing was blocked' cannot yet be")
        out.append("      distinguished from 'nothing was watched'. Use your agent once.")

    out += ["", f"  Last run: {last_activity or 'nothing recorded yet'}", ""]
    return "\n".join(out)


def collect_and_render() -> str:
    """Gather from every store and render. Each probe is independently guarded: one unreadable
    store must degrade THAT LINE, never blank the whole answer — a status command that dies is a
    status command that gets replaced by guessing."""
    from . import history

    try:
        from .guard import CLAUDE_USER_SETTINGS, status as guard_status
        guard_text = guard_status()
        guard_installed = "NOT installed" not in guard_text
        guard_path: Path | None = CLAUDE_USER_SETTINGS
    except Exception:                              # noqa: BLE001
        guard_installed, guard_path = False, None

    try:
        from .discover import discover_servers
        found = discover_servers()
        entries = found[0] if isinstance(found, tuple) else found
        agents = agents_on_this_machine(entries)
    except Exception:                              # noqa: BLE001
        agents = {}

    try:
        store = history.load(history.default_path())
        servers = store.get("servers") or {}
        pending = history.pending(store)
        baseline_total = len([k for k in servers if k not in pending])
    except Exception:                              # noqa: BLE001
        pending, baseline_total = [], 0

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

    return render(guard_installed=guard_installed, guard_path=guard_path, agents=agents,
                  baseline_total=baseline_total, pending=pending,
                  behaviour_tools=behaviour_tools, enforce_available=enforce_available,
                  last_activity=last_activity, activity=activity)
