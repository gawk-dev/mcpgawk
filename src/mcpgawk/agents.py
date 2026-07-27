"""Agent adapters — where each coding agent lets us inspect an MCP call before it runs.

WHY THIS FILE. `mcpgawk status` on the author's machine reported Claude Code covered and SIX other
agents — Cursor, Codex, Gemini CLI, Kiro, Claude Desktop, Windsurf — as "no hook point", reachable
with no check at all. That was true only of our implementation, not of the agents: five of the
seven expose a pre-execution hook. The gap was ours.

THE SHAPE, per the architecture note: an adapter is CONFIG + PAYLOAD + VERDICT, and nothing else.
The decision itself stays in `guard_hook.decide`, which every adapter calls. Adding an agent must
never mean adding a second opinion about whether a call is safe — that is the drift this codebase
has paid for repeatedly (five readers of history.json, two source/sink classifiers, two copies of
the session predicates).

WHAT DIFFERS BETWEEN AGENTS, and why each field below exists:

* **the event name** — `PreToolUse` (Claude Code, Codex), `beforeMCPExecution` (Cursor),
  `pre_mcp_tool_use` (Windsurf), `BeforeTool` (Gemini CLI). No two agree.
* **the payload** — all provide a tool name and its arguments, under different keys.
* **the deny signal** — Claude Code and Codex take a JSON `permissionDecision`; Cursor takes
  `{"permission": "deny"}`; Gemini takes `{"decision": "deny"}`. **Exit code 2 is the one signal
  every hook-capable agent in this set understands**, so it is emitted alongside the JSON as a
  belt-and-braces deny.
* **the failure default** — and this one is a security property, not a detail. **Cursor allows the
  call when a hook errors unless `failClosed: true` is set.** A naive port would therefore install
  something that looks like protection and silently isn't, which is the exact failure `status`
  exists to prevent. Every Cursor install written here sets it.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class AgentAdapter:
    """One interception point. `key` matches the client ids `discover` attributes servers to, so
    `status` can line coverage up against the fleet it already found."""
    key: str
    label: str
    config: Path
    #: The hook format flag passed to the hook script, so ONE script serves every agent.
    fmt: str
    #: Reads (tool_name, arguments) out of this agent's event payload.
    parse: Callable[[dict], tuple[str | None, dict]]
    #: Builds this agent's own "deny" response from our reason string.
    deny: Callable[[str], dict]


# --------------------------------------------------------------------------------------------- #
# payload readers — each one documented against the agent's published shape
# --------------------------------------------------------------------------------------------- #

def _parse_claude(event: dict) -> tuple[str | None, dict]:
    """Claude Code PreToolUse: {"tool_name": "mcp__srv__tool", "tool_input": {...}}."""
    name = event.get("tool_name")
    args = event.get("tool_input")
    return (name if isinstance(name, str) else None), (args if isinstance(args, dict) else {})


def _parse_cursor(event: dict) -> tuple[str | None, dict]:
    """Cursor beforeMCPExecution: tool_name plus `tool_input` — which Cursor documents as the
    params **as a JSON string**, not an object. Decoded here rather than in the decision core, so
    the core keeps one input shape."""
    import json

    name = event.get("tool_name")
    raw = event.get("tool_input")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {}
    return (name if isinstance(name, str) else None), (raw if isinstance(raw, dict) else {})


def _parse_codex(event: dict) -> tuple[str | None, dict]:
    """Codex PreToolUse: {"tool_name": ..., "tool_input": {...}, "session_id", "cwd", "turn_id"}.
    Same shape as Claude Code for the fields we read."""
    return _parse_claude(event)


# --------------------------------------------------------------------------------------------- #
# verdict writers
# --------------------------------------------------------------------------------------------- #

def _deny_claude(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _deny_cursor(reason: str) -> dict:
    """Cursor expects {"permission": "allow"|"ask"|"deny"}, with snake_case message keys
    (`user_message` / `agent_message`) — confirmed against cursor.com/docs/agent/hooks, not
    inferred from the Claude Code shape."""
    return {"permission": "deny", "user_message": reason, "agent_message": reason}


def _deny_codex(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


ADAPTERS: dict[str, AgentAdapter] = {
    "claude-code": AgentAdapter(
        key="claude-code", label="Claude Code",
        config=Path.home() / ".claude" / "settings.json",
        fmt="claude", parse=_parse_claude, deny=_deny_claude),
    "cursor": AgentAdapter(
        key="cursor", label="Cursor",
        config=Path.home() / ".cursor" / "hooks.json",
        fmt="cursor", parse=_parse_cursor, deny=_deny_cursor),
    "codex": AgentAdapter(
        key="codex", label="Codex",
        config=Path.home() / ".codex" / "hooks.json",
        fmt="codex", parse=_parse_codex, deny=_deny_codex),
}

#: Agents with MCP support but NO documented pre-execution interception point. Listed so `status`
#: can say why they are uncovered instead of leaving a silent hole: VS Code exposes no API that can
#: block a tool call (only declarative auto-approve settings), and Claude Desktop offers a static
#: MDM-pushed allow/deny policy with no visibility into arguments. Both need the proxy path.
NO_HOOK_POINT = {
    "vscode": "VS Code exposes no API that can block a tool call — needs the proxy",
    "claude-desktop": "Claude Desktop has no lifecycle hooks — needs the proxy",
}


def adapter_for(key: str) -> AgentAdapter | None:
    return ADAPTERS.get(key)


def parse_event(fmt: str, event: dict) -> tuple[str | None, dict]:
    for adapter in ADAPTERS.values():
        if adapter.fmt == fmt:
            return adapter.parse(event)
    return _parse_claude(event)


def deny_payload(fmt: str, reason: str) -> dict:
    for adapter in ADAPTERS.values():
        if adapter.fmt == fmt:
            return adapter.deny(reason)
    return _deny_claude(reason)


def installed_agents() -> dict[str, bool]:
    """{agent key: is our hook present}. Only reports agents whose config actually exists —
    claiming coverage for an agent that is not on this machine would be noise, and claiming a gap
    for one would be a false alarm."""
    from . import guard

    out: dict[str, bool] = {}
    for key, adapter in ADAPTERS.items():
        if adapter.config.is_file():
            out[key] = guard.is_installed_for(adapter)
    return out
