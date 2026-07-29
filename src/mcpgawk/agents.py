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


def _parse_kimi(event: dict) -> tuple[str | None, dict]:
    """Kimi CLI hooks (Beta): 13 lifecycle events modelled on Claude Code's, including
    `PreToolUse` with the same tool_name/tool_input payload for the fields we read
    (docs/roadmap-agent-coverage-2026-07-28.md)."""
    return _parse_claude(event)


def _parse_windsurf(event: dict) -> tuple[str | None, dict]:
    """Windsurf `pre_mcp_tool_use` — the only agent in this set that shares NO field with the
    others. Its payload nests everything under `tool_info` and names the parts differently:

        {"agent_action_name": "pre_mcp_tool_use",
         "tool_info": {"mcp_server_name": "github",
                       "mcp_tool_name": "create_issue",
                       "mcp_tool_arguments": {...}}}

    Verified against docs.devin.ai/desktop/cascade/hooks, not inferred. This adapter originally
    reused the Claude parser, which reads a top-level `tool_name` that does not exist here — so
    every Windsurf call parsed as "not an MCP tool", was never judged, was never even logged, and
    the hook exited 0. It installed cleanly and `status` reported Windsurf as COVERED while
    checking nothing, which is worse than having no adapter at all.

    Windsurf also supplies the server SEPARATELY and the tool name BARE (`create_issue`, not
    `mcp__github__create_issue`), so the canonical name is composed here. Composing is safe: both
    halves come from the agent, and `parse_mcp_tool_name` splits on the first `__` after the
    prefix, so a tool name containing `__` survives while a server name containing one would not —
    the same constraint every other client's own joining convention already imposes.
    """
    info = event.get("tool_info")
    if not isinstance(info, dict):
        return None, {}
    server, tool = info.get("mcp_server_name"), info.get("mcp_tool_name")
    if not isinstance(server, str) or not isinstance(tool, str) or not server or not tool:
        return None, {}
    args = info.get("mcp_tool_arguments")
    return f"mcp__{server}__{tool}", (args if isinstance(args, dict) else {})


def _parse_gemini(event: dict) -> tuple[str | None, dict]:
    """Gemini CLI `BeforeTool`: `tool_name` + `tool_input` (a real object, unlike Cursor's
    string), alongside `mcp_context`/`original_request_name`/`session_id`/`cwd`, which we do not
    need (docs/roadmap-agent-coverage-2026-07-28.md)."""
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


def _deny_kimi(reason: str) -> dict:
    """Kimi blocks on EXIT CODE 2 (see guard_hook.DENY_BY_EXIT); the JSON is emitted alongside in
    the Claude-compatible shape its hook system is modelled on, so the reason reaches any log."""
    return _deny_claude(reason)


def _deny_gemini(reason: str) -> dict:
    """Gemini CLI's documented verdict: `{"decision": "deny", "reason": ...}` — its own shape, not
    Claude's. Exit 2 also denies, and we emit both (belt and braces, like Cursor)."""
    return {"decision": "deny", "reason": reason}


def _deny_windsurf(reason: str) -> dict:
    """Windsurf's only documented deny channel is EXIT CODE 2 (guard_hook.DENY_BY_EXIT); the JSON
    is informational — the reason a human or log reads, not the verdict mechanism."""
    return {"decision": "deny", "reason": reason}


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
    "kimi": AgentAdapter(
        key="kimi", label="Kimi CLI",
        # The only TOML hook config so far — [[hooks]] tables in the main config file, not a
        # dedicated hooks.json. guard.py has a dedicated text-preserving writer for it.
        config=Path.home() / ".kimi" / "config.toml",
        fmt="kimi", parse=_parse_kimi, deny=_deny_kimi),
    "gemini-cli": AgentAdapter(
        key="gemini-cli", label="Gemini CLI",
        # Hooks live in the same settings.json discover already reads servers from; the event is
        # BeforeTool (not PreToolUse) — see guard._gemini_install.
        config=Path.home() / ".gemini" / "settings.json",
        fmt="gemini", parse=_parse_gemini, deny=_deny_gemini),
    "windsurf": AgentAdapter(
        key="windsurf", label="Windsurf",
        # USER-level hooks only. The root-protected system level (/Library/... , /etc/windsurf)
        # is deliberately out of v1 scope — an enterprise concern, sequenced after the solo
        # journey (docs/enterprise-sso-rbac-2026-07-27.md).
        config=Path.home() / ".codeium" / "windsurf" / "hooks.json",
        fmt="windsurf", parse=_parse_windsurf, deny=_deny_windsurf),
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
