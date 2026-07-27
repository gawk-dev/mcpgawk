"""`mcpgawk guard` — put the approved baseline in the agent's loop.

The proxy (`mcpgawk enforce`) is the strong control: it sees every call and can block, redact and
audit. But it requires rewiring each server's config to launch through it. The guard is the cheap
one: a single PreToolUse hook, installed once, that checks every MCP tool call your agent makes
against what you approved — no rewiring, no proxy, no per-server change.

**Against the comparable feature in Snyk's agent-scan** (`reference/mcp-scan-hist/guard.py`, read
2026-07-27): theirs is a thin forwarder with no local logic — it base64-encodes the whole hook
payload, POSTs it to `api.snyk.io`, and echoes back whatever the server decides. It needs a minted
push key, it uploads every tool call you make, and its `curl` has NO `--max-time`, so an
unreachable endpoint stalls the tool call until the agent's own timeout fires. Ours decides
locally, in ~10ms, with nothing leaving the machine and nothing to authenticate to.

Two safety properties theirs lacks, both deliberate here:
  * **Atomic writes.** Theirs does a plain `write_text()` on your settings file; a crash or a
    concurrent write leaves it truncated, and a broken settings.json is silently ignored by the
    client — you would lose every OTHER hook and setting you had. We write a temp file in the same
    directory and `os.replace()` it, which is atomic on POSIX and Windows.
  * **Uninstall never deletes a file it did not create.** Theirs removes the whole managed Codex
    `requirements.toml`, taking any admin content with it. We only ever remove our own entries.

SCOPE, stated honestly: Claude Code only, for now. Cursor and Codex use different hook schemas
(`hooks.json` with a flat entry list, and a TOML requirements file respectively). Registering
those without being able to test them would be claiming coverage we have not verified — the
installer names them as unsupported rather than writing a config shape we have never seen work.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

#: Our entries are identified by this marker inside the command string, so uninstall can remove
#: exactly ours and leave every other hook — including another vendor's — untouched.
MARKER = "mcpgawk-guard"

#: Bounded so a wedged hook cannot hold up a tool call. The client fails OPEN on timeout, which is
#: the right default for an availability-critical path — but 10s is already ~1000x the measured
#: 10ms cost, so hitting it means something is genuinely wrong.
HOOK_TIMEOUT_S = 10

#: Only MCP tools. A guard that matched `*` would run on every Bash and Edit call for nothing.
MCP_MATCHER = "mcp__.*"

CLAUDE_USER_SETTINGS = Path.home() / ".claude" / "settings.json"


def hook_script_path() -> Path:
    """The decision module, invoked BY PATH so the package `__init__` (and the MCP SDK behind it)
    is never imported on the hot path — measured 190ms → 10ms per tool call."""
    return (Path(__file__).parent / "guard_hook.py").resolve()


def hook_command(python: str | None = None) -> str:
    """The command string written into settings. Absolute interpreter AND absolute script: the
    hook runs with whatever cwd and PATH the agent happens to have, so neither can be assumed."""
    interpreter = python or sys.executable
    return f'"{interpreter}" "{hook_script_path()}"  # {MARKER}'


def _load_settings(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardError(
            f"{path} is not readable JSON ({exc}). Refusing to touch it — fix or move it first, "
            f"because overwriting would destroy whatever settings are in there."
        ) from exc
    return data if isinstance(data, dict) else {}


class GuardError(RuntimeError):
    """A condition the operator must resolve. Never raised for 'already installed'."""


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    """Temp file in the SAME directory, then os.replace — atomic on POSIX and Windows. A settings
    file truncated by a crash mid-write is silently ignored by the client, which would drop every
    other hook and setting the user had."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".mcpgawk-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _backup(path: Path) -> Path | None:
    if not path.is_file():
        return None
    backup = path.with_suffix(path.suffix + ".mcpgawk-backup")
    shutil.copy2(path, backup)
    return backup


def _is_ours(entry: dict) -> bool:
    return MARKER in str(entry.get("command", ""))


def _pretooluse_groups(settings: dict[str, Any]) -> list[dict[str, Any]]:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return []
    groups = hooks.get("PreToolUse")
    return groups if isinstance(groups, list) else []


def is_installed(settings: dict[str, Any]) -> bool:
    return any(
        any(_is_ours(h) for h in (g.get("hooks") or []) if isinstance(h, dict))
        for g in _pretooluse_groups(settings) if isinstance(g, dict)
    )


def install(path: Path | None = None, *, python: str | None = None) -> str:
    """Add our PreToolUse hook, preserving everything already there. Idempotent: re-running
    updates our entry in place rather than appending a second one."""
    target = path or CLAUDE_USER_SETTINGS
    settings = _load_settings(target)
    already = is_installed(settings)

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise GuardError(f'{target}: "hooks" is not an object — refusing to overwrite it.')
    groups = hooks.get("PreToolUse")
    if not isinstance(groups, list):
        groups = []
    # Drop only OUR entries; everything else — other vendors, the user's own — is carried through.
    cleaned: list[dict[str, Any]] = []
    preserved = 0
    for group in groups:
        if not isinstance(group, dict):
            cleaned.append(group)
            continue
        entries = [h for h in (group.get("hooks") or [])
                   if not (isinstance(h, dict) and _is_ours(h))]
        removed = len(group.get("hooks") or []) - len(entries)
        if entries or not removed:
            preserved += len(entries)
            cleaned.append({**group, "hooks": entries} if removed else group)

    cleaned.append({
        "matcher": MCP_MATCHER,
        "hooks": [{"type": "command", "command": hook_command(python),
                   "timeout": HOOK_TIMEOUT_S}],
    })
    hooks["PreToolUse"] = cleaned

    backup = _backup(target)
    _atomic_write(target, settings)
    verb = "updated" if already else "installed"
    note = f"mcpgawk guard {verb} in {target}"
    if preserved:
        note += f" ({preserved} other PreToolUse hook(s) left untouched)"
    if backup:
        note += f"\n  previous settings backed up to {backup}"
    return note


def uninstall(path: Path | None = None) -> str:
    """Remove ONLY our entries. Never deletes the settings file, never touches another vendor's
    hook, and leaves an empty structure tidy rather than removing keys the user may rely on."""
    target = path or CLAUDE_USER_SETTINGS
    if not target.is_file():
        return f"mcpgawk guard: nothing to remove — {target} does not exist"
    settings = _load_settings(target)
    if not is_installed(settings):
        return f"mcpgawk guard: not installed in {target} — nothing removed"

    hooks = settings.get("hooks", {})
    groups = _pretooluse_groups(settings)
    kept: list[dict[str, Any]] = []
    for group in groups:
        if not isinstance(group, dict):
            kept.append(group)
            continue
        entries = [h for h in (group.get("hooks") or [])
                   if not (isinstance(h, dict) and _is_ours(h))]
        if entries:
            kept.append({**group, "hooks": entries})
        # a group that held only our hook disappears with it
    if kept:
        hooks["PreToolUse"] = kept
    else:
        hooks.pop("PreToolUse", None)
        if not hooks:
            settings.pop("hooks", None)

    backup = _backup(target)
    _atomic_write(target, settings)
    out = f"mcpgawk guard removed from {target}"
    if backup:
        out += f"\n  previous settings backed up to {backup}"
    return out


def status(path: Path | None = None) -> str:
    target = path or CLAUDE_USER_SETTINGS
    try:
        settings = _load_settings(target)
    except GuardError as exc:
        return f"mcpgawk guard: {exc}"
    if not target.is_file():
        return (f"mcpgawk guard: NOT installed (no {target}).\n"
                f"  `mcpgawk guard install` adds a PreToolUse hook that checks every MCP tool "
                f"call against your approved baseline.")
    if not is_installed(settings):
        others = sum(len(g.get("hooks") or []) for g in _pretooluse_groups(settings)
                     if isinstance(g, dict))
        line = f"mcpgawk guard: NOT installed in {target}"
        if others:
            line += f" ({others} other PreToolUse hook(s) present — install merges, never replaces)"
        return line

    script = hook_script_path()
    healthy = script.is_file()
    lines = [f"mcpgawk guard: INSTALLED in {target}",
             f"  matcher: {MCP_MATCHER} (MCP tool calls only)",
             f"  timeout: {HOOK_TIMEOUT_S}s",
             f"  script:  {script}{'' if healthy else '  ← MISSING, the hook cannot run'}"]
    lines.append("  decision: local — reads your approved baseline; nothing leaves this machine.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    action = args[0] if args else "status"
    override = None
    if "--settings" in args:
        i = args.index("--settings")
        if i + 1 >= len(args):
            print("mcpgawk guard: --settings needs a path", file=sys.stderr)
            return 2
        override = Path(args[i + 1])

    try:
        if action in ("status", "-h", "--help"):
            if action != "status":
                print("usage: mcpgawk guard [status|install|uninstall] [--settings PATH]\n\n"
                      "Installs a Claude Code PreToolUse hook that checks every MCP tool call "
                      "against your approved baseline, locally.")
                return 0
            print(status(override))
            return 0
        if action == "install":
            print(install(override))
            print("  Claude Code picks this up without a restart.")
            return 0
        if action == "uninstall":
            print(uninstall(override))
            return 0
    except GuardError as exc:
        print(f"mcpgawk guard: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"mcpgawk guard: could not write settings: {exc}", file=sys.stderr)
        return 2

    print(f"mcpgawk guard: unknown action {action!r} "
          f"(expected status, install or uninstall)", file=sys.stderr)
    return 2
