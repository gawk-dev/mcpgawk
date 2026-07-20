"""DISCOVER — find the MCP servers already configured across the machine's IDE clients, zero-config.

`mcpgawk scan` with no arguments should just work: locate every MCP config a developer already has
(Claude Desktop / Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, …), parse it tolerantly, and
return the servers to scan — deduped by launch identity so a server configured in three clients is
scanned once, not three times.

Dependency-light on purpose (no json5): standard JSON covers almost every file; only VS Code's
`settings.json` uses comments/trailing commas, handled by a small STRING-AWARE preprocessor (a naive
`//` strip would corrupt an `https://` url inside a remote server entry — the exact bug this avoids).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_MAX_CONFIG_BYTES = 20 * 1024 * 1024  # hostile-fs cap: never read a 2GB "config"

# Per-OS config locations. Each: (client, relative-path-from-home, shape). `shape` picks how to pull
# the server map out of the parsed JSON — see _extract(). Order matters only for which display name a
# deduped server keeps (first sighting wins).
_SHAPE_MCPSERVERS = "mcpServers"          # {"mcpServers": {...}}
_SHAPE_CLAUDE_CODE = "claude_code"        # {"projects": {"<path>": {"mcpServers": {...}}}}
_SHAPE_VSCODE_SERVERS = "vscode_servers"  # {"servers": {...}}
_SHAPE_VSCODE_MCP = "vscode_mcp"          # {"mcp": {"servers": {...}}}
_SHAPE_CODEX_TOML = "codex_toml"          # TOML: [mcp_servers.<name>] command/args | url
_SHAPE_DXT_MANIFEST = "dxt_manifest"      # {"name": ..., "server": {"mcp_config": {...}}} — one per dir


#: Every IDE client discovery supports. This is the CANARY REGISTRY (F3 pattern): the anti-drift
#: harness asserts it agrees exactly with what `_locations` actually returns on every platform, and
#: that each named client has a live end-to-end discovery test. Adding a client here without wiring
#: it up — or wiring one up without naming it here — fails the build in the same PR.
SUPPORTED_CLIENTS: tuple[str, ...] = (
    "antigravity", "claude-code", "claude-desktop", "claude-desktop-extension", "codex", "cursor",
    "gemini-cli", "kiro", "vscode", "windsurf",
)

#: The config SHAPES we know how to read. Same lock: a new shape needs a live test that proves
#: servers are actually extracted from it, not just that the file was found.
SUPPORTED_SHAPES: tuple[str, ...] = (
    _SHAPE_CLAUDE_CODE, _SHAPE_CODEX_TOML, _SHAPE_DXT_MANIFEST, _SHAPE_MCPSERVERS,
    _SHAPE_VSCODE_MCP, _SHAPE_VSCODE_SERVERS,
)


def _locations(platform: str) -> list[tuple[str, str, str]]:
    mac = platform == "darwin"
    win = platform.startswith("win")
    locs: list[tuple[str, str, str]] = []

    def add(client: str, mac_p: str | None, linux_p: str | None, win_p: str | None, shape: str) -> None:
        p = mac_p if mac else (win_p if win else linux_p)
        if p:
            locs.append((client, p, shape))

    add("claude-desktop",
        "Library/Application Support/Claude/claude_desktop_config.json", None,
        "AppData/Roaming/Claude/claude_desktop_config.json", _SHAPE_MCPSERVERS)
    add("claude-code", ".claude.json", ".claude.json", ".claude.json", _SHAPE_CLAUDE_CODE)
    add("cursor", ".cursor/mcp.json", ".cursor/mcp.json", ".cursor/mcp.json", _SHAPE_MCPSERVERS)
    # VS Code: servers can live in settings.json (under "mcp.servers") OR a dedicated mcp.json.
    add("vscode",
        "Library/Application Support/Code/User/settings.json", ".config/Code/User/settings.json",
        "AppData/Roaming/Code/User/settings.json", _SHAPE_VSCODE_MCP)
    add("vscode",
        "Library/Application Support/Code/User/mcp.json", ".config/Code/User/mcp.json",
        "AppData/Roaming/Code/User/mcp.json", _SHAPE_VSCODE_SERVERS)
    add("vscode", None, ".vscode/mcp.json", ".vscode/mcp.json", _SHAPE_VSCODE_SERVERS)
    add("windsurf",
        ".codeium/windsurf/mcp_config.json", ".codeium/windsurf/mcp_config.json",
        ".codeium/windsurf/mcp_config.json", _SHAPE_MCPSERVERS)
    # Long tail — all the plain-`mcpServers` shape, pure data:
    add("gemini-cli", ".gemini/settings.json", ".gemini/settings.json", ".gemini/settings.json", _SHAPE_MCPSERVERS)
    add("kiro", ".kiro/settings/mcp.json", ".kiro/settings/mcp.json", ".kiro/settings/mcp.json", _SHAPE_MCPSERVERS)
    add("antigravity",
        ".gemini/antigravity/mcp_config.json", ".gemini/antigravity/mcp_config.json",
        ".gemini/antigravity/mcp_config.json", _SHAPE_MCPSERVERS)
    # Codex keeps its config in TOML, not JSON — the only client so far that does. Its servers were
    # invisible purely because we assumed every client speaks JSON.
    add("codex", ".codex/config.toml", ".codex/config.toml", ".codex/config.toml", _SHAPE_CODEX_TOML)
    # Claude Desktop EXTENSIONS are a separate install channel: each one ships its own manifest and
    # is NEVER written into claude_desktop_config.json, so reading that file alone misses every
    # extension the user installed from the directory. One server per manifest, hence the glob.
    add("claude-desktop-extension",
        "Library/Application Support/Claude/Claude Extensions/*/manifest.json", None,
        "AppData/Roaming/Claude/Claude Extensions/*/manifest.json", _SHAPE_DXT_MANIFEST)
    return locs


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments — STRING-AWARE, so `//` inside an "https://…" value survives."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:  # escape: keep the escaped char verbatim
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _drop_trailing_commas(text: str) -> str:
    """Remove a comma that directly precedes a } or ] — STRING-AWARE (won't touch a comma in a value)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # skip the comma
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _tolerant_loads(text: str) -> dict[str, Any] | None:
    """Standard JSON first (the common case); only on failure apply the string-aware jsonc cleanup.
    Returns None on anything that still won't parse or isn't an object — the caller skips it."""
    for candidate in (text, None):
        raw = candidate if candidate is not None else _drop_trailing_commas(_strip_comments(text))
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        return data if isinstance(data, dict) else None
    return None


def _toml_loads(text: str) -> dict[str, Any] | None:
    """Parse TOML with the stdlib (3.11+) or the `tomli` backport, and simply give up if neither is
    available. Discovery is dependency-light on purpose: missing one client's config format must
    degrade to "that client wasn't scanned", never to an install error or a crash."""
    try:
        import tomllib as _toml
    except ImportError:                       # pragma: no cover - 3.10 only
        try:
            import tomli as _toml             # type: ignore[no-redef]
        except ImportError:
            return None
    try:
        data = _toml.loads(text)
    except Exception:                         # noqa: BLE001 — malformed config is skipped, never fatal
        return None
    return data if isinstance(data, dict) else None


def _read_config(path: Path, shape: str = "") -> dict[str, Any] | None:
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None  # PermissionError etc. — a missing/unreadable config is not an error, just absent
    if shape == _SHAPE_CODEX_TOML:
        return _toml_loads(text)
    return _tolerant_loads(text)


def _extract(data: dict[str, Any], shape: str) -> dict[str, Any]:
    """Pull the {name: entry} server map out of a parsed config by its shape."""
    if shape == _SHAPE_CLAUDE_CODE:
        # ~/.claude.json holds servers in TWO places and we must read BOTH:
        #   * top-level `mcpServers` — where `claude mcp add -s user` writes (USER scope), and
        #   * `projects.<abs-path>.mcpServers` — per-project (LOCAL/PROJECT scope).
        # The original code read only the per-project half, on an explicit comment claiming there is
        # no top-level key. That was simply wrong, and it was invisible because the one server that
        # happened to be in BOTH places still showed up. Live cost on the author's own machine: a
        # user-scope server was silently absent from every scan — a discovery tool
        # reporting a clean, complete-looking fleet it had not actually enumerated.
        merged: dict[str, Any] = {}
        if isinstance(data.get("mcpServers"), dict):
            merged.update(data["mcpServers"])
        projects = data.get("projects")
        if isinstance(projects, dict):
            for proj in projects.values():
                if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
                    merged.update(proj["mcpServers"])
        return merged
    if shape == _SHAPE_CODEX_TOML:
        # `[mcp_servers.<name>]` only. config.toml also carries `[projects."..."]` and top-level
        # settings, none of which are servers — reading the whole table would invent entries.
        servers = data.get("mcp_servers")
        return {n: e for n, e in servers.items() if isinstance(e, dict)} if isinstance(servers, dict) else {}
    if shape == _SHAPE_DXT_MANIFEST:
        # One extension = one server. The launch spec lives at server.mcp_config, and the human name
        # at the manifest's top level. `${__dirname}` placeholders are left ALONE: they're resolved
        # by the host at launch, and the consent prompt should show the user what the host will
        # actually run rather than a path we guessed at.
        server = data.get("server")
        cfg = server.get("mcp_config") if isinstance(server, dict) else None
        if not isinstance(cfg, dict) or not (cfg.get("command") or cfg.get("url")):
            return {}
        return {str(data.get("name") or data.get("display_name") or "extension"): cfg}
    if shape == _SHAPE_VSCODE_MCP:
        mcp = data.get("mcp")
        servers = mcp.get("servers") if isinstance(mcp, dict) else None
        return servers if isinstance(servers, dict) else {}
    if shape == _SHAPE_VSCODE_SERVERS:
        servers = data.get("servers")
        return servers if isinstance(servers, dict) else {}
    servers = data.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


def _identity(entry: dict[str, Any]) -> tuple[Any, ...] | None:
    """The launch identity of a server, for cross-client dedup — a server is the same server whether
    Cursor or VS Code points at it. None for an entry we can't identify/scan (no command and no url)."""
    if not isinstance(entry, dict):
        return None
    if entry.get("command"):
        args = entry.get("args") or []
        return ("stdio", entry["command"], tuple(args) if isinstance(args, list) else (args,))
    if entry.get("url"):
        return ("remote", entry["url"])
    return None


def detect_unscannable(home: Path | str | None = None,
                       platform: str | None = None) -> list[dict[str, str]]:
    """MCP capabilities that exist for this user but that NO local scan can reach.

    Two kinds, and both matter because staying silent about them lets the fleet list imply a
    completeness it doesn't have:

      * ACCOUNT-HOSTED connectors (claude.ai Gmail/Drive/Canva/…): configured in the user's
        Anthropic account, executed on Anthropic's infrastructure. There is no local endpoint and no
        local config — nothing to connect to, so they can be NAMED but never measured.
      * NATIVE-MESSAGING hosts (claude-in-chrome): a browser capability wired through a Chrome host
        manifest, not an MCP server entry at all.

    This list is DELIBERATELY described as incomplete by its caller: the evidence is a local cache
    of connectors that happened to need auth, so a connector the user added and never re-authorised
    (canva, on the author's own machine) leaves no trace on disk. Reporting it as the definitive set
    would be the same overclaim we just fixed in discovery.
    """
    home_path = Path(home) if home is not None else Path.home()
    plat = platform if platform is not None else sys.platform
    found: list[dict[str, str]] = []

    cache = _read_config(home_path / ".claude" / "mcp-needs-auth-cache.json")
    for name in sorted(cache or {}):
        found.append({"name": str(name), "kind": "account-hosted",
                      "why": "runs in your Anthropic account — no local endpoint to scan"})

    hosts = {
        "darwin": "Library/Application Support/Google/Chrome/NativeMessagingHosts",
        "linux": ".config/google-chrome/NativeMessagingHosts",
    }.get("darwin" if plat == "darwin" else "linux" if not plat.startswith("win") else "win",
          "AppData/Local/Google/Chrome/User Data/NativeMessagingHosts")
    host_dir = home_path / hosts
    if host_dir.is_dir():
        for manifest in sorted(host_dir.glob("com.anthropic.*.json")):
            found.append({"name": manifest.stem.replace("com.anthropic.", "").replace("_", "-"),
                          "kind": "browser-host",
                          "why": "a Chrome native-messaging host, not an MCP server entry"})
    return found


def discover_servers(home: Path | str | None = None, platform: str | None = None) -> dict[str, dict[str, Any]]:
    """Find every scannable MCP server configured on this machine, deduped by launch identity.

    Returns {display_name: entry} ready to hand to `probe`. `home`/`platform` are injectable so this
    is unit-testable against a temp tree without touching the real machine.
    """
    home_path = Path(home) if home is not None else Path.home()
    plat = platform if platform is not None else sys.platform

    by_identity: dict[tuple[Any, ...], tuple[str, dict[str, Any]]] = {}
    order: list[tuple[Any, ...]] = []
    # Which client(s) each deduped server came from. Dedup-by-identity is right (scan a server once,
    # not three times) but it was THROWING AWAY the attribution — and "which of my tools is this
    # configured in?" is the first question anyone asks of a fleet list, especially when they want
    # to go and remove it.
    clients_of: dict[tuple[Any, ...], list[str]] = {}
    for _client, rel, shape in _locations(plat):
        # A location may be a GLOB (`Claude Extensions/*/manifest.json`) — some clients install each
        # server in its own directory rather than listing them in one config file.
        paths = sorted(home_path.glob(rel)) if "*" in rel else [home_path / rel]
        for path in paths:
            data = _read_config(path, shape)
            if not data:
                continue
            for name, entry in _extract(data, shape).items():
                ident = _identity(entry)
                if ident is None:
                    continue
                if _client not in clients_of.setdefault(ident, []):
                    clients_of[ident].append(_client)   # recorded even on a duplicate sighting
                if ident in by_identity:
                    continue
                by_identity[ident] = (str(name), entry)
                order.append(ident)

    out: dict[str, dict[str, Any]] = {}
    for ident in order:
        name, entry = by_identity[ident]
        disp, i = name, 2
        while disp in out:  # two DIFFERENT servers with the same config name — disambiguate
            disp, i = f"{name}#{i}", i + 1
        # Attribution rides along under a reserved key. `probe` ignores unknown keys, and _identity
        # never reads it, so this cannot affect what gets scanned or how it dedupes.
        out[disp] = {**entry, "_clients": sorted(clients_of.get(ident, []))}
    return out
