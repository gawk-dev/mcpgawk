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

from . import credentials

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
_SHAPE_ZED = "zed_context_servers"        # {"context_servers": {...}} — Zed's name for the same thing
_SHAPE_OPENCODE = "opencode_mcp"          # {"mcp": {"<n>": {"type": "local", "command": [...]}}}
_SHAPE_AMP = "amp_settings"               # {"amp.mcpServers": {...}} — note the dotted key
_SHAPE_GOOSE_YAML = "goose_yaml"          # YAML: extensions: {<n>: {type, cmd, args | uri}}
_SHAPE_CONTINUE_YAML = "continue_yaml"    # YAML: mcpServers is a LIST of {name, command|url, ...}


#: Every IDE client discovery supports. This is the CANARY REGISTRY (F3 pattern): the anti-drift
#: harness asserts it agrees exactly with what `_locations` actually returns on every platform, and
#: that each named client has a live end-to-end discovery test. Adding a client here without wiring
#: it up — or wiring one up without naming it here — fails the build in the same PR.
SUPPORTED_CLIENTS: tuple[str, ...] = (
    "amp", "antigravity", "claude-code", "claude-desktop", "claude-desktop-extension", "cline",
    "codex", "continue", "cursor", "gemini-cli", "goose", "junie", "kimi", "kiro", "lmstudio",
    "opencode", "roo", "vscode", "warp", "windsurf", "zed",
)

#: The config SHAPES we know how to read. Same lock: a new shape needs a live test that proves
#: servers are actually extracted from it, not just that the file was found.
SUPPORTED_SHAPES: tuple[str, ...] = (
    _SHAPE_AMP, _SHAPE_CLAUDE_CODE, _SHAPE_CODEX_TOML, _SHAPE_CONTINUE_YAML, _SHAPE_DXT_MANIFEST,
    _SHAPE_GOOSE_YAML, _SHAPE_MCPSERVERS, _SHAPE_OPENCODE, _SHAPE_VSCODE_MCP,
    _SHAPE_VSCODE_SERVERS, _SHAPE_ZED,
)

#: Clients whose config location could NOT be verified against official documentation, recorded
#: so the gap is a decision on file rather than an oversight. Adding a guessed path would let us
#: CLAIM support while finding nothing — the exact "absence reads as safety" failure this module
#: exists to avoid (see docs/research-litellm-onboarding-gateway-journey-2026-08-01.md §3):
#:   * Trae — docs describe only the in-app "Add manually" dialog; the paths circulating come
#:     from a community issue and disagree with each other.
#:   * JetBrains AI Assistant — verified UI-only: servers live in IDE options, with no documented
#:     on-disk file. Its sibling Junie DOES have one and is supported below.
UNVERIFIED_CLIENTS: tuple[str, ...] = ("trae", "jetbrains-ai-assistant")


def _locations(platform: str) -> list[tuple[str, str, str]]:
    mac = platform == "darwin"
    win = platform.startswith("win")
    locs: list[tuple[str, str, str]] = []

    def add(client: str, mac_p: str | None, linux_p: str | None, win_p: str | None, shape: str) -> None:
        p = mac_p if mac else (win_p if win else linux_p)
        if p:
            locs.append((client, p, shape))

    # LINUX CLAUDE DESKTOP (decision, 2026-08-02): Anthropic now ships an official Linux build
    # (code.claude.com/docs/en/desktop-linux, ~June 2026) but documents NO config path for it;
    # `~/.config/Claude/…` is corroborated only by community sources. Read it anyway: a Linux
    # user previously got NOTHING from this client, and the downside of a wrong path here is an
    # `absent` row in a report that names every location examined — never a silent miss, and
    # never a claim of coverage. Revisit when Anthropic documents the path.
    add("claude-desktop",
        "Library/Application Support/Claude/claude_desktop_config.json",
        ".config/Claude/claude_desktop_config.json",
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
    # Kimi CLI: servers in ~/.kimi/mcp.json (Claude Desktop-compatible shape); its HOOKS live
    # separately in ~/.kimi/config.toml — see agents.py.
    add("kimi", ".kimi/mcp.json", ".kimi/mcp.json", ".kimi/mcp.json", _SHAPE_MCPSERVERS)
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

    # --- clients added 2026-08-02, each path checked against official docs or the project's own
    # --- source (research: docs/research-mcp-client-config-paths-2026-08-02.md). Anything that
    # --- could not be verified is in UNVERIFIED_CLIENTS above rather than guessed at here.

    # Cline: a VS Code extension, so its config lives in VS Code's per-extension globalStorage
    # (path construction verified in cline's own disk.ts), plus a standalone CLI location.
    _CLINE_EXT = "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
    add("cline",
        f"Library/Application Support/Code/User/{_CLINE_EXT}",
        f".config/Code/User/{_CLINE_EXT}",
        f"AppData/Roaming/Code/User/{_CLINE_EXT}", _SHAPE_MCPSERVERS)
    add("cline", ".cline/data/settings/cline_mcp_settings.json",
        ".cline/data/settings/cline_mcp_settings.json",
        ".cline/data/settings/cline_mcp_settings.json", _SHAPE_MCPSERVERS)
    # Roo Code: same VS Code globalStorage convention (extension id third-party-documented; the
    # project itself is ARCHIVED as of 2026-05, so this serves existing installs). Its
    # project-scoped `.roo/mcp.json` is the officially documented one — see _PROJECT_LOCATIONS.
    _ROO_EXT = "globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"
    add("roo",
        f"Library/Application Support/Code/User/{_ROO_EXT}",
        f".config/Code/User/{_ROO_EXT}",
        f"AppData/Roaming/Code/User/{_ROO_EXT}", _SHAPE_MCPSERVERS)
    # Zed calls them CONTEXT servers; same MCP underneath, different key.
    add("zed", ".config/zed/settings.json", ".config/zed/settings.json",
        "AppData/Roaming/Zed/settings.json", _SHAPE_ZED)
    # Junie (JetBrains) — the sibling that DOES have a documented file.
    add("junie", ".junie/mcp/mcp.json", ".junie/mcp/mcp.json", ".junie/mcp/mcp.json",
        _SHAPE_MCPSERVERS)
    # LM Studio: the documented path, plus the cache location an open bug report says macOS
    # actually writes. Both are read; whichever exists contributes.
    add("lmstudio", ".lmstudio/mcp.json", ".lmstudio/mcp.json", ".lmstudio/mcp.json",
        _SHAPE_MCPSERVERS)
    add("lmstudio", ".cache/lm-studio/mcp.json", ".cache/lm-studio/mcp.json", None,
        _SHAPE_MCPSERVERS)
    # Warp: note the DOT-prefixed filename inside ~/.warp/.
    add("warp", ".warp/.mcp.json", ".warp/.mcp.json", ".warp/.mcp.json", _SHAPE_MCPSERVERS)
    add("opencode", ".config/opencode/opencode.json", ".config/opencode/opencode.json",
        ".config/opencode/opencode.json", _SHAPE_OPENCODE)
    add("amp", ".config/amp/settings.json", ".config/amp/settings.json",
        ".config/amp/settings.json", _SHAPE_AMP)
    # Goose and Continue are YAML, the only two so far. Without PyYAML their configs report
    # `no-yaml-parser` rather than vanishing (see _yaml_loads).
    add("goose", ".config/goose/config.yaml", ".config/goose/config.yaml",
        "AppData/Roaming/Block/goose/config/config.yaml", _SHAPE_GOOSE_YAML)
    add("continue", ".continue/config.yaml", ".continue/config.yaml",
        ".continue/config.yaml", _SHAPE_CONTINUE_YAML)
    return locs


#: Project-scoped config files, relative to a PROJECT directory rather than to $HOME. These are
#: the shape a team commits to its repo — the dominant pattern for shared MCP configs, and the
#: one discovery was blind to: a server every developer on a project loads was invisible here
#: purely because it lives beside the code instead of in a dotfile.
_PROJECT_LOCATIONS: tuple[tuple[str, str, str], ...] = (
    ("claude-code", ".mcp.json", _SHAPE_MCPSERVERS),
    ("cursor", ".cursor/mcp.json", _SHAPE_MCPSERVERS),
    ("vscode", ".vscode/mcp.json", _SHAPE_VSCODE_SERVERS),
    # Officially documented project scopes for the 2026-08-02 client tier.
    ("roo", ".roo/mcp.json", _SHAPE_MCPSERVERS),
    ("junie", ".junie/mcp/mcp.json", _SHAPE_MCPSERVERS),
    ("warp", ".warp/.mcp.json", _SHAPE_MCPSERVERS),
    ("opencode", "opencode.json", _SHAPE_OPENCODE),
    ("amp", ".amp/settings.json", _SHAPE_AMP),
)

#: How many project directories to sweep. Claude Code's `projects` map grows without bound on a
#: long-lived machine, and discovery must stay fast enough to run on every `mcpgawk scan`.
_MAX_PROJECTS = 40


def project_dirs(home: Path, cwd: Path | None = None) -> list[Path]:
    """Which project directories to look in: the ones this machine's agents actually know about
    (Claude Code records every project it has opened in ~/.claude.json) plus the current working
    directory, which is where a developer running `mcpgawk scan` in their repo expects a hit.

    Newest-first is not available — the file records no timestamps — so the cap takes the map's
    own order and the report names how many were examined, never implying the rest were clean.
    """
    out: list[Path] = []
    seen: set[str] = set()
    try:
        home_resolved = str(home.resolve())
    except OSError:
        home_resolved = str(home)

    def add(p: Path) -> None:
        try:
            rp = p.resolve()
        except OSError:
            return
        # $HOME is itself in Claude Code's project map on a real machine, and sweeping it as a
        # project re-reads ~/.cursor/mcp.json under an absolute path — the same file reported
        # twice, which reads as two sources agreeing when it is one source counted twice.
        if str(rp) == home_resolved:
            return
        if str(rp) not in seen and rp.is_dir():
            seen.add(str(rp))
            out.append(rp)

    if cwd is not None:
        add(cwd)
    data = _read_config(home / ".claude.json")
    projects = (data or {}).get("projects")
    if isinstance(projects, dict):
        for raw in list(projects)[:_MAX_PROJECTS]:
            add(Path(str(raw)))
    return out


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


#: Per-source outcomes for the discovery report. "absent" is the only status that carries no news;
#: every other non-"ok" value is a fact the user must be able to see, because a config that exists
#: and yielded nothing is NOT the same as having no servers (protect.py's rule: "nothing was found"
#: and "nothing was looked at" must never render alike).
ABSENT, UNREADABLE, TOO_LARGE, UNPARSABLE, NO_PARSER, OK = (
    "absent", "unreadable", "too-large", "unparsable", "no-yaml-parser", "ok")


def _yaml_loads(text: str) -> dict[str, Any] | None:
    """Parse YAML if PyYAML is present. Discovery is dependency-light on purpose, so a missing
    parser degrades to a REPORTED gap (`no-yaml-parser`), never to a client that quietly
    contributes nothing — the same rule TOML follows for Codex on Python 3.10."""
    try:
        import yaml as _yaml
    except ImportError:
        return None
    try:
        data = _yaml.safe_load(text)          # safe_load: a config file must never construct objects
    except Exception:                         # noqa: BLE001 — malformed config is skipped, never fatal
        return None
    return data if isinstance(data, dict) else None


def _yaml_available() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


def _read_config_status(path: Path, shape: str = "") -> tuple[dict[str, Any] | None, str]:
    """Read one config file and say WHY when there is nothing to return. The status is the
    difference between a silent miss and a reportable one — a PermissionError, an oversized file
    and a parse failure all used to collapse into the same None as a file that isn't there."""
    try:
        if not path.is_file():
            return None, ABSENT
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            return None, TOO_LARGE  # hostile-fs cap, not a parse verdict
        # utf-8-sig: a BOM-prefixed config (common on Windows and from some editors) used to fail
        # json.loads on the BOM and silently discard the client's ENTIRE config.
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None, UNREADABLE  # PermissionError etc. — reportable, never an exception
    if shape in (_SHAPE_GOOSE_YAML, _SHAPE_CONTINUE_YAML):
        if not _yaml_available():
            return None, NO_PARSER
        data = _yaml_loads(text)
    elif shape == _SHAPE_CODEX_TOML:
        data = _toml_loads(text)
    else:
        data = _tolerant_loads(text)
    return (data, OK) if data is not None else (None, UNPARSABLE)


def _read_config(path: Path, shape: str = "") -> dict[str, Any] | None:
    data, _status = _read_config_status(path, shape)
    return data


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
    if shape == _SHAPE_ZED:
        servers = data.get("context_servers")
        return servers if isinstance(servers, dict) else {}
    if shape == _SHAPE_OPENCODE:
        servers = data.get("mcp")
        return servers if isinstance(servers, dict) else {}
    if shape == _SHAPE_AMP:
        # The key is literally dotted ("amp.mcpServers"), matching how it is written in VS Code
        # settings — not a nested object.
        servers = data.get("amp.mcpServers")
        return servers if isinstance(servers, dict) else {}
    if shape == _SHAPE_GOOSE_YAML:
        exts = data.get("extensions")
        if isinstance(exts, dict):
            return {n: e for n, e in exts.items() if isinstance(e, dict)}
        # The docs show a LIST form; real config.yaml files are commonly the map above. Both are
        # accepted rather than picking one and silently losing the other operator's servers.
        if isinstance(exts, list):
            return {str(e.get("name") or f"extension{i}"): e
                    for i, e in enumerate(exts) if isinstance(e, dict)}
        return {}
    if shape == _SHAPE_CONTINUE_YAML:
        # Continue's `mcpServers` is a LIST whose entries carry their own `name` — the only
        # list-shaped server declaration among every client we read.
        servers = data.get("mcpServers")
        if isinstance(servers, list):
            return {str(e.get("name") or f"server{i}"): e
                    for i, e in enumerate(servers) if isinstance(e, dict)}
        if isinstance(servers, dict):          # tolerate the object form if a user writes one
            return servers
        return {}
    if shape == _SHAPE_VSCODE_MCP:
        mcp = data.get("mcp")
        servers = mcp.get("servers") if isinstance(mcp, dict) else None
        return servers if isinstance(servers, dict) else {}
    if shape == _SHAPE_VSCODE_SERVERS:
        servers = data.get("servers")
        return servers if isinstance(servers, dict) else {}
    servers = data.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


def _normalise_entry(entry: Any) -> Any:
    """Fold client-specific spellings of an endpoint into the two keys the rest of the pipeline
    reads (`probe` launches from entry["command"]/["args"] or entry["url"]).

    Windsurf/Cline write `serverUrl`; Gemini CLI's streamable-HTTP entries write `httpUrl`; Goose
    writes `cmd` and `uri`; opencode writes `command` as a LIST holding the executable and its
    arguments together. Before this each of those was dropped at `_identity` with no trace — the
    server simply wasn't in the fleet, which on a discovery tool reads as "clean".
    """
    if not isinstance(entry, dict):
        return entry
    out = entry
    # opencode: command is ["npx", "-y", "server"] — one list, not command + args.
    cmd = out.get("command")
    if isinstance(cmd, list) and cmd:
        out = {**out, "command": str(cmd[0]), "args": [str(a) for a in cmd[1:]]}
    # Goose: `cmd` instead of `command`.
    if not out.get("command") and out.get("cmd"):
        out = {**out, "command": out["cmd"]}
    if not out.get("url"):
        # Goose remote uses `uri`; Windsurf `serverUrl`; Gemini CLI `httpUrl`.
        alias = out.get("serverUrl") or out.get("httpUrl") or out.get("uri")
        if alias:
            out = {**out, "url": alias}
    return out


def _is_disabled(entry: Any) -> bool:
    """`disabled: true` (Cursor/VS Code mcp.json) means the CLIENT will not launch this server.
    Scanning it as live overstates the fleet; dropping it silently understates it. So it is
    skipped AND counted, and the report names it."""
    return isinstance(entry, dict) and entry.get("disabled") is True


def _identity(entry: dict[str, Any]) -> tuple[Any, ...] | None:
    """The launch identity of a server, for cross-client dedup — a server is the same server whether
    Cursor or VS Code points at it. None for an entry we can't identify/scan (no command and no url)."""
    if not isinstance(entry, dict):
        return None
    if entry.get("command"):
        args = entry.get("args") or []
        # ENV IS PART OF THE IDENTITY. Same binary, different credentials is a DIFFERENT server: two
        # GitHub orgs, two Slack workspaces, dev vs prod tokens — all the same command and args,
        # pointed at different data. Collapsing them scanned the first and left the rest invisible:
        # never measured, never baselined, and therefore never guarded, while the fleet list implied
        # they were covered. Found by planting 33 servers that differed only by env and watching
        # them render as one. Values are only ever compared here, never printed or persisted.
        return ("stdio", entry["command"],
                tuple(args) if isinstance(args, list) else (args,), credentials.material(entry))
    if entry.get("url"):
        # THE SAME REASONING APPLIES TO REMOTE ENTRIES, and it is the common shape for hosted
        # servers: one URL, two accounts, told apart only by the token in `headers`. Keyed on the
        # URL alone, the second was deduped away — never scanned, never baselined, never guarded,
        # while the fleet list implied it was covered. Same helper as history's identity, so the
        # count of servers you have and the baseline a call is judged against cannot disagree.
        return ("remote", entry["url"], credentials.material(entry))
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


def discover_report(home: Path | str | None = None, platform: str | None = None,
                    cwd: Path | str | None = None
                    ) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """The full answer: (servers, sources) — what was found AND what was looked at.

    `sources` has one row per registered location: {client, path, status, servers, disabled,
    unrecognised} where `path` is home-relative, `status` is one of ABSENT/UNREADABLE/TOO_LARGE/
    UNPARSABLE/OK, `disabled` lists entries the client itself has switched off, and `unrecognised`
    lists entries whose launch shape we could not identify (no command/url after normalisation).
    This exists because discover_servers() alone cannot honour the product's own rule — "nothing
    was found" and "nothing was looked at" must never render alike (protect.py) — a BOM'd config,
    a PermissionError and a genuinely empty machine all used to produce the same empty dict.
    """
    home_path = Path(home) if home is not None else Path.home()
    plat = platform if platform is not None else sys.platform
    cwd_path = Path(cwd) if cwd is not None else Path.cwd()

    sources: list[dict[str, Any]] = []
    by_identity: dict[tuple[Any, ...], tuple[str, dict[str, Any]]] = {}
    order: list[tuple[Any, ...]] = []
    # Which client(s) each deduped server came from. Dedup-by-identity is right (scan a server once,
    # not three times) but it was THROWING AWAY the attribution — and "which of my tools is this
    # configured in?" is the first question anyone asks of a fleet list, especially when they want
    # to go and remove it.
    clients_of: dict[tuple[Any, ...], list[str]] = {}
    # …and what each client CALLS it. Attribution without the name is only half the answer: a fleet
    # row showed the first-seen name under every client, so Gemini's group listed a server Gemini's
    # config does not contain, and `--only <the name that client uses>` matched nothing at all.
    # "Which of my tools is this in?" is useless if the row does not use the name you will find there.
    names_of: dict[tuple[Any, ...], dict[str, str]] = {}
    aliases_of: dict[tuple[Any, ...], set[str]] = {}
    def sweep(base: Path, _client: str, rel: str, shape: str, label: str | None = None) -> None:
        # A location may be a GLOB (`Claude Extensions/*/manifest.json`) — some clients install each
        # server in its own directory rather than listing them in one config file. For a glob the
        # report row aggregates its matches; zero matches is ABSENT like a missing file.
        is_glob = "*" in rel
        paths = sorted(base.glob(rel)) if is_glob else [base / rel]
        row: dict[str, Any] = {"client": _client, "path": label or rel, "status": ABSENT,
                               "servers": 0, "disabled": [], "unrecognised": []}
        for path in paths:
            data, status = _read_config_status(path, shape)
            # A problem status sticks even when a later glob match parses fine — one unreadable
            # manifest among ten good ones is still a fact the report must carry.
            if status != ABSENT and row["status"] in (ABSENT, OK):
                row["status"] = status
            if not data:
                continue
            for name, entry in _extract(data, shape).items():
                # WHERE this server was declared. For a Claude Desktop extension that directory is
                # the literal meaning of `${__dirname}` in its own manifest, so without it the
                # server can be displayed but never launched — which is how a whole install
                # channel became unverifiable while the page blamed the user's config (38i-q).
                # Reserved key: `probe` ignores unknown keys and `_identity` never reads it.
                if shape == _SHAPE_DXT_MANIFEST and isinstance(entry, dict):
                    entry = {**entry, "_manifest_dir": str(path.parent)}
                entry = _normalise_entry(entry)
                if _is_disabled(entry):
                    row["disabled"].append(str(name))
                    continue
                ident = _identity(entry)
                if ident is None:
                    row["unrecognised"].append(str(name))
                    continue
                row["servers"] += 1
                if _client not in clients_of.setdefault(ident, []):
                    clients_of[ident].append(_client)   # recorded even on a duplicate sighting
                # First name wins PER CLIENT, so a client that lists the same server twice keeps the
                # name it showed first, and every other client keeps its own.
                names_of.setdefault(ident, {}).setdefault(_client, str(name))
                # …and EVERY name any config gives it, for lookup. A client can list the same
                # server twice under two names; only one can be displayed, but both are names the
                # user can reasonably type at `--only`.
                aliases_of.setdefault(ident, set()).add(str(name))
                if ident in by_identity:
                    continue
                by_identity[ident] = (str(name), entry)
                order.append(ident)
        sources.append(row)

    for _client, rel, shape in _locations(plat):
        sweep(home_path, _client, rel, shape)
    # PROJECT SCOPE. A repo-committed .mcp.json is how a team shares servers, and it was invisible
    # to a $HOME-only sweep — so a whole class of servers (the ones a team agreed on) never
    # appeared on any surface. Only ABSENT-free rows are reported, or an untouched machine would
    # carry 3 noise rows per project it has ever opened.
    for proj in project_dirs(home_path, cwd_path):
        before = len(sources)
        for _client, rel, shape in _PROJECT_LOCATIONS:
            sweep(proj, _client, rel, shape, label=str(proj / rel))
        sources[before:] = [r for r in sources[before:] if r["status"] != ABSENT]

    out: dict[str, dict[str, Any]] = {}
    for ident in order:
        name, entry = by_identity[ident]
        disp, i = name, 2
        while disp in out:  # two DIFFERENT servers with the same config name — disambiguate
            disp, i = f"{name}#{i}", i + 1
        # Attribution rides along under a reserved key. `probe` ignores unknown keys, and _identity
        # never reads it, so this cannot affect what gets scanned or how it dedupes.
        out[disp] = {**entry, "_clients": sorted(clients_of.get(ident, [])),
                     "_names": dict(sorted(names_of.get(ident, {}).items())),
                     "_aliases": sorted(aliases_of.get(ident, set()))}
    return out, sources


def problem_lines(sources: list[dict[str, Any]]) -> list[str]:
    """Human lines for every source that existed but could not be fully used — the render-ready
    half of discover_report(), shared by the CLI and the panel so the two surfaces cannot drift.
    ABSENT rows are silence (no file is not a problem); everything else is named so a partial
    sweep can never pass as a complete one."""
    lines: list[str] = []
    for s in sources:
        where = f"{s['client']}: ~/{s['path']}"
        if s["status"] == NO_PARSER:
            lines.append(f"{where} — this config is YAML and PyYAML is not installed, so this "
                         f"client's servers are NOT included (pip install pyyaml)")
        elif s["status"] not in (OK, ABSENT):
            lines.append(f"{where} — {s['status']} (this client's servers are NOT included)")
        if s.get("unrecognised"):
            names = ", ".join(s["unrecognised"][:4])
            lines.append(f"{where} — {len(s['unrecognised'])} entr"
                         f"{'y' if len(s['unrecognised']) == 1 else 'ies'} in a shape we don't "
                         f"recognise, skipped: {names}")
        if s.get("disabled"):
            names = ", ".join(s["disabled"][:4])
            lines.append(f"{where} — {len(s['disabled'])} server(s) disabled by the client "
                         f"itself, not scanned: {names}")
    return lines


def discover_servers(home: Path | str | None = None, platform: str | None = None,
                     cwd: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Find every scannable MCP server configured on this machine, deduped by launch identity.

    Returns {display_name: entry} ready to hand to `probe`. `home`/`platform` are injectable so this
    is unit-testable against a temp tree without touching the real machine. Callers that need to
    say WHY a fleet looks the way it does use `discover_report()` — same sweep, plus the
    per-source outcome rows.
    """
    servers, _sources = discover_report(home, platform, cwd)
    return servers
