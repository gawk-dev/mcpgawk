"""Agent-SKILLS scanning — the free scanner grows the other half of the attack surface.

An agent skill (a `SKILL.md` file plus whatever sits beside it) is model-facing text that gets
loaded straight into an agent's context, with none of the review pressure an MCP server's
tools/list gets. Invariant/Snyk's agent-scan treats skills scanning as half its product — but its
client performs NO analysis: it discovers, parses and uploads raw skill content to Snyk's API,
which returns the verdicts (issue codes E004–E006, W007–W014). This module is our local-first
counterpart: the same discovery breadth, the detection done entirely on this machine, no content
ever uploaded.

Coverage honesty (stated here once, surfaced by the CLI):
  * COVERED, signal-grade: suspicious download URLs (shorteners / raw IPs / file hosts /
    executable downloads, ≈E005), fetch-and-execute incl. base64-hidden (≈E006 subset),
    hardcoded secrets with redacted evidence (≈W008), credential-emission instructions (≈W007),
    runtime instruction fetch (≈W012), missing/unparseable SKILL.md (≈W014), plus every existing
    text detector: hidden Unicode (≈W021), hidden markup, reader-directed injection (≈E004
    signal-grade), secret-exfil directives.
  * NOT covered, deliberately: semantic intent classification (full E004), financial-capability
    (W009), third-party-content-exposure (W011) and system-service (W013) classification — those
    need a model, and a regex pretending to be one would alternate between silence and noise.
    They are listed as not-checked rather than silently absent.

Skill-directory path inventory cross-checked against Snyk agent-scan v0.5.12 (Apache-2.0,
reference/mcp-scan-hist — its researched, source-cited discoverers) and trimmed to user-scope +
system-scope paths that exist on disk. Discovery here NEVER executes anything and reads only
files under the skill roots, with hard bounds (depth/count/size) the reference walk lacks.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from sys import platform as _sys_platform

from .signals import Finding, _scan_text, detect_skill_content, detect_skill_malformed

# Registered hosts — same canary discipline as discover.SUPPORTED_CLIENTS: adding a path below
# without registering its host here (or vice versa) fails tests/test_canary_skills.py.
SUPPORTED_SKILL_HOSTS = (
    "amp",
    "antigravity",
    "claude-code",
    "codex",
    "cursor",
    "gemini-cli",
    "kiro",
    "opencode",
    "vscode-copilot",
    "windsurf",
)

#: (host, home-relative path). A path may be shared between hosts (e.g. ~/.agents/skills) —
#: dedup happens on the resolved directory, attribution keeps every host that watches it.
_HOME_SKILL_DIRS: tuple[tuple[str, str], ...] = (
    ("claude-code", ".claude/skills"),
    ("codex", ".agents/skills"),
    ("codex", ".codex/skills"),
    ("cursor", ".cursor/skills"),
    ("cursor", ".cursor/skills-cursor"),
    ("vscode-copilot", ".copilot/skills"),
    ("windsurf", ".codeium/windsurf/skills"),
    ("antigravity", ".gemini/skills"),
    ("antigravity", ".gemini/antigravity/skills"),
    ("antigravity", ".agent/skills"),
    ("antigravity", ".agents/skills"),
    ("gemini-cli", ".gemini/skills"),
    ("kiro", ".kiro/skills"),
    ("opencode", ".config/opencode/skills"),
    ("opencode", ".config/opencode/skill"),
    ("opencode", ".claude/skills"),
    ("opencode", ".agents/skills"),
    ("amp", ".config/agents/skills"),
)

#: Glob patterns relative to home (plugin caches: each match is itself a skills root).
_HOME_SKILL_GLOBS: tuple[tuple[str, str], ...] = (
    ("claude-code", ".claude/plugins/cache/*/skills"),
    ("claude-code", ".claude/plugins/cache/*/*/skills"),
    ("opencode", ".cache/opencode/skills/*"),
)

#: Absolute system-scope paths (admin-managed skills apply to every user).
_SYSTEM_SKILL_DIRS: tuple[tuple[str, str], ...] = (
    ("codex", "/etc/codex/skills"),
    ("windsurf", "/etc/windsurf/skills"),
)
_DARWIN_SKILL_DIRS: tuple[tuple[str, str], ...] = (
    ("windsurf", "/Library/Application Support/Windsurf/skills"),
)

#: Project-relative skill roots, applied to explicitly given directories (and their ancestors
#: are NOT walked — an explicit path means exactly that path's project).
PROJECT_SKILL_DIRS: tuple[str, ...] = (
    ".claude/skills",
    ".agents/skills",
    ".agent/skills",
    ".cursor/skills",
    ".windsurf/skills",
    ".kiro/skills",
    ".opencode/skills",
    ".opencode/skill",
    ".amp/skills",
    ".github/skills",
)

_MAX_WALK_DEPTH = 10        # the reference commands-walk cap; its skills walk had NO bound
_MAX_FILES_PER_SKILL = 200
_MAX_TEXT_BYTES = 1_000_000
_TEXT_SUFFIXES = {".md", ".txt", ".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".yaml", ".yml",
                  ".json", ".toml"}


@dataclass
class SkillFile:
    relpath: str
    kind: str            # "text" | "binary" | "oversize"
    sha256: str = ""     # binary/oversize files: identity without content


@dataclass
class SkillSnapshot:
    name: str                      # frontmatter name, or the directory name if unparseable
    root: str                      # absolute path of the skill directory
    hosts: list[str]               # which agent host(s) load skills from this root
    description: str = ""          # frontmatter description ("" when absent)
    files: list[SkillFile] = field(default_factory=list)
    files_seen: int = 0
    capped: bool = False
    findings: list[Finding] = field(default_factory=list)


def _frontmatter(text: str) -> tuple[dict[str, str], str | None]:
    """Minimal frontmatter reader: presence + top-level scalar keys. Detection needs exactly
    `name`/`description` existence — a YAML dependency for that would be a new supply-chain
    exposure in a security scanner, bought to parse two fields."""
    if not text.startswith("---"):
        return {}, "no frontmatter block — the skill declares no name/description to review"
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, "unterminated frontmatter block"
    fields: dict[str, str] = {}
    for line in parts[1].splitlines():
        if ":" in line and not line.startswith((" ", "\t", "#")):
            key, _, value = line.partition(":")
            fields[key.strip().lower()] = value.strip().strip("'\"")
    missing = [k for k in ("name", "description") if not fields.get(k)]
    if missing:
        return fields, f"frontmatter missing required field(s): {', '.join(missing)}"
    return fields, None


def _find_skill_md(directory: Path) -> Path | None:
    try:
        for child in directory.iterdir():
            if child.is_file() and child.name.lower() == "skill.md":
                return child
    except OSError:
        pass
    return None


def _walk_bounded(root: Path):
    """Deterministic bounded walk — depth/count enforcement happens in parse_skill."""
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            children = sorted(d.iterdir(), reverse=True)
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue  # a symlink can point anywhere on disk — out of scope by design
            if child.is_dir():
                if depth + 1 <= _MAX_WALK_DEPTH:
                    stack.append((child, depth + 1))
            elif child.is_file():
                yield child


def parse_skill(directory: Path, hosts: list[str]) -> SkillSnapshot:
    """One skill directory → snapshot + findings. Never raises: unreadable/unparseable structure
    is a `skill:malformed` finding, not an exception — a skill that resists review is the point."""
    directory = directory.resolve()
    snap = SkillSnapshot(name=directory.name, root=str(directory), hosts=hosts)

    skill_md = _find_skill_md(directory)
    if skill_md is None:
        snap.findings.extend(detect_skill_malformed(
            "no SKILL.md in the skill directory — nothing states what this skill claims to do",
            f"{directory.name}/"))
    else:
        try:
            text = skill_md.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            text = ""
            snap.findings.extend(detect_skill_malformed(
                f"SKILL.md unreadable: {type(exc).__name__}: {exc}", f"{directory.name}/SKILL.md"))
        fields, structural = _frontmatter(text)
        if structural:
            snap.findings.extend(detect_skill_malformed(structural, f"{directory.name}/SKILL.md"))
        snap.name = fields.get("name") or directory.name
        snap.description = fields.get("description", "")

    for f in _walk_bounded(directory):
        snap.files_seen += 1
        if len(snap.files) >= _MAX_FILES_PER_SKILL:
            snap.capped = True
            continue  # keep counting so the cap is quantified
        rel = str(f.relative_to(directory))
        origin = f"{directory.name}/{rel}"
        try:
            size = f.stat().st_size
        except OSError:
            continue
        if f.suffix.lower() not in _TEXT_SUFFIXES:
            snap.files.append(SkillFile(rel, "binary", _sha256(f)))
            continue
        if size > _MAX_TEXT_BYTES:
            snap.files.append(SkillFile(rel, "oversize", _sha256(f)))
            snap.findings.extend(detect_skill_malformed(
                f"text file exceeds {_MAX_TEXT_BYTES} bytes and was NOT content-scanned", origin))
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            snap.findings.extend(detect_skill_malformed(
                f"unreadable: {type(exc).__name__}: {exc}", origin))
            continue
        snap.files.append(SkillFile(rel, "text"))
        # prose_markdown: a skill file is a document, so an HTML comment is authoring, not a
        # poisoning carrier — unless it hides something. See signals._markdown_comment_is_benign.
        snap.findings.extend(_scan_text(text, origin, prose_markdown=f.suffix.lower() == ".md"))
        snap.findings.extend(detect_skill_content(text, origin))
    return snap


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return "unreadable"
    return h.hexdigest()


def _skill_roots(home: Path) -> dict[Path, list[str]]:
    roots: dict[Path, list[str]] = {}

    def add(host: str, p: Path) -> None:
        if not p.is_dir():
            return
        rp = p.resolve()
        hosts = roots.setdefault(rp, [])
        if host not in hosts:
            hosts.append(host)

    for host, rel in _HOME_SKILL_DIRS:
        add(host, home / rel)
    for host, pattern in _HOME_SKILL_GLOBS:
        for match in sorted(home.glob(pattern)):
            add(host, match)
    for host, abs_path in _SYSTEM_SKILL_DIRS:
        add(host, Path(abs_path))
    if _sys_platform == "darwin":
        for host, abs_path in _DARWIN_SKILL_DIRS:
            add(host, Path(abs_path))
    return roots


def discover_skills(home: Path | None = None,
                    explicit_paths: list[Path] | None = None) -> list[SkillSnapshot]:
    """Find and parse every skill. `explicit_paths` entries may be: a skill directory (contains
    SKILL.md), a skills ROOT (its subdirectories are skills), or a project root (its
    PROJECT_SKILL_DIRS are checked). Explicit paths replace host discovery entirely — pointing
    the scanner at something means scanning that thing, not that thing plus your whole machine."""
    snaps: list[SkillSnapshot] = []
    seen: set[str] = set()

    def scan_root(root: Path, hosts: list[str]) -> None:
        try:
            children = sorted(root.iterdir())
        except OSError:
            return
        for child in children:
            if child.is_dir() and not child.is_symlink() and _find_skill_md(child) is not None:
                key = str(child.resolve())
                if key not in seen:
                    seen.add(key)
                    snaps.append(parse_skill(child, hosts))

    if explicit_paths:
        for p in explicit_paths:
            p = p.expanduser()
            if _find_skill_md(p) is not None:               # a single skill directory
                key = str(p.resolve())
                if key not in seen:
                    seen.add(key)
                    snaps.append(parse_skill(p, ["explicit"]))
                continue
            project_roots = [p / rel for rel in PROJECT_SKILL_DIRS if (p / rel).is_dir()]
            if project_roots:                                # a project root
                for r in project_roots:
                    scan_root(r, ["explicit"])
                continue
            if p.is_dir():                                   # a skills root (or empty — say so)
                scan_root(p, ["explicit"])
                continue
            snaps.append(SkillSnapshot(
                name=str(p), root=str(p), hosts=["explicit"],
                findings=detect_skill_malformed("path does not exist or is not a directory",
                                                str(p))))
        return snaps

    home = (home or Path.home()).expanduser()
    for root, hosts in sorted(_skill_roots(home).items()):
        scan_root(root, hosts)
    return snaps
