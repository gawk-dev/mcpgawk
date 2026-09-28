"""SUPPLY-CHAIN — opt-in, egress-required package-registry lookups.

Deliberately NOT part of the default zero-egress scan (same precedent as the opt-in exact
`count_tokens` mode, HANDOFF §7). Only runs when `--supply-chain` is passed. Queries the
public npm registry or PyPI JSON API for the package a stdio server is launched from, and
reports:

  * MISSING   — the registry answered 404: the name is not registered. An AI agent that suggests
                an MCP server which does not exist hands an attacker a name to register
                ("slopsquatting"). Nothing to trust yet; do not launch it.
  * YOUNG     — the NAME was first published fewer than `YOUNG_DAYS` days ago (npm `time.created`,
                PyPI earliest upload across all releases), or has `THIN_RELEASES` releases or fewer.
                A young name is exactly what a squatter registers.
  * DEPRECATED (npm) / YANKED (PyPI) for the resolved version.

A network failure, timeout or any non-404 HTTP status is reported as "could not check" — never as
"does not exist". Only the package name + optional pinned version are ever sent (one GET of the
package's public metadata document) — never the tool inventory, never anything else. A launch
command that does not name a registry package (a path, a script, `uv run`, `npm run`) is skipped,
never sent.

TIMING: the lookup runs BEFORE anything launches and before the launch-consent prompt, for every
stdio target — including servers the person then declines. That is deliberate: it is the only way
a made-up or brand-new name is caught before it runs, and a name the registry does not have is
never launched at all.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

_NPX_LIKE = {"npx", "npm", "pnpm", "yarn", "bunx"}
_PY_LIKE = {"uvx", "uv", "pipx", "pip", "pip3"}
_TIMEOUT = 5.0

#: A name first published fewer than this many days ago is YOUNG.
YOUNG_DAYS = 30
#: A name with this many releases or fewer has a THIN history, whatever its age.
THIN_RELEASES = 2


@dataclass
class SupplyChainFinding:
    ecosystem: str            # "npm" | "pypi"
    package: str
    version: str | None
    deprecated: bool
    detail: str | None = None
    error: str | None = None             # could not check (network, timeout, non-404 status)
    missing: bool = False                # registry answered 404 — the name is not registered
    first_published: str | None = None   # YYYY-MM-DD of the name's first-ever publish
    age_days: int | None = None
    release_count: int | None = None
    young: bool = False                  # age_days < YOUNG_DAYS or release_count <= THIN_RELEASES


def _split_npm_spec(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        rest = spec[1:]
        if "@" in rest:
            name, _, ver = rest.partition("@")
            return f"@{name}", ver
        return spec, None
    if "@" in spec:
        name, _, ver = spec.partition("@")
        return name, ver
    return spec, None


_PYPI_SPEC = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?(.*)$")


def _split_pypi_spec(spec: str) -> tuple[str, str | None]:
    """`pkg`, `pkg==1.2.3`, `pkg[extra]`, uv's `pkg@1.2.3`, `pkg>=1` → (name, exact pin or None)."""
    m = _PYPI_SPEC.match(spec.strip())
    if not m:
        return spec, None
    name, rest = m.group(1), m.group(2).strip()
    if rest.startswith("==") and not rest.startswith("==="):
        pin = rest[2:].split(";")[0].split(",")[0].strip()
        return name, pin or None
    if rest.startswith("@"):
        pin = rest[1:].strip()
        return name, (pin if pin and pin != "latest" else None)
    return name, None


def extract_package(command: str, args: list[str]) -> tuple[str, str] | None:
    """Best-effort: (ecosystem, package-spec) from a stdio launch command. None if unrecognised
    (e.g. a bare local binary) — supply-chain check is skipped, not guessed at."""
    base = command.rsplit("/", 1)[-1]
    tokens = [base, *args]
    if base in _NPX_LIKE:
        for t in tokens[1:]:
            if t.startswith("-"):
                continue
            return "npm", t
    elif base in _PY_LIKE:
        for t in tokens[1:]:
            if t.startswith("-"):
                continue
            return "pypi", t
    return None


# Flags whose VALUE is the package to fetch, and flags whose value is something else to step over.
_NPM_PKG_FLAGS = {"-p", "--package"}
_NPM_VALUE_FLAGS = {"--registry", "--cache", "--prefix", "-C", "--cwd", "--userconfig", "--call", "-c"}
_NPM_RUNNER_SUBCOMMANDS = {"exec", "x", "dlx"}
_PY_PKG_FLAGS = {"--from", "--spec"}
_PY_VALUE_FLAGS = {"--python", "-p", "--with", "--with-requirements", "--directory", "--project",
                   "--index-url", "-i", "--index", "--extra-index-url", "--default-index",
                   "--find-links", "-f", "--cache-dir", "--config-file", "--constraints",
                   "--overrides", "--python-preference"}
_NPM_NAME = re.compile(r"^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$", re.I)
# A registry name, optional extras, then nothing, a version specifier, or uv's `@version` — never a
# path, a URL or a git reference (`git+https://…` would otherwise parse as the name "git").
_PY_SPEC_OK = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?:\[[^\]]*\])?"
                         r"(?:\s*(?:===?|>=|<=|~=|!=|<|>)[^/:@\s]+(?:\s*,\s*(?:===?|>=|<=|~=|!=|<|>)[^/:@\s,]+)*"
                         r"|@[^/:@\s]+)?$")


def _first_positional(args: list[str], pkg_flags: set[str], value_flags: set[str]) -> tuple[str, bool] | None:
    """First positional token, or the value of a package flag. Returns (token, from_pkg_flag)."""
    i = 0
    while i < len(args):
        t = args[i]
        if t.startswith("-"):
            flag, eq, val = t.partition("=")
            if flag in pkg_flags:
                if eq:
                    return val, True
                return (args[i + 1], True) if i + 1 < len(args) else None
            if flag in value_flags and not eq:
                i += 2
                continue
            i += 1
            continue
        return t, False
    return None


def registry_target(command: str, args: list[str]) -> tuple[str, str] | None:
    """(ecosystem, package-spec) ONLY when the launch command names a registry package — the
    stricter sibling of `extract_package`. A 404 is evidence a name does not exist only if what we
    asked about was a name, so a path, a script, `uv run`, `npm run` or a git URL never reaches the
    registry: it returns None ("not recognised") instead of a false "does not exist"."""
    base = command.rsplit("/", 1)[-1]
    rest = list(args)
    if base in _NPX_LIKE:
        if base in {"npm", "pnpm", "yarn"}:
            first = _first_positional(rest, set(), _NPM_VALUE_FLAGS)
            if first is None or first[0] not in _NPM_RUNNER_SUBCOMMANDS:
                return None                      # npm run / install / start … — not a package launch
            rest = rest[rest.index(first[0]) + 1:]
        hit = _first_positional(rest, _NPM_PKG_FLAGS, _NPM_VALUE_FLAGS)
        if hit is None:
            return None
        name, _ = _split_npm_spec(hit[0])
        return ("npm", hit[0]) if _NPM_NAME.match(name) else None
    if base in _PY_LIKE:
        if base == "uv":
            first = _first_positional(rest, set(), _PY_VALUE_FLAGS)
            if first is None or first[0] != "tool":
                return None                      # `uv run` runs a local project or script
            rest = rest[rest.index("tool") + 1:]
            first = _first_positional(rest, set(), _PY_VALUE_FLAGS)
            if first is None or first[0] != "run":
                return None
            rest = rest[rest.index("run") + 1:]
        elif base in {"pipx"}:
            first = _first_positional(rest, set(), _PY_VALUE_FLAGS)
            if first is None or first[0] != "run":
                return None
            rest = rest[rest.index("run") + 1:]
        elif base in {"pip", "pip3"}:
            return None                          # pip installs; it does not launch a server
        hit = _first_positional(rest, _PY_PKG_FLAGS, _PY_VALUE_FLAGS)
        if hit is None:
            return None
        return ("pypi", hit[0]) if _PY_SPEC_OK.match(hit[0].strip()) else None
    return None


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "mcpgawk (local supply-chain check)"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 — explicit opt-in egress
        return json.loads(resp.read().decode("utf-8"))


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _age(finding: SupplyChainFinding, first: datetime | None, releases: int | None,
         now: datetime | None) -> None:
    now = now or datetime.now(timezone.utc)
    finding.release_count = releases
    if first is not None:
        finding.first_published = first.date().isoformat()
        finding.age_days = max(0, (now - first).days)
    finding.young = ((finding.age_days is not None and finding.age_days < YOUNG_DAYS)
                     or (releases is not None and first is not None and releases <= THIN_RELEASES))


def _failure(ecosystem: str, name: str, pin: str | None, e: Exception) -> SupplyChainFinding:
    # A 404 from the registry is an ANSWER — the name is not registered. Everything else (a
    # timeout, DNS, 429, 5xx) is the absence of an answer and must never read as "does not exist".
    if isinstance(e, urllib.error.HTTPError) and e.code == 404:
        return SupplyChainFinding(ecosystem, name, pin, deprecated=False, missing=True)
    return SupplyChainFinding(ecosystem, name, pin, deprecated=False, error=f"{type(e).__name__}: {e}")


# `fetch` is injectable so tests can assert against real registry response shapes without
# making a live network call in CI (a flaky/slow thing to depend on for a pass/fail gate).
# `now` is injectable for the same reason: an age compared against the real clock is a time bomb.
def check_npm(spec: str, fetch=_get_json, now: datetime | None = None) -> SupplyChainFinding:
    name, pin = _split_npm_spec(spec)
    try:
        data = fetch(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
        version = pin or (data.get("dist-tags") or {}).get("latest")
        versions = data.get("versions") or {}
        meta = versions.get(version or "", {})
        dep = meta.get("deprecated")
        f = SupplyChainFinding("npm", name, version, deprecated=bool(dep), detail=dep or None)
        _age(f, _parse_time((data.get("time") or {}).get("created")), len(versions) or None, now)
        return f
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as e:
        return _failure("npm", name, pin, e)


def check_pypi(spec: str, fetch=_get_json, now: datetime | None = None) -> SupplyChainFinding:
    name, pin = _split_pypi_spec(spec)
    try:
        data = fetch(f"https://pypi.org/pypi/{name}/json")
        version = pin or data["info"]["version"]
        all_releases = data.get("releases") or {}
        releases = all_releases.get(version) or []
        yanked = any(r.get("yanked") for r in releases)
        reason = next((r.get("yanked_reason") for r in releases if r.get("yanked")), None)
        f = SupplyChainFinding("pypi", name, version, deprecated=yanked, detail=reason)
        uploads = [t for files in all_releases.values() for r in (files or [])
                   if (t := _parse_time(r.get("upload_time_iso_8601") or r.get("upload_time")))]
        _age(f, min(uploads) if uploads else None,
             sum(1 for files in all_releases.values() if files) or None, now)
        return f
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as e:
        return _failure("pypi", name, pin, e)


def check(command: str, args: list[str], fetch=_get_json,
          now: datetime | None = None) -> SupplyChainFinding | None:
    found = registry_target(command, args)
    if not found:
        return None
    ecosystem, spec = found
    return check_npm(spec, fetch, now) if ecosystem == "npm" else check_pypi(spec, fetch, now)
