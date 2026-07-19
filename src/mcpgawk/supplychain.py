"""SUPPLY-CHAIN — opt-in, egress-required package-registry lookups.

Deliberately NOT part of the default zero-egress scan (same precedent as the opt-in exact
`count_tokens` mode, HANDOFF §7). Only runs when `--supply-chain` is passed. Queries the
public npm registry or PyPI JSON API for the package a stdio server is launched from, and
reports whether the resolved version is deprecated (npm) or yanked (PyPI). Only the package
name + optional pinned version are ever sent — never the tool inventory, never anything else.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

_NPX_LIKE = {"npx", "npm", "pnpm", "yarn", "bunx"}
_PY_LIKE = {"uvx", "uv", "pipx", "pip", "pip3"}
_TIMEOUT = 5.0


@dataclass
class SupplyChainFinding:
    ecosystem: str            # "npm" | "pypi"
    package: str
    version: str | None
    deprecated: bool
    detail: str | None = None
    error: str | None = None


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


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "mcpgawk (local supply-chain check)"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 — explicit opt-in egress
        return json.loads(resp.read().decode("utf-8"))


# `fetch` is injectable so tests can assert against real registry response shapes without
# making a live network call in CI (a flaky/slow thing to depend on for a pass/fail gate).
def check_npm(spec: str, fetch=_get_json) -> SupplyChainFinding:
    name, pin = _split_npm_spec(spec)
    try:
        data = fetch(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
        version = pin or (data.get("dist-tags") or {}).get("latest")
        meta = (data.get("versions") or {}).get(version or "", {})
        dep = meta.get("deprecated")
        return SupplyChainFinding("npm", name, version, deprecated=bool(dep), detail=dep or None)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as e:
        return SupplyChainFinding("npm", name, pin, deprecated=False, error=f"{type(e).__name__}: {e}")


def check_pypi(spec: str, fetch=_get_json) -> SupplyChainFinding:
    name, pin = _split_npm_spec(spec)   # same @version convention isn't PyPI's, but handles bare names fine
    try:
        data = fetch(f"https://pypi.org/pypi/{name}/json")
        version = pin or data["info"]["version"]
        releases = data.get("releases", {}).get(version) or []
        yanked = any(r.get("yanked") for r in releases)
        reason = next((r.get("yanked_reason") for r in releases if r.get("yanked")), None)
        return SupplyChainFinding("pypi", name, version, deprecated=yanked, detail=reason)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as e:
        return SupplyChainFinding("pypi", name, pin, deprecated=False, error=f"{type(e).__name__}: {e}")


def check(command: str, args: list[str], fetch=_get_json) -> SupplyChainFinding | None:
    found = extract_package(command, args)
    if not found:
        return None
    ecosystem, spec = found
    return check_npm(spec, fetch) if ecosystem == "npm" else check_pypi(spec, fetch)
