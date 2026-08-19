"""Is THIS install stale? — the check the journey plan requires on every run.

The product's own history motivates it: the author ran a 7-releases-stale build for six days with
nothing warning anyone (tests/test_user_journey.py's preamble). A stale security scanner is worse
than a stale anything-else, because its silence reads as "all clear".

Deliberately small and deliberately quiet:

  * ONE advisory line, on stderr — never stdout, so `--json` consumers are untouched;
  * CACHED (default ~20h): the index is asked at most once a day, not once per run;
  * NEVER load-bearing: any failure — no network, bad JSON, weird versions — returns None. An
    update hint must never fail, slow, or noise up the run it rides on (same rule as the spool:
    logging is a duty, not a precondition);
  * OPT-OUT: MCPGAWK_NO_UPDATE_CHECK=1 disables the check entirely. The fetch is one anonymous
    GET of the public package index — the same egress `scan` already performs for supply-chain
    checks — but a local-first tool owes the user the off switch.

The index URL is overridable (MCPGAWK_UPDATE_INDEX_URL) so tests can point the REAL installed
binary at a file:// fixture instead of pypi.org.
"""
from __future__ import annotations

import json
import os
import re
import time
from importlib.metadata import PackageNotFoundError, version

from . import history, supplychain

#: Sits beside the rest of mcpgawk's state; MCPGAWK_HISTORY relocates it for tests.
CACHE_NAME = "update-check.json"
CACHE_TTL_S = 20 * 3600
ENV_DISABLE = "MCPGAWK_NO_UPDATE_CHECK"
ENV_INDEX = "MCPGAWK_UPDATE_INDEX_URL"
DEFAULT_INDEX = "https://pypi.org/pypi/mcpgawk/json"


def _cache_path() -> str:
    return os.path.join(os.path.dirname(history.default_path()), CACHE_NAME)


def _parse(v: str) -> tuple[int, ...] | None:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:3]) if nums else None


def _latest(fetch) -> str | None:
    """Newest published version, through the cache. Any failure is cached as a MISS with a fresh
    timestamp, so an offline machine retries tomorrow instead of on every single run."""
    cache = _cache_path()
    now = time.time()
    try:
        data = json.loads(open(cache, encoding="utf-8").read())
        if now - float(data.get("checked_at", 0)) < CACHE_TTL_S:
            latest = data.get("latest")
            return latest if isinstance(latest, str) else None
    except (OSError, ValueError):
        pass

    latest = None
    try:
        payload = fetch(os.environ.get(ENV_INDEX) or DEFAULT_INDEX)
        candidate = (payload.get("info") or {}).get("version")
        latest = candidate if isinstance(candidate, str) else None
    except Exception:  # noqa: BLE001 — no network is a normal state, not an error
        latest = None
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        with open(cache, "w", encoding="utf-8") as f:
            json.dump({"checked_at": now, "latest": latest}, f)
    except OSError:
        pass
    return latest


def currency_line(fetch=supplychain._get_json) -> str:
    """The one line `--version` prints UNDER the version: is this build current, or not, or unknown.

    `advisory()` deliberately stays silent on "up to date", "disabled" and "could not tell" — right
    for a warning nobody asked for, wrong here. A beta tester ran `mcpgawk --version`, read
    `mcpgawk 0.1.29`, and had no way to know whether that was the current build; answering it took
    eight checks across three registries (2026-08-19). The one command a person runs when they want
    to know if they are current should answer that question.

    Never guesses: an unreachable index says so rather than implying either answer.
    """
    try:
        installed = version("mcpgawk")
    except PackageNotFoundError:
        return "installed from source — no published version to compare against"
    if os.environ.get(ENV_DISABLE) == "1":
        return f"update check disabled ({ENV_DISABLE}=1) — cannot say whether this is current"
    try:
        latest = _latest(fetch)
    except Exception:                              # noqa: BLE001 — an advisory must never fail
        latest = None
    if latest is None:
        return "could not reach PyPI, so whether this is the newest build is UNKNOWN"
    have, newest = _parse(installed), _parse(latest)
    if have is None or newest is None:
        return f"newest on PyPI is {latest} (could not compare version numbers)"
    if newest > have:
        return (f"OUT OF DATE — {latest} is newer. Upgrade: "
                f"uv tool install --force mcpgawk   (or: pip install --upgrade mcpgawk)")
    return "up to date"


def advisory(fetch=supplychain._get_json) -> str | None:
    """The one line, or None. None means: up to date, disabled, or COULD NOT TELL — an advisory
    that guesses would train people to ignore it, so silence covers every uncertain case."""
    try:
        if os.environ.get(ENV_DISABLE) == "1":
            return None
        try:
            installed = version("mcpgawk")
        except PackageNotFoundError:
            return None
        latest = _latest(fetch)
        if latest is None:
            return None
        have, newest = _parse(installed), _parse(latest)
        if have is None or newest is None or newest <= have:
            return None
        return (f"mcpgawk {latest} is out (you have {installed}) — a stale scanner misses what "
                f"newer checks catch. Upgrade: uv tool install --force mcpgawk")
    except Exception:  # noqa: BLE001 — an update hint must never cost a run anything
        return None
