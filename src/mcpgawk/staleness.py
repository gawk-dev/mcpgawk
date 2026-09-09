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
# `version` is NOT imported: this module defines its own below, deliberately shadowing the
# metadata one, because metadata answers 'what is installed' and every caller here needs
# 'what is running'. Importing it too would be a second, wrong answer sitting in the same
# namespace — and ruff F811 rightly refuses to let both exist.
from importlib.metadata import PackageNotFoundError

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


def _cached() -> tuple[str | None, float | None]:
    """What the cache holds and how old it is, in seconds. (None, None) when there is no usable
    cache. A cached MISS (latest None) still returns its age, so a caller can tell "we asked
    and got nothing" from "we never asked"."""
    try:
        data = json.loads(open(_cache_path(), encoding="utf-8").read())
        age = time.time() - float(data.get("checked_at", 0))
        latest = data.get("latest")
        return (latest if isinstance(latest, str) else None), age
    except (OSError, ValueError, TypeError):
        return None, None


def _fetch_and_cache(fetch) -> str | None:
    """Ask the index NOW and record the answer. Any failure is cached as a MISS with a fresh
    timestamp, so an offline machine retries tomorrow instead of on every single run."""
    latest = None
    try:
        payload = fetch(os.environ.get(ENV_INDEX) or DEFAULT_INDEX)
        candidate = (payload.get("info") or {}).get("version")
        latest = candidate if isinstance(candidate, str) else None
    except Exception:  # noqa: BLE001 — no network is a normal state, not an error
        latest = None
    cache = _cache_path()
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        with open(cache, "w", encoding="utf-8") as f:
            json.dump({"checked_at": time.time(), "latest": latest}, f)
    except OSError:
        pass
    return latest


def _latest(fetch) -> str | None:
    """Newest published version, through the cache — the advisory's path, asked at most once a
    day."""
    latest, age = _cached()
    if age is not None and age < CACHE_TTL_S:
        return latest
    return _fetch_and_cache(fetch)


def version(_name: str = "mcpgawk") -> str:
    """SHADOWS `importlib.metadata.version` ON PURPOSE, module-wide, and answers a better question.

    Metadata says what DISTRIBUTION is installed. This module needs to know what CODE IS RUNNING,
    and the two part company the moment a source tree sits ahead of an older install on sys.path:
    on 2026-09-09 `--version` announced "0.1.34 — OUT OF DATE" while executing 0.1.40, and offered
    an upgrade command that would have done nothing. An editable install goes wrong the same way as
    soon as pyproject is bumped, since its recorded version is fixed at install time.

    Shadowing rather than adding a new seam is deliberate: every caller and every existing test in
    this module already routes through this name, so the correction reaches all of them at once
    instead of leaving some readers on the old answer. The resolution itself has ONE definition, in
    `mcpgawk.__init__`. Raises PackageNotFoundError for an uninstalled source tree so the callers'
    existing handling is unchanged.
    """
    from . import __version__
    if __version__ == "0+unknown":
        raise PackageNotFoundError(_name)
    return __version__


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
    # A DIRECT QUESTION EARNS A FRESH ANSWER. This line used to read through the advisory's
    # 20-hour cache, and on 2026-09-03 it printed "up to date" for a 0.1.33 install nine hours
    # after 0.1.34 reached PyPI — the cache was the sole cause (an empty HOME saw the upgrade).
    # The one command a person runs to ask whether they are current must not answer from
    # yesterday's fetch and call it the present tense. The cache is only a fallback, and when
    # it is used the line says how old it is.
    stale_note = ""
    try:
        # Read the cache BEFORE asking: a failed fetch overwrites it with a miss (so the advisory
        # retries tomorrow, not every run), and the fallback needs the answer that was there.
        cached, age = _cached()
        latest = _fetch_and_cache(fetch)
        if latest is None:
            if cached is not None and age is not None:
                latest = cached
                hours = int(age // 3600)
                stale_note = (f" — PyPI could not be reached just now; this is what it said "
                              f"{hours} hour{'s' if hours != 1 else ''} ago, so a newer build "
                              f"since then would not show here")
    except Exception:                              # noqa: BLE001 — an advisory must never fail
        latest = None
    if latest is None:
        return "could not reach PyPI, so whether this is the newest build is UNKNOWN"
    have, newest = _parse(installed), _parse(latest)
    if have is None or newest is None:
        return f"newest on PyPI is {latest} (could not compare version numbers){stale_note}"
    if newest > have:
        return (f"OUT OF DATE — {latest} is newer. Upgrade: "
                f"uv tool install --force mcpgawk   (or: pip install --upgrade mcpgawk)")
    return "up to date" + stale_note


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
