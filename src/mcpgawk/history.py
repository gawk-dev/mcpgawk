"""Local, human-readable drift history. JSON on disk — never leaves the machine.

Default: $MCPGAWK_HISTORY or ~/.mcpgawk/history.json. This is the ONLY state mcpgawk persists,
and it's the user's own machine. No sync, no cloud.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from typing import Any

from .probe import ServerSnapshot


def default_path() -> str:
    return os.environ.get("MCPGAWK_HISTORY") or os.path.expanduser("~/.mcpgawk/history.json")


def load(path: str | None = None) -> dict[str, Any]:
    path = path or default_path()
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"servers": {}}


def save(store: dict[str, Any], path: str | None = None) -> None:
    path = path or default_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Unique temp name per process: a FIXED `path + ".tmp"` meant two concurrent scans wrote the
    # same temp file and one produced a truncated/interleaved JSON before renaming it over the real
    # history — losing the whole store, not just one record.
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())   # the rename is atomic; without fsync its CONTENT need not be
        os.replace(tmp, path)      # atomic
    finally:
        if os.path.exists(tmp):    # a failed write must not litter the user's ~/.mcpgawk
            try:
                os.remove(tmp)
            except OSError:
                pass


@contextmanager
def locked(path: str | None = None):
    """Hold an exclusive lock for a whole read-modify-write cycle.

    `load()` → mutate → `save()` is a read-modify-write, and mcpgawk legitimately runs concurrently
    (a zero-arg scan in one terminal, a CI scan in another). Unserialised, the second writer's
    `save()` overwrites a store loaded before the first writer's append — silently dropping drift
    history, which is the one thing this file exists to keep.

    Degrades to a no-op where advisory locks aren't available (Windows without msvcrt, exotic
    filesystems). Losing the lock must never stop a scan — history is a convenience, not the
    product, and a scanner that refuses to run because it can't lock a cache is worse than one that
    races on it."""
    path = path or default_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock_path = path + ".lock"
    fh = None
    try:
        fh = open(lock_path, "a+")
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except (ImportError, AttributeError, OSError):
            try:
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            except Exception:      # noqa: BLE001 — no lock available; proceed unserialised
                pass
        yield
    except OSError:
        yield                      # could not even open the lock file — still let the scan finish
    finally:
        if fh is not None:
            try:
                fh.close()         # closing releases both flock and msvcrt locks
            except OSError:
                pass


def record(key: str, rec: dict[str, Any], path: str | None = None,
           keep: int = 50, migrate_from: tuple[str, ...] = (),
           alias: str | None = None) -> dict[str, Any] | None:
    """Append `rec` under `key` and return the APPROVED baseline, the whole cycle under one lock.

    Returning the baseline from inside the lock is what makes drift correct under concurrency:
    reading "what am I diffing against" and writing "what I see now" have to be one indivisible
    step, or two concurrent scans each diff against a baseline the other just replaced.

    ADR-0012: this returns the last **approved** record, NOT the last *seen* one. Returning the last
    seen record meant a rug-pull was reported exactly once — the poisoned description became the
    baseline and the next scan was silently clean, so an attacker only had to survive one scan. The
    baseline now moves only when a human runs `approve`.

    First sighting is trust-on-first-use: with nothing approved yet, this record becomes the
    baseline and `None` is returned, so a first scan never reports drift against itself.
    """
    path = path or default_path()
    with locked(path):
        store = load(path)
        _migrate(store, key, migrate_from)
        base = approved(store, key)
        entry = store.setdefault("servers", {}).setdefault(key, {})
        if base is None:
            entry["approved"] = rec          # trust-on-first-use
        if alias:
            # The key is the server's asserted identity; the user thinks in config names. Remember
            # every name this server has been configured under so `approve <name>` resolves.
            entry["aliases"] = sorted(set(entry.get("aliases", [])) | {alias})
        append(store, key, rec, keep=keep)
        save(store, path)
    return base


def approve(key: str, path: str | None = None) -> dict[str, Any] | None:
    """Adopt the most recent sighting of `key` as the approved baseline. Returns it.

    The explicit acknowledgement ADR-0012 requires. Until this runs, drift keeps reporting — and
    keeps failing CI — which is the whole point: an alarm that clears itself is worse than no alarm,
    because it looks like coverage.
    """
    path = path or default_path()
    with locked(path):
        store = load(path)
        latest = last(store, key)
        if latest is None:
            return None
        store.setdefault("servers", {}).setdefault(key, {})["approved"] = latest
        save(store, path)
    return latest


def resolve(store: dict[str, Any], wanted: str) -> str | None:
    """Find the stored key for what a user typed.

    They know the name in their `mcp.json`; the store is keyed by the identity the server asserts.
    Accepts the exact key, a recorded config-name alias, or the bare asserted name.
    """
    servers = store.get("servers", {})
    if wanted in servers:
        return wanted
    if f"mcp:{wanted}" in servers:
        return f"mcp:{wanted}"
    for key, entry in servers.items():
        if wanted in entry.get("aliases", []):
            return key
    return None


def identity_change(store: dict[str, Any], key: str, alias: str | None) -> str | None:
    """The key this config entry used to resolve to, when the server has RE-IDENTIFIED itself.

    Keying on the server's asserted name (ADR-0012 N4) closed rename evasion but opened its mirror:
    a server that changes the name it asserts gets a brand-new key, and a brand-new key is a first
    sighting — which is silence. Renaming yourself would mean your rug-pull is never diffed against
    anything.

    So when the same config entry now resolves somewhere new, say so. Returns the prior key, or
    None when this is a genuinely new entry.
    """
    if not alias or key in store.get("servers", {}):
        return None
    for other, entry in store.get("servers", {}).items():
        if other != key and alias in entry.get("aliases", []):
            return other
    return None


def pending(store: dict[str, Any]) -> list[str]:
    """Keys whose newest sighting differs from the approved baseline — i.e. unacknowledged drift."""
    out = []
    for key, entry in store.get("servers", {}).items():
        base, latest = approved(store, key), last(store, key)
        if base and latest and base.get("items") != latest.get("items"):
            out.append(key)
    return sorted(out)


def approved(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    """The record drift diffs against. Falls back to the OLDEST sighting for stores written before
    ADR-0012, so upgrading does not silently adopt a state the user never approved."""
    entry = store.get("servers", {}).get(key, {})
    if "approved" in entry:
        return entry["approved"]
    hist = entry.get("history", [])
    return hist[0] if hist else None


def _migrate(store: dict[str, Any], key: str, legacy_keys: tuple[str, ...]) -> None:
    """Move a pre-existing baseline onto `key` when the identity scheme changed underneath it.

    Without this, shipping the server-asserted identity would itself orphan every user's baseline on
    upgrade — the exact silent-reset this ADR exists to prevent, caused by the fix for it."""
    servers = store.setdefault("servers", {})
    if key in servers:
        return
    for old in legacy_keys:
        if old in servers:
            servers[key] = servers.pop(old)
            return


def should_record(snap: ServerSnapshot) -> bool:
    """Only a successful probe may become history.

    An errored snapshot carries an empty tool list. Recorded, it would read as "every tool was
    removed" and then become the baseline — so anyone able to make a server fail to probe could
    erase the record of what it used to look like."""
    return not snap.error


def key_for(snap: ServerSnapshot) -> str:
    """Stable identity for a server across config edits.

    Prefers what the server asserts about itself in `initialize` (`serverInfo.name`), so renaming an
    entry in `mcp.json` no longer starts a fresh baseline with no drift — previously a one-line
    evasion and an easy way to lose history by accident.

    Falls back to the old `transport:name` when a server declares nothing. Note the asserted name is
    server-controlled: changing it is itself a re-identification, which surfaces as a first sighting
    rather than as silence. That is a deliberate trade — see ADR-0012.
    """
    asserted = (snap.server_info or {}).get("name")
    if isinstance(asserted, str) and asserted.strip():
        return f"mcp:{asserted.strip()}"
    return legacy_key_for(snap)


def legacy_key_for(snap: ServerSnapshot) -> str:
    """The pre-ADR-0012 identity. Kept so `record(..., migrate_from=...)` can adopt an existing
    baseline instead of orphaning it."""
    return f"{snap.transport}:{snap.name}"


def last(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    hist = store.get("servers", {}).get(key, {}).get("history", [])
    return hist[-1] if hist else None


def append(store: dict[str, Any], key: str, record: dict[str, Any], keep: int = 50) -> None:
    hist = store.setdefault("servers", {}).setdefault(key, {}).setdefault("history", [])
    hist.append(record)
    del hist[:-keep]  # bounded — keep the last `keep` sightings
