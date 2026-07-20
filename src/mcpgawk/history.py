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
           keep: int = 50) -> dict[str, Any] | None:
    """Append `rec` under `key` and return the PREVIOUS record, the whole cycle under one lock.

    Returning the previous record from inside the lock is what makes drift correct under
    concurrency: reading "what did I see last time" and writing "what I see now" have to be one
    indivisible step, or two concurrent scans each diff against a baseline the other just replaced.
    """
    path = path or default_path()
    with locked(path):
        store = load(path)
        prev = last(store, key)
        append(store, key, rec, keep=keep)
        save(store, path)
    return prev


def key_for(snap: ServerSnapshot) -> str:
    return f"{snap.transport}:{snap.name}"


def last(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    hist = store.get("servers", {}).get(key, {}).get("history", [])
    return hist[-1] if hist else None


def append(store: dict[str, Any], key: str, record: dict[str, Any], keep: int = 50) -> None:
    hist = store.setdefault("servers", {}).setdefault(key, {}).setdefault("history", [])
    hist.append(record)
    del hist[:-keep]  # bounded — keep the last `keep` sightings
