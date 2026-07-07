"""Local, human-readable drift history. JSON on disk — never leaves the machine.

Default: $MCPGAWK_HISTORY or ~/.mcpgawk/history.json. This is the ONLY state mcpgawk persists,
and it's the user's own machine. No sync, no cloud.
"""
from __future__ import annotations

import json
import os
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
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, sort_keys=True)
    os.replace(tmp, path)  # atomic


def key_for(snap: ServerSnapshot) -> str:
    return f"{snap.transport}:{snap.name}"


def last(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    hist = store.get("servers", {}).get(key, {}).get("history", [])
    return hist[-1] if hist else None


def append(store: dict[str, Any], key: str, record: dict[str, Any], keep: int = 50) -> None:
    hist = store.setdefault("servers", {}).setdefault(key, {}).setdefault("history", [])
    hist.append(record)
    del hist[:-keep]  # bounded — keep the last `keep` sightings
