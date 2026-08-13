"""A token store and a monitoring database must be owner-only — created that way, not narrowed after.

Sixth increment of the 2026-08-13 sweep. These two sinks differ from the previous five: the OAuth
store is SUPPOSED to hold a credential, so the question is not "is it redacted" but "who can read
it". Measured on the operator's own machine:

| object | mode found | every sibling store |
|---|---|---|
| `~/.gawk/oauth/` | 0755 | `history.json`, `runs.db`, `enforce-audit.db` all 0600 |

(The paid pillar's `monitor.db` was 0644 for the same reason and is covered by
`tests/test_monitor_db_is_owner_only.py`, which cannot live in this file: this one is synced to the
PUBLIC repo, where `gawk_platform` does not exist. The public suite caught that import — the layer
invariant working, not a formality.)

Severity is bounded and stated honestly: `~/.gawk` itself is 0700, so today the PARENT is what
protects both. A mode on the object survives a copy, a backup, a tarball and a change to the
parent's mode; the parent's does not travel with the file.

The token write was the sharper of the two: `write_text` then `chmod(0o600)` with the OSError
SWALLOWED, so a freshly created token file is 0644 for the gap between the two calls — and stays
0644 with a live OAuth token in it, permanently and silently, if the chmod fails. `os.open` with an
explicit mode closes both.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest


def _mode(path: str | Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def store(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("GAWK_OAUTH_STORE", str(tmp_path / "oauth"))
    import importlib

    from mcpgawk import oauth_login
    importlib.reload(oauth_login)
    yield oauth_login
    importlib.reload(oauth_login)


def test_a_token_file_is_created_owner_only(store):
    fresh = store.FileTokenStorage("https://fresh.invalid/mcp")
    fresh._write({"access_token": "CANARY_TOKEN_98765"})
    assert _mode(fresh._path) == 0o600, "a live OAuth token is readable by other local users"
    assert _mode(Path(fresh._path).parent) == 0o700, "the token directory is not owner-only"


def test_the_token_file_is_owner_only_even_if_chmod_fails(store, monkeypatch):
    """The reachable bad state, not a hypothetical: the old code swallowed the chmod error, so a
    filesystem that refuses chmod left a live token world-readable forever. The mode now comes from
    `os.open` itself, so there is nothing to fail."""
    fresh = store.FileTokenStorage("https://fresh2.invalid/mcp")

    def refuse(self, mode):
        raise OSError("chmod refused")

    monkeypatch.setattr(Path, "chmod", refuse)
    fresh._write({"access_token": "CANARY_TOKEN_98765"})
    assert _mode(fresh._path) == 0o600
    assert "CANARY_TOKEN_98765" in Path(fresh._path).read_text(encoding="utf-8"), \
        "sanity: the token really was written, so the mode assertion is not vacuous"


def test_a_store_written_before_the_fix_is_repaired_on_the_next_write(store):
    """O_CREAT honours a mode only for a NEW file. An 0644 file left by the old code has to be
    narrowed on the next token refresh, or the fix never reaches anyone who already logged in."""
    fresh = store.FileTokenStorage("https://legacy.invalid/mcp")
    fresh._path.parent.mkdir(parents=True, exist_ok=True)
    fresh._path.write_text("{}", encoding="utf-8")
    fresh._path.chmod(0o644)
    fresh._write({"access_token": "CANARY_TOKEN_98765"})
    assert _mode(fresh._path) == 0o600, "a pre-existing world-readable token store stayed that way"
