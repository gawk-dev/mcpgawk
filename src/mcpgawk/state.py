"""The on-disk boundary for one user's state. Every local store goes through here.

WHY. Everything this product writes locally is sensitive in the ordinary sense: the drift history is
a complete inventory of your MCP servers and their tool descriptions, the enforce audit log is every
tool call and every block reason, the licence cache holds a key, and the run registry says what you
ran and when. All of it was created with the process umask — `0644` files in `0755` directories —
so on any machine with a second account (a shared workstation, a CI runner, a dev container, a
compromised service account) another local user could read the lot. A security tool that leaks your
inventory to the neighbour is not a small irony; it is the product failing at its own premise.

The OAuth token store already wrote `0600` files, which is how we know the intent existed. It simply
was not applied anywhere else, because each store rolled its own `makedirs` + `open`. One helper,
used by every store, is the difference between an intent and a guarantee.

THE RULE: owner-only. Directories `0700`, files `0600`.

Applied by REMOVING group and other bits, never by forcing a fixed mode. If an operator has hardened
a file further (say `0400`), tightening must not loosen it back — a "secure default" that quietly
relaxes someone's deliberate choice is a downgrade wearing the right label.

Best-effort by design. A filesystem without POSIX modes (FAT, some network mounts, Windows) cannot
honour this, and refusing to work there would trade a real feature for a mode bit we cannot set
anyway. What it must never do is fail silently in a way that reads as "secured" — `harden()` reports
whether it actually applied.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

#: Owner-only. Group and other get nothing.
DIR_MODE = 0o700
FILE_MODE = 0o600

#: SQLite writes these beside the database; they hold the same data mid-transaction and are useless
#: to protect the main file without.
_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")


def _tighten(path: Path, keep_mask: int) -> bool:
    """Strip group/other bits. Returns True if the path ended up owner-only."""
    try:
        current = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return False
    wanted = current & keep_mask          # only ever removes bits
    if wanted != current:
        try:
            path.chmod(wanted)
        except OSError:
            return False
    return not (wanted & (stat.S_IRWXG | stat.S_IRWXO))


def secure_dir(path: str | os.PathLike) -> Path:
    """Create (if needed) and tighten a state directory. Returns it."""
    p = Path(path)
    try:
        p.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    except OSError:
        return p                            # caller's own write will surface the real problem
    _tighten(p, 0o700)                      # existing dirs created before this shipped
    return p


def secure_file(path: str | os.PathLike) -> bool:
    """Tighten a state file to owner-only. Returns whether it is now owner-only."""
    return _tighten(Path(path), 0o600)


def harden(path: str | os.PathLike, *, sidecars: bool = False) -> bool:
    """Tighten a file and its parent directory. With `sidecars`, also SQLite's -wal/-shm/-journal.

    Returns True only if everything it touched is owner-only, so a caller can tell the difference
    between "secured" and "could not secure" instead of assuming.
    """
    p = Path(path)
    ok = True
    if p.parent != p:
        ok &= _tighten(p.parent, 0o700) if p.parent.exists() else True
    if p.exists():
        ok &= secure_file(p)
    if sidecars:
        for suffix in _SQLITE_SIDECARS:
            side = Path(str(p) + suffix)
            if side.exists():
                ok &= secure_file(side)
    return ok


def warn_if_exposed(path: str | os.PathLike, label: str) -> None:
    """Say so, once, if a state file is readable by other local users and we could not fix it.

    Silence here would be the failure mode this module exists to prevent: the operator believes the
    boundary holds because nothing said otherwise.
    """
    p = Path(path)
    if not p.exists():
        return
    try:
        mode = stat.S_IMODE(p.stat().st_mode)
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(f"mcpgawk: {label} at {p} is readable by other users on this machine "
              f"(mode {mode:o}) and could not be tightened. Anything in it should be treated as "
              f"shared.", file=sys.stderr)
