"""Local, human-readable drift history. JSON on disk — never leaves the machine.

Default: $MCPGAWK_HISTORY or ~/.mcpgawk/history.json. This is the ONLY state mcpgawk persists,
and it's the user's own machine. No sync, no cloud.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from contextlib import contextmanager
from typing import Any

from . import state
from .probe import ServerSnapshot


def default_path() -> str:
    return os.environ.get("MCPGAWK_HISTORY") or os.path.expanduser("~/.mcpgawk/history.json")


class InvalidServerKey(ValueError):
    """A proposed NEW trust-store key that is not a server identity mcpgawk could have produced."""


#: Every scheme `key_for` / `legacy_key_for` can emit. A top-level entry is created by exactly one
#: thing — a server we probed — so its key is always `<scheme>:<name>`. That prefix, not a character
#: class, is the honest discriminator: the real store legitimately contains
#: `mcp:BrowserStack MCP Server` (spaces and all), while the junk rows were bare `s` and `srv`.
SERVER_KEY_SCHEMES = ("mcp", "stdio", "http", "sse")

#: A key is a permanent row that `status` and `baseline` COUNT as "a server you approved", so it is
#: also a display string. Bound the length and refuse control characters rather than render them.
_MAX_SERVER_KEY = 256


def validated_server_key(key: str) -> str:
    """The one gate on what may BECOME a top-level trust-store entry. Returns `key` unchanged.

    Every writer used `setdefault(key, {})` on whatever string it was handed, so
    `mcpgawk monitor approve srv` wrote that literal string as an approved server — no scheme, no
    alias, no validation. `mcpgawk status` and `mcpgawk baseline` then counted and rendered it: the
    founder's real store reported **15 approved servers where 13 were real**, the two extras being
    `s` and `srv` leaked out of `tests/test_monitor_approve_cli.py`. An inflated count of "servers
    you approved" is not cosmetic — it is the number the product uses to tell someone how much of
    their fleet is covered, so it overstates coverage in the one place that must never overstate.

    Raises rather than normalising. A caller holding a name this rejects does not know what it is
    approving; rewriting it quietly would move that confusion into the store instead of stopping it.
    Callers with a bare config name (monitor's `server_id`) must say which scheme they mean — see
    `spine.publish`, which resolves first and falls back to `mcp:` explicitly.

    Applied only on CREATION (see `server_entry`): an existing key, including a legacy junk row,
    stays writable so that muting or re-approving a server recorded by an older build still works.
    """
    if not isinstance(key, str):
        raise InvalidServerKey(f"server key must be a string, got {type(key).__name__}")
    if not key or key.strip() != key:
        raise InvalidServerKey(f"{key!r} is empty or has surrounding whitespace")
    if len(key) > _MAX_SERVER_KEY:
        raise InvalidServerKey(
            f"server key is {len(key)} characters, over the {_MAX_SERVER_KEY} limit")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in key):
        raise InvalidServerKey(f"{key!r} contains control characters")
    scheme, sep, name = key.partition(":")
    if not sep or scheme not in SERVER_KEY_SCHEMES or not name.strip():
        raise InvalidServerKey(
            f"{key!r} is not a server identity — a trust-store entry is written as "
            f"'<scheme>:<name>' with scheme one of {', '.join(SERVER_KEY_SCHEMES)} "
            f"(e.g. 'mcp:{key}'). This would become a permanent row that `mcpgawk status` counts "
            f"as a server you approved."
        )
    return key


def server_entry(store: dict[str, Any], key: str) -> dict[str, Any]:
    """The ONLY way to reach a server's entry for writing. Validates on creation.

    Gated here, at the write, rather than in each command: "every caller validates" is a property
    that decays the moment someone adds a caller, and this store has four writers already.
    `tests/test_server_key_gate_invariant.py` fails the build if a fifth reaches `servers` directly.
    """
    servers = store.setdefault("servers", {})
    if key not in servers:
        validated_server_key(key)
    return servers.setdefault(key, {})


#: Environment markers set by coding agents. Their presence means the process was started by an
#: agent, so whoever is "typing" is a model — not the human whose trust decision this is.
AGENT_ENV_MARKERS = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "AI_AGENT", "CURSOR_TRACE_ID")

#: The deliberate escape hatch for CI, which legitimately has no TTY and no human. Deliberately NOT
#: mentioned in any blocked-call message: the whole point is that an agent reading a denial cannot
#: learn the bypass from it.
APPROVE_OVERRIDE_ENV = "MCPGAWK_APPROVE_NONINTERACTIVE"


class ApprovalBlocked(RuntimeError):
    """A process with no demonstrable human present tried to move a trusted baseline.

    Raised by the WRITERS, not by the commands. Every command that approves already checks the gate
    itself so it can print a decent message and exit 4; this exists so that a route which forgets to
    — or one written next year — fails loudly instead of moving the baseline anyway. That is not
    hypothetical: `mcpgawk monitor approve` was exactly such a route, and it exited 0.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def approval_blocked_reason() -> str | None:
    """Why this process must not be allowed to move the trusted baseline, or None if it may.

    THE HOLE THIS CLOSES (found 2026-07-27 by running the product as an agent would): the guard
    blocked a malicious tool, and the denial text told the agent to run `mcpgawk approve <server>`
    to accept the change. The agent has a shell. It ran it, and the malicious tool was allowed on
    the retry — the control handed its own bypass to the audience most likely to be acting on an
    injected instruction.

    Approval is the one operation that must come from the human. It is the moment trust moves, so
    it is gated on evidence a human is present: an interactive terminal, and no agent-session
    marker in the environment. Both, because either alone is weak — an agent can run without a TTY
    marker set, and a human can be inside an agent's terminal.

    Lives HERE, in the store module, rather than beside the command that first needed it. The gate
    guards a WRITE to this file; keeping it next to one caller is what let another caller reach the
    same write without it.
    """
    agent = [m for m in AGENT_ENV_MARKERS if os.environ.get(m)]
    if os.environ.get(APPROVE_OVERRIDE_ENV) == "1":
        return None
    if agent:
        return (f"this looks like an agent session ({', '.join(agent)} set). Moving the trusted "
                f"baseline is a decision for the person at the keyboard, not for the assistant — "
                f"a blocked tool call is exactly when an agent would be asked to approve its way "
                f"past one. Run this yourself in your own terminal.")
    if not sys.stdin.isatty():
        return ("no interactive terminal. Approving a changed server is a trust decision and needs "
                "a human present; refusing rather than assuming consent.")
    return None


def require_human_approval() -> None:
    """Raise `ApprovalBlocked` unless a human is demonstrably present.

    The single call every function that moves a trusted baseline must make.
    `tests/test_baseline_writer_gate_invariant.py` enumerates those functions and fails the build
    if one of them stops making it.
    """
    reason = approval_blocked_reason()
    if reason is not None:
        raise ApprovalBlocked(reason)


def load(path: str | None = None) -> dict[str, Any]:
    path = path or default_path()
    # Tighten on READ as well as write. A file created by an older version stays world-readable
    # until something rewrites it, and a user who only ever reads (a `runs` or `baseline` call)
    # would keep the exposure indefinitely. Cheap, and it converges every install on first touch.
    state.harden(path)
    return load_checked(path)[0]


def load_checked(path: str | None = None) -> tuple[dict[str, Any], str | None]:
    """`(store, error)` — the same read, plus the reason it came back empty.

    "This machine has approved nothing yet" and "the file holding every approval is unreadable"
    both returned `{"servers": {}}`, so a corrupt store rendered as a calm, confident empty panel:
    no servers, no findings, nothing wrong. The caller could not say otherwise, because the
    information had already been discarded here.

    Still degrades rather than raising — a security tool that refuses to start because its own
    store is damaged does more harm than the drift it was watching for — but the reason now
    travels with the result, so every surface can say it out loud.
    """
    path = path or default_path()
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return {"servers": {}}, None            # a fresh machine: genuinely nothing approved yet
    except json.JSONDecodeError as exc:
        return {"servers": {}}, (
            f"the approved-baseline store at {path} is not readable JSON "
            f"(line {exc.lineno}, column {exc.colno}) — nothing shown reflects what you approved"
        )
    except OSError as exc:
        return {"servers": {}}, (
            f"the approved-baseline store at {path} could not be read ({exc.strerror}) — "
            f"nothing shown reflects what you approved"
        )


def save(store: dict[str, Any], path: str | None = None) -> None:
    path = path or default_path()
    # Owner-only: this file is a complete inventory of the user's MCP servers and their tool
    # descriptions. It was world-readable until 2026-07-27 — see state.py.
    state.secure_dir(os.path.dirname(path))
    # NEVER overwrite an unreadable store without keeping a copy. `load` degrades a corrupt file to
    # an empty store, so a scan that reads-then-writes would quietly replace every approval the
    # user ever made with `{}` — the damage indistinguishable from having approved nothing. Two
    # credential files were destroyed this way in one day; this is the same shape, on the file that
    # holds the entire trust baseline.
    if os.path.exists(path) and load_checked(path)[1] is not None:
        keep = f"{path}.corrupt-{int(time.time())}"
        try:
            shutil.copy2(path, keep)
            print(f"mcpgawk: {path} was unreadable; a copy was kept at {keep} before it was "
                  f"replaced. If it held approvals you still want, recover them from that copy.",
                  file=sys.stderr)
        except OSError as exc:
            print(f"mcpgawk: {path} is unreadable AND could not be backed up ({exc}). "
                  f"Refusing to overwrite it — fix or move it, then re-run.", file=sys.stderr)
            return
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
        state.secure_file(path)
    finally:
        if os.path.exists(tmp):    # a failed write must not litter the user's ~/.mcpgawk
            try:
                os.remove(tmp)
            except OSError:
                pass
    # EVERY save regenerates the hot-path projection. This is what lets the agent hook consume an
    # artefact the canonical writer produced instead of re-deriving the approved surface itself —
    # drift between the two readers stops being possible instead of being test-detected
    # (docs/architecture-runtime-monitoring-2026-07-27.md §4).
    _write_projection(store, path)


#: The flat, stdlib-parsable file the agent hook reads instead of this store. Always a sibling of
#: the history file it projects, so an MCPGAWK_HISTORY override relocates both together.
PROJECTION_NAME = "guard-baseline.json"
PROJECTION_SCHEMA = "gawk.guard-projection/1"


def projection_path(path: str | None = None) -> str:
    return os.path.join(os.path.dirname(path or default_path()), PROJECTION_NAME)


def _write_projection(store: dict[str, Any], path: str) -> None:
    """Project the APPROVED surface (tools + aliases per server, nothing else) into a small flat
    file, stamped with the stat of the history file it was derived from. The hook compares that
    stamp before trusting the projection: a mismatch means someone wrote the store without coming
    through here, and the hook must defer rather than enforce yesterday's baseline.

    Best-effort but never silent: a failure here means the hook will (loudly) defer until the next
    successful save, which is the safe direction — it must not fail the scan/approve that called us.
    """
    try:
        st = os.stat(path)
        servers: dict[str, Any] = {}
        for key, entry in (store.get("servers") or {}).items():
            if not isinstance(entry, dict):
                continue
            rec = entry.get("approved")
            if not isinstance(rec, dict) or not isinstance(rec.get("tools"), dict):
                continue
            servers[key] = {"tools": dict(rec["tools"]),
                            "aliases": list(entry.get("aliases") or [])}
        projection = {"schema": PROJECTION_SCHEMA,
                      "source": {"mtime_ns": st.st_mtime_ns, "size": st.st_size},
                      "servers": servers}
        proj = projection_path(path)
        tmp = f"{proj}.{os.getpid()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(projection, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, proj)
            state.secure_file(proj)
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    except Exception as exc:  # noqa: BLE001 — the projection is derived state; the store write stood
        print(f"mcpgawk: could not regenerate the guard projection ({type(exc).__name__}: {exc}). "
              f"The agent hook will defer (not enforce) until the next successful scan/approve.",
              file=sys.stderr)


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
        entry = server_entry(store, key)
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

    Gated at the WRITE, not only at the command. Every caller already checks — but "every caller
    checks" is a property that decays the moment someone adds a caller, and it did.
    """
    require_human_approval()
    path = path or default_path()
    with locked(path):
        store = load(path)
        latest = last(store, key)
        if latest is None:
            return None
        server_entry(store, key)["approved"] = latest
        save(store, path)
    return latest


def mute_finding(name: str, finding_id: str, path: str | None = None,
                 undo: bool = False) -> str | None:
    """Record (or withdraw) a human's "this finding is wrong" for one server.

    Design-contract item 4: the false-positive affordance. A muted finding is NEVER dropped from
    any surface — it renders as "muted by you", because absence-is-not-safety applies to our own
    mistakes too: a wrong mute must stay reviewable, and a report that silently omits what the
    user silenced is indistinguishable from a report that never found it.

    `finding_id` is `<tool>/<kind>` exactly as the report prints it. Returns the resolved store
    key, or None when no tracked server matches `name` (nothing is written in that case)."""
    from datetime import datetime, timezone

    path = path or default_path()
    with locked(path):
        store = load(path)
        key = resolve(store, name)
        if key is None:
            return None
        entry = server_entry(store, key)
        muted_ids = entry.setdefault("muted", {})
        if undo:
            muted_ids.pop(finding_id, None)
        else:
            muted_ids[finding_id] = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        save(store, path)
    return key


def muted(store: dict[str, Any], key: str | None) -> dict[str, Any]:
    """`{finding_id: {"at": ...}}` the human has marked wrong for this server. Empty when none."""
    if key is None:
        return {}
    entry = (store.get("servers") or {}).get(key)
    raw = entry.get("muted") if isinstance(entry, dict) else None
    return dict(raw) if isinstance(raw, dict) else {}


def muted_total(store: dict[str, Any]) -> int:
    """How many findings the human has muted, fleet-wide — surfaced by `status` so suppression
    stays a visible, countable decision rather than quiet forgetting."""
    return sum(len(entry.get("muted") or {})
               for entry in (store.get("servers") or {}).values() if isinstance(entry, dict))


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


def display_name(store: dict[str, Any], key: str) -> str:
    """What the USER calls this server — the name in their own config, not our internal key.

    The store is keyed by the identity the SERVER asserts, so a rename cannot orphan a baseline.
    That key (`mcp:notes-pro`) is the wrong thing to show a person: they know the name they typed
    in mcp.json. Two surfaces got this wrong in different ways — `status` printed the raw key, and
    the protect report joined every alias with a comma so ONE server read as two ("cli-stdio,
    mcpgawk"). One helper, so they cannot disagree again.

    Where a server genuinely has several names (the same binary configured twice, under different
    names, in different agents), the extras are shown as an aside rather than as equals — that is
    real information, but it is not two servers.
    """
    servers = store.get("servers") or {}
    entry = servers.get(key) or {}
    aliases = [a for a in (entry.get("aliases") or []) if a]
    if not aliases:
        return key
    primary = aliases[0]

    # AMBIGUITY IS WORSE THAN THE RAW KEY. Two different servers can carry the same alias — every
    # `--stdio` scan is labelled `cli-stdio`, so a fleet can show two rows reading identically.
    # A user then cannot tell which one changed, and `mcpgawk approve cli-stdio` is a coin flip.
    # Where the name does not identify one server, say which one.
    sharing = [k for k, v in servers.items()
               if k != key and primary in ((v or {}).get("aliases") or [])]
    if sharing:
        return f"{primary} [{key}]"
    if len(aliases) == 1:
        return primary
    return f"{primary} (also configured as {', '.join(aliases[1:])})"


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
    servers = store.get("servers") or {}
    if key in servers:
        return
    for old in legacy_keys:
        if old in servers:
            # Creates the new key, so it goes through the same gate as any other creation — a
            # migration must not be the one path that can mint an entry nothing validated.
            server_entry(store, key).update(servers.pop(old))
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


#: Every transport a legacy `{transport}:{name}` key could have used.
_TRANSPORTS = ("stdio", "http", "sse")


def transport_variant_keys(snap: ServerSnapshot) -> tuple[str, ...]:
    """Every legacy `{transport}:{name}` key this server could already be recorded under (B3).

    A NAMELESS server (no `serverInfo.name`) is keyed by its transport, so switching stdio→http would
    silently orphan its baseline and start a fresh one — a config edit erasing history, the exact
    class of silent reset ADR-0012 exists to stop. Migrating from every transport variant lets the new
    key adopt the old baseline instead. Harmless for a NAMED server: its `mcp:name` key already exists
    (transport-independent), so `_migrate` no-ops rather than adopting anything."""
    return tuple(f"{t}:{snap.name}" for t in _TRANSPORTS)


def last(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    hist = store.get("servers", {}).get(key, {}).get("history", [])
    return hist[-1] if hist else None


def append(store: dict[str, Any], key: str, record: dict[str, Any], keep: int = 50) -> None:
    hist = server_entry(store, key).setdefault("history", [])
    hist.append(record)
    del hist[:-keep]  # bounded — keep the last `keep` sightings
