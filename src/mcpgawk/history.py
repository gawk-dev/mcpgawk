"""Local, human-readable drift history. JSON on disk — never leaves the machine.

Default: $MCPGAWK_HISTORY or ~/.mcpgawk/history.json. This is the ONLY state mcpgawk persists,
and it's the user's own machine. No sync, no cloud.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import time
from contextlib import contextmanager
from typing import Any

from . import state
from .probe import ServerSnapshot


#: The store's single owner also owns the two literals that name it, so anything that must build
#: a redirected store path (a test harness, `mcpgawk demo`) references these instead of repeating
#: the strings — which is what the layer invariant `test_only_history_py_derives_the_history_store
#: _path` enforces.
STORE_ENV = "MCPGAWK_HISTORY"
STORE_FILENAME = "history.json"


def default_path() -> str:
    return os.environ.get(STORE_ENV) or os.path.expanduser(f"~/.mcpgawk/{STORE_FILENAME}")


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
#: learn the bypass from it. It waives ONLY the missing terminal, never an agent-session marker:
#: an agent with a shell can set an env var as easily as a pipeline can (founder 2026-09-27).
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
    # The agent check comes FIRST and the CI hatch cannot waive it. Until 2026-09-27 the hatch was
    # read first, so `MCPGAWK_APPROVE_NONINTERACTIVE=1 mcpgawk approve` from inside an agent
    # session moved the baseline — one env var, settable by the very agent this gate exists to stop.
    if agent:
        return (f"this looks like an agent session ({', '.join(agent)} set). Moving the trusted "
                f"baseline is a decision for the person at the keyboard, not for the assistant — "
                f"a blocked tool call is exactly when an agent would be asked to approve its way "
                f"past one. Run this yourself in your own terminal.")
    if os.environ.get(APPROVE_OVERRIDE_ENV) == "1":
        return None
    if not _stdin_is_tty():
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


#: Agents whose children are the agent's own tool calls. MEASURED: `claude` (Claude Code 2.1.289,
#: 2026-10-05 — `ps` ancestry of a Bash tool call reads zsh → claude → -zsh → login → Terminal). The
#: rest are those agents' own CLI names, not yet measured. A detached child (`nohup … &` in a
#: subshell) is reparented to init and escapes this walk — measured the same day — so this is
#: evidence, never proof.
AGENT_PROCESS_NAMES = frozenset({"claude", "codex", "gemini", "kimi", "opencode", "goose", "aider",
                                 "cursor-agent"})


def _stdin_is_tty() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (ValueError, OSError):
        return False


def _process_ancestry() -> list[str]:
    """Names of this process's ancestors, nearest first; [] where they cannot be read."""
    if os.name != "posix":
        return []
    import subprocess
    try:
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,comm="], capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    parent: dict[int, int] = {}
    name: dict[int, str] = {}
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            parent[int(parts[0])] = int(parts[1])
            name[int(parts[0])] = os.path.basename(parts[2].strip())
    chain: list[str] = []
    pid, seen = os.getppid(), set()
    while pid > 1 and pid in name and pid not in seen:
        seen.add(pid)
        chain.append(name[pid])
        pid = parent.get(pid, 0)
    return chain


def agent_process() -> str | None:
    """The first ancestor that is an agent (`AGENT_PROCESS_NAMES`), or None."""
    for n in _process_ancestry():
        if n.lstrip("-").lower() in AGENT_PROCESS_NAMES:
            return n
    return None


def approval_evidence(source: str = "cli") -> dict[str, Any]:
    """What this process can show about WHO is approving, recorded beside every approval.

    A person is present only with a terminal, no agent-session marker and no agent process above
    us. A same-user agent can forge or evade every one of these, so this is never proof: it is what
    lets every surface NAME an approval that came without a person, instead of showing it as "you
    approved it" (FOUNDER 2026-10-05, "Block + name it"). A panel approval is never a person's on
    this evidence alone: the panel's process is the person's, the POST may not be.
    """
    markers = [m for m in AGENT_ENV_MARKERS if os.environ.get(m)]
    proc = agent_process()
    terminal = _stdin_is_tty()
    return {"source": source, "terminal": terminal, "agent_markers": markers,
            "agent_process": proc, "hatch": os.environ.get(APPROVE_OVERRIDE_ENV) == "1",
            "person_present": source != "panel" and terminal and not markers and proc is None}


def evidence_words(ev: Any) -> str | None:
    """"approved without a person present — <why>", or None when a person was present or the
    approval predates the evidence (unknown is not re-judged). Never names the hatch's variable: an
    agent reads these surfaces, and the name is the bypass."""
    if not isinstance(ev, dict) or ev.get("person_present", True) is not False:
        return None
    why: list[str] = []
    if ev.get("agent_process"):
        why.append(f"an agent ({ev['agent_process']}) was running it")
    if ev.get("agent_markers"):
        why.append("an agent session was marked")
    if ev.get("source") == "panel":
        why.append("it came from the panel and was not confirmed at a terminal")
    elif not ev.get("terminal"):
        why.append("no terminal")
    if ev.get("hatch"):
        why.append("an automation setting allowed it")
    return "approved without a person present — " + "; ".join(why or ["no sign of a person"])


def load(path: str | None = None) -> dict[str, Any]:
    return load_checked_hardened(path)[0]


def load_checked_hardened(path: str | None = None) -> tuple[dict[str, Any], str | None]:
    """`load_checked` plus the tighten-on-read that `load()` performs — in ONE place.

    Tighten on READ as well as write. A file created by an older version stays world-readable
    until something rewrites it, and a user who only ever reads (a `runs` or `baseline` call)
    would keep the exposure indefinitely. Cheap, and it converges every install on first touch.

    Split out for callers that need BOTH the harden and the read error: `spine.approved_pin`
    treated "the store raised" as its unreadable signal, but this layer never raises — the error
    travels in the tuple — so the trust-on-first-use refusal was dead code on the one failure it
    was written for. A caller reading through `load()` gets the `[0]` that discards the error;
    a caller pairing `state.harden` with `load_checked` by hand is the second copy of a rule
    that then drifts. This is the single door for "harden, read, and keep the reason".
    """
    path = path or default_path()
    state.harden(path)
    return load_checked(path)


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
    tail = "nothing shown reflects what you approved"
    try:
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
    except FileNotFoundError:
        return {"servers": {}}, None            # a fresh machine: genuinely nothing approved yet
    except json.JSONDecodeError as exc:
        return {"servers": {}}, (
            f"the approved-baseline store at {path} is not readable JSON "
            f"(line {exc.lineno}, column {exc.colno}) — {tail}"
        )
    except UnicodeDecodeError as exc:
        # A ValueError, like JSONDecodeError, but raised by the file's text decoding before the
        # parser sees a character — so it escaped every handler here and crashed the caller.
        return {"servers": {}}, (
            f"the approved-baseline store at {path} is not UTF-8 text "
            f"(byte {exc.start}) — {tail}"
        )
    except RecursionError:
        # Nesting deeper than the interpreter's stack: the stdlib parser raises instead of
        # reporting a malformed document. A few KB of `[` is enough.
        return {"servers": {}}, (
            f"the approved-baseline store at {path} is nested too deeply to read — {tail}"
        )
    except OSError as exc:
        return {"servers": {}}, (
            f"the approved-baseline store at {path} could not be read ({exc.strerror}) — {tail}"
        )
    # VALID JSON IS NOT YET A STORE. A bare `[]`/`7`/`null` came back AS the store with error None,
    # and every reader then raised on `.get` — or, worse, read it as "nothing approved". A
    # non-object `servers` raised AttributeError out of the alias shed below. Both degrade the way
    # unreadable JSON does: the empty store, plus the reason.
    if not isinstance(store, dict):
        return {"servers": {}}, (
            f"the approved-baseline store at {path} holds a JSON {_json_kind(store)}, not an "
            f"object — {tail}"
        )
    if "servers" in store and not isinstance(store["servers"], dict):
        return {"servers": {}}, (
            f"the approved-baseline store at {path} has a `servers` field that is a JSON "
            f"{_json_kind(store['servers'])}, not an object — {tail}"
        )
    # A store written before the synthetic-alias gate still carries placeholders. Shed them
    # HERE so every alias reader gets the cleaned view, not just the ones that also save.
    _shed_synthetic_aliases(store)
    # The same for a secret a released masker left in an alias or a key: no reader sees it.
    _scrub_leaked_identities(store)
    return store, None


def _json_kind(value: Any) -> str:
    """The JSON type name of a parsed value, for a message a person reads."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


#: The item-key shape drift mints: `tool.<name>`, `prompt.<name>`, `resource.<uri>`. The IDENT half
#: is server-controlled, and until 2026-08-13 it went to disk verbatim while only the description
#: text was redacted — so a tool NAMED with a credential, or the ordinary shape of a URI-only
#: resource (`https://host/doc?apiKey=…`), wrote a live key into `history.json` as a MAP KEY, in
#: `texts`, `items`, `tools`, `schemas`, `props` and `annotations` at once.
_KIND_PREFIX = ("tool.", "prompt.", "resource.")


def _mask_ident(ident: str) -> str:
    """Mask a credential inside one item identity, shape-preserving.

    URL-shaped idents go through `redact_url` (keeps the host and the parameter NAMES, so a drift
    report can still say WHICH resource changed); everything else through the prose redactor.
    Idempotent: a masked ident carries no credential shape, so re-masking is a no-op — which is
    what lets this run at both ingress and the write without compounding.
    """
    from .redact import redact_ident
    kind, _, rest = ident.partition(".")
    if f"{kind}." in _KIND_PREFIX and rest:
        return f"{kind}.{_mask_ident(rest)}"
    return redact_ident(ident)


#: Bumped whenever the REDACTION RULES change, so every stored record is masked again once under
#: the new rules instead of keeping whatever the old ones produced. Raised to 2 on 2026-09-11 when
#: the redactors began consuming the detector's 46 provider signatures — records written before
#: that carry only the old structural masking.
#:
#: WHY A STAMP AT ALL. `save()` re-redacted every record of every server on every write: measured
#: 0.944 s and 80,159 calls over 593 immutable, already-masked records, which is the dominant cost
#: of a store write and the main driver of lock hold time. Skipping records already masked at the
#: CURRENT version keeps the boundary's guarantee — an unstamped record from any writer, present or
#: future, is still masked here — while making the work proportional to what actually changed.
#: Moving redaction into the callers would have been the other way to make it cheap, and it is
#: exactly the defect this module's own docstring warns about: a rule that lives in one caller is
#: not a rule.
_REDACTION_VERSION = 2

#: The stamp's key. Leading underscore so it reads as machinery, not as recorded evidence.
#:
#: CONTENT-BOUND, NOT A BARE FLAG. The stamp is a claim, and a claim about content must be checked
#: against that content or it is just a request to be trusted. The value is
#: `"<version>:<digest of the record's redactable fields>"`, so anything that edits a record after
#: it was masked — a migration, a hand edit, a rewrite by another tool — changes the digest and the
#: record is masked again. Caught by an existing test on the first run: it simulates a pre-gate
#: store by replacing "[REDACTED]" with a raw credential, which a bare version stamp would have
#: sailed straight past, leaving the credential on disk and inventing drift against it.
_REDACTED_AT = "_redacted"


def _redaction_stamp(rec: dict[str, Any]) -> str:
    """`<version>:<digest>` over everything in the record except the stamp itself."""
    body = {k: v for k, v in rec.items() if k != _REDACTED_AT}
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    return f"{_REDACTION_VERSION}:{digest}"


def _is_proven_masked(rec: dict[str, Any]) -> bool:
    """True only when the record still matches the stamp it carries, under the CURRENT rules."""
    stamp = rec.get(_REDACTED_AT)
    return isinstance(stamp, str) and stamp == _redaction_stamp(rec)


def redact_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Mask credential shapes in one record, IN PLACE. Field-aware, never a whole-blob pass.

    ADR-0012 says redaction happens at the persistence boundary. It did not: the only `redact()`
    call lived in `drift._item_texts`, one caller, covering descriptions alone — the seventh
    instance of this repo's most repeated defect, a rule living in one file instead of on the write.

    A whole-blob `redact()` is deliberately NOT what this does. The store holds identity the drift
    report must show verbatim — pins, item hashes, timestamps — and this module's own doctrine is
    that over-redaction destroys the evidence the feature exists to display (`fleet.py` records an
    attempt at exactly that, backed out because it mangled ordinary paths). So: map KEYS are item
    identities and go through `_mask_ident`; prose VALUES (`texts`, annotation values, property
    names) go through the prose redactor; hashes and scalars are left alone.

    Applied at BOTH `record()` ingress and `save()`. Ingress masks the caller's own object in place
    so the record that gets compared for drift is the same one that gets stored — mask only on the
    way to disk and every scan would diff a raw `current` against a masked baseline and report a
    rename that never happened. `save()` then catches every other writer, present and future
    (`baseline.approve` writes measured annotations through its own direct save).
    """
    from .redact import redact
    for field, value in list(rec.items()):
        if not isinstance(value, dict):
            continue
        masked: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(v, str) and field == "texts":
                v = redact(v) or v
            elif isinstance(v, dict):
                # annotations: {ident: {title: "…"}} — server-authored prose, one level down.
                v = {ak: (redact(av) or av) if isinstance(av, str) else av for ak, av in v.items()}
            elif isinstance(v, list):
                # props: {ident: [property names]} — server-chosen names, same trust as an ident.
                v = [(_mask_ident(i) if isinstance(i, str) else i) for i in v]
            masked[_mask_ident(k) if isinstance(k, str) else k] = v
        rec[field] = masked
    rec[_REDACTED_AT] = _redaction_stamp(rec)   # binds the claim to what was actually masked
    return rec


def entry_records(entry: dict[str, Any]) -> list[Any]:
    """EVERY full record an entry stores: the approval, the sightings, and the copies kept for the
    latch (`changed_since_approval`) and the original baseline (`original_approved`). One list, so
    the masking at `save` cannot miss a record-shaped key added later (found 2026-10-09: a pre-gate
    credential survived in `original_approved` because the loop named approved + history only)."""
    return [entry.get("approved"), *(entry.get("history") or []),
            entry.get("changed_since_approval"), entry.get("original_approved")]


def save(store: dict[str, Any], path: str | None = None) -> None:
    path = path or default_path()
    # THE persistence boundary — every writer lands here (record, approve, baseline). Masking here
    # rather than in each caller is the whole point: a rule that lives in one caller is not a rule.
    # The same argument carries the alias shed: converge the FILE, so a store repaired in memory by
    # one read does not go back to disk carrying the placeholders again.
    _shed_synthetic_aliases(store)
    # Aliases and keys are identities `redact_record` never touches; re-mask them here too, so a
    # secret a released masker wrote into one does not go back to disk (or into the projection).
    _scrub_leaked_identities(store)
    for entry in (store.get("servers") or {}).values():
        if not isinstance(entry, dict):
            continue
        for rec in entry_records(entry):
            # Skip only what is PROVABLY already masked under the current rules. Anything
            # unstamped — a record from `baseline.approve`'s direct save, from an older version,
            # or from a writer that does not exist yet — is masked here exactly as before, so the
            # boundary's guarantee is unchanged. Bumping `_REDACTION_VERSION` re-masks everything
            # once. See the note on that constant for the cost this avoids.
            if isinstance(rec, dict) and not _is_proven_masked(rec):
                redact_record(rec)
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
#: /2 added `identities` + `placeholder_names` (top level; `servers` is unchanged, approved rows only),
#: so the hook can resolve a name over EVERY record in `resolve_all`'s order. A /1 reader ignores
#: both and behaves exactly as before; a /2 reader that finds them absent fails closed in strict mode.
PROJECTION_SCHEMA = "gawk.guard-projection/2"


def _permission_growth(approved: dict[str, Any], last: dict[str, Any]) -> dict[str, list[str]]:
    """`{tool: [what grew]}` between the approved record and the last sighting, by
    `drift.DriftReport.permission_changes`. Empty when nothing grew or the records cannot be
    compared — never a guess."""
    from . import drift
    try:
        report = drift.compare(approved, last)
    except Exception:                                  # noqa: BLE001 — a projection must still write
        return {}
    if report is None:
        return {}
    keys = dict.fromkeys(list(report.annotation_changed) + list(report.schema_changed))
    out: dict[str, list[str]] = {}
    for key in keys:
        if isinstance(key, str) and key.startswith("tool."):
            grown = report.permission_changes(key)
            if grown:
                out[key[len("tool."):]] = grown
    return out


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
    from . import drift     # local: keeps the module graph acyclic, as drift does for signals

    try:
        st = os.stat(path)
        servers: dict[str, Any] = {}
        for key, entry in (store.get("servers") or {}).items():
            if not isinstance(entry, dict):
                continue
            rec = entry.get("approved")
            if not isinstance(rec, dict) or not isinstance(rec.get("tools"), dict):
                continue
            # NOT skipped on an unreadable `schema_version`. That was tried and reverted the same
            # day: omitting a server makes the hook read "never approved", which DEFERS — i.e.
            # allows every call on it — where the previous behaviour denied (hashes from another
            # algorithm cannot match). Worse, the omission is undetectable: this function stamps
            # `source` with the current store stat, so the staleness check passes and the hook
            # trusts a projection it cannot know is partial. A loud refusal in the report path plus
            # a silent fail-open in the enforce path is the worst combination available.
            # Covering the enforcing reader properly needs the projection to CARRY the refusal
            # (so the hook can deny loudly rather than infer from absence) — see HANDOFF.
            row = {"tools": dict(rec["tools"]),
                   "aliases": list(entry.get("aliases") or [])}
            # THE LAST SIGHTING, so the hook can deny the rug-pull it could never see: the hook
            # cannot list a server per call, but every scan and every monitor tick already writes
            # a full record into `history[]`. Its `{tool: hash}` and `measured_at` ride along as
            # `seen`/`seen_at`; the decision core compares `seen[tool]` against the approved hash
            # and the reason names the sighting time — a deny on the last sighting, not on this
            # call (2026-09-05, slice 1 of docs/plan-mcpgawk-fit-readiness-friction-2026-09-05.md).
            # Absent when the server has no sighting at all: an older projection reads the same.
            approved_at = entry.get("approved_at")
            if isinstance(approved_at, str):
                row["approved_at"] = approved_at      # for the confidence line; absent = not recorded
            sightings = entry.get("history")
            last = sightings[-1] if isinstance(sightings, list) and sightings else None
            # ONLY when the two maps were minted by the SAME RULE. `baseline.publish` (monitor
            # approval) writes this field under `fingerprint.surface_hashes` while every sighting
            # writes it under `drift._tool_hashes`; comparing across them denied all 22 tools of a
            # server whose pin proved it had not changed (kite, measured 2026-09-08). Withholding
            # `seen` is the precise stand-down: `declared_verdict` skips the content check when it
            # has no live hash, and tool NAMES — which need no hash — keep enforcing exactly.
            if not drift.tools_comparable(rec):
                row["seen_not_compared"] = drift.TOOLS_NOT_COMPARED.format(server=key)
            elif isinstance(last, dict) and isinstance(last.get("tools"), dict):
                if drift.tools_comparable(last):
                    row["seen"] = dict(last["tools"])
                    measured = last.get("measured_at")
                    if isinstance(measured, str):
                        row["seen_at"] = measured
                    # PERMISSION GROWTH since approval, judged by scan's own `compare` so the guard
                    # refuses exactly what scan reports as an escalation or a new destination
                    # parameter (FOUNDER 2026-10-06). `seen` carries the description only; without
                    # this, a dropped read-only or a new `forward_to` was allowed (measured).
                    grown = _permission_growth(rec, last)
                    if grown:
                        row["permission_changes"] = grown
                    # THE LATCH: tools that changed at an earlier sighting since approval and are
                    # back to their approved form now (`reverted_tools`, the panel reads the same).
                    reverted = reverted_tools(store, key)
                    if reverted:
                        row["reverted"] = reverted
                else:
                    row["seen_not_compared"] = drift.TOOLS_NOT_COMPARED.format(server=key)
            # The APPROVED parameter names per tool, so the hook can catch the smuggled-field
            # rug-pull at call time: a schema widened after approval breaks nothing by itself,
            # but an agent FILLING a parameter the human never approved — and one shaped like a
            # credential — is the attack becoming real ([FOUNDER] 2026-08-15: "do the right
            # thing without breaking any expected flow"). Absent props (older records) simply
            # skip the check.
            props = rec.get("props")
            if isinstance(props, dict):
                row["props"] = {ident[len("tool."):]: list(v)
                                for ident, v in props.items()
                                if isinstance(ident, str) and ident.startswith("tool.")
                                and isinstance(v, list)}
            # CARRY the refusal rather than implying it by absence. A record this build cannot
            # interpret must neither be enforced (its hashes were computed by rules we do not know)
            # nor silently omitted (absent reads as "never approved", which DEFERS = allows, and the
            # hook cannot tell a partial projection from a complete one because `source` still
            # stamps fresh). Emitting the server with an explicit reason and NO tools lets the hook
            # say why it is standing down.
            stored = rec.get("schema_version")
            if stored is not None and (not isinstance(stored, int)
                                       or stored > drift.RECORD_SCHEMA):
                row = {"tools": {}, "aliases": row["aliases"],
                       "unreadable": (f"its approved record was written by a newer mcpgawk "
                                      f"(record schema {stored!r}; this build reads "
                                      f"{drift.RECORD_SCHEMA})")}
            servers[key] = row
        # EVERY RECORD'S IDENTITY, approved or not: its key and the config names it answers to,
        # nothing else (no surface, no hashes, no sightings). `servers` holds approved rows only,
        # and a hook resolving a name over approved rows alone does not do what `resolve` does:
        # when `<name>` is the key of an UNAPPROVED record (resolve -> `mcp:<name>`, no baseline)
        # and an approved record carries `<name>` as an alias, the hook enforced the OTHER record's
        # baseline — in strict mode, a call to a never-approved server let through (found by
        # tests/test_differential_duplicates.py pair 5, pinned by
        # tests/test_guard_resolves_like_history.py). With every identity in hand the hook runs
        # `resolve_all`'s exact order and lands where `resolve` lands. Kept OUT of `servers` on
        # purpose: older readers treat a row there as "approved".
        identities = {key: [a for a in ((entry.get("aliases") or [])
                                        if isinstance(entry, dict) else [])
                            if isinstance(a, str)]
                      for key, entry in (store.get("servers") or {}).items()}
        projection = {"schema": PROJECTION_SCHEMA,
                      "source": {"mtime_ns": st.st_mtime_ns, "size": st.st_size},
                      "servers": servers,
                      "identities": identities,
                      # `resolve_all` refuses a placeholder label outright; carried rather than
                      # duplicated, so the hook's copy of the rule cannot drift from this one.
                      "placeholder_names": sorted(SYNTHETIC_NAMES),
                      # STRICT rides in the same file the hook already trusts, so the hook needs no
                      # second reader of history.json to know whether "no baseline" means deny.
                      "guard": {"strict": guard_strict(store)}}
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
                # Windows-only module: a checker running on POSIX sees no attributes on it at all,
                # which is the same fact this branch already exists to handle.
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)   # type: ignore[attr-defined]
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


#: Names an ad-hoc scan invents for a target that HAS no config name (`--http`, `--stdio`,
#: `--sse`). They are labels for one run, never identities, and they must never be recorded as
#: aliases: the same placeholder is reused for every ad-hoc scan, so it accumulates on unrelated
#: servers and then names none of them. Measured on the founder's store 2026-08-27 —
#: `cli-http` was an alias on BOTH `mcp:Kite MCP Server` and `mcp:Notion MCP`, so
#: `resolve("cli-http")` returned None: an approve by that name could not land anywhere, and the
#: alias table said two different servers answered to one word.
#:
#: Gated HERE, at the write, and not in the callers: every path that records a sighting goes
#: through this function, and a rule enforced in one caller is a rule the next caller will miss.
SYNTHETIC_NAMES = frozenset({"cli-http", "cli-stdio", "cli-sse"})


def _shed_synthetic_aliases(store: dict[str, Any]) -> int:
    """Strip placeholder labels from every record's alias list. Returns how many were removed.

    THE WRITE GATE CAME LATER THAN THE DATA. `record` has refused to write a `SYNTHETIC_NAMES`
    alias since 2026-08-27, but stores written before it keep what they already had — measured on
    the founder's machine 2026-09-02: `cli-stdio` sat on FOUR records (`driftling`, `mcpgawk`,
    `notes-pro`, `secure-filesystem-server`). A gate on new writes does nothing about them.

    WHY IT IS NOT INERT, though today it looks it. Four records answering to one word makes
    `resolve` return None, so nothing lands — which reads as harmless. It is one deletion away from
    harm: drop three of those servers and the word resolves to the SURVIVOR, and
    `mcpgawk approve cli-stdio` then moves a baseline the operator never meant to touch, silently.
    The hazard is not the collision; it is the collision ENDING.

    Both doors, deliberately. On READ so every alias reader — the panel, the fleet rows, the
    protect report, `baseline.export`, the guard hook's projection — is covered by one change
    instead of fourteen; on WRITE so the file itself converges the first time anything saves.
    """
    shed = 0
    for entry in (store.get("servers") or {}).values():
        if not isinstance(entry, dict):
            continue
        aliases = entry.get("aliases")
        if not isinstance(aliases, list):
            continue
        kept = [a for a in aliases if a not in SYNTHETIC_NAMES]
        if len(kept) != len(aliases):
            shed += len(aliases) - len(kept)
            entry["aliases"] = kept
    return shed


#: What every release up to 0.1.69 left of a Slack webhook URL that also carried userinfo: the
#: basic-auth signature swallowed scheme, userinfo and host as `[REDACTED]`, and the rest — the
#: webhook's secret path — no longer matched the webhook signature, which is anchored on that host.
#: No current masking can see it, because the anchor is gone; only this shape can.
_LEAKED_WEBHOOK_RESIDUE = re.compile(
    r"\[REDACTED\]/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")


def _scrub_residue(value: str) -> str:
    from .redact import PLACEHOLDER
    return _LEAKED_WEBHOOK_RESIDUE.sub(PLACEHOLDER, value)


def _scrub_identity(value: str) -> str:
    """One stored identity string (an alias, a key's target half, a fleet URL) under the CURRENT
    masking, plus the residue no current rule recognises. Idempotent on anything already masked."""
    out = _scrub_residue(value)
    return adhoc_target(out) if _is_adhoc_target(out) else out


def _scrub_key(key: str) -> str:
    transport, sep, rest = key.partition(":")
    if sep and transport in _TRANSPORTS:
        return f"{transport}:{_scrub_identity(rest)}"      # a nameless ad-hoc server: the target
    return _scrub_residue(key)


def _baseline_rank(entry: dict[str, Any]) -> tuple[bool, bool]:
    """Which of two entries that turn out to be one identity keeps the record."""
    explicit = bool(entry.get("approved_at")) or entry.get("approved_via") == "approve"
    return explicit, isinstance(entry.get("approved"), dict)


def _scrub_leaked_identities(store: dict[str, Any]) -> int:
    """Re-mask every server's aliases and KEY, and the fleet's recorded targets. Returns how many
    strings changed.

    `save()` re-masks RECORDS (`redact_record`), and a record's stamp binds only the record. Aliases
    and keys are identities and were never re-masked, so a secret a released masker left in one
    stayed on disk for good — measured 2026-10-05: a Slack webhook secret behind userinfo, stored by
    0.1.69 as `[REDACTED]/services/T…/B…/<secret>` in the alias and in the nameless server's key.

    A KEY IS AN IDENTITY, so a scrubbed key is a MIGRATION, not an edit: the entry moves to the key
    a scan of the same target computes today (`key_for` → `adhoc_target`), keeping its approved
    baseline and provenance, exactly as `record`'s legacy-key migration would have moved it. If that
    key is already taken, the two are one identity under the current rules: the entry a person
    approved explicitly wins, then one with any baseline, then the one already there; aliases are
    merged.

    Both doors, like the synthetic-alias shed: on READ so every reader sees no secret, on WRITE so
    the file — and the guard projection derived from it — converges the first time anything saves.
    """
    changed = 0
    servers = store.get("servers")
    if isinstance(servers, dict):
        for key in list(servers):
            entry = servers[key]
            if isinstance(entry, dict) and isinstance(entry.get("aliases"), list):
                new: list[Any] = []
                for a in entry["aliases"]:
                    a2 = _scrub_identity(a) if isinstance(a, str) else a
                    if a2 not in new:
                        new.append(a2)
                if new != entry["aliases"]:
                    changed += 1
                    entry["aliases"] = new
            new_key = _scrub_key(key) if isinstance(key, str) else key
            if new_key == key:
                continue
            changed += 1
            moved = servers.pop(key)
            there = servers.get(new_key)
            if not isinstance(there, dict) or not isinstance(moved, dict):
                servers[new_key] = moved
                continue
            winner, loser = ((moved, there) if _baseline_rank(moved) > _baseline_rank(there)
                             else (there, moved))
            aliases = list(winner.get("aliases") or [])
            aliases += [a for a in (loser.get("aliases") or []) if a not in aliases]
            winner["aliases"] = aliases
            servers[new_key] = winner
    fleet = store.get(FLEET_KEY)
    entries = fleet.get("entries") if isinstance(fleet, dict) else None
    for target in (entries.values() if isinstance(entries, dict) else ()):
        if not isinstance(target, dict):
            continue
        if isinstance(target.get("url"), str):
            url = _scrub_identity(target["url"])
            if url != target["url"]:
                target["url"], changed = url, changed + 1
        if isinstance(target.get("command"), list):
            cmd = [(_scrub_identity(t) if "://" in t else _scrub_residue(t))
                   if isinstance(t, str) else t for t in target["command"]]
            if cmd != target["command"]:
                target["command"], changed = cmd, changed + 1
    return changed



def record(key: str, rec: dict[str, Any], path: str | None = None,
           keep: int = 50, migrate_from: tuple[str, ...] = (),
           alias: str | None = None, adopt_first: bool = True) -> dict[str, Any] | None:
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

    EXCEPT for a server that APPEARED after the fleet was approved (`adopt_first=False`, decided
    by the caller against `fleet_appeared`). Its sighting is kept — `approve <name>` needs one to
    adopt — but it is marked AWAITING_APPROVAL and never becomes the baseline here. Measured on
    0.1.68: a planted `mcp-sync` entry became its own approval on first sight. Once marked, no
    later scan adopts it either, whatever the caller passes: only `approve` and `approve --fleet`
    clear the mark, and both go through the human gate.
    """
    path = path or default_path()
    # IN PLACE, before anything compares it: the caller keeps this same object and diffs it against
    # the baseline this function returns. Masking only on the way to disk would diff a raw `current`
    # against a masked baseline and report a rename on every scan of a credentialled server.
    redact_record(rec)
    # A nameless ad-hoc server keyed under the RELEASED masking is this server's own record.
    migrate_from = tuple(migrate_from) + _legacy_adhoc_keys(key, alias)
    if alias and _is_adhoc_target(alias):
        alias = adhoc_target(alias)      # at the write, so no caller can store a key in a URL
    with locked(path):
        store = load(path)
        adopted = _migrate(store, key, migrate_from, alias)
        base = approved(store, key)
        entry = server_entry(store, key)
        if base is None and (not adopt_first or entry.get(AWAITING_APPROVAL)):
            entry[AWAITING_APPROVAL] = "appeared"
            if not isinstance(entry.get("appeared_at"), str):
                entry["appeared_at"] = rec.get("measured_at") or _now_iso()
        elif base is None:
            keep_original(entry, rec, "first-sighting")
            entry["approved"] = rec          # trust-on-first-use
            # Say HOW it became the baseline. Without this a first sighting and a human `approve`
            # from before approved_at existed looked alike, and drift told a user who never
            # approved anything "changed since you approved it" (new-developer walk, 2026-09-26).
            entry["approved_via"] = "first-sighting"
        if adopted:
            # AN ADOPTED RECORD'S ALIASES MAY NAME OTHER SERVERS. A record conflated under the old
            # identity carries the config name of EVERY entry that shared it — so keeping them here
            # would let the bug survive its own fix: until the sibling entry is itself re-scanned,
            # the guard's alias lookup would single-match this record and enforce a baseline the
            # sibling's owner never reviewed. Only the entry actually claiming the record keeps its
            # name; a claim with no alias to attribute keeps none, because a name we cannot
            # attribute is exactly the thing that must not resolve.
            entry["aliases"] = [alias] if alias else []
        if alias and alias not in SYNTHETIC_NAMES:
            # The key is the server's asserted identity; the user thinks in config names. Remember
            # every name this server has been configured under so `approve <name>` resolves.
            entry["aliases"] = sorted(set(entry.get("aliases", [])) | {alias})
        append(store, key, rec, keep=keep)
        save(store, path)
    return base


#: Longest `--reason` kept on an approval record. A reason is a sentence, not a document.
APPROVAL_REASON_MAX = 500


def approval_change(prev: Any, latest: Any) -> dict[str, Any]:
    """What an approval of `latest` accepts, measured against the previous approval `prev`.

    Names, not content: tools added and removed, descriptions rewritten, inputs reshaped,
    annotations changed, and permission growth by scan's own rule. `{"first_approval": True}` when
    nothing was approved before; `{"compared": False}` when the two records cannot be compared
    (different hashing rules), so the record never claims a diff it did not make."""
    from . import drift
    tools = latest.get("tools") if isinstance(latest, dict) else None
    if not isinstance(prev, dict):
        return {"first_approval": True, "tools": len(tools) if isinstance(tools, dict) else 0}
    try:
        report = drift.compare(prev, latest)
    except Exception:                                   # noqa: BLE001 — a record must still write
        report = None
    if report is None or getattr(report, "unreadable", None):
        return {"compared": False}
    split = report.of_kind("tool")
    growth: dict[str, list[str]] = {}
    for k in dict.fromkeys(list(report.annotation_changed) + list(report.schema_changed)):
        if isinstance(k, str) and k.startswith("tool."):
            grown = report.permission_changes(k)
            if grown:
                growth[k[len("tool."):]] = grown
    return {"tools_added": split["added"], "tools_removed": split["removed"],
            "descriptions_changed": split["changed"],
            "schemas_changed": [k[5:] for k in report.schema_changed if k.startswith("tool.")],
            "annotations_changed": [k[5:] for k in report.annotation_changed
                                    if k.startswith("tool.")],
            "permission_growth": growth}


def change_words(change: Any) -> str | None:
    """One line for a person: "+1 tool (forward_note), 2 descriptions rewritten", or None."""
    if not isinstance(change, dict):
        return None
    if change.get("first_approval"):
        n = change.get("tools") or 0
        return f"first approval, {n} tool{'s' if n != 1 else ''}"
    if change.get("compared") is False:
        return "not comparable with the previous approval"

    def _names(xs: list[str]) -> str:
        return ", ".join(xs[:3]) + (f" and {len(xs) - 3} more" if len(xs) > 3 else "")

    parts: list[str] = []
    for field, sign in (("tools_added", "+"), ("tools_removed", "−")):
        xs = list(change.get(field) or [])
        if xs:
            parts.append(f"{sign}{len(xs)} tool{'s' if len(xs) != 1 else ''} ({_names(xs)})")
    for field, words in (("descriptions_changed", "description{} rewritten"),
                         ("schemas_changed", "input schema{} reshaped")):
        n = len(change.get(field) or [])
        if n:
            parts.append(f"{n} " + words.format("s" if n != 1 else ""))
    growth = change.get("permission_growth") or {}
    if growth:
        parts.append(f"permission growth on {_names(sorted(growth))}")
    total = original_words(change.get("since_original"))
    if total:
        inner = {k: v for k, v in change.items() if k != "since_original"}
        return f"{change_words(inner)}; {total}"
    reverted = change.get("changed_and_reverted")
    if isinstance(reverted, dict):
        what = change_words(reverted) or "a change"
        when = str(change.get("changed_at") or "")[:10]
        return (", ".join(parts) + "; " if parts else "") + \
            f"changed{(' on ' + when) if when else ''} and changed back ({what})"
    return ", ".join(parts) or "no change to its tools since the previous approval"


def approve(key: str, path: str | None = None, *,
            expect_pin: str | None = None, source: str = "cli",
            reason: str | None = None) -> dict[str, Any] | None:
    """Adopt the most recent sighting of `key` as the approved baseline. Returns it.

    The explicit acknowledgement ADR-0012 requires. Until this runs, drift keeps reporting — and
    keeps failing CI — which is the whole point: an alarm that clears itself is worse than no alarm,
    because it looks like coverage.

    Gated at the WRITE, not only at the command. Every caller already checks — but "every caller
    checks" is a property that decays the moment someone adds a caller, and it did.
    """
    require_human_approval()
    evidence = approval_evidence(source)
    path = path or default_path()
    with locked(path):
        store = load(path)
        latest = last(store, key)
        if latest is None:
            return None
        # ADOPT WHAT WAS REVIEWED, NOT WHAT IS NEWEST. `mcpgawk monitor approve` accepts the
        # snapshot the operator looked at; between that look and this write the daemon may have
        # recorded a newer sighting. Refusing inside the lock is the only place the check is
        # airtight (2026-09-04, ledger 109).
        if expect_pin is not None and str(latest.get("pin") or "") != str(expect_pin):
            return None
        entry = server_entry(store, key)
        # WHAT was accepted, against the previous approval, and WHY if the person said (Yashigani
        # read, candidate 3): "approved by me at 10:02" never answered "approved what?".
        entry["approved_change"] = approval_change(entry.get("approved"), latest)
        # A change that reverted is still what this approval answers: record it, or the record
        # says nothing was accepted while a person just cleared a held change (the latch).
        _held = held_sighting(store, key)
        if isinstance(_held, dict) and _held is not latest \
                and not _surface_differs(entry.get("approved"), latest):
            entry["approved_change"]["changed_and_reverted"] = approval_change(
                entry.get("approved"), _held)
            entry["approved_change"]["changed_at"] = _held.get("measured_at")
        _why = (reason or "").strip()
        if _why:
            entry["approved_reason"] = _why[:APPROVAL_REASON_MAX]
        else:
            entry.pop("approved_reason", None)
        _total = since_original(entry, latest)
        if _total is not None:
            entry["approved_change"]["since_original"] = _total
        keep_original(entry, latest, "approve")
        entry["approved"] = latest
        clear_review(entry)                  # the held change is answered by this approval
        entry.pop(AWAITING_APPROVAL, None)
        # PROVENANCE. `cli status` has printed `approved —` since the field it reads was never
        # written (2026-09-03); and "approved when, by whom" is the first thing a security team
        # asks of a baseline ("Approved May 18 · By: Security Admin"). Single operator today, so
        # `by` is the OS user at this host — honest, and the slot RBAC fills later.
        entry["approved_at"] = _now_iso()
        entry["approved_by"] = _operator()
        entry["approved_via"] = "approve"
        entry["approved_evidence"] = evidence
        admit_to_fleet(store, key)
        save(store, path)
    return latest


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _operator() -> str:
    """`user@host` for the person running this command. Never a secret, never guessed."""
    import getpass
    import socket
    try:
        user = getpass.getuser()
    except Exception:                                  # noqa: BLE001 — no passwd entry
        user = "unknown"
    return f"{user}@{socket.gethostname().split('.')[0]}"


def approval_provenance(store: dict[str, Any], key: str) -> tuple[str | None, str | None]:
    """(approved_at, approved_by) for a server, or (None, None) — absent is stated, not invented:
    a baseline approved before these fields existed says so rather than borrowing its
    measurement time."""
    e = (store.get("servers") or {}).get(key) or {}
    at, by = e.get("approved_at"), e.get("approved_by")
    return (at if isinstance(at, str) else None), (by if isinstance(by, str) else None)


def baseline_origin(store: dict[str, Any], key: str) -> str | None:
    """How a server's baseline was set — THE one rule every surface words its change from:

    * "approve": a person ran `mcpgawk approve` (or `approve --fleet` adopted it while held);
    * "fleet": a first sighting that a later `approve --fleet` accepted — the fleet approval
      recorded this server's config entry, after the baseline was measured (`fleet_covers`);
    * "first-sighting": trust on first use, and nobody has approved it since;
    * None: a baseline older than the field, whose origin is unknown and is not guessed.

    `approve --fleet` adopts only HELD sightings, so a server first seen before it keeps
    `approved_via: first-sighting` on disk; deciding "fleet" here, and not in a caller, is what
    keeps the scan, protect, the panel and `baseline` from disagreeing (e2e, 2026-10-05)."""
    e = (store.get("servers") or {}).get(key) or {}
    if e.get("approved_at") or e.get("approved_via") == "approve":
        return "unattended" if evidence_words(e.get("approved_evidence")) else "approve"
    via = e.get("approved_via")
    if via is None:
        # NO MARKER AT ALL. `approve` has stamped approved_at / approved_by / approved_via on every
        # path since APPROVAL_MARKERS_SINCE; the first-sighting fallback only began labelling
        # itself on 2026-09-26. A record from the window between, with no marker, can only be a
        # first sighting — a real approval would have left its stamp. Older than the window it
        # is unknown, and unknown is said as unknown, never as "you approved" (notion and
        # brandfetch, 2026-10-09: the scan told the founder they had approved two servers that
        # were first-sighting fallbacks from 15 Sep).
        at = str((e.get("approved") or {}).get("measured_at") or "")
        if at < APPROVAL_MARKERS_SINCE:
            return None
        via = "first-sighting"
    if via != "first-sighting":
        return None
    if not fleet_covers(store, key):
        return "first-sighting"
    return "unattended" if evidence_words((fleet_baseline(store) or {}).get("evidence")) else "fleet"


def unattended_reason(store: dict[str, Any], key: str) -> str | None:
    """Why this server's baseline was approved without a person present, or None. The one sentence
    every surface prints for an "unattended" origin (`baseline_origin`)."""
    e = (store.get("servers") or {}).get(key) or {}
    if e.get("approved_at") or e.get("approved_via") == "approve":
        return evidence_words(e.get("approved_evidence"))
    if e.get("approved_via") == "first-sighting" and fleet_covers(store, key):
        return evidence_words((fleet_baseline(store) or {}).get("evidence"))
    return None


def fleet_covers(store: dict[str, Any], key: str) -> bool:
    """A first-sighting baseline that an `approve --fleet` made AFTER it was recorded accepted:
    the fleet approval is dated at or after the baseline's measurement, and it recorded a config
    entry this server answers to. Time alone also marked an ad-hoc `--stdio` server, which no
    fleet approval ever listed, as approved by one."""
    from datetime import datetime
    fleet = fleet_baseline(store)
    base = approved(store, key)
    if not fleet or not isinstance(base, dict):
        return False
    try:
        approved_at = datetime.fromisoformat(str(fleet.get("approved_at")).replace("Z", "+00:00"))
        measured = datetime.fromisoformat(str(base.get("measured_at")).replace("Z", "+00:00"))
        if approved_at < measured:
            return False
    except (TypeError, ValueError):
        return False
    aliases = {str(a) for a in (((store.get("servers") or {}).get(key) or {}).get("aliases") or [])}
    return any(str(fk).partition("/")[2] in aliases for fk in (fleet.get("entries") or {}))


#: `approve` has written approved_at / approved_by / approved_via on every path since this
#: release date (e133152c, shipped in 0.1.35 on 2026-09-05). A record approved on or after it
#: with no marker was therefore never through `approve` — see `baseline_origin`.
APPROVAL_MARKERS_SINCE = "2026-09-05"

#: Origins whose baseline a person stands behind. None — a baseline older than
#: APPROVAL_MARKERS_SINCE with no marker — is UNKNOWN, and an unknown origin is not a person's
#: approval: until 2026-10-09 it kept the "you approved" words, which asserted a decision the
#: record cannot show. Unknown is worded as "its baseline" on every surface.
VOUCHED_ORIGINS = frozenset({"approve", "fleet"})


def vouched(origins: "list[str | None]") -> bool:
    """True when a person stands behind EVERY one of these baselines (see `VOUCHED_ORIGINS`)."""
    return bool(origins) and all(o in VOUCHED_ORIGINS for o in origins)


def since_words(origins: "list[str | None]", *, plural: bool | None = None) -> str:
    """What a change is measured since, for a sentence: "since you approved it/them" only when a
    person approved every baseline; "since its first sighting" for one that nobody did; "since
    its/their baseline" for a mix. `plural` overrides the count for a "server(s)" sentence."""
    many = (len(origins) != 1) if plural is None else plural
    if vouched(origins):
        return "since you approved them" if many else "since you approved it"
    if not many and list(origins) == ["first-sighting"]:
        return "since its first sighting"
    return "since their baseline" if many else "since its baseline"


def changed_since(store: dict[str, Any], keys: "list[str]", *, plural: bool | None = None) -> str:
    """`since_words` for stored servers."""
    return since_words([baseline_origin(store, k) for k in keys], plural=plural)


def changed_head(origin: "str | None", when: "str | None") -> str:
    """THE sentence for one server that moved off its baseline: "changed since …", worded from
    `baseline_origin`. The scan's drift head, the panel's /next headline and `baseline` all print
    this one string, so they cannot disagree about who approved what (2026-10-09: the scan said
    "since you approved it 23 days ago" and /next said "nobody has approved this server yet" of
    the same record). `when` is already a phrase — "23 days ago" or "on 2026-09-15" — or None."""
    w = f" {when}" if when else ""
    if origin == "first-sighting":
        # Trust on first use is not a decision (new-developer walk, 2026-09-26).
        return f"changed since first seen{w}; you have not approved this server yet"
    if origin == "unattended":
        # Approved with no person present: "you approved it" claims a decision nobody made.
        return f"changed since its baseline, approved{w} without a person present"
    if origin == "fleet":
        # First seen, then accepted by `approve --fleet`: the date is the sighting's, said so.
        return f"changed since first seen{w}, the baseline your fleet approval accepted"
    if origin == "approve":
        return f"changed since you approved it{w}" if when else "changed after you approved it"
    # Unknown: a record older than APPROVAL_MARKERS_SINCE with no marker. Neither a person nor
    # nobody can be asserted; say what the anchor is and that the record does not say who set it.
    return (f"changed since its baseline, recorded{w}; who approved it is not on record"
            if when else "changed since its baseline; who approved it is not on record")


def at_baseline_words(origins: "list[str | None]", *, plural: bool = False) -> str:
    """THE words after "N server(s)" for records sitting at their baseline, from `baseline_origin`:
    "at an approved baseline" only when a person stands behind every one (`vouched`); "at a
    baseline with no person's approval on record" when none does; the split when mixed. The bare run's Protected
    line, `status`'s EXPECTED BEHAVIOUR count and the panel's See step print this one string
    (2026-10-09: all three said "at an approved baseline" of first-sighting records). An empty
    set describes nothing and keeps the plain words."""
    if not origins or vouched(origins):
        return "at their approved baseline" if plural else "at an approved baseline"
    # Not vouched: a first sighting (nobody), an unattended approval (no person present) or a
    # record older than the markers (not on record). One phrase that is true of all three and
    # asserts neither "you approved" nor "nobody did" — the same line `changed_head` walks.
    n_v = sum(1 for o in origins if o in VOUCHED_ORIGINS)
    if n_v == 0:
        return "at a baseline with no person's approval on record"
    return (f"at a baseline — {n_v} you approved, {len(origins) - n_v} with no person's "
            f"approval on record")


def at_baseline_words_for(store: dict[str, Any], keys: "list[str]", *, plural: bool = False) -> str:
    """`at_baseline_words` for stored servers."""
    return at_baseline_words([baseline_origin(store, k) for k in keys], plural=plural)


def changed_within(store: dict[str, Any], days: int = 7,
                   now: "float | None" = None) -> list[tuple[str, str]]:
    """Servers whose surface first MOVED from its approved pin within the last `days`, as
    `(key, first_changed_at)`. The fleet change rate an operator reads at a glance ("Changes
    (7d): 12"), computed from the sightings already in the store — no new measurement.

    "First moved" is the earliest sighting after the approval whose pin differs; a server that
    changed three weeks ago and again yesterday counts by its first move, because the question
    is "what started needing me this week", not "what is still pending".

    HONEST ABOUT RETENTION: the store keeps a bounded number of sightings. If the OLDEST kept
    sighting after the approval already differs, the first move happened at or before it and
    cannot be dated — such a server is left OUT rather than dated by whatever survived
    (browserstack, scanned daily, would otherwise have read "changed this week" for a change
    from 19 days earlier, 2026-09-03). A move counts only when a kept sighting AT the approved
    pin precedes the first differing one.
    """
    import time as _time
    from datetime import datetime, timezone
    horizon = (now if now is not None else _time.time()) - days * 86400
    out: list[tuple[str, str]] = []
    for key, e in (store.get("servers") or {}).items():
        if not isinstance(e, dict):
            continue
        approved = e.get("approved")
        if not isinstance(approved, dict) or not approved.get("pin"):
            continue
        since = str(approved.get("measured_at") or "")
        seen_at_pin = False
        for sighting in e.get("history") or []:
            if not isinstance(sighting, dict):
                continue
            at = str(sighting.get("measured_at") or "")
            if at < since:
                continue
            if sighting.get("pin") == approved.get("pin"):
                seen_at_pin = True
                continue
            if not seen_at_pin:
                break                               # first move predates what was kept: undatable
            try:
                ts = datetime.fromisoformat(at.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                break
            if ts.timestamp() >= horizon:
                out.append((key, at))
            break                                   # the FIRST move decides; later ones do not
    return sorted(out, key=lambda kv: kv[1], reverse=True)


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

    None when nothing matches AND when the name is AMBIGUOUS — an alias of several records. This
    used to take the first match, which is the write-side twin of the bug the enforcing reader
    already defers on: an operator typing `mcpgawk approve billing` would move the approved baseline
    of whichever record happened to sort first, and nothing would say so.

    The routine source of collisions was the placeholder every ad-hoc scan reused (`cli-stdio` and
    friends). Those are refused outright now — see `resolve_all` and `_shed_synthetic_aliases` —
    so a genuine collision means two config entries really do share a name, which is rare and worth
    refusing loudly. Callers that need to explain the ambiguity use `resolve_all`.
    """
    matches = resolve_all(store, wanted)
    return matches[0] if len(matches) == 1 else None


def resolve_all(store: dict[str, Any], wanted: str) -> list[str]:
    """Every stored key `wanted` could mean. Same order as `resolve`: exact key, then the bare
    asserted name, then config-name aliases. An exact match is unambiguous by construction — only
    the alias scan can return several."""
    servers = store.get("servers", {})
    if wanted in servers:
        return [wanted]
    if f"mcp:{wanted}" in servers:
        return [f"mcp:{wanted}"]
    if wanted in SYNTHETIC_NAMES:
        # A PLACEHOLDER NEVER NAMES A SERVER. `--stdio`/`--http`/`--sse` scans all label their one
        # target the same way, so the word belongs to no server in particular. Refusing it here is
        # the invariant that does not depend on the data being clean: an old store still carrying
        # `cli-stdio` on a single record would otherwise single-match, and `approve cli-stdio`
        # would move a baseline the operator never named.
        return []
    # An ad-hoc alias is stored masked (`adhoc_target`); the person may paste the raw URL.
    names = {wanted, adhoc_target(wanted)} if _is_adhoc_target(wanted) else {wanted}
    found = [key for key, entry in servers.items()
             if names & set(entry.get("aliases") or [])]
    if found or not _is_adhoc_target(wanted):
        return found
    # A record not re-scanned since the masking fix still carries the RELEASED alias. A fallback,
    # not a peer: the old form collapsed hosts, so it answers only when no exact alias does — and
    # several records sharing it come back as several, which `resolve` refuses as ambiguous.
    legacy = _legacy_adhoc_target(wanted)
    return [key for key, entry in servers.items()
            if legacy in (entry.get("aliases") or [])] if legacy not in names else []


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


_LAUNCHERS = frozenset({"npx", "uvx", "bunx", "pnpm", "yarn", "node", "deno", "bun", "python",
                        "python3", "uv", "docker", "podman"})


def _is_adhoc_target(alias: str) -> bool:
    """A URL or a command line (what `_adhoc_name` records), as opposed to a config entry's name."""
    if "://" in alias:
        return True
    head = alias.split()[0] if alias.split() else ""
    return "/" in head or (head in _LAUNCHERS and len(alias.split()) > 1)


def adhoc_target(target: str) -> str:
    """The form an AD-HOC target (a URL or command you typed) is stored and printed in.

    Credential shapes masked, everything else kept: this is an identity, so the host, path, package
    and version must survive (the diagnostics masker `report_redact.redact_command` drops them). A
    raw `?apiKey=` URL used to land verbatim in history.json as an alias, and now also forms the key
    of a nameless server, which the drift block prints as the `approve` command (2026-09-26)."""
    from .redact import redact, redact_url
    if "://" in target and " " not in target.strip():
        masked = redact_url(target) or target
        # THE USERINFO IS MASKED APART FROM THE HOST. `redact_url` turns `u:pass@a.dev` into
        # `u:***@a.dev`, and the basic-auth provider signature then read `***` as a password and
        # swallowed scheme, userinfo and host whole: `https://u:pass@a.dev/mcp` and
        # `https://u:pass@b.dev/mcp` both stored as `[REDACTED]/mcp`, one identity for two hosts.
        # So the prose redactor sees the URL WITHOUT its userinfo (every other shape, including
        # host-anchored ones, still fires) and the userinfo on its own (a token carried as the
        # username is still masked), and the two are put back together.
        scheme_end = masked.find("://") + 3
        netloc_end = next((i for i in range(scheme_end, len(masked)) if masked[i] in "/?#"),
                          len(masked))
        netloc = masked[scheme_end:netloc_end]
        if "@" in netloc:
            creds, hostport = netloc.rsplit("@", 1)
            head = masked[:scheme_end] + hostport
            bare = redact(head + masked[netloc_end:]) or head
            if not bare.startswith(head):
                # A shape anchored on the host itself fired (a Slack webhook is its host): there is
                # no host left to keep, so return that masking whole. NOT `redact(masked)`, the
                # released form: there the basic-auth signature consumed the URL up to the first
                # `/` before the webhook shape could match, and the webhook's secret survived.
                return bare
            # A credential-shaped username is masked whole, as `***`: the redactor's bracketed
            # placeholder inside a netloc reads as an IPv6 literal and breaks the URL.
            creds = creds if redact(creds) == creds else "***"
            return f"{masked[:scheme_end]}{creds}@{bare[scheme_end:]}"
        return redact(masked) or target
    # A COMMAND gets only its URLs masked (`mcp-remote <url?key=…>`, the credential shape seen in
    # launch lines). `redact()` reads `name@version` as an address: `npx -y a@1.0.0` and
    # `npx -y b@2.0.0` both became `npx -y [REDACTED]`, one key for two servers again.
    # EACH URL IS MASKED AS A URL TARGET IS, provider signatures included. Structural masking
    # alone (`redact_urls_in_text`) kept `mcp-remote <a Slack incoming-webhook URL>` verbatim, its
    # /services/T…/B…/<secret> path and all: a webhook's secret is its path, not a parameter or a
    # password (2026-10-05). No literal URL here: the privacy-policy egress test reads every host
    # string in the free package as a host it contacts.
    from .redact import _URL_IN_TEXT
    return _URL_IN_TEXT.sub(lambda m: adhoc_target(m.group(0)), target) or target


def _legacy_adhoc_target(target: str) -> str:
    """`adhoc_target` as every release up to 0.1.69 computed it — kept because its output is an
    identity KEY in users' stores (`http:<it>` for a nameless ad-hoc server, and the alias of a
    named one). For a `user:pass@host` URL it lost the host (`[REDACTED]/mcp`); the fixed form
    keeps it, which re-keys that server. Without this derivation the upgrade would orphan the
    baseline: a "new" server, a first sighting, silence — the reset ADR-0012 exists to prevent.
    Used only to FIND an old record (`record`'s migration, `resolve_all`'s fallback), never to
    write one."""
    from .redact import redact, redact_url, redact_urls_in_text
    if "://" in target and " " not in target.strip():
        return redact(redact_url(target) or target) or target
    return redact_urls_in_text(target) or target


def _legacy_adhoc_keys(key: str, raw_alias: str | None) -> tuple[str, ...]:
    """The key a NAMELESS ad-hoc server had under `_legacy_adhoc_target`, when it differs.

    `key_for` keys such a server `{transport}:{adhoc_target(target)}`, and the scan passes the same
    target as the alias. `cli` builds `migrate_from` from the snapshot alone, which never sees the
    target — so the derivation lives here, at the one write every scan goes through."""
    if not raw_alias or not _is_adhoc_target(raw_alias):
        return ()
    transport, _, rest = key.partition(":")
    if transport not in _TRANSPORTS or rest != adhoc_target(raw_alias):
        return ()
    old = _legacy_adhoc_target(raw_alias)
    return (f"{transport}:{old}",) if old != rest else ()


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
    # AN AD-HOC TARGET IS NOT A NAME. `scan --stdio "<cmd>"` / `--http <url>` records the command
    # line or URL as the alias (cli._adhoc_name) so `approve` can match what was typed; shown as
    # the name, `status` printed a whole temp-path command line (new-developer re-walk,
    # 2026-09-26). Where the server asserted a name and every alias is such a target, show the
    # asserted name: `approve <it>` resolves through the `mcp:` form.
    asserted = key[len("mcp:"):].split("#", 1)[0] if key.startswith("mcp:") else ""
    if asserted and aliases and all(_is_adhoc_target(a) for a in aliases):
        return asserted
    if not aliases:
        return key
    # A CONFIG NAME BEATS A TARGET. Aliases are stored sorted, so a URL alias from `scan --http`
    # sorted ahead of the config name and the fleet read "https://<host>/mcp (also
    # configured as notion)" above "approve <name>" (2026-10-09). The ad-hoc targets are how the
    # server was reached, not what it is called: they are neither the name nor the aside.
    named = [a for a in aliases if not _is_adhoc_target(a)] or aliases
    primary = named[0]

    # AMBIGUITY IS WORSE THAN THE RAW KEY. Two different servers can carry the same alias, and a
    # fleet then shows two rows reading identically: a user cannot tell which one changed, and
    # `approve <that name>` is a coin flip. The routine source of this — the placeholder every
    # ad-hoc scan reused — is gone (`_shed_synthetic_aliases`), so what is left is two config
    # entries genuinely sharing a name. Rarer, and still worth saying out loud.
    sharing = [k for k, v in servers.items()
               if k != key and primary in ((v or {}).get("aliases") or [])]
    if sharing:
        return f"{primary} [{key}]"
    if len(named) == 1:
        return primary
    return f"{primary} (also configured as {', '.join(named[1:])})"


def pending(store: dict[str, Any]) -> list[str]:
    """Keys whose newest sighting differs from the approved baseline — i.e. unacknowledged drift.

    ALL drift-relevant axes, not items alone. Found live 2026-08-15: browserstack's input
    schemas changed (createLCASteps gained `requires_authentication`) — the scan reported the
    drift, the surface pin caught it, and this function compared `items` only, so Decisions
    said "0 waiting on you" while scan said "review the change, then approve". A schema-only
    widening is the exact rug-pull class the pin was extended for (audit B2); a decision queue
    that cannot see it is a queue the attacker routes around. An axis is compared only when
    BOTH records carry it, so stores approved before that axis existed do not flood the queue
    on upgrade — their drift stays invisible until the next approve, exactly as before."""
    out = []
    for key, entry in store.get("servers", {}).items():
        base, latest = approved(store, key), sighting_to_review(store, key)
        if not (base and latest):
            continue
        # ONE rule, imported — not a second opinion. This function compared the whole `items`
        # maps, so a kind the baseline never enumerated queued a decision that `drift.compare`
        # then correctly found nothing in: a blocked server with an empty diff. Same import, same
        # answer, both surfaces (dadan, 2026-09-09).
        #
        # THE WHOLE RULE, not the half of it that was copied here. Filtering `items` by
        # `comparable_kinds` reproduced compare's kind rule but not its LEGACY rule: a baseline
        # approved before item fingerprints carries only `tools`, which compare promotes to
        # `tool.*` keys and diffs against the sighting's tools. Read here as an absent `items` map,
        # it differed from every modern sighting, so an UNCHANGED server was queued on upgrade —
        # the flood this docstring promises never happens. So the decision IS compare's verdict,
        # on exactly the surface fields a person is asked to review.
        from . import drift as _drift
        r = _drift.compare(base, latest)
        if r is not None and (r.added or r.removed or r.changed or r.schema_changed
                              or r.annotation_changed):
            out.append(key)
    return sorted(out)


def approved(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    """The record drift diffs against. Falls back to the OLDEST sighting for stores written before
    ADR-0012, so upgrading does not silently adopt a state the user never approved."""
    entry = store.get("servers", {}).get(key, {})
    if "approved" in entry:
        return entry["approved"]
    if entry.get(AWAITING_APPROVAL):
        # An appeared server was never approved — the oldest-sighting fallback is for stores
        # written before ADR-0012, and applied here it would adopt the sighting on the next read.
        return None
    hist = entry.get("history", [])
    return hist[0] if hist else None


def same_surface(store: dict[str, Any], key: str, rec: dict[str, Any]) -> bool:
    """True when the APPROVED baseline under `key` carries the same tool-surface pin as `rec`.

    The pin is the rug-pull anchor: an identical pin means the tools, their schemas and their
    descriptions are the exact surface a human approved. A server that re-identifies (lands on a
    new store key) while presenting that same surface has not rug-pulled — there is nothing changed
    to hide behind the new name — so its baseline may carry over rather than being treated as an
    unreviewed stranger. A missing baseline, a missing pin on either side, or a differing pin all
    return False, so the caller falls back to the honest "different server" path. This is the
    discriminator that separates an auth-state change (kite signed out advertises no name, so it
    keys by config name) from a genuine rename-evasion (a new name AND a changed surface).

    Compares the pin only, not `pin_basis`: a baseline minted under an older pin RULE has a
    different pin for an identical surface, so this returns False and the caller keeps the alarm.
    That is the conservative direction (a false "different server" on a rule upgrade, never a
    suppressed rename), so it is left as-is rather than reaching across bases.
    """
    base = approved(store, key)
    if not isinstance(base, dict):
        return False
    prior, now = base.get("pin"), rec.get("pin")
    return bool(prior) and prior == now


def _migrate(store: dict[str, Any], key: str, legacy_keys: tuple[str, ...],
             alias: str | None = None) -> bool:
    """Move a pre-existing baseline onto `key` when the identity scheme changed underneath it.

    Without this, shipping the server-asserted identity would itself orphan every user's baseline on
    upgrade — the exact silent-reset this ADR exists to prevent, caused by the fix for it."""
    servers = store.get("servers") or {}
    if key in servers:
        return False
    for old in list(legacy_keys) + _shed_credential_keys(servers, key, alias):
        if old not in servers:
            continue
        if not _may_adopt(servers[old], old, alias):
            continue
        # Creates the new key, so it goes through the same gate as any other creation — a
        # migration must not be the one path that can mint an entry nothing validated.
        server_entry(store, key).update(servers.pop(old))
        return True
    return False


def credential_shed_keys(store: dict[str, Any], key: str, alias: str | None) -> tuple[str, ...]:
    """`_shed_credential_keys` for callers that must know the answer BEFORE recording.

    `record()` applies the migration itself, but the scan also has to decide whether to ANNOUNCE a
    re-identification. A key the migration is about to adopt is not a different server, and saying
    "its baseline does not carry over" about a baseline that does is a false alarm that would fire
    once for every OAuth server on upgrade. One function, consulted by both."""
    return tuple(_shed_credential_keys(store.get("servers") or {}, key, alias))


def _shed_credential_keys(servers: dict[str, Any], key: str, alias: str | None) -> list[str]:
    """Discriminated records this now-UNDISCRIMINATED entry could already be recorded under.

    `legacy_identity_keys` covers the direction identity has moved before: bare -> discriminated,
    when an entry gained a login. This is its mirror, and it opened on 2026-08-27 when the
    discriminator stopped hashing a token this machine attached for itself (see
    `credentials.IDENTITY_AS_DECLARED`). Every OAuth server keyed `mcp:<name>#<token-hash>` now
    keys `mcp:<name>`, and without this every one of those baselines is orphaned on upgrade — the
    silent reset ADR-0012 exists to prevent, caused once again by the fix for a different one.

    Store-aware because it has to be: the snapshot no longer carries the fingerprint it is shedding,
    so the old key is not derivable from it — only findable.

    AMBIGUITY IS REFUSED, not resolved by sort order. Several discriminated records naming this
    alias means one server was genuinely tracked under several accounts; adopting whichever comes
    first would hand this entry an approval granted to a different account. Returning nothing gives
    an honest first sighting instead, which asks a human rather than assuming one.
    """
    if not key.startswith("mcp:") or "#" in key or not alias:
        return []
    prefix = f"{key}#"
    found = [k for k, rec in servers.items()
             if k.startswith(prefix) and alias in ((rec or {}).get("aliases") or [])]
    return found if len(found) == 1 else []


def _may_adopt(record: dict[str, Any], old_key: str, alias: str | None) -> bool:
    """May this entry take over `old_key`'s record — or does that record belong to someone else?

    A `{transport}:{name}` key is scoped to ONE config name, so adopting it can only ever reclaim
    this entry's own history (B3). `mcp:<asserted>` is not: once the login is part of the identity,
    an entry WITHOUT credentials keeps that bare key as its live, current identity. A credentialled
    sibling asserting the same name would otherwise walk off with it — destroying a real baseline
    and inheriting an approval granted to a different account, which is both halves of the bug this
    identity change exists to close, reintroduced by its own migration.

    So a bare `mcp:` record is adoptable only when it names this entry as one of its aliases. A
    genuinely conflated pre-upgrade record does (every `--track` scan records `alias=sn.name`); a
    stranger's live record does not.
    """
    if old_key.split(":", 1)[-1] in SYNTHETIC_NAMES:
        # `http:cli-http` was the key of EVERY nameless ad-hoc target, so one record can hold
        # several servers' history (bureau's tools "removed", inference's "added", 2026-09-26).
        # Reclaim it only when this target is the one server it ever answered to.
        names = {adhoc_target(a) for a in (record.get("aliases") or []) if isinstance(a, str)}
        return bool(alias) and names == {alias}
    if not old_key.startswith("mcp:"):
        return True
    return bool(alias) and alias in (record.get("aliases") or [])


def should_record(snap: ServerSnapshot) -> bool:
    """Only a successful probe may become history.

    An errored snapshot carries an empty tool list. Recorded, it would read as "every tool was
    removed" and then become the baseline — so anyone able to make a server fail to probe could
    erase the record of what it used to look like."""
    return not snap.error


def key_for(snap: ServerSnapshot, target: str | None = None) -> str:
    """Stable identity for a server across config edits.

    Prefers what the server asserts about itself in `initialize` (`serverInfo.name`), so renaming an
    entry in `mcp.json` no longer starts a fresh baseline with no drift — previously a one-line
    evasion and an easy way to lose history by accident.

    Falls back to the old `transport:name` when a server declares nothing. Note the asserted name is
    server-controlled: changing it is itself a re-identification, which surfaces as a first sighting
    rather than as silence. That is a deliberate trade — see ADR-0012.

    THE LOGIN IS PART OF THE IDENTITY when the entry carries one (ADR-0012 addendum, 2026-08-10).
    The asserted name alone made the same server configured twice with different credentials — a
    work GitHub and a personal one — collapse onto one baseline, so approving the tools on one made
    the guard wave calls through on the other, a server the user never reviewed. Reproduced, then
    fixed here. The discriminator is appended ONLY when the entry has an `env`/`headers` login, so
    every credential-free server keys exactly as before and no existing baseline is disturbed.
    """
    asserted = (snap.server_info or {}).get("name")
    if isinstance(asserted, str) and asserted.strip():
        key = f"mcp:{asserted.strip()}"
        # A nameless server already keys by its CONFIG name (`transport:name`), which is distinct
        # per entry — the conflation is only possible under a shared asserted name.
        return f"{key}#{snap.credential_fingerprint}" if snap.credential_fingerprint else key
    if target and snap.name in SYNTHETIC_NAMES:
        # A NAMELESS AD-HOC TARGET is keyed by what was typed. Its label is a placeholder shared by
        # every `--http` (or `--stdio`) scan, so `transport:name` put every such server on ONE record
        # and the second reported the first's tools as drift. Every server on the 2026-07-28
        # revision is nameless: `server/discover` carries no serverInfo (probe._snapshot).
        return f"{snap.transport}:{adhoc_target(target)}"
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


def legacy_identity_keys(snap: ServerSnapshot) -> tuple[str, ...]:
    """Every key this server could ALREADY be recorded under, for `record(..., migrate_from=...)`.

    The transport variants (B3), plus — for an entry that now carries a credential discriminator —
    the un-discriminated `mcp:<asserted>` it was keyed under before that change. Without this the
    fix for credential conflation would orphan every existing approval on upgrade, which is the
    silent baseline reset ADR-0012 exists to prevent, caused by the fix for a different one.

    Where two entries shared a conflated record, the FIRST one re-scanned adopts it and the other
    gets an honest first sighting. Which one wins is scan order; both keep working, and only the
    loser re-approves.
    """
    keys = list(transport_variant_keys(snap))
    asserted = (snap.server_info or {}).get("name")
    if snap.credential_fingerprint and isinstance(asserted, str) and asserted.strip():
        keys.append(f"mcp:{asserted.strip()}")
    return tuple(keys)


def last(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    hist = store.get("servers", {}).get(key, {}).get("history", [])
    return hist[-1] if hist else None


#: The entry key holding the first sighting since approval that differed from it (see `append`).
REVIEW_KEY = "changed_since_approval"


def _surface_differs(base: Any, rec: Any, *, by_pin_across_rules: bool = False) -> bool:
    """True when `rec` differs from `base` on the surface a person is asked to review: the exact
    rule `pending` has always used (drift.compare, all axes). False when they cannot be compared.

    `by_pin_across_rules` is for THE LATCH only (holding a sighting until a person approves): there
    a false difference is permanent, so across two hashing rules the pin decides. The last-sighting
    rule keeps compare's answer unchanged, so `pending` and `scan` keep agreeing
    (tests/test_monitor_shares_full_records.py)."""
    if not (isinstance(base, dict) and isinstance(rec, dict)):
        return False
    from . import drift as _drift
    # TWO HASHING RULES, ONE PIN. A monitor sighting (`baseline.record_observed`) stores tool hashes
    # under the surface rule, a scan under the content rule; compared tool by tool, an unchanged
    # server read as every tool "changed" (measured 2026-10-08: same pin, 2/2 tools "changed"). The
    # pin is computed one way by both writers, so across rules it is the evidence.
    try:
        if by_pin_across_rules and _drift.tools_basis_of(base) != _drift.tools_basis_of(rec):
            pa, pb = base.get("pin"), rec.get("pin")
            return isinstance(pa, str) and isinstance(pb, str) and pa != pb
    except Exception:                                   # noqa: BLE001 — fall through to compare
        pass
    try:
        r = _drift.compare(base, rec)
    except Exception:                                   # noqa: BLE001 — never block a write on this
        return False
    return bool(r is not None and (r.added or r.removed or r.changed or r.schema_changed
                                   or r.annotation_changed))


def _approval_anchor(entry: dict[str, Any], base: dict[str, Any]):
    """When the current approval was made: `approved_at`, else the approved record's measured_at
    (a first-sighting or monitor approval records no approved_at). None when neither parses."""
    from datetime import datetime
    for raw in (entry.get("approved_at"), base.get("measured_at")):
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def held_sighting(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    """The FIRST sighting since the current approval that differed from it, or None: the latched
    record (`append`), else, for stores written before the latch existed, the first such sighting
    still in history, dated after `approved_at` (or the approved record's measured_at)."""
    entry = (store.get("servers") or {}).get(key) or {}
    base = entry.get("approved")
    if not isinstance(base, dict):
        return None
    held = entry.get(REVIEW_KEY)
    if isinstance(held, dict):
        return held
    anchor = _approval_anchor(entry, base)
    if anchor is None:
        return None
    from datetime import datetime
    for s in entry.get("history") or []:
        raw = s.get("measured_at") if isinstance(s, dict) else None
        try:
            at = datetime.fromisoformat(raw.replace("Z", "+00:00")) if isinstance(raw, str) else None
        except ValueError:
            at = None
        if at is not None and at > anchor and _surface_differs(base, s, by_pin_across_rules=True):
            return s
    return None


def sighting_to_review(store: dict[str, Any], key: str) -> dict[str, Any] | None:
    """The sighting a person must review for this server, or None. ONE rule for pending, decide and
    the panel: the LAST sighting when it differs from the approval (what `approve` would accept, so
    the diff shown is the diff approved); else the held sighting (`held_sighting`), so a change that
    reverted stays open until a person approves. A server that never changed has nothing."""
    base = approved(store, key)
    if not isinstance(base, dict):
        return None
    latest = last(store, key)
    if _surface_differs(base, latest):
        return latest
    return held_sighting(store, key)


def reverted_tools(store: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    """`{tool: {"at", "hash", "permission_changes"}}` for THE LATCH: tools whose description changed
    or whose permissions grew at the held sighting (`held_sighting`) and are back to the approved
    form at the last sighting. Per tool, so a tool that never changed stays allowed. Empty unless the
    approved, held and last records were all minted by the content rule (the stand-down `seen`
    obeys: across rules a per-tool hash comparison is meaningless). ONE rule: the guard projection
    and the panel both read it."""
    from . import drift
    entry = (store.get("servers") or {}).get(key) or {}
    rec, held = entry.get("approved"), held_sighting(store, key)
    hist = entry.get("history") or []
    latest = hist[-1] if hist else None
    if not all(isinstance(x, dict) and isinstance(x.get("tools"), dict) for x in (rec, held, latest)):
        return {}
    if held is latest or not all(drift.tools_comparable(x) for x in (rec, held, latest)):
        return {}
    held_growth, grown_now = _permission_growth(rec, held), _permission_growth(rec, latest)
    at = held.get("measured_at") if isinstance(held.get("measured_at"), str) else None
    out: dict[str, dict[str, Any]] = {}
    for tool, approved_hash in rec["tools"].items():
        then, now = held["tools"].get(tool), latest["tools"].get(tool)
        content_back = isinstance(then, str) and then != approved_hash and now == approved_hash
        growth_back = bool(held_growth.get(tool)) and not grown_now.get(tool)
        if content_back or growth_back:
            out[tool] = {"at": at, "hash": then, "permission_changes": held_growth.get(tool) or []}
    return out


#: THE ORIGINAL BASELINE (2026-10-08): the first record this server was trusted at, kept beside
#: `approved` and never moved, so a person can see what the server has become since, not only the
#: last step (a widening in small steps never shows a total otherwise). For the person only: the
#: guard enforces `approved`.
ORIGINAL_KEY = "original_approved"


def keep_original(entry: dict[str, Any], new: dict[str, Any], via: str) -> None:
    """Record the original baseline, once, just before `approved` is first set or moved. A store
    written before this existed keeps the approval being replaced, labelled "earliest-known" so no
    surface calls it the first. Every path that sets `approved` calls this."""
    if isinstance(entry.get(ORIGINAL_KEY), dict):
        return
    prior = entry.get("approved")
    if isinstance(prior, dict):
        entry[ORIGINAL_KEY] = prior
        entry["original_via"] = "earliest-known"
        entry["original_approved_at"] = entry.get("approved_at") or prior.get("measured_at")
    elif isinstance(new, dict):
        entry[ORIGINAL_KEY] = new
        entry["original_via"] = via
        entry["original_approved_at"] = (_now_iso() if via != "first-sighting"
                                         else new.get("measured_at") or _now_iso())


def _same_record(a: Any, b: Any) -> bool:
    return (isinstance(a, dict) and isinstance(b, dict) and a.get("pin") == b.get("pin")
            and a.get("measured_at") == b.get("measured_at"))


def since_original(entry: dict[str, Any], latest: Any) -> dict[str, Any] | None:
    """The change from the original baseline to `latest`, labelled with how the original was
    recorded; None when the original IS the current approval (the one diff already says it)."""
    orig = entry.get(ORIGINAL_KEY)
    if not isinstance(orig, dict) or _same_record(orig, entry.get("approved")):
        return None
    change = approval_change(orig, latest)
    change["original_via"] = entry.get("original_via")
    change["original_at"] = entry.get("original_approved_at")
    return change


def original_words(change: Any) -> str | None:
    """"since first seen 2026-10-01: +1 tool (forward_note), …", or None."""
    if not isinstance(change, dict):
        return None
    when = str(change.get("original_at") or "")[:10]
    label = {"first-sighting": "since first seen", "approve": "since first approval",
             "earliest-known": "since the earliest approval on record"}.get(
                 str(change.get("original_via")), "since the earliest approval on record")
    inner = {k: v for k, v in change.items() if k not in ("original_via", "original_at")}
    what = change_words(inner) or "no change"
    return f"{label}{(' ' + when) if when else ''}: {what}"


def clear_review(entry: dict[str, Any]) -> None:
    """A person approved: the held sighting is answered. Every approval path calls this."""
    entry.pop(REVIEW_KEY, None)


def append(store: dict[str, Any], key: str, record: dict[str, Any], keep: int = 50) -> None:
    entry = server_entry(store, key)
    hist = entry.setdefault("history", [])
    hist.append(record)
    del hist[:-keep]  # bounded — keep the last `keep` sightings
    # THE LATCH (2026-10-08). The FIRST sighting since approval that differs from it is kept on the
    # entry, outside the trimmed history, until a person approves again. Without it a server could
    # serve a poisoned tool for one window and revert before the next scan: every reader compared
    # the approval with the LAST sighting only, so [approved A, hostile B, A again] left nothing
    # open (measured). Kept here, at the one append every writer goes through, so a monitor sighting
    # and a scan sighting latch alike; and kept whole, so the hold outlives 50 later sightings.
    base = entry.get("approved")
    if (isinstance(base, dict) and not isinstance(entry.get(REVIEW_KEY), dict)
            and not entry.get(AWAITING_APPROVAL)
            and _surface_differs(base, record, by_pin_across_rules=True)):
        entry[REVIEW_KEY] = record


# ------------------------------------------------------------------------------------------- #
# THE FLEET BASELINE. Trust-on-first-use answers "what did this server look like when I first saw
# it" — it cannot answer "should this server be here at all". A remote entry planted in an agent
# config was scanned, labelled CLEAN and given a baseline on its first run (0.1.68, 2026-10-04).
# `approve --fleet` records which entries a person accepted; anything discovered afterwards that
# is not in that list is APPEARED, and its first sighting is kept without becoming a baseline.
# ------------------------------------------------------------------------------------------- #

#: Top-level key in history.json holding the approved fleet.
FLEET_KEY = "fleet"
#: Marker on a server entry whose sighting is kept but must not become its baseline.
AWAITING_APPROVAL = "awaiting_approval"
#: Top-level key holding guard settings the hook reads through the projection.
GUARD_KEY = "guard"


def _fleet_token(tok: str) -> str:
    """One launch token as stored: credential shapes masked, identity kept. A `name@version`
    package spec is left alone — `redact()` reads it as an address and would mask the package."""
    from .redact import redact
    if "://" in tok:
        return adhoc_target(tok)
    if _PACKAGE_SPEC.match(tok):
        return tok
    return redact(tok) or tok


#: `name@version` / `@scope/name@version` — the only `@` shape left unmasked. A bare "contains @"
#: test let `--token=abc@123` through verbatim.
_PACKAGE_SPEC = re.compile(r"^@?[\w.-]+(/[\w.-]+)?@[\w.^~<>=*-]+$")


def fleet_targets(discovered: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """`{"<client>/<config name>": {"kind", "command"|"url", "sha256"}}` for a discovery map.

    The stored command/url is MASKED (history.json is a file people open); the comparison runs on
    `sha256` of the raw launch target, so masking can never make two different targets look the
    same. `env` and `headers` are never stored."""
    out: dict[str, dict[str, Any]] = {}
    for disp, e in (discovered or {}).items():
        if not isinstance(e, dict):
            continue
        if e.get("command"):
            args = e.get("args") or []
            raw = [str(e["command"]), *(str(a) for a in (args if isinstance(args, list)
                                                          else [args]))]
            target: dict[str, Any] = {"kind": "stdio",
                                      "command": [_fleet_token(t) for t in raw]}
        elif e.get("url"):
            raw = [str(e["url"])]
            target = {"kind": "http", "url": adhoc_target(str(e["url"]))}
        else:
            continue
        target["sha256"] = hashlib.sha256(json.dumps(raw).encode("utf-8")).hexdigest()
        names = e.get("_names")
        keys = ([f"{c}/{n}" for c, n in names.items()] if isinstance(names, dict) and names
                else [f"config/{disp}"])
        for k in keys:
            out[k] = dict(target)
    return out


def fleet_baseline(store: dict[str, Any]) -> dict[str, Any] | None:
    """The approved fleet, or None when `approve --fleet` has never run on this machine."""
    fleet = store.get(FLEET_KEY)
    if isinstance(fleet, dict) and isinstance(fleet.get("entries"), dict):
        return fleet
    return None


def fleet_appeared(fleet: dict[str, Any] | None,
                   discovered: dict[str, Any]) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """`{display name: [(client/name, target), …]}` for every discovered entry that is not in the
    approved fleet — new, or the same name now pointing at a different command or URL. Empty when
    there is no fleet baseline: nothing was approved, so nothing can have appeared after it."""
    if fleet is None:
        return {}
    approved_entries = fleet.get("entries") or {}
    out: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for disp, e in (discovered or {}).items():
        for k, t in fleet_targets({disp: e}).items():
            prior = approved_entries.get(k)
            if not isinstance(prior, dict) or prior.get("sha256") != t["sha256"]:
                out.setdefault(disp, []).append((k, t))
    return out


def held(store: dict[str, Any]) -> list[str]:
    """Keys whose sighting is kept but was never approved — servers that appeared after the fleet
    approval and are waiting on a person."""
    return sorted(k for k, e in (store.get("servers") or {}).items()
                  if isinstance(e, dict) and e.get(AWAITING_APPROVAL) and "approved" not in e)


def held_display_name(store: dict[str, Any], key: str, discovered: dict[str, Any]) -> str:
    """The name a held store key is shown under — the panel's `classified_servers` rule exactly:
    the discovered config name that is one of its aliases, else its first alias, else the key."""
    entry = (store.get("servers") or {}).get(key) or {}
    aliases = [str(a) for a in (entry.get("aliases") or []) if a]
    return next((a for a in aliases if a in (discovered or {})), None) or \
        (aliases[0] if aliases else key)


def appeared_now(store: dict[str, Any], discovered: dict[str, Any]
                 ) -> tuple[dict[str, list[tuple[str, dict[str, Any]]]], str | None]:
    """ONE answer to "which servers appeared after the fleet approval?" for the CLI, `status` and
    the panel — `({display name: [(client/name or store key, target)]}, approval date)`.

    Two populations, because either alone misses one. `fleet_appeared` judges discovery as WRITTEN
    against the approved fleet; `held` is every store entry whose sighting was kept without ever
    being approved — including one whose config entry has since gone, which discovery alone can
    no longer see. Three surfaces each answering this their own way is how one HOME read "1
    appeared", "2 at an approved baseline" and "At baseline 0" at once (walk, 2026-10-05).

    Returns ({}, None) when no fleet was ever approved and nothing is held. Pure: it RAISES on bad
    input, and every caller turns that into a stated "the fleet check could not run", never into
    an empty answer."""
    fleet = fleet_baseline(store)
    held_keys = held(store)
    if fleet is None and not held_keys:
        return {}, None
    since = (str((fleet or {}).get("approved_at") or "")[:10] or "an earlier date")
    appeared = fleet_appeared(fleet, discovered)
    for key in held_keys:
        name = held_display_name(store, key, discovered)
        if name in appeared:
            continue
        if name in (discovered or {}):
            appeared[name] = list(fleet_targets({name: discovered[name]}).items()) or \
                [(key, {"kind": "held"})]
        else:
            appeared[name] = [(key, {"kind": "held"})]
    return appeared, since


def admit_to_fleet(store: dict[str, Any], key: str,
                   discovered: dict[str, Any] | None = None) -> list[str]:
    """Add the config entries that name `key` to the approved fleet. Returns the entries written.

    Called INSIDE every gated writer of `approved`, under its lock, in its write. Approving one
    server used to write its baseline and not its fleet entry, so the scan after `mcpgawk approve
    mcp-sync` — the exact step every surface told the operator to take — printed "APPEARED (1)" and
    "Protected: 2 server(s)" on the same run (live drive, 2026-10-05). Only this server's entries
    are written (its aliases that a config names today, keyed client/name as `fleet_targets` keys
    them), each stamped with its own `admitted_at`; the fleet's `approved_at` is not touched,
    because nobody re-approved the fleet.

    No fleet record: nothing to do — this never invents one. Discovery unreadable: said on stderr
    and nothing written, so the server stays NAMED as appeared; that is the safe direction."""
    fleet = fleet_baseline(store)
    if fleet is None:
        return []
    if discovered is None:
        try:
            from .discover import discover_report
            discovered, _sources = discover_report()
        except Exception as exc:                   # noqa: BLE001 - say it, never go quiet
            print(f"mcpgawk: approved {key}, but its fleet entry was NOT written — the agent "
                  f"configs could not be read ({type(exc).__name__}: {exc}). It will still be "
                  f"named as appeared; run `mcpgawk approve --fleet` once they can be read.",
                  file=sys.stderr)
            return []
    entry = (store.get("servers") or {}).get(key) or {}
    names = [str(a) for a in (entry.get("aliases") or []) if a and str(a) in (discovered or {})]
    written: list[str] = []
    now = _now_iso()
    for name in names:
        for fk, target in fleet_targets({name: discovered[name]}).items():
            fleet["entries"][fk] = {**target, "admitted_at": now}
            written.append(fk)
    return written


def approve_fleet(discovered: dict[str, Any],
                  path: str | None = None) -> tuple[int, list[str]]:
    """Record `discovered` as the approved fleet, and adopt every held sighting. Returns (number of
    fleet entries, keys adopted). Gated exactly like `approve`: this moves trust."""
    require_human_approval()
    evidence = approval_evidence()
    path = path or default_path()
    entries = fleet_targets(discovered)
    adopted: list[str] = []
    with locked(path):
        store = load(path)
        now = _now_iso()
        store[FLEET_KEY] = {"approved_at": now, "approved_by": _operator(), "entries": entries,
                            "evidence": evidence}
        for key in held(store):
            latest = last(store, key)
            if latest is None:
                continue
            entry = server_entry(store, key)
            keep_original(entry, latest, "approve")
            entry["approved"] = latest
            clear_review(entry)              # the held change is answered by this approval
            entry.pop(AWAITING_APPROVAL, None)
            entry["approved_at"] = now
            entry["approved_by"] = _operator()
            entry["approved_via"] = "approve"
            entry["approved_evidence"] = evidence
            adopted.append(key)
        save(store, path)
    return len(entries), adopted


def guard_strict(store: dict[str, Any]) -> bool:
    """Whether the guard refuses calls to a server with no baseline."""
    guard = store.get(GUARD_KEY)
    return isinstance(guard, dict) and guard.get("strict") is True


def set_guard_strict(on: bool, path: str | None = None) -> None:
    """Persist strict mode. Switching it OFF loosens the guard, so it needs the person at the
    keyboard; switching it on only tightens and needs no gate."""
    if not on:
        require_human_approval()
    path = path or default_path()
    with locked(path):
        store = load(path)
        guard = store.get(GUARD_KEY)
        store[GUARD_KEY] = {**(guard if isinstance(guard, dict) else {}), "strict": bool(on)}
        save(store, path)
