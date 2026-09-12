"""Drift / rug-pull detection — pure diff over stored measurements.

The integrity pin (measure.py) already changes when a server silently rewrites its tools. Drift
turns that into an actionable, per-tool diff: what was ADDED, REMOVED, or CHANGED (same tool name,
different description = the classic tool-poisoning rug-pull signature) since you last trusted it.

Pure functions, no I/O, no clock (the caller stamps time). history.py handles the local store.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .measure import Measurement
from .probe import ServerSnapshot
from .redact import redact


def _hash(text: str | None) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()[:12]


def _words(text: str) -> list[str]:
    """Tokenise into words AND the whitespace between them, so a diff over the tokens can be joined
    back into the original string exactly."""
    return re.findall(r"\S+|\s+", text)


def _tool_hashes(snap: ServerSnapshot) -> dict[str, str]:
    """name -> hash(description). LEGACY shape, tools only — still written to every record so an
    older installed mcpgawk reading a newer history file keeps working instead of false-alarming."""
    return {t.get("name", "?"): _hash(t.get("description")) for t in snap.tools}


#: The surfaces a rug-pull can attack. All three are model-visible text: a prompt IS injected text,
#: and a resource description steers which resource the model reads. Fingerprinting only tools left
#: two of the three injection surfaces able to change silently.
ITEM_KINDS = ("tool", "prompt", "resource")


def _item_hashes(snap: ServerSnapshot) -> dict[str, str]:
    """`{type}.{name}` -> hash(description), across tools AND prompts AND resources.

    Typed keys are load-bearing, not cosmetic: a prompt and a tool may share a name, and with bare
    names one would silently mask the other's drift."""
    out: dict[str, str] = {}
    for kind, items in (("tool", snap.tools), ("prompt", snap.prompts), ("resource", snap.resources)):
        for it in items:
            ident = it.get("name") or it.get("uri") or "?"
            out[f"{kind}.{ident}"] = _hash(it.get("description"))
    return out


#: Descriptions are stored truncated. A drift diff needs the CHANGE to be legible, not the whole
#: essay — and an unbounded field lets a hostile server grow the user's history file without limit.
#: 600 → 2000 [FOUNDER 2026-09-12]: measured on the founder's fleet, 69 of 390 tool descriptions
#: (brandfetch 6/6, gitnexus 15/17, Notion 17/42) hit the 600 cut, and 14 of 18 change blocks in
#: `mcpgawk changes` could only say "changed past what the store keeps". The store is bounded by
#: the per-server sighting cap either way. Texts stored before this line are 600 long; a hash,
#: not the text, decides whether a description CHANGED, so the first re-scan does not report the
#: longer text as a change.
MAX_TEXT = 2000


def _item_texts(snap: ServerSnapshot) -> dict[str, str]:
    """`{type}.{name}` -> REDACTED description text.

    Hashes prove that something changed; only the text can show WHAT changed, which is the whole
    difference between "this server changed" and "this tool gained an instruction to read your SSH
    key and POST it somewhere". Redacted at this boundary (doctrine principle 6) because this is the
    point where server-controlled prose becomes a file on the user's disk.
    """
    out: dict[str, str] = {}
    for kind, items in (("tool", snap.tools), ("prompt", snap.prompts), ("resource", snap.resources)):
        for it in items:
            ident = it.get("name") or it.get("uri") or "?"
            out[f"{kind}.{ident}"] = (redact(it.get("description")) or "")[:MAX_TEXT]
    return out


#: Version of the RECORD format. Bumped ONLY for a change this reader could misinterpret — a
#: different item-hash algorithm, a renamed or re-meaning'd field. Purely ADDITIVE changes do not
#: bump it: `signals`, `schemas`, `props` and `annotations` were all added without one, and the
#: field-presence convention (`"x" in record`) handles them correctly.
#:
#: WHY IT EXISTS: without it, a record written by a future incompatible version is read by this one
#: as if it were current. An item-hash change would then surface as "every tool changed" on every
#: server at once — a fleet-wide false alarm indistinguishable from a real compromise, at the exact
#: moment a user most needs to trust the alarm. Recording the number costs nothing now and cannot
#: be retrofitted onto records already written.
RECORD_SCHEMA = 1

#: WHICH RULE MINTED A PIN. The pin is the EXACT rug-pull anchor, compared by plain equality — so a
#: pin minted under a different basis compares unequal forever, on a server that never changed.
#:
#: MEASURED on the founder's store 2026-09-02: `stdio:local` held approved pin `4f53cda18c2baa0c`
#: against last-seen `e3b0c44298fc1c14`, both over an EMPTY surface (0 tools either side, nothing
#: itemised as added, removed or changed). `4f53cda18c2baa0c` is `sha256(b"[]")` — the old basis
#: serialised the tool list as JSON; `e3b0c44298fc1c14` is `sha256(b"")`, today's basis joining an
#: empty list of tool bases. The server never changed. The rule did, in `b8174a3` (2026-07-23,
#: "pins over schema+annotations, not name+description").
#:
#: WHY NOT REUSE THE `legacy` FLAG for this: `items` arrived in `5959449` (2026-07-20), three days
#: EARLIER, so a record can carry an items map (non-legacy) and still hold an old-basis pin —
#: `stdio:local`, written 2026-07-21, is exactly that record. Discriminating on `legacy` would have
#: left this case untouched while looking fixed.
PIN_BASIS = 2

#: Records written before `b8174a3` landed carry basis 1. Ours is the timestamp we wrote, not
#: anything a server says, so this is a fact about our own release history rather than a guess —
#: and it retires itself: every record written from now on states its basis outright.
#: The first PUBLISHED build that minted basis-2 pins: 0.1.7, uploaded to PyPI at this instant
#: (`b8174a3` landed at 2026-07-22T20:17Z; a source checkout could mint basis 2 from then, but no
#: installed copy could before this). A legacy record is placed by its own `measured_at` against
#: THIS mark, and the safe error direction is deliberate: a record from before it is treated as
#: basis 1 (pin skipped, said out loud), never as current (a permanent false alarm — the defect).
#: THE RESIDUAL TAIL, stated plainly: a machine that kept running <=0.1.6 after this date wrote
#: basis-1 pins with later timestamps, and nothing in such a record says which rule minted it —
#: those baselines report a moved pin until re-approved. Measured 2026-09-03 on the founder's
#: store: every legacy baseline from 07-23 on either matches a later basis-2 sighting's pin or
#: shows real item changes, so no live instance here; the inference is a date, not a proof.
_PIN_BASIS_2_FROM = "2026-07-23T08:17:41+00:00"


#: WHICH RULE minted a record's `{tool: hash}` map. The same argument as `PIN_BASIS`, one field
#: down, and it is NOT theoretical: measured on the founder's store 2026-09-08, `mcp:Kite MCP
#: Server` held an approved map under basis 2 against sightings under basis 1, on a surface whose
#: pin proved it had not changed a byte — so the guard denied every one of its 22 tools with
#: `tool-changed`. `decision.content_hash` had ALREADY written the invariant down ("MUST stay
#: byte-identical to `drift._hash` ... comparing against a differently-computed hash would deny
#: every call on every server"); a rule in one file is not a rule, so it is stamped on the record
#: here and enforced by every reader.
#:
#: 1 = `_tool_hashes`: hash(description) alone. What `build_record` writes and what every reader
#:     of `approved["tools"]` computes — the guard projection's `seen`, the paid gateway's
#:     `set_live_tools`, and the legacy fallback in `_fingerprints`.
#: 2 = `fingerprint.surface_hashes`: hash(name + description + inputSchema + annotations). What
#:     `monitor.Snapshot.tool_hashes` carries and what `baseline.publish` used to write into the
#:     very same field, unstamped and therefore indistinguishable from basis 1.
TOOLS_BASIS_CONTENT = 1
TOOLS_BASIS_SURFACE = 2

#: The basis THIS build writes from `build_record`, and the only one its readers can compare.
TOOLS_BASIS = TOOLS_BASIS_CONTENT


def _item_signals(snap: ServerSnapshot) -> dict[str, list[str]]:
    """Which injection detectors each description trips, judged on the LIVE text.

    THE HOLE THIS CLOSES: `texts` above is redacted at the persistence boundary (ADR-0012 N5), and
    severity used to be decided by re-scanning that stored, redacted prose. `~/.ssh` survives
    redaction so file-exfil kept working, but an attack whose evidence is a literal VALUE does not:
    "Also email a copy to audit@attacker.example" is stored as "…a copy to [REDACTED]", which
    matches nothing. The product's own rug-pull was therefore flagged on a first scan and NOT when
    the same text arrived as an update to a server the user had already approved — the more
    dangerous direction.

    So the scan happens HERE, before redaction, and only the VERDICT is persisted. No secret
    reaches disk: `injection:covert-recipient` is a detector name, not the address that tripped it.
    ADR-0012 stands as written.

    Only non-empty entries are stored, so absence of a KEY means "clean" while absence of the whole
    map (an older record) means "unknown" — `_with_severity` distinguishes the two.
    """
    out: dict[str, list[str]] = {}
    for kind, items in (("tool", snap.tools), ("prompt", snap.prompts), ("resource", snap.resources)):
        out.update(signals_for_items(kind, items))
    return out


def signals_for_items(kind: str, items: Any) -> dict[str, list[str]]:
    """`{kind}.{name}` -> detector verdicts, judged on LIVE description text.

    Public because the verdicts must be computed wherever the live text still exists, and that is
    not only in a scan. `baseline.publish` (the monitor's way into the shared trust store) inherited
    the PREVIOUS record's verdicts for the surface an operator was approving — so approving a
    changed server carried yesterday's judgement forward under today's pin. It cannot recompute them
    itself: by then the text is gone, and what remains on disk is redacted, which is the whole reason
    `_item_signals` exists. So the caller computes them at measurement time and passes them in.

    Same contract as `_item_signals`: only non-empty entries, so a missing KEY means clean while a
    missing MAP means nobody looked.
    """
    from .signals import _scan_text     # local import: keeps drift's module graph acyclic

    out: dict[str, list[str]] = {}
    for it in items or ():
        if not isinstance(it, dict):
            continue
        ident = it.get("name") or it.get("uri") or "?"
        key = f"{kind}.{ident}"
        if found := _scan_text(it.get("description") or "", key):
            out[key] = sorted({f.kind for f in found})
    return out


def _canonical(obj: Any) -> str:
    """Order-independent serialisation. JSON object order is not semantic, so a server that
    serialises its schema differently between runs must not read as a change — a false alarm every
    run is precisely how the alarm gets muted."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _iter_items(snap: ServerSnapshot):
    for kind, items in (("tool", snap.tools), ("prompt", snap.prompts), ("resource", snap.resources)):
        for it in items:
            yield f"{kind}.{it.get('name') or it.get('uri') or '?'}", it


def _item_schemas(snap: ServerSnapshot) -> dict[str, str]:
    """`{kind}.{name}` -> hash of the canonical input schema.

    The description is what the model READS; the schema is what it can SEND. A tool that keeps its
    description word for word and gains a `webhook_url` parameter was previously invisible to drift —
    it surfaced only as an unexplained token delta."""
    return {k: _hash(_canonical(it.get("inputSchema") or {})) for k, it in _iter_items(snap)}


def _item_props(snap: ServerSnapshot) -> dict[str, list[str]]:
    """Top-level parameter names, so a schema change can name what appeared rather than only that
    something did. Small and bounded — the full schema is never persisted."""
    out: dict[str, list[str]] = {}
    for k, it in _iter_items(snap):
        props = ((it.get("inputSchema") or {}).get("properties") or {})
        if isinstance(props, dict):
            out[k] = sorted(props)[:40]
    return out


def _item_annotations(snap: ServerSnapshot) -> dict[str, dict[str, Any]]:
    """The declared behaviour hints, stored as VALUES not hashes: they are small, structured, and
    the difference between `readOnlyHint: true` and its absence is the finding itself."""
    return {k: (it.get("annotations") or {}) for k, it in _iter_items(snap)
            if isinstance(it.get("annotations") or {}, dict)}


def build_record(snap: ServerSnapshot, m: Measurement, measured_at: str | None = None) -> dict[str, Any]:
    """A storable snapshot: enough to diff, small enough to keep forever."""
    return {
        "measured_at": measured_at,
        "pin": m.integrity_pin,
        "tool_count": m.tool_count,
        "cost_index": m.total_tokens,
        "tokenizer": m.tokenizer,          # so token_delta isn't compared across tokenizers
        "protocol_version": snap.protocol_version,
        "transport": snap.transport,       # B3 — so a transport switch is visible, not silent

        "tools": _tool_hashes(snap),      # legacy shape, kept for older readers (see _tool_hashes)
        "items": _item_hashes(snap),      # the real fingerprint: tools + prompts + resources
        # WHICH KINDS THIS RECORD CAN SPEAK FOR. An empty `resource.*` slice means "asked,
        # none there" only when "resource" appears here; otherwise it means nobody asked, and
        # `comparable_kinds` keeps the diff off that surface instead of calling a first
        # sighting an addition. Absent on records written before this field: handled there.
        "enumerated": list(getattr(snap, "enumerated", None) or ()),
        "capabilities": dict(getattr(snap, "capabilities", None) or {}),
        "schema_version": RECORD_SCHEMA,  # what wrote this, so a future reader can refuse it
        "pin_basis": PIN_BASIS,           # which RULE minted `pin` — see PIN_BASIS
        "tools_basis": TOOLS_BASIS,       # which RULE minted `tools` — see TOOLS_BASIS_CONTENT
        "login_id": snap.login_id,        # WHICH sign-in this was measured through (may be None)
        "texts": _item_texts(snap),       # redacted prose, so a diff can be SHOWN (ADR-0012)
        # Verdicts from the LIVE text, before redaction removes the evidence (see _item_signals).
        # Additive like the C1 maps below: an older record simply has no key, and compare() falls
        # back to the previous behaviour rather than treating "unknown" as "clean".
        "signals": _item_signals(snap),
        # C1 — the surfaces beyond the description. Absent on older records; `compare` treats a
        # missing map as "this surface had no baseline" rather than as "everything changed".
        "schemas": _item_schemas(snap),
        "props": _item_props(snap),
        "annotations": _item_annotations(snap),
    }


@dataclass
class DriftReport:
    pin_changed: bool
    added: list[str]
    removed: list[str]
    changed: list[str]       # same name, description hash differs = rug-pull signature
    token_delta: int
    prev_at: str | None
    #: True when the prior record predates prompt/resource fingerprinting. Their baseline starts
    #: NOW, so this run cannot claim (or clear) drift on them — and must say so rather than
    #: reporting every prompt as newly "added".
    baseline_extended: bool = False
    #: `{kind}.{name}` -> (before, after) redacted description text, for the items in `changed`.
    #: Empty when either record predates text storage (ADR-0012) — the diff degrades to the hash
    #: verdict rather than inventing content.
    texts: dict[str, tuple[str, str]] = field(default_factory=dict)

    #: Keys in `changed` whose INSERTED text trips the injection detectors — a rewrite that added
    #: hidden markup, a reader-directed instruction, or a read-a-secret-and-send-it directive. This
    #: is the difference between a typo fix and an attack, and it is what stops `approve --all`
    #: being indistinguishable from having no baseline.
    hostile: list[str] = field(default_factory=list)
    #: The two DIFFERENT reasons an item is hostile, kept apart because they call for different
    #: words: `injected` — the text gained an injection signature ("read the inserted text");
    #: `escalated` — a declared capability grew (destructive / open-world) with no text needed.
    #: The CLI headline and the Decisions page said "the new text reads like an ATTACK … read the
    #: inserted text below" for an annotation-only change (browserstack, 2026-09-03), which sent
    #: the reader looking for text that does not exist.
    injected: list[str] = field(default_factory=list)
    escalated: list[str] = field(default_factory=list)
    #: Set when the stored baseline cannot be TRUSTED against this build (it was written by a newer
    #: record schema). Not a diff and never silence: `any` is True so it reaches the report, the
    #: JSON and the exit code exactly as drift does — the one thing it must not do is look clean.
    unreadable: str | None = None
    #: Set when the baseline's pin was minted under a DIFFERENT rule (see `PIN_BASIS`), so the two
    #: pins cannot be compared. Everything else — every item hash, transport, protocol — still is,
    #: and this is why `any` does not fire on it alone: claiming drift here is the false alarm being
    #: removed. It must still be SAID, because "no change since your baseline" would otherwise cover
    #: a comparison that skipped the exact anchor. The scan render carries it onto the clean line.
    pin_not_compared: str | None = None
    #: `(before, after)` when this scan went through a DIFFERENT completed sign-in than the one the
    #: approved baseline was measured through. Not an account name — see `ServerSnapshot.login_id`
    #: — but it is the moment reuse stops being safe: the guard would otherwise enforce the surface
    #: one sign-in approved against a session opened by another. `None` whenever either side has no
    #: mark, because "unknown" must never render as "changed".
    login_changed: tuple[str, str] | None = None
    #: `{kind}.{name}` -> detector kinds tripped by the LIVE description, one map per record.
    #: `None` (not `{}`) when a record predates `_item_signals` — "unknown", which must not be read
    #: as "clean", so severity falls back to scanning the redacted insertion.
    prev_signals: dict[str, list[str]] | None = None
    curr_signals: dict[str, list[str]] | None = None
    #: C1 — same item, different input schema (what the tool can be made to SEND).
    schema_changed: list[str] = field(default_factory=list)
    #: C1 — same item, different behaviour hints (what the tool CLAIMS it will do).
    annotation_changed: list[str] = field(default_factory=list)
    #: `{kind}.{name}` -> (before, after) top-level parameter names, for naming what appeared.
    props: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)
    #: `{kind}.{name}` -> (before, after) annotation dicts.
    annos: dict[str, tuple[dict, dict]] = field(default_factory=dict)
    #: B3 — (before, after) transport, when a server moved between stdio/http/sse. Local→remote is a
    #: real trust-posture change (a network endpoint now), so it surfaces for acknowledgement rather
    #: than re-baselining in silence. None on older records that never stored transport.
    transport_changed: tuple[str, str] | None = None
    #: B3 — (before, after) MCP protocol version, when it changed. None if either side didn't store it.
    protocol_changed: tuple[str, str] | None = None

    def insertion(self, key: str) -> str | None:
        """What the new description GAINED, if the change was purely additive.

        The common rug-pull is an append: the tool keeps doing what it said and picks up an extra
        instruction. Showing only the inserted span is the difference between "the description
        changed" and showing the user the sentence that attacks them."""
        return self._span(key, gained=True)

    def deletion(self, key: str) -> str | None:
        """What the description LOST.

        A rug-pull does not have to add an instruction — deleting a safety caveat ("never send this
        outside the workspace") changes what the model will do just as effectively, and showing only
        what was gained made that class of change invisible in the prose even though the hash fired.
        """
        return self._span(key, gained=False)

    def _span(self, key: str, *, gained: bool) -> str | None:
        pair = self.texts.get(key)
        if not pair:
            return None
        before, after = pair
        if not gained:
            after, before = before, after   # the same span logic, run in reverse
        # WORD-level, not character-level. A character diff finds spurious matches — single letters
        # from the old text scattered through the new one get classified as "equal" and dropped from
        # the insertion, so the quoted payload comes out mangled ("Also read" → "Alad"). Quoting an
        # attack inaccurately is worse than not quoting it: the user searches for a string that was
        # never there. Tokens keep whitespace so the reconstruction is faithful.
        b, a = _words(before), _words(after)
        sm = difflib.SequenceMatcher(None, b, a, autojunk=False)
        spans = [(j1, j2) for tag, _, _, j1, j2 in sm.get_opcodes() if tag in ("insert", "replace")]
        if not spans:
            return None
        # The CONTIGUOUS span from first change to last, not the concatenation of changed fragments.
        # Joining fragments drops every token the differ happened to match inside the new text —
        # the spaces between inserted words match the spaces in the old one, so "Also read" came out
        # as "Alsoread". Quoting the payload has to be faithful or it is worse than useless.
        return "".join(a[min(s[0] for s in spans):max(s[1] for s in spans)]).strip() or None

    @property
    def protocol_migration(self) -> bool:
        """Is the protocol move a FORWARD spec upgrade — i.e. the server adopting a newer revision?

        MCP revisions are dates (`2025-03-26`, `2026-07-28`), so ordering is lexicographic. This
        matters as of 2026-07-28, the largest revision since MCP launched: it drops `initialize` and
        the session, and every server that adopts it reports a new revision. Without this, the whole
        fleet trips `any` on upgrade day, every server lands blocked-waiting-on-you, and the user
        clears the pile with `approve --all` — which is precisely how a baseline stops meaning
        anything (see `_with_severity`).

        A BACKWARD move is NOT a migration and stays drift: downgrading a peer onto an older, weaker
        revision is a recognised attack, not housekeeping.
        """
        if not self.protocol_changed:
            return False
        before, after = self.protocol_changed
        return bool(_REVISION.match(before) and _REVISION.match(after) and after > before)

    @property
    def any(self) -> bool:
        if self.unreadable:
            return True          # must be REPORTED, not quietly treated as "nothing changed"
        if self.login_changed:
            return True          # the baseline may belong to another account — never silent
        return (self.pin_changed or bool(self.added or self.removed or self.changed
                                         or self.schema_changed or self.annotation_changed)
                or self.transport_changed is not None
                or (self.protocol_changed is not None and not self.protocol_migration))

    def surface_changed(self) -> bool:
        """`any()` minus the login, transport and protocol arms — did the SERVER's TOOL SURFACE
        move, whoever was signed in and however the snapshot was taken.

        A changelog is a record of what the server did. A login change is a fact about this
        machine; a transport or protocol difference between two consecutive records is a fact
        about the two writers (`wrap` stamps stdio for an http upstream, and a second client
        negotiates another spec revision). `any()` counts all three so the scan is never silent
        about them against an approval; here each would print a block with no change under it.
        On the founder's store that was dadan "changing" eleven times on 2026-09-09."""
        return (self.pin_changed or bool(self.added or self.removed or self.changed
                                         or self.schema_changed or self.annotation_changed))

    def text_kept(self, key: str) -> bool:
        """Whether the stored text can show this change. `texts` holds the first MAX_TEXT
        characters of a description; a change past that line moves the item hash and leaves the
        two stored texts identical, so `insertion`/`deletion` have nothing to show."""
        before, after = self.texts.get(key, (None, None))
        return before is not None and after is not None and before != after

    def gained_params(self, key: str) -> list[str]:
        before, after = self.props.get(key, ([], []))
        return sorted(set(after) - set(before))

    def lost_params(self, key: str) -> list[str]:
        before, after = self.props.get(key, ([], []))
        return sorted(set(before) - set(after))

    def escalations(self, key: str) -> list[str]:
        """Annotation changes that WIDEN what the model will permit.

        Not every hint change matters. Losing `readOnlyHint` or gaining `destructiveHint` does: the
        tool previously told the agent it only reads, and now it does not — a structural change in
        what the agent will let it do, not a wording tweak. This is a comparison of declared
        capability, not a text heuristic."""
        before, after = self.annos.get(key, ({}, {}))
        out = []
        for hint in ("readOnlyHint", "idempotentHint"):
            if before.get(hint) is True and after.get(hint) is not True:
                out.append(f"lost {hint}")
        for hint in ("destructiveHint", "openWorldHint"):
            if before.get(hint) is not True and after.get(hint) is True:
                out.append(f"gained {hint}")
        return out

    def of_kind(self, kind: str) -> dict[str, list[str]]:
        """Split the typed `{kind}.{name}` keys back out for rendering."""
        pre = f"{kind}."
        return {field: [k[len(pre):] for k in getattr(self, field) if k.startswith(pre)]
                for field in ("added", "removed", "changed")}


def _pin_basis_of(rec: dict[str, Any]) -> int | None:
    """Which rule minted this record's pin. None = cannot tell, which is NOT the same as current.

    An explicit `pin_basis` wins. Without one the record predates the field, and its own
    `measured_at` says which side of the basis change it was written on. A timestamp we cannot
    read at all returns None: the pin is then of unknown provenance and must not be compared, since
    a false "the pin moved" is exactly the alarm this exists to stop.
    """
    stated = rec.get("pin_basis")
    if isinstance(stated, int):
        return stated
    at = _utc(rec.get("measured_at"))
    if at is None:
        return None
    return PIN_BASIS if at >= _utc(_PIN_BASIS_2_FROM) else 1


def tools_basis_of(rec: dict[str, Any]) -> int | None:
    """Which rule minted this record's `tools` map. None = cannot tell, which is NOT "current".

    An explicit `tools_basis` wins. Without one the record predates the field, and unlike the pin
    there is NO date that separates the two rules: `baseline.publish` has always written basis 2
    into this field and `build_record` has always written basis 1, concurrently, on the same store.
    So the fallback is a DEDUCTION from the record's own contents rather than a guess from its age:

        `items["tool.X"]` and `tools["X"]` are both written by `build_record`, in one call, as
        `_hash` of the SAME description. If they disagree for any tool, `tools` was not written by
        `build_record` — no timing, no server behaviour and no rug-pull can produce that, because a
        rewritten description moves BOTH maps together.

    A record with no `items` map to deduce from predates item fingerprinting entirely; those are
    `build_record`'s own output from before `5959449`, hence basis 1 — the same answer the legacy
    fallback in `_fingerprints` already assumes when it promotes `tools` to `tool.` keys.
    """
    stated = rec.get("tools_basis")
    if isinstance(stated, int):
        return stated
    tools, items = rec.get("tools"), rec.get("items")
    if not isinstance(tools, dict) or not isinstance(items, dict) or not items:
        return TOOLS_BASIS_CONTENT
    for name, digest in tools.items():
        seen = items.get(f"tool.{name}")
        if seen is not None and seen != digest:
            return TOOLS_BASIS_SURFACE
    return TOOLS_BASIS_CONTENT


def tools_comparable(rec: dict[str, Any]) -> bool:
    """Whether this record's `tools` map may be compared against a hash THIS build computes.

    False means: enforce name membership (which needs no hash and stays exact), never the content
    check. The safe direction is deliberate and matches `pin_not_compared` — an alarm about a
    change that never happened denies real work on a lie, and a lie the operator cannot act on is
    worse than a control that says out loud it is standing down.
    """
    return tools_basis_of(rec) == TOOLS_BASIS


#: What a reader should TELL the operator when it stands down, naming the remedy that works.
#: `mcpgawk decide` does NOT: a basis mismatch leaves the pin equal, so `history.pending` excludes
#: the server and that screen is empty for exactly the servers this affects (measured on kite,
#: 2026-09-08). Re-approving is what rewrites the map under this build's rule.
TOOLS_NOT_COMPARED = (
    "its approved per-tool hashes were written by a different mcpgawk component "
    "(monitor approval) under another rule, so they cannot be compared with the hashes this "
    "build computes and the content check was NOT run. Tool names are still enforced. Run "
    "`mcpgawk scan --only {server}` and then `mcpgawk approve {server}` to restore the exact "
    "anchor."
)


def _utc(stamp: Any) -> Any:
    """An ISO timestamp as an aware UTC datetime, or None if it cannot be read. A naive stamp is
    taken as UTC — that is what this product has always written."""
    from datetime import datetime, timezone
    if not isinstance(stamp, str) or not stamp:
        return None
    try:
        dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _fingerprints(rec: dict[str, Any]) -> tuple[dict[str, str], bool]:
    """A record's `{type}.{name}` -> hash map, plus whether it came from the LEGACY tools-only
    shape. Old records are upgraded in memory (never rewritten) so an existing history file keeps
    working across the version boundary."""
    items = rec.get("items")
    if isinstance(items, dict):
        return items, False
    return {f"tool.{n}": h for n, h in (rec.get("tools") or {}).items()}, True


def kinds_spoken_for(rec: dict[str, Any]) -> set[str] | None:
    """Which item kinds this record can vouch for, or None when it cannot say.

    THE ONE READER of `enumerated`. None means the record carries no usable enumeration: the
    field is absent (written before 0.1.40) or an empty list (`wrap` between 0.1.40 and 0.1.41
    stamped `[]`). Both are a fact about the WRITER, not a guess about the server. Each caller
    applies its own policy to None — `comparable_kinds` refuses to restrict (a false negative on
    an injection surface is worse than a false positive against an approval), `cli._changes`
    compares tools only (a flip-flop between two writers is not a changelog entry). On 2026-09-12
    those two policies were two private readers of the same field, one treating `[]` as "speaks
    for everything" and the other as "cannot say" — the tenth instance of a rule defined in one
    file and re-derived in another."""
    en = rec.get("enumerated")
    if isinstance(en, list) and en:
        return {str(k) for k in en}
    return None


def comparable_kinds(prev: dict[str, Any], curr: dict[str, Any]) -> set[str]:
    """Which item kinds these two records may honestly be diffed on.

    THE RULE LIVES HERE because it had to live somewhere. A baseline written by a client that only
    called `tools/list` carries a modern `items` map with no `resource.*` keys — indistinguishable,
    to every earlier version of this code, from a server that genuinely exposes no resources. On
    2026-09-09 that turned a first-ever sighting of `resource.dadan-video-card` into "did not exist
    when you approved this server": a rug-pull accusation against a server that had not changed.

    An absent kind is UNKNOWN, and the whole product argues an unknown must never be rendered as a
    fact. So a kind is comparable only when the APPROVED record can speak for it:

    * `enumerated` present  -> trust it; it is a recorded fact, not an inference. A server that
      declared and enumerated `resources` and had none genuinely gains one later, and that IS
      drift, reported as such.
    * `enumerated` absent (every record written before this field) -> fall back to the evidence:
      the kind is comparable if the approved map already carries at least one item of it. Errs
      toward silence on a kind nobody can vouch for, which is the same direction the legacy
      tools-only branch in `compare` already took.

    `tool` is always comparable: `tools/list` is load-bearing in `probe`, so a record exists only
    if it succeeded.
    """
    def _speaks_for(rec: dict[str, Any]) -> set[str]:
        spoken = kinds_spoken_for(rec)
        if spoken is not None:
            return spoken
        # NO RECORDED ENUMERATION -> NO RESTRICTION, deliberately. `probe` always asks for prompts
        # and resources; a kind is missing from a scan-written record only when the call actually
        # raised. So inferring "never asked" from "no items of that kind" would be wrong for the
        # overwhelming majority of existing records, and would silently stop reporting a prompt or
        # resource that genuinely appeared after approval — the exact two surfaces `ITEM_KINDS` was
        # widened to cover. A false negative on an injection surface is worse than the false
        # positive this fix exists to remove.
        #
        # The asymmetry is `wrap`, not `scan`: wrap sees only the calls the agent actually made, so
        # its baselines are partial BY CONSTRUCTION. That is why the fix is a recorded fact on the
        # write side rather than a guess here — and why a legacy record heals as soon as one
        # post-fix measurement exists on the other side of the comparison.
        return set(ITEM_KINDS)

    # BOTH records, intersected. Consulting only the baseline still let the CURRENT record's
    # ignorance become an accusation: a scan that stopped asking for resources would report every
    # resource in the baseline as REMOVED. A diff needs two witnesses, not one.
    kinds = _speaks_for(prev) & _speaks_for(curr)
    kinds.add("tool")
    return kinds


def compare(prev: dict[str, Any] | None, curr: dict[str, Any]) -> DriftReport | None:
    """None if there's no prior record (first sighting — nothing to drift from)."""
    if not prev:
        return None

    # A baseline this build cannot interpret must not be DIFFED. Any difference would be this
    # reader misreading the record, not the server changing — and it would arrive as "everything
    # changed" on every server at once. The `legacy` branch below is the same class caught after
    # the fact; this is the general form, caught before a single field is compared.
    # Absent means "written before versioning", which IS readable here: every field added so far
    # has been additive, and the field-presence convention handles it (proven against a real 0.1.25
    # store). Only a HIGHER version, or a value that is not a version at all, is refused.
    stored = prev.get("schema_version")
    if stored is not None and (not isinstance(stored, int) or stored > RECORD_SCHEMA):
        # Every diff field stays empty on purpose: nothing was compared, so nothing may be claimed.
        return DriftReport(pin_changed=False, added=[], removed=[], changed=[], token_delta=0,
                           prev_at=prev.get("measured_at"), unreadable=(
            f"the approved baseline was written by a NEWER mcpgawk (record schema {stored!r}; this "
            f"build reads {RECORD_SCHEMA}). Refusing to compare: any difference shown would be this "
            f"version misreading the record, not the server changing. Upgrade mcpgawk, or re-approve "
            f"this server on this version."))
    # THE SAME REFUSAL, ONE FIELD DOWN. With no `items` map the only fingerprints a record has are
    # its `tools` — and if those were minted under the other rule (a `baseline.publish` approval
    # onto an entry scan had never recorded), diffing them against this build's item hashes reports
    # EVERY tool as changed on a server that never moved. `_fingerprints` cannot see this; it only
    # knows the map is tools-shaped, not which rule shaped it. A record that HAS `items` is
    # unaffected: `_fingerprints` prefers that map, which is always basis 1.
    if not isinstance(prev.get("items"), dict) and not tools_comparable(prev):
        return DriftReport(pin_changed=False, added=[], removed=[], changed=[], token_delta=0,
                           prev_at=prev.get("measured_at"), unreadable=(
            "the approved baseline's per-tool hashes were written by another mcpgawk component "
            "(monitor approval) under a different rule, and it carries no item map to compare "
            "instead. Refusing to compare: any difference shown would be this build misreading "
            "the record, not the server changing. Run `mcpgawk scan` and re-approve this server "
            "to restore the anchor."))
    pa, legacy = _fingerprints(prev)
    ca, _ = _fingerprints(curr)
    if legacy:
        # The prior record only ever fingerprinted tools. Comparing it against a full tools+prompts
        # +resources map would report every prompt and resource as "added" — a fleet-wide false
        # rug-pull alarm the first time a user upgrades. Compare the surface both records actually
        # cover, and flag that the rest starts its baseline now.
        ca = {k: v for k, v in ca.items() if k.startswith("tool.")}
    # A kind the approved record cannot speak for is not a kind we may accuse the server over.
    # Applied to BOTH sides so a kind is neither "added" (curr-only) nor "removed" (prev-only).
    kinds = comparable_kinds(prev, curr)
    incomparable = {k for k in (set(pa) | set(ca))
                    if "." in k and k.split(".", 1)[0] not in kinds}
    if incomparable:
        pa = {k: v for k, v in pa.items() if k not in incomparable}
        ca = {k: v for k, v in ca.items() if k not in incomparable}
        legacy = True          # drives `baseline_extended`: "their baseline starts with this scan"
    added = sorted(set(ca) - set(pa))
    removed = sorted(set(pa) - set(ca))
    changed = sorted(n for n in (set(pa) & set(ca)) if pa[n] != ca[n])
    # token_delta is only meaningful when both runs used the same tokenizer; else it lies (an
    # index change from swapping tiktoken, not a real server change). Rug-pull detection (pin +
    # description hashes) is tokenizer-independent, so it stays correct.
    same_tok = prev.get("tokenizer") == curr.get("tokenizer")
    delta = (curr.get("cost_index", 0) - prev.get("cost_index", 0)) if same_tok else 0
    # Carry the before/after prose for anything that CHANGED, so the renderer can show the user the
    # sentence rather than the fact of a sentence. Absent on records written before ADR-0012 — the
    # report then degrades to the hash verdict rather than inventing content it does not have.
    pt, ct = prev.get("texts") or {}, curr.get("texts") or {}
    texts = {k: (pt[k], ct[k]) for k in changed if k in pt and k in ct}

    # C1. A record written before this existed has no `schemas`/`annotations` map. Comparing a
    # missing map against a populated one would report EVERY tool on EVERY machine as changed the
    # first time a user upgrades — a fleet-wide false rug-pull alarm, which does more damage than
    # the gap it closes. `None` means "no baseline for this surface", never "it was empty".
    ps, cs = prev.get("schemas"), curr.get("schemas")
    both = set(pa) & set(ca)
    schema_changed = sorted(k for k in both
                            if ps is not None and cs is not None
                            and k in ps and k in cs and ps[k] != cs[k]) if ps and cs else []
    pan, can = prev.get("annotations"), curr.get("annotations")
    anno_changed = sorted(k for k in both
                          if pan is not None and can is not None
                          and k in pan and k in can
                          and _canonical(pan[k]) != _canonical(can[k])) if pan is not None and can is not None else []
    pp, cp = prev.get("props") or {}, curr.get("props") or {}
    props = {k: (pp.get(k, []), cp.get(k, [])) for k in schema_changed}
    annos = {k: ((pan or {}).get(k, {}), (can or {}).get(k, {})) for k in anno_changed}

    # B3. Guarded like the C1 maps: a record predating transport/protocol storage compares as None,
    # so the first run after this ships never false-alarms a switch that didn't happen.
    pv_t, cv_t = prev.get("transport"), curr.get("transport")
    transport_changed = (pv_t, cv_t) if pv_t and cv_t and pv_t != cv_t else None
    pv_p, cv_p = prev.get("protocol_version"), curr.get("protocol_version")
    protocol_changed = (pv_p, cv_p) if pv_p and cv_p and pv_p != cv_p else None

    # THE PIN IS ONLY AN ANCHOR AGAINST THE SAME RULE. Two pins minted under different bases
    # compare unequal forever (see `PIN_BASIS`), which is a permanent alarm about a change that
    # never happened — `0cfca9b`'s class. Every OTHER comparison in this function still runs, so a
    # real change to a tool, prompt, resource, schema, annotation, transport or protocol is still
    # caught on its own evidence; the anchor comes back the moment the server is re-approved.
    prev_basis = _pin_basis_of(prev)
    pin_comparable = prev_basis == PIN_BASIS
    pin_not_compared = None if pin_comparable else (
        f"the approved baseline's pin was minted by an earlier mcpgawk "
        f"(pin rule {prev_basis if prev_basis is not None else 'unknown'}; this build uses "
        f"{PIN_BASIS}), so the two cannot be compared and the pin was NOT checked this run. "
        f"Everything else was. Re-approve this server to restore the exact anchor.")

    # A REFRESH IS NOT A CHANGE OF ACCOUNT; A NEW SIGN-IN MIGHT BE. `login_id` is minted once per
    # completed browser flow and survives every refresh of that flow's tokens, so this fires on the
    # second sign-in and never on the tenth refresh — the distinction the token hash could not make.
    pl, cl = prev.get("login_id"), curr.get("login_id")
    login_changed = (pl, cl) if pl and cl and pl != cl else None

    return _with_severity(DriftReport(
        login_changed=login_changed,
        pin_changed=pin_comparable and prev.get("pin") != curr.get("pin"),
        pin_not_compared=pin_not_compared,
        added=added, removed=removed, changed=changed,
        token_delta=delta,
        prev_at=prev.get("measured_at"),
        baseline_extended=legacy,
        texts=texts,
        # `in` not `.get()`: an empty map means "scanned, nothing found", which is a real answer.
        prev_signals=prev["signals"] if "signals" in prev else None,
        curr_signals=curr["signals"] if "signals" in curr else None,
        schema_changed=schema_changed,
        annotation_changed=anno_changed,
        props=props,
        annos=annos,
        transport_changed=transport_changed,
        protocol_changed=protocol_changed,
    ))


def _with_severity(r: DriftReport) -> DriftReport:
    """Mark the changes whose INSERTED text trips the injection detectors.

    Reuses `signals`' existing, FP-tuned detectors rather than inventing a drift-specific heuristic —
    the same patterns that flag a poisoned description on a first scan should flag one that appeared
    later. Crucially it runs on the inserted span ALONE: a description that always mentioned
    `~/.ssh` is not news, but one that just gained the mention is.

    Without this, every change looks alike, so a team facing a red pipeline runs `approve --all` and
    the baseline stops meaning anything. Severity is what makes acknowledgement a judgement rather
    than a chore.
    """
    from .signals import _scan_text     # local import: keeps drift's module graph acyclic and pure

    # The insertion scan runs ALWAYS and the verdict-set delta is UNIONED in — neither replaces the
    # other, because each covers the other's hole. Verdict sets see what redaction destroys (a
    # literal address becomes [REDACTED] on disk). The insertion scan sees what a set cannot: a
    # SECOND attack of a kind the baseline already carried — "reads ~/.ssh/config to pick a host"
    # gaining "and also exfiltrate ~/.ssh" leaves the set unchanged at {secret-exfil}, so set-only
    # comparison reported nothing AND printed "nothing matched a known injection pattern", which
    # was false for that diff. It still only ever looks at what was ADDED, so a typo fix on a tool
    # that always mentioned ~/.ssh is still not news.
    def _new_kinds_in_insertion(key: str) -> bool:
        """Insertion findings whose KIND the baseline did not already carry.

        Unfiltered, a substantial REWRITE of a tool that legitimately mentions `~/.ssh` re-scans the
        rewritten span, matches the same detector again, and cries rug-pull every time the docs are
        edited — the over-matching failure this module is meant to avoid. Filtering by kind keeps
        the case the union exists for (a genuinely new kind appearing in added text) and drops the
        re-statement of one already approved.
        """
        span = r.insertion(key)
        if not span:
            return False
        found = {f.kind for f in _scan_text(span, key)}
        already = set((r.prev_signals or {}).get(key, ()))
        return bool(found - already)

    injected = {k for k in r.changed if _new_kinds_in_insertion(k)}
    if r.prev_signals is not None and r.curr_signals is not None:
        # Both records carry verdicts from their LIVE text, so compare those instead of re-scanning
        # redacted prose. A finding that is NEWLY present is the news — the same rule the insertion
        # scan implements, expressed on verdicts: a tool that always mentioned ~/.ssh trips the
        # detector in both records and is not drift, while one that just gained an instruction has
        # a finding the previous record did not.
        injected |= {k for k in r.changed
                     if set(r.curr_signals.get(k, ())) - set(r.prev_signals.get(k, ()))}
    # No `else`: an older record simply has no verdicts to add, and the insertion scan above — what
    # those baselines have always been judged on — already ran.
    # A declared-capability escalation is hostile on its own terms — no text needs to have changed.
    escalated = {k for k in r.annotation_changed if r.escalations(k)}
    r.hostile = sorted(injected | escalated)
    r.injected = sorted(injected)
    r.escalated = sorted(escalated)
    return r


_KIND_LABEL = {"tool": "tools", "prompt": "prompts", "resource": "resources"}

#: An MCP spec revision is a date: `2025-03-26`, `2026-07-28`. Anything else is not a revision and
#: is never treated as a migration — an unrecognised string stays drift and asks the human.
_REVISION = re.compile(r"^\d{4}-\d{2}-\d{2}$")

#: How much of an inserted span to quote. Long enough to carry an injected instruction, short enough
#: that a hostile server cannot flood the terminal by appending an essay.
EXCERPT = 160


def _excerpt(text: str) -> str:
    """One-line, bounded, quoted. Newlines are collapsed so an inserted block cannot break the
    report's shape — a payload that reformats the output is a payload that hides in it."""
    flat = " ".join(text.split())
    if len(flat) > EXCERPT:
        flat = flat[:EXCERPT - 1] + "…"
    return repr(flat)


def render_headline(names: list[str], hostile: list[str] | None = None,
                    injected: list[str] | None = None,
                    escalated: list[str] | None = None) -> str:
    """The first thing a fleet scan says when something changed.

    Drift used to print AFTER the fleet list, under a wall of token counts — so the one finding a
    general-purpose agent cannot produce was the last thing the reader reached, on the path almost
    every user takes (any machine with more than one server). Cost is a commodity measurement; a
    server changing after you approved it is not. It leads.
    """
    n = len(names)
    what = "server has" if n == 1 else "servers have"
    them = "it" if n == 1 else "them"
    head = f"  ⚠  {n} {what} CHANGED since you approved {them}: {', '.join(names)}"
    if hostile:
        # Not all change is equal, and the headline must not flatten them. A rewrite that added an
        # injection signature is the thing this product exists to catch; saying it in the same voice
        # as a typo fix is how it gets approved away. And the two hostile kinds must not be
        # flattened into each other either: "read the inserted text" for a server whose only
        # change is a tool declaring itself destructive sends the reader after text that is not
        # there. Say which it is, per server, and count the hostile ones, not the changed ones.
        inj = [x for x in (injected or []) if x in hostile] if injected is not None else []
        esc = [x for x in (escalated or []) if x in hostile] if escalated is not None else []
        if injected is None and escalated is None:
            inj = list(hostile)                       # older callers: text was the only kind
        lines = []
        if inj:
            lines.append(f"  ⛔ {n} {what} CHANGED, and on {', '.join(inj)} the new text reads "
                         f"like an ATTACK.")
            lines.append("     Do NOT approve until you have read the inserted text below.")
        if esc:
            lines.append((f"  ⛔ {n} {what} CHANGED, and " if not inj else "     Also: ")
                         + f"{', '.join(esc)} now DECLARES MORE POWER than you approved "
                         f"(a tool marked itself destructive or open-world).")
            lines.append("     Do NOT approve until you have read what it gained below.")
        return "\n".join(lines)
    return (f"{head}\n"
            f"     Review the change below, then `mcpgawk approve <name>` to accept it.")


def ago(stamp: str | None, now: datetime | None = None) -> str | None:
    """"4 days ago" rather than an ISO timestamp.

    How long a poisoned description has been live is the part a reader can act on — a machine
    timestamp makes them do arithmetic before they can feel the answer."""
    if not stamp:
        return None
    try:
        then = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    now = now or datetime.now(then.tzinfo)
    secs = (now - then).total_seconds()
    if secs < 0:
        return None                      # a clock skew must not produce "in -3 days"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        n = int(secs // size)
        if n:
            return f"{n} {unit}{'s' if n > 1 else ''} ago"
    return "just now"


def render(name: str, r: DriftReport, head: str | None = None) -> str:
    """One renderer for every diff surface. `head` replaces the DRIFT headline when the two records
    are not "your approval" and "now" — `changes` compares consecutive snapshots that were never
    approved, and "changed since you approved it" there would claim a decision nobody made."""
    if r.unreadable:
        # No diff, because there is no diff we could stand behind. Say that plainly rather than
        # printing a comparison the reader has just declared untrustworthy.
        return (f"    ⚠ BASELINE NOT READABLE on {name} — {r.unreadable}\n"
                f"        Until then this server is NOT being compared against anything.")
    when = ago(r.prev_at)
    approval = head is None      # the default caller compares "your approval" with "now"
    if head is not None:
        pass
    elif when:
        # `prev_at` is the APPROVED sighting's time — the age of the baseline, not of the change.
        # "changed 19 days ago" read as if the change were dated (2026-09-03); it is not. Say
        # what the timestamp is.
        head = f"    ⟳ DRIFT on {name} — changed since you approved it {when}:"
    elif r.prev_at:
        head = f"    ⟳ DRIFT on {name} — changed since {r.prev_at}, after you approved it:"
    else:
        head = f"    ⟳ DRIFT on {name} — changed after you approved it:"
    lines = [head]
    for kind in ITEM_KINDS:
        split = r.of_kind(kind)
        if split["changed"]:
            # "(rug-pull signature)" is an ACCUSATION, so it is made only where there is evidence
            # for it — `r.hostile`, the same set that earns the per-line INJECTION SIGNATURE mark
            # below. Printing it on every rewrite meant a typo fix and a poisoning attempt arrived
            # in identical words, which is how a team learns to run `approve --all` without reading.
            # That is the failure this whole module exists to prevent (see `_with_severity`).
            tag = (" (rug-pull signature)"
                   if any(f"{kind}.{s}" in r.hostile for s in split["changed"]) else "")
            lines.append(f"        ! {kind} description CHANGED{tag}: "
                         f"{', '.join(split['changed'])}")
            # Show WHAT it gained. "helper's description changed" tells a user to go and look;
            # quoting the instruction that was inserted tells them what they are looking at, which
            # is the entire difference between an alert and an explanation.
            for short in split["changed"]:
                key = f"{kind}.{short}"
                gained, lost = r.insertion(key), r.deletion(key)
                if gained:
                    mark = "  ← INJECTION SIGNATURE" if key in r.hostile else ""
                    lines.append(f"            {short} gained: {_excerpt(gained)}{mark}")
                if lost:
                    # A deleted safety caveat steers the model as effectively as an added
                    # instruction. Showing only what was gained made that class invisible.
                    lines.append(f"            {short} lost:   {_excerpt(lost)}")
                if not gained and not lost and not r.text_kept(key):
                    # The hash moved and the stored text did not: the change sits past the
                    # characters this store kept (two of Notion's four changes in Aug–Sep 2026
                    # did). A bare "CHANGED" with nothing under it reads as a detector that
                    # cannot explain itself; say what it cannot see and why. The number is the
                    # length of the text that WAS stored, not today's MAX_TEXT — a record cut at
                    # 600 before the limit rose to 2000 must not claim 2000.
                    kept = len((r.texts.get(key) or ("", ""))[0]) or MAX_TEXT
                    lines.append(f"            {short}: the description changed past the "
                                 f"{kept} characters the store kept — re-scan with --detail "
                                 f"to read the current text")
        # C1 — the description is what the model READS; these are what the tool can SEND and what it
        # CLAIMS it will do. Both were previously invisible unless the prose happened to change too.
        for key in [k for k in r.schema_changed if k.startswith(f"{kind}.")]:
            short = key[len(kind) + 1:]
            added_params, dropped_params = r.gained_params(key), r.lost_params(key)
            params = ""
            if added_params:
                params += f" — gained parameter(s): {', '.join(added_params)}"
            if dropped_params:
                params += f" — removed: {', '.join(dropped_params)}"
            lines.append(f"        ! {kind} input schema CHANGED: {short}{params}")
        for key in [k for k in r.annotation_changed if k.startswith(f"{kind}.")]:
            short = key[len(kind) + 1:]
            esc = r.escalations(key)
            mark = f" ({', '.join(esc)})  ← CAPABILITY ESCALATION" if esc else ""
            lines.append(f"        ! {kind} annotations CHANGED: {short}{mark}")
        if split["added"]:
            lines.append(f"        + {_KIND_LABEL[kind]} added: {', '.join(split['added'])}")
        if split["removed"]:
            lines.append(f"        - {_KIND_LABEL[kind]} removed: {', '.join(split['removed'])}")
    if r.transport_changed and approval:
        before, after = r.transport_changed
        note = (" — a LOCAL server is now a REMOTE endpoint; its trust posture changed"
                if before == "stdio" and after in ("http", "sse") else "")
        lines.append(f"        ! TRANSPORT changed: {before} → {after}{note}")
    elif r.transport_changed:
        # A changelog compares consecutive RECORDS, and two writers record the same server through
        # different transports: `wrap` is a stdio bridge and stamps stdio for an http upstream
        # (wrap.py `_snapshot`). On the founder's store 2026-09-09 that read as dadan flipping
        # stdio↔http eleven times in a day. It is a fact about how the snapshot was taken, so it
        # is shown as one — never as the server changing.
        before, after = r.transport_changed
        lines.append(f"        · recorded over {after}; the previous snapshot over {before}")
    if r.protocol_changed and (approval or r.protocol_migration):
        before, after = r.protocol_changed
        # Still SHOWN either way — a migration is worth seeing. It just isn't a decision.
        lines.append(f"        · MCP spec migration: {before} → {after} (newer revision, not drift)"
                     if r.protocol_migration else
                     f"        ! MCP protocol changed: {before} → {after}")
    elif r.protocol_changed:
        before, after = r.protocol_changed
        lines.append(f"        · negotiated MCP {after}; the previous snapshot {before}")
    if r.token_delta:
        lines.append(f"        Δ cost index: {r.token_delta:+d} tok")
    if r.login_changed and approval:
        lines.append("        ! SIGNED IN AS SOMEONE ELSE, possibly: this scan went through a "
                     "different sign-in than the one your baseline was approved under. mcpgawk "
                     "cannot read WHICH account (no MCP token here carries an issuer or subject), "
                     "only that the sign-in is not the same one. If you switched accounts, this "
                     "baseline describes the other account's surface — re-approve to adopt this "
                     "one.")
    elif r.login_changed:
        lines.append("        · a different sign-in than the previous snapshot — if you switched "
                     "accounts, part of this change may be the other account's surface")
    if r.pin_not_compared:
        lines.append(f"        · {r.pin_not_compared}")
    if r.baseline_extended and approval:
        lines.append("        (prompts/resources were not fingerprinted before now — their "
                     "baseline starts with this scan)")
    elif r.baseline_extended:
        lines.append("        (prompts/resources were not fingerprinted in the earlier snapshot — "
                     "only tools were compared here)")
    if r.changed and not r.hostile:
        # Absence of a signature is NOT a clean bill of health, and saying nothing here would let
        # the quieter wording read as "harmless". The detectors are pattern-based and bounded; the
        # diff above is the evidence, and the human is still the one deciding.
        lines.append("        Nothing in what changed matched a known injection pattern — that is "
                     + ("not proof it is safe. Read the diff above before approving."
                        if approval else "not proof it was safe."))
    return "\n".join(lines)
