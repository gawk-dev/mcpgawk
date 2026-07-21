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
MAX_TEXT = 600


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
        "tools": _tool_hashes(snap),      # legacy shape, kept for older readers (see _tool_hashes)
        "items": _item_hashes(snap),      # the real fingerprint: tools + prompts + resources
        "texts": _item_texts(snap),       # redacted prose, so a diff can be SHOWN (ADR-0012)
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
    #: C1 — same item, different input schema (what the tool can be made to SEND).
    schema_changed: list[str] = field(default_factory=list)
    #: C1 — same item, different behaviour hints (what the tool CLAIMS it will do).
    annotation_changed: list[str] = field(default_factory=list)
    #: `{kind}.{name}` -> (before, after) top-level parameter names, for naming what appeared.
    props: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)
    #: `{kind}.{name}` -> (before, after) annotation dicts.
    annos: dict[str, tuple[dict, dict]] = field(default_factory=dict)

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
    def any(self) -> bool:
        return self.pin_changed or bool(self.added or self.removed or self.changed
                                        or self.schema_changed or self.annotation_changed)

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


def _fingerprints(rec: dict[str, Any]) -> tuple[dict[str, str], bool]:
    """A record's `{type}.{name}` -> hash map, plus whether it came from the LEGACY tools-only
    shape. Old records are upgraded in memory (never rewritten) so an existing history file keeps
    working across the version boundary."""
    items = rec.get("items")
    if isinstance(items, dict):
        return items, False
    return {f"tool.{n}": h for n, h in (rec.get("tools") or {}).items()}, True


def compare(prev: dict[str, Any] | None, curr: dict[str, Any]) -> DriftReport | None:
    """None if there's no prior record (first sighting — nothing to drift from)."""
    if not prev:
        return None
    pa, legacy = _fingerprints(prev)
    ca, _ = _fingerprints(curr)
    if legacy:
        # The prior record only ever fingerprinted tools. Comparing it against a full tools+prompts
        # +resources map would report every prompt and resource as "added" — a fleet-wide false
        # rug-pull alarm the first time a user upgrades. Compare the surface both records actually
        # cover, and flag that the rest starts its baseline now.
        ca = {k: v for k, v in ca.items() if k.startswith("tool.")}
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

    return _with_severity(DriftReport(
        pin_changed=prev.get("pin") != curr.get("pin"),
        added=added, removed=removed, changed=changed,
        token_delta=delta,
        prev_at=prev.get("measured_at"),
        baseline_extended=legacy,
        texts=texts,
        schema_changed=schema_changed,
        annotation_changed=anno_changed,
        props=props,
        annos=annos,
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

    injected = {k for k in r.changed if (span := r.insertion(k)) and _scan_text(span, k)}
    # A declared-capability escalation is hostile on its own terms — no text needs to have changed.
    escalated = {k for k in r.annotation_changed if r.escalations(k)}
    r.hostile = sorted(injected | escalated)
    return r


_KIND_LABEL = {"tool": "tools", "prompt": "prompts", "resource": "resources"}

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


def render_headline(names: list[str], hostile: list[str] | None = None) -> str:
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
        # as a typo fix is how it gets approved away.
        h = ", ".join(hostile)
        return (f"  ⛔ {n} {what} CHANGED, and the new text reads like an ATTACK: {h}\n"
                f"     Do NOT approve until you have read the inserted text below.")
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


def render(name: str, r: DriftReport) -> str:
    when = ago(r.prev_at)
    if when:
        head = f"    ⟳ DRIFT on {name} — changed {when}, after you approved it:"
    elif r.prev_at:
        head = f"    ⟳ DRIFT on {name} — changed since {r.prev_at}, after you approved it:"
    else:
        head = f"    ⟳ DRIFT on {name} — changed after you approved it:"
    lines = [head]
    for kind in ITEM_KINDS:
        split = r.of_kind(kind)
        if split["changed"]:
            lines.append(f"        ! {kind} description CHANGED (rug-pull signature): "
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
        # C1 — the description is what the model READS; these are what the tool can SEND and what it
        # CLAIMS it will do. Both were previously invisible unless the prose happened to change too.
        for key in [k for k in r.schema_changed if k.startswith(f"{kind}.")]:
            short = key[len(kind) + 1:]
            gained, lost = r.gained_params(key), r.lost_params(key)
            detail = ""
            if gained:
                detail += f" — gained parameter(s): {', '.join(gained)}"
            if lost:
                detail += f" — removed: {', '.join(lost)}"
            lines.append(f"        ! {kind} input schema CHANGED: {short}{detail}")
        for key in [k for k in r.annotation_changed if k.startswith(f"{kind}.")]:
            short = key[len(kind) + 1:]
            esc = r.escalations(key)
            mark = f" ({', '.join(esc)})  ← CAPABILITY ESCALATION" if esc else ""
            lines.append(f"        ! {kind} annotations CHANGED: {short}{mark}")
        if split["added"]:
            lines.append(f"        + {_KIND_LABEL[kind]} added: {', '.join(split['added'])}")
        if split["removed"]:
            lines.append(f"        - {_KIND_LABEL[kind]} removed: {', '.join(split['removed'])}")
    if r.token_delta:
        lines.append(f"        Δ cost index: {r.token_delta:+d} tok")
    if r.baseline_extended:
        lines.append("        (prompts/resources were not fingerprinted before now — their "
                     "baseline starts with this scan)")
    return "\n".join(lines)
