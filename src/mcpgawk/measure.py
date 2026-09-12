"""BOUND — measure a snapshot. Pure, offline, deterministic.

The EXACT/INDEX/BOUNDED wall (enforced here):
  * EXACT  — structural capability facts + integrity pin. Facts, not estimates.
  * INDEX  — token cost via a *named* tokenizer (cl100k). A comparable ranking index, NOT
             an absolute Claude count (tiktoken undercounts Claude ~15-20%). Honestly labelled.
  * BOUNDED— heuristic risk signals. NOT in v1 (security is a 0-FP fast-follow). Kept out of
             this module entirely so an estimate can never contaminate a fact.

No network. No LLM. Scanning the inventory is pure computation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .fingerprint import surface_pin
from .probe import ServerSnapshot

TOKENIZER_NAME = "cl100k_base (approx index; not Claude-exact)"

# Structural capability detectors — deliberately conservative, fact-level only.
# Mutating verbs — ONE list, used to build both patterns below. A second hand-written list would
# be a second definition of "write", and the two would drift.
#
# The 2026-07-21 additions (second row) came from comparing this scanner against a general-purpose
# agent: a real brokerage server's order-placement tool — an irreversible real-money trade — was not
# counted as a write, because "place" was missing. Kept to verbs unambiguous in isolation:
# "start"/"stop"/"open"/"close" are excluded, since "start date" and "open issue" appear constantly
# in read-only descriptions.
_WRITE_VERBS = (
    "create", "delete", "remove", "write", "update", "send", "post", "put", "patch", "execute",
    "run", "modify", "drop", "insert", "upload", "push", "merge", "deploy", "revoke", "grant",
    "edit", "rename", "move", "set", "add",
    "place", "cancel", "submit", "issue", "transfer", "buy", "sell", "trade", "schedule",
    "publish", "archive", "enable", "disable", "reset", "rotate", "approve", "reject", "terminate",
    # [FOUNDER 2026-09-11] Authentication is a write. `login` establishes a session — it changes
    # state on the server even though it mutates no record, and kite's `login` fell out of the
    # write set when its all-defaults annotations stopped being treated as a declaration.
    # MEASURED over the 390 recorded tools before adding: `login` newly flags exactly the three
    # kite login tools and nothing else. `authenticate` flags nothing today and is here so the
    # rule generalises rather than matching one literal spelling. `authorize`, `connect` and
    # `sign` were considered and REJECTED — each brought a false positive (a permission check, a
    # resend editor handshake, and Revolut's `get_trading_setup`).
    "login", "authenticate",
)


def _third_person(verb: str) -> str:
    """"create" -> "creates", "modify" -> "modifies", "patch" -> "patches". English, not a lookup
    table, so adding a verb above needs no second edit."""
    if verb.endswith("y") and verb[-2] not in "aeiou":
        return verb[:-1] + "ies"
    if verb.endswith(("s", "x", "z", "ch", "sh", "o")):
        return verb + "es"
    return verb + "s"


_WRITE = re.compile(r"\b(" + "|".join(_WRITE_VERBS) + r")\b", re.I)

# THIRD-PERSON, ANCHORED TO THE START OF THE DESCRIPTION — and anchored for a reason.
#
# The bare pattern above matches "create" but not "creates", so every third-person description was
# invisible to write detection: "Creates a file", "Sends an email", "Deletes the record" all read as
# read-only. That is arguably the dominant phrasing in real tool descriptions, so write counts were
# undercounted across the board — the product's headline claim, low.
#
# Matching "<verb>s" ANYWHERE would trade that for false positives on plural NOUNS, and the worst
# offenders are exactly the words in the list: "Lists issues", "Gets updates", "Returns test runs",
# "Lists OAuth grants", "Shows scheduled posts". All read-only, all would flag.
#
# The grammar separates them: a third-person verb LEADS a description; a plural noun FOLLOWS a verb.
# So the -s form counts only as the first word. Known and accepted limitation: a description that
# opens with a plural noun ("Posts and comments for a blog") is missed — rare, and failing closed on
# a naming style is better than crying wolf on every list-shaped tool.
_WRITE_LEADING = re.compile(
    r"^\W*(?:it\s+|this\s+tool\s+)?(" + "|".join(_third_person(v) for v in _WRITE_VERBS) + r")\b",
    re.I)

#: Parameter-name words that mean "the CALLER chooses a destination". This is the STRUCTURAL half
#: of exfil detection and the stronger half: whoever controls that argument controls where data
#: goes, whatever the prose says.
_EXFIL_PARAM_WORDS = frozenset(
    {"url", "uri", "endpoint", "webhook", "href", "callback", "redirect"})

#: The old rule was `re.compile(r"\b(url|uri|...)\b")` applied to the raw property name, and `_` is
#: a WORD character — so `\burl\b` never matched `source_url`. That is not an edge case: snake_case
#: is the dominant convention in MCP input schemas, so the parameter arm only ever fired on a
#: property named EXACTLY `url`. Measured on a live 70-tool server (2026-09-10): it missed
#: `source_url`, `audio_url`, `image_url`, `cta_url` and `meeting_url` — including `upload_video`,
#: where the server fetches a URL the caller supplies, which is the textbook shape this rule exists
#: to catch. Meanwhile the count was driven entirely by the NAME arm matching prose. The strong
#: signal was dead and the weak one was doing all the work.
#:
#: Splitting the identifier first is what makes it precise rather than merely wider: `source_url`
#: tokenises to {source, url} and matches, while `file_name` tokenises to {file, name} and does
#: not. A looser regex (dropping `\b`) would have matched `curling_urn`.
def _param_tokens(name: str) -> set[str]:
    """`sourceUrl`, `source_url`, `source-url`, `source.url` -> {'source', 'url'}."""
    return {t.lower() for t in re.findall(r"[A-Za-z]+",
                                          re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name))}


#: A list of destinations is still destinations. `file_urls` and `data_source_urls` are real
#: parameters on a live server (Notion, measured 2026-09-10) and the singular-only rule read
#: neither — the same failure as `\burl\b` against `source_url`, one spelling further on.
#:
#: `redirect` is deliberately EXCLUDED from the plural form. In the plural it names a policy,
#: not a place: `follow_redirects`, `max_redirects`. Adding it would flag a boolean flag as a
#: caller-supplied destination, which is the class of overclaim this arm exists to avoid.
_EXFIL_PARAM_PLURALS = frozenset(w + "s" for w in _EXFIL_PARAM_WORDS - {"redirect"})


#: An ID that REFERS to a destination is not a destination. `webhookId` selects a webhook the
#: account already has; the endpoint it delivers to was chosen when that webhook was created, not
#: by this caller. Measured on the live resend server (2026-09-10): `remove-webhook(webhookId)`
#: and `replay-webhook-event(eventId, webhookId)` were both counted as caller-supplied
#: destinations, and neither lets the caller name a place.
#:
#: This NARROWS the arm, which is the only safe direction: the standing rule is never to widen
#: the vocabulary to improve a number, and an arm whose whole claim is "whoever controls this
#: argument controls where data goes" must not fire on an argument that controls no such thing.
#:
#: An explicit url-ish token still wins — `webhook_url_id` names a URL and is read as one — so
#: the rule drops references, not spellings.
#:
#: What this does NOT say: that `replay-webhook-event` sends nothing outward. It plainly does —
#: it queues a delivery to the stored endpoint. It says this arm cannot see that, because the
#: destination is not in the call. Observing a delivery is `mcpgawk verify`'s job, not a
#: schema reader's.
_REFERENCE_TOKENS = frozenset({"id", "ids"})
_URLISH_TOKENS = frozenset({"url", "uri", "urls", "uris", "href", "hrefs"})


def _is_destination_param(name: str) -> bool:
    toks = _param_tokens(name)
    if not (toks & _EXFIL_PARAM_WORDS or toks & _EXFIL_PARAM_PLURALS):
        return False
    return not (toks & _REFERENCE_TOKENS and not toks & _URLISH_TOKENS)


_EXFIL_NAME = re.compile(r"\b(fetch|http|request|download|browse|scrape|curl|web)\b", re.I)


@dataclass
class ToolMeasure:
    name: str
    tokens: int                      # INDEX
    write: bool                      # BOUNDED (declaration first, then a verb heuristic)
    # BOUNDED, and it was mis-annotated EXACT until 2026-09-10 — which is how a regex over the tool
    # name came to headline a report as though it were a structural fact. It reads readOnlyHint
    # first; absent that, it pattern-matches. Both arms can be wrong, and the report must say so.
    exfil_capable: bool              # see `exfil_basis` below for WHY it is true
    annotations: dict[str, Any]      # EXACT (declared)
    # Both EXACT counts, not judgements. They exist so grade.py can ask whether a tool is described
    # in proportion to what it does; the judgement lives there, the facts live here. Kept on this
    # side of the wall for the same reason `write` is: counting is a fact, deciding is not.
    param_count: int = 0
    description_words: int = 0
    #: WHY `exfil_capable` is true: "param:<name>" (structural — the tool takes a destination from
    #: its caller) or "wording:<word>" (lexical — only its prose suggests network reach), and ""
    #: when it is false. The report prints this so a reader can weigh the two arms differently
    #: instead of receiving one number over both.
    #:
    #: DEFAULTED, and last, on purpose: it is DERIVED from the same tool `exfil_capable` is derived
    #: from, so a caller that builds a ToolMeasure by hand (every test fixture, and `grade.py`'s
    #: callers) must not be forced to restate it. Empty then means "not flagged, or nobody said" —
    #: which is exactly what the renderer treats as "no claim to make".
    exfil_basis: str = ""


@dataclass
class Measurement:
    tokenizer: str
    total_tokens: int                # INDEX — sum at connect
    tool_count: int
    tools: list[ToolMeasure]
    integrity_pin: str               # EXACT — rug-pull anchor
    prompt_count: int = 0
    resource_count: int = 0
    caveats: list[str] = field(default_factory=list)
    # Carried through from the snapshot so the label layer has a TYPED failure signal and never has
    # to infer "did the scan fail?" from caveat wording (the old false-CLEAN footgun).
    is_failure: bool = False
    error_kind: str | None = None    # closed set — see ServerSnapshot.error_kind


def _encoder():
    try:
        import tiktoken
        return tiktoken.get_encoding("cl100k_base"), TOKENIZER_NAME
    except Exception:
        return None, "chars/4 (rough fallback — tiktoken unavailable)"


def _count(enc, text: str) -> int:
    return len(enc.encode(text)) if enc is not None else max(1, len(text) // 4)


def _exfil_basis(tool: dict[str, Any], ann: dict[str, Any] | None = None) -> str:
    """WHY this tool was flagged, in the product's own words. `""` means it was not.

    Two arms of very different strength, and the report was printing one number over both:

      * ``param:<name>`` — the tool takes a DESTINATION from its caller (`source_url`,
        `webhook_url`). Structural: whoever controls that argument controls where data goes,
        whatever the prose says.
      * ``wording:<word>`` — only the name or description suggests network reach. Lexical, and
        routinely wrong: on a live 70-tool server, "request" matched inside the product's own noun
        "recording request" twice.

    Naming the basis is the point. A one-line headline that asserts "can reach the network" over
    both arms overstates the weak one, and the operator cannot tell which tools it is confident
    about. Neither arm OBSERVES anything — `mcpgawk verify` is what does that.

    A DECLARATION OUTRANKS BOTH, exactly as in `_is_write`. That arm was missing until 2026-09-10,
    and two tools that declared `readOnlyHint: true` were reported as the server's leak path.
    """
    _ann = ann or tool.get("annotations") or {}
    if is_default_fill(_ann):                # same rule as `_is_write`, stated once (see is_default_fill)
        _ann = {}                            # a no-op today: default-fill has readOnlyHint false, which never silences
    if _ann.get("readOnlyHint") is True:
        return ""
    # Parameter first: it is the strongest evidence, so it should be the reported reason when
    # several arms fire (`add_watermark` has an `image_url` AND the word "http" in its prose).
    for k in ((tool.get("inputSchema") or {}).get("properties") or {}):
        if _is_destination_param(k):
            return f"param:{k}"
    # THE TOOL'S OWN NAME NAMES A DESTINATION. `fetch_url` is not a chance word in prose — the
    # tool advertises what it does in its identifier, and a schema-less tool would otherwise be
    # demoted to "wording" alongside a description that merely says "curl". Same destination
    # vocabulary as the parameter arm, so this is one rule applied in two places rather than a
    # second list that drifts: `fetch_url` -> {fetch, url} qualifies, while
    # `create_recording_request` -> {create, recording, request} does not, and neither does
    # `prepare_upload`.
    #
    # A NAME MUST SPELL OUT A URL, not merely mention a thing that has one. `remove-webhook` and
    # `replay-webhook-event` (live resend, measured 2026-09-10) name the OBJECT they act on; the
    # endpoint was chosen when that webhook was created. Reusing the full parameter vocabulary
    # here read both as destinations — and when the reference rule above stopped their
    # `webhookId` param from firing, they simply fell through to this arm and the structural
    # total never moved. A fix that only re-buckets rows is not a fix.
    #
    # Store-wide before this narrowing, across 390 tools on 15 servers, the name arm's ONLY hits
    # were those two false positives. It costs nothing measured and removes both.
    name = tool.get("name", "")
    if _param_tokens(name) & _URLISH_TOKENS:
        return f"name:{name}"
    m = _EXFIL_NAME.search(name + " " + (tool.get("description") or ""))
    return f"wording:{m.group(0).lower()}" if m else ""


def _exfil_capable(tool: dict[str, Any], ann: dict[str, Any] | None = None) -> bool:
    return bool(_exfil_basis(tool, ann))


#: Which arm found it, as one rule rather than a prefix string retyped per surface.
#:
#: `param:` and `name:` are STRUCTURAL — something in the call names a destination, so whoever
#: controls it controls where data goes. `wording:` is LEXICAL: a word in prose, and measured at
#: 0 true positives out of 11 across 390 tools on 15 real servers (2026-09-10).
#:
#: [FOUNDER 2026-09-10] Only the structural arms are COUNTED. The lexical ones are still shown,
#: labelled as wording-only — the decision was to stop inflating a number, not to hide anything.
#: The report sent to a reviewer had already drawn the line here (`scripts/gen_dadan.py`) while
#: the product had not, so its own screens counted tools that report would never have listed.
#:
#: Callers must ask through this function. A prefix tuple copied into a second file is how
#: display rules drift apart from counting rules.
def is_structural_basis(basis: str | None) -> bool:
    """True when the destination is IN the call, not merely in the prose about it."""
    return str(basis or "").startswith(("param:", "name:"))


#: The MCP spec's documented defaults for the four behaviour hints, read from the installed
#: `mcp.types.ToolAnnotations` docstrings rather than recalled: readOnlyHint false, destructiveHint
#: true, idempotentHint false, openWorldHint true.
_MCP_DEFAULT_HINTS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}


#: [FOUNDER 2026-09-11] An annotation block that is EXACTLY the spec defaults is treated as
#: UNANNOTATED, because that is what a server library emits when it serialises a struct nobody
#: filled in — it is the shape of the absence, not a statement.
#:
#: MEASURED: kite carries this identical block on all 22 tools. `cancel_order` and `get_profile`
#: are annotated identically, which is the discriminator — a tuple that cannot tell an
#: order-canceller from a profile reader is not describing either of them. `destructiveHint: true`
#: there then short-circuited `_is_write` and called 16 pure reads writes. The MCP spec itself says
#: "Clients should never make tool use decisions based on ToolAnnotations received from untrusted
#: servers"; this is the narrow version of that — do not make a decision on a value nobody set.
#:
#: EXACTLY FOUR KEYS, ALL PRESENT, ALL EQUAL. Deliberately strict. `{"readOnlyHint": false}` alone
#: is a real declaration and stays one, as does any three-of-four subset: a partial block is
#: someone choosing, and the regression tests that pin those (Emergent's `pause_job`, the
#: readiness write-scope cases) are pinning real behaviour. `title` is ignored — it is prose and
#: says nothing about behaviour.
#:
#: WHERE THIS MUST NOT BE APPLIED, and why the demotion is a LOCAL REBIND rather than a
#: normalisation of the stored dict:
#:   * `drift.py` and `fingerprint.py` compare and hash the RAW annotations. Demoting there would
#:     fire a false rug-pull on every existing kite baseline and, worse, would hide a genuine
#:     `destructiveHint: false -> default` risk gain.
#:   * `panel.py`'s "Declared" column reports what the server SAID. That stays literal.
#:   * `enforce/derive_scopes.py` derives POLICY. `unguarded` is allow-by-default while
#:     `write:<tool>` is deny-by-default, so demoting there would flip kite's order-placing tools
#:     from guarded to open. Policy reads raw hints, deliberately.
def is_default_fill(ann: dict[str, Any] | None) -> bool:
    """True when this annotation block is indistinguishable from one nobody filled in."""
    if not isinstance(ann, dict):
        return False
    return {k: v for k, v in ann.items() if k != "title"} == _MCP_DEFAULT_HINTS


def _is_write(tool: dict[str, Any], ann: dict[str, Any]) -> bool:
    if is_default_fill(ann):                 # a struct nobody filled in declares nothing; fall through to the verbs
        ann = {}                             # LOCAL rebind only — the stored tuple stays raw for drift and the panel
    if ann.get("destructiveHint") is True:   # a declared-destructive tool mutates, even if the verb heuristic misses it
        return True                          # (e.g. Emergent's `pause_job` — "pause" isn't a write-verb)
    if ann.get("readOnlyHint") is True:      # declared read-only wins over the verb heuristic
        return False
    description = (tool.get("description") or "").strip()
    text = tool.get("name", "") + " " + description
    # Bare verb anywhere ("create_file", "will delete the row"), OR a third-person verb leading the
    # description ("Creates a file") — see _WRITE_LEADING for why the second one is anchored.
    return bool(_WRITE.search(text)) or bool(_WRITE_LEADING.match(description))


def measure(snap: ServerSnapshot, enc=None, tokenizer_name: str | None = None) -> Measurement:
    if enc is None and tokenizer_name is None:
        enc, tokenizer_name = _encoder()
    tools: list[ToolMeasure] = []
    total = 0
    for t in snap.tools:
        # Tokenise exactly what a model's context would carry for this tool.
        blob = json.dumps({k: t.get(k) for k in ("name", "description", "inputSchema", "annotations")
                           if t.get(k) is not None}, sort_keys=True)
        tk = _count(enc, blob)
        total += tk
        ann = t.get("annotations") or {}
        props = ((t.get("inputSchema") or {}).get("properties") or {})
        tools.append(ToolMeasure(
            name=t.get("name", "?"), tokens=tk,
            write=_is_write(t, ann), exfil_capable=_exfil_capable(t, ann),
            exfil_basis=_exfil_basis(t, ann), annotations=ann,
            param_count=len(props),
            description_words=len((t.get("description") or "").split())))
    # Integrity pin over the WHOLE tool surface — name + description + canonical input schema +
    # annotations (audit B2). A rug-pull that only widens a schema or flips readOnlyHint keeps the
    # name+description identical, so the old name+description-only pin missed it; this does not.
    pin = surface_pin(snap.tools)
    m = Measurement(
        # A Measurement always NAMES its tokenizer: token counts are only comparable within one,
        # and `drift` refuses to compare a delta across two. "unknown" is a real answer here — a
        # caller that passed an encoder without naming it — and it is a visibly wrong one, which is
        # the point: silently storing None would make the comparison look valid.
        tokenizer=tokenizer_name or "unknown", total_tokens=total, tool_count=len(tools), tools=tools,
        integrity_pin=pin, prompt_count=len(snap.prompts), resource_count=len(snap.resources))
    if snap.error:
        m.is_failure = True
        m.error_kind = snap.error_kind
        m.caveats.append(f"probe error: {snap.error}")
    if snap.transport_corrected:
        # NOT a failure — we got a full measurement. But the user's config is wrong, and saying
        # nothing would leave them with a declaration that still breaks every other client.
        m.caveats.append(
            f"declared transport `{snap.declared_transport}` did not answer; scanned "
            f"`{snap.transport}` at {snap.resolved_url} instead — update your config")
    return m
