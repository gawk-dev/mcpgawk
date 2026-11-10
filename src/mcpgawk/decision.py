"""The decision core — the ONE place a runtime verdict is computed.

`(call, expectations) → verdict + basis`. Pure and stdlib-only: this runs inside the agent hook's
hot path (which must never import the MCP SDK — see guard_hook.py's docstring) AND inside the paid
enforcement gateway. Both call THIS function; neither holds its own copy of the rule. A new
interception point gets the identical verdict by construction, so the two-implementations drift
class is structurally impossible rather than test-pinned
(docs/architecture-runtime-monitoring-2026-07-27.md §4).

The free tier evaluates the DECLARED tier: membership of the human-approved baseline surface.
The paid tiers (observed behaviour, operator policy) EXTEND this same core — they run after it,
they never fork it, and they may only ADD denials (positive-only composition: a deeper tier
promotes a verdict, never clears one this tier issued).

This module is loaded two ways and must support both: as `mcpgawk.decision` (the package), and by
absolute file path with no parent package (guard_hook._load_sibling). Therefore: no relative
imports, no package imports, standard library only.
"""
from __future__ import annotations

import re

#: The evidence tier a verdict rests on. The basis travels with every verdict — a caller cannot
#: calibrate trust in a deny (or in the absence of one) without knowing what evidence produced it.
BASIS_DECLARED = "declared"
#: What verify WATCHED the tool do in a sandbox. Evidence, not inference — and free-tier since
#: Task 0's answer: a free install both produces observations (verify) and consumes them (here).
BASIS_OBSERVED = "observed"

#: The only two verdicts the declared tier issues. There is deliberately no "allow": on the agent
#: hook, "allow" means "skip the human's permission prompt", which a security layer must never
#: volunteer (see guard_hook.py). "defer" means "we found nothing — carry on as normal".
DENY = "deny"
DEFER = "defer"


#: HOW THE BASELINE WAS SET, as every denial says it. The values are `history.baseline_origin`'s,
#: carried to the hook in the projection row ("unknown" = history could not tell; None = the caller
#: did not say). The words are `history.changed_head`'s — the one sentence the scan, /next and
#: `baseline` print — which this module cannot import (stdlib only, loaded by path), so
#: tests/test_guard_words_who_set_the_baseline.py pins that the two agree.
#: FOUND 2026-11-06: every denial said "CHANGED since you approved it" of a first-sighting baseline
#: nobody approved, while the scan beside it said "you have not approved this server yet" — the
#: 2026-10-09 rule had reached every surface but this one. "you approved it" stays where a person
#: did (FOUNDER 2026-11-06, "leave you approved it").
def _anchor(origin: str | None) -> dict[str, str]:
    if origin == "approve":
        return {"since": "since you approved it", "they": "after they approved it",
                "they_added": "since they approved it", "in": "the approved baseline",
                "note": "", "appeared": "after this server was approved", "after": "after approval",
                "label": "approved",
                "trusted": "a tool you trusted", "more": "more than was approved",
                "props": "when the user approved it", "never": "you never approved",
                "covered": "the approved baseline", "was_there": "when you approved this server"}
    if origin == "fleet":
        since = "since first seen, the baseline your fleet approval accepted"
        they = "since their fleet approval accepted it"
        note, trusted = "accepted by your fleet approval", "a tool your fleet approval accepted"
    elif origin == "first-sighting":
        since = "since first seen; you have not approved this server yet"
        they = "since it was first seen (they have not approved this server yet)"
        note, trusted = "first seen; you have not approved this server yet", "a tool already in use"
    elif origin == "unattended":
        since = "since its baseline, approved without a person present"
        they = "since its baseline, which was approved without a person present"
        note, trusted = "approved without a person present", "a tool already in use"
    elif origin == "unsigned":
        # A locked machine (approval_lock) holding an approval no valid signature vouches for.
        since = "since its baseline; this machine cannot verify who approved it"
        they = "since its baseline (this machine cannot verify who approved it)"
        note, trusted = "this machine cannot verify who approved it", "a tool already in use"
    elif origin == "unknown":
        since = "since its baseline; who approved it is not on record"
        they = "since its baseline (who approved it is not on record)"
        note, trusted = "who approved it is not on record", "a tool already in use"
    else:
        # The caller did not say. Claim nothing about who set the baseline — not even that the
        # record does not say, which a caller that never looked cannot know.
        since, they, note, trusted = ("since its baseline", "since its baseline was recorded", "",
                                      "a tool already in use")
    return {"since": since, "they": they, "they_added": they, "in": "the baseline",
            "note": f" ({note})" if note else "", "appeared": "after the baseline was recorded",
            "after": "after the baseline was recorded", "label": "baseline", "trusted": trusted, "more": "more than its baseline allowed",
            "props": "in its baseline", "never": "not in its baseline",
            "covered": "its baseline", "was_there": "when its baseline was recorded"}


def content_hash(description: str | None) -> str:
    """The approved-surface fingerprint of one tool's model-visible text.

    MUST stay byte-identical to `drift._hash`, which writes the `{tool: hash}` map into the trust
    store — comparing against a differently-computed hash would deny every call on every server.
    `tests/test_rugpull_runtime.py` pins the two together.
    """
    import hashlib
    return hashlib.sha256((description or "").encode()).hexdigest()[:12]


#: Parameter names an agent should never be filling unless the human approved that exact field.
#: Deliberately narrow — the founder's constraint is "without breaking any expected flow", and a
#: benign new parameter (a sort order, a page size) must keep working. What must NOT keep working
#: is the smuggled-field rug-pull: a tool approved with {city} quietly gaining {api_key}, which
#: the agent then helpfully fills with a credential.
_CREDENTIAL_SHAPED = re.compile(
    r"(?i)(?:^|[_\-.])(?:token|secret|password|passwd|credential|api[_\-]?key|apikey|"
    r"auth|bearer|cookie|private[_\-]?key|access[_\-]?key|session[_\-]?id)(?:$|[_\-.])")


def smuggled_credential_args(args: dict | None,
                             approved_props: list[str] | None) -> list[str]:
    """Argument keys of THIS call that (a) were never in the approved parameter list and
    (b) are credential-shaped. Empty when the check cannot run (no props recorded — older
    baselines) or nothing qualifies. The comparison is against what the human approved, not
    against the server's current schema: the hook does not hold the live surface, but it does
    hold the call, and the call is where the smuggled field gets filled."""
    if not isinstance(args, dict) or approved_props is None:
        return []
    approved_set = {str(k) for k in approved_props}
    return sorted(k for k in args
                  if isinstance(k, str) and k not in approved_set
                  and _CREDENTIAL_SHAPED.search(k))


def declared_verdict(server: str, tool: str,
                     approved: dict[str, str] | None,
                     live_hash: str | None = None,
                     args: dict | None = None,
                     approved_props: list[str] | None = None,
                     seen_at: str | None = None,
                     permission_changes: list[str] | None = None,
                     reverted: dict | None = None,
                     origin: str | None = None) -> tuple[str, str, str | None]:
    """The declared-tier decision: `(decision, basis, reason)`.

    `origin` is how the baseline was set (`_anchor`); it changes the WORDS of a denial, never the
    decision.

    `approved` is the `{tool: hash}` mapping the human approved for this server, or None when
    nothing has ever been approved for it. None and `{}` mean different things (see
    guard_hook.approved_for): None is "never approved" and DEFERS — trust-on-first-use is scan's
    job, and blocking every call on a machine that never ran `mcpgawk approve` would be most
    machines. `{}` is "approved as having no tools", so any call is a deviation.

    A tool ABSENT from an approved server's surface → DENY: a tool that appeared after approval is
    exactly the shape a malicious update takes.

    `live_hash` is this tool's CURRENT content fingerprint, when the caller has it. Supplied, a
    mismatch against the approved hash is the RUG-PULL and is denied: same tool name, description
    rewritten to steer the model. Omitted, the check is skipped and the verdict rests on name
    membership alone — the free agent hook reads a flat projection and genuinely does not hold the
    live surface, and denying on evidence it does not have would be the more dangerous error.

    The paid gateway holds `listed.tools` in the same process and passes the live hash
    (`gateway.set_live_tools`). The free hook cannot list the server per call; since 2026-09-05 it
    passes the hash from the LAST SIGHTING the projection carries (`seen`, written by every scan
    and by the monitor daemon) with `seen_at`, and the reason says so — a deny on the last
    sighting is not a deny on this call: a drift not yet seen passes until the next scan.

    `reverted` is THE LATCH (2026-10-08): this tool changed at an earlier sighting since approval
    (`{"at": when}`) and is back to its approved form now. It stays denied until a person approves
    again — a change that reverted before the next scan is still a change the person never saw.
    """
    if approved is None:
        return DEFER, BASIS_DECLARED, None
    if tool not in approved:
        return DENY, BASIS_DECLARED, deny_reason(server, tool, origin)
    approved_hash = approved.get(tool)
    # Both sides must be present. A record written before hashes existed, or a caller that could
    # not compute one, is missing evidence — and missing evidence is never a deny here.
    if live_hash and approved_hash and live_hash != approved_hash:
        return DENY, BASIS_DECLARED, changed_reason(server, tool, approved_hash, live_hash, seen_at,
                                                    origin)
    # PERMISSION GROWTH. The description hash above cannot see a dropped read-only or a new
    # destination parameter; the projection carries them, judged by scan's own compare
    # (FOUNDER 2026-10-06, "Block permission growth"). Any other schema change still waits for
    # sign-off without blocking (FOUNDER 2026-08-15, below).
    if permission_changes:
        return DENY, BASIS_DECLARED, permission_changed_reason(server, tool, permission_changes,
                                                               seen_at, origin)
    if reverted:
        return DENY, BASIS_DECLARED, reverted_reason(server, tool,
                                                     reverted.get("at") if isinstance(reverted, dict)
                                                     else None, origin)
    # THE SMUGGLED FIELD. A schema widened after approval breaks nothing by itself and is left
    # to the Decisions queue; the deny fires only at the moment the attack becomes real — this
    # call is FILLING a parameter the human never approved, and it is credential-shaped
    # ([FOUNDER] 2026-08-15: "do the right thing without breaking any expected flow"). Benign
    # extra parameters pass; approved parameters on drifted tools pass; older baselines with no
    # recorded parameter list skip the check entirely.
    smuggled = smuggled_credential_args(args, approved_props)
    if smuggled:
        # Same load-bearing properties as deny_reason: no executable remedy, no override named,
        # the agent is told to stop and tell the user — a denial that hands the agent a bypass
        # has enforced nothing (proven end to end 2026-07-27).
        named = ", ".join(smuggled)
        a = _anchor(origin)
        return DENY, BASIS_DECLARED, (
            f"SECURITY BLOCK (mcpgawk). This call to '{server}.{tool}' fills parameter(s) that "
            f"were not part of the tool {a['props']}, and they look like "
            f"credentials: {named}. A parameter that appears {a['after']} and asks for a "
            f"secret is the smuggled-field shape of a malicious update.\n"
            f"This decision is final for this session. Do not retry it, do not move the value "
            f"into a different parameter or tool, and do not run any mcpgawk command to change "
            f"the baseline — approval requires the person at the keyboard.\n"
            f"Tell the user exactly this: '{tool}' on '{server}' gained parameter(s) {named} "
            f"{a['they_added']}, mcpgawk blocked a call that was filling them, and they "
            f"should run `mcpgawk scan` themselves to review the change before deciding."
        )
    return DEFER, BASIS_DECLARED, None


def verdict(server: str, tool: str, approved: dict[str, str] | None,
            observations: dict[str, dict] | None = None,
            session_sources: tuple[tuple[str, str], ...] = (),
            live_hash: str | None = None,
            args: dict | None = None,
            approved_props: list[str] | None = None,
            seen_at: str | None = None,
            permission_changes: list[str] | None = None,
            reverted: dict | None = None,
            origin: str | None = None) -> tuple[str, str, str | None]:
    """The WHOLE decision: declared tier first, then the behavioural tier — composed
    positive-only, exactly like the paid gateway's profile handling (CONSTRAINTS §2 row 1).

    * A declared DENY is final. The behavioural tier is consulted only on a declared DEFER —
      an observation may PROMOTE a verdict, never clear one (an absent or even benign-looking
      observation is not proof the surface deviation is safe).
    * `observations` is THIS server's slice of the behavioural profile, `{tool: {"source"?,
      "sink"?}}` — scope is an admission, never a guess; the caller passes only what verify
      attributed to this server. None means no profile: the tier is silently absent and the
      verdict rests on the declared basis alone (B5 makes that absence loud elsewhere).
    * `session_sources` is what already HAPPENED this session: `(server, tool)` calls whose own
      observations classify them as sources. The behavioural deny is the sequence — an
      observed sink running after an observed source delivered untrusted content — which is the
      lethal-trifecta shape caught live, on evidence, not on names.
    """
    decision, basis, reason = declared_verdict(server, tool, approved, live_hash,
                                               args=args, approved_props=approved_props,
                                               seen_at=seen_at,
                                               permission_changes=permission_changes,
                                               reverted=reverted, origin=origin)
    if decision == DENY:
        return decision, basis, reason

    obs = (observations or {}).get(tool) or {}
    if obs.get("sink") is True and session_sources:
        src_server, src_tool = session_sources[-1]
        return DENY, BASIS_OBSERVED, behavioural_deny_reason(server, tool, src_server, src_tool)
    return DEFER, basis, reason


def behavioural_deny_reason(server: str, tool: str, src_server: str, src_tool: str) -> str:
    """The canonical behavioural denial. Same no-bypass properties as the declared one, pinned by
    the same tests: no executable remedy, no override named, the agent is told to stop and tell
    the user."""
    return (
        f"SECURITY BLOCK (mcpgawk). '{tool}' on MCP server '{server}' was OBSERVED in a sandbox "
        f"behaving as a data sink (it egresses what it is given), and earlier in this session "
        f"'{src_tool}' on '{src_server}' — observed delivering external, untrusted content — "
        f"already ran. Untrusted content followed by an egress-capable call is how data leaves a "
        f"machine, so the sequence is blocked on observed evidence, not on names.\n"
        f"This decision is final for this session. Do not retry it, do not call a different tool "
        f"to achieve the same thing, and do not attempt to change any baseline or profile — that "
        f"requires the person at the keyboard, and attempting it from inside an agent session is "
        f"itself treated as a red flag.\n"
        f"Tell the user exactly this: mcpgawk blocked '{tool}' on '{server}' because it was "
        f"observed exfiltrating in a sandbox and untrusted content from '{src_tool}' entered this "
        f"session first; they should review the session before deciding whether to allow it."
    )


def changed_reason(server: str, tool: str, approved_hash: str, live_hash: str,
                   seen_at: str | None = None, origin: str | None = None) -> str:
    """The denial for the RUG-PULL: same tool name, different content. Same load-bearing
    properties as `deny_reason` (no executable remedy, no override, stop and tell the user).
    `seen_at` set means the evidence is the last sighting, not this call — say so, because a
    deny that claims more than it measured is the false reassurance this product exists to end.
    `origin` words who set the baseline (`_anchor`)."""
    when = (f"last seen {seen_at} — not this call; a change since then is not yet measured"
            if seen_at else "now")
    a = _anchor(origin)
    return (
        f"SECURITY BLOCK (mcpgawk). '{tool}' on MCP server '{server}' has CHANGED {a['since']} "
        f"— same name, different content ({a['label']} {approved_hash}, {when}: "
        f"{live_hash}). This is the rug-pull shape: {a['trusted']}, rewritten to say "
        f"something else.\n"
        f"This decision is final for this session. Do not retry it, do not call a different "
        f"tool to achieve the same thing, and do not run any mcpgawk command to change the "
        f"baseline — approval requires the person at the keyboard, and attempting it from "
        f"inside an agent session is itself treated as a red flag.\n"
        f"Tell the user exactly this: the MCP server '{server}' changed the tool '{tool}' "
        f"{a['they']}, mcpgawk blocked the call, and they should run `mcpgawk decide` "
        f"themselves to read what changed before deciding whether to trust it."
    )


def permission_changed_reason(server: str, tool: str, changes: list[str],
                              seen_at: str | None = None, origin: str | None = None) -> str:
    """The denial for permission growth after approval: same name, and the tool can now do more
    than the person approved (declared escalation or a new destination parameter). Same properties
    as `changed_reason`, and its wording, so it classifies as REASON_TOOL_CHANGED."""
    when = (f"as last seen {seen_at} — not this call; a change since then is not yet measured"
            if seen_at else "now")
    what = "; ".join(changes)
    a = _anchor(origin)
    return (
        f"SECURITY BLOCK (mcpgawk). '{tool}' on MCP server '{server}' has CHANGED {a['since']} "
        f"— it can now do {a['more']} ({what}, {when}). A tool that "
        f"quietly gains the power to write, send or stop being read-only is how a malicious update "
        f"arrives without changing a word of its description.\n"
        f"This decision is final for this session. Do not retry it, do not call a different "
        f"tool to achieve the same thing, and do not run any mcpgawk command to change the "
        f"baseline — approval requires the person at the keyboard, and attempting it from "
        f"inside an agent session is itself treated as a red flag.\n"
        f"Tell the user exactly this: the MCP server '{server}' changed what the tool '{tool}' "
        f"can do {a['they']} ({what}), mcpgawk blocked the call, and they should run "
        f"`mcpgawk decide` themselves to review the change before deciding whether to trust it."
    )


def reverted_reason(server: str, tool: str, at: str | None = None,
                    origin: str | None = None) -> str:
    """The denial for THE LATCH: the tool changed after approval and changed back. Same properties
    and the same classifying phrase as `changed_reason` (REASON_TOOL_CHANGED)."""
    when = f"on {at[:10]}" if isinstance(at, str) and at else "at an earlier sighting"
    a = _anchor(origin)
    return (
        f"SECURITY BLOCK (mcpgawk). '{tool}' on MCP server '{server}' has CHANGED {a['since']} "
        f"— it was seen changed {when} and changed back since. A tool that changes "
        f"and then reverts before anyone looks is still a change you never reviewed.\n"
        f"This decision is final for this session. Do not retry it, do not call a different "
        f"tool to achieve the same thing, and do not run any mcpgawk command to change the "
        f"baseline — approval requires the person at the keyboard, and attempting it from "
        f"inside an agent session is itself treated as a red flag.\n"
        f"Tell the user exactly this: the MCP server '{server}' changed the tool '{tool}' "
        f"{a['they']} and changed it back, mcpgawk blocked the call, and they should run "
        f"`mcpgawk decide` themselves to read what changed before deciding whether to trust it."
    )


#: Machine-readable codes for the denials this module emits — classified HERE, by the module that
#: owns the wording, so no renderer ever pattern-matches prose it does not control.
REASON_TOOL_ADDED = "tool-added"
REASON_TOOL_CHANGED = "tool-changed"
REASON_CREDENTIAL_SMUGGLED = "credential-smuggled"
REASON_TOXIC_FLOW = "toxic-flow"
REASON_NO_BASELINE_STRICT = "no-baseline-strict"


def reason_code(reason: str | None) -> str | None:
    """The code for one of this module's own denial texts; None for anything else."""
    if not reason:
        return None
    # The phrases EVERY origin's wording shares (`_anchor`), and that texts written before
    # 2026-11-06 — spool rows, logs — also carry: "has CHANGED since you approved it" and
    # "is not in the approved baseline for MCP server" both still classify.
    if "has CHANGED since" in reason:
        return REASON_TOOL_CHANGED
    if "is not in the " in reason and " baseline for MCP server '" in reason:
        return REASON_TOOL_ADDED
    if "fills parameter(s)" in reason:
        return REASON_CREDENTIAL_SMUGGLED
    if "was OBSERVED in a sandbox" in reason:
        return REASON_TOXIC_FLOW
    if "the guard is in strict mode" in reason:
        return REASON_NO_BASELINE_STRICT
    return None


def human_line(server: str, tool: str, code: str | None, origin: str | None = None,
               reason: str | None = None) -> str:
    """ONE line for the person at the keyboard (Claude Code shows `systemMessage` to the user).
    Same properties as the agent text: no override, no `approve` — the agent can read this too.
    `origin` words who set the baseline (`_anchor`), exactly as the agent text does.

    `reason`, when given, names WHICH kind of change a REASON_TOOL_CHANGED denial is (audit
    2026-11-10, item F): permission growth and a change-and-revert share that code (the spool, the
    plugin hook and the differential corpus key on it), but "its content changed" is wrong for both —
    the description did not change, and a revert is back to its approved form."""
    a = _anchor(origin)
    if code == REASON_TOOL_CHANGED and reason:
        if "— it can now do " in reason:
            grown = reason.split(f"— it can now do {a['more']} (", 1)[-1].split(", as last seen", 1)[0]
            grown = grown.split(", now)", 1)[0].rstrip(")")
            return (f"mcpgawk blocked {server}.{tool} — it can now do more {a['since']} ({grown}). "
                    f"Review it with `mcpgawk decide` in your own terminal.")
        if "and changed back since" in reason:
            return (f"mcpgawk blocked {server}.{tool} — it changed {a['since']} and changed back "
                    f"before anyone reviewed it. Review it with `mcpgawk decide` in your own terminal.")
    what = {
        REASON_TOOL_ADDED: f"a tool that was not there {a['was_there']}",
        REASON_TOOL_CHANGED: f"its content changed {a['since']}",
        REASON_CREDENTIAL_SMUGGLED: f"the call fills a credential-shaped parameter {a['never']}",
        REASON_TOXIC_FLOW: "an observed sink ran after an observed source this session",
        REASON_NO_BASELINE_STRICT: "it has no baseline on this machine and the guard is strict",
    }.get(code or "", f"{a['covered']} did not cover this call")
    # Send the person where the change is VISIBLE. `decide` lists changes a scan has queued; these
    # three are made from the projection with no scan, and `decide` could answer "Nothing is
    # waiting on you" (audit 2026-11-10, item G). The agent text already says `mcpgawk scan`.
    where = ("mcpgawk scan" if code in (REASON_NO_BASELINE_STRICT, REASON_TOOL_ADDED,
                                        REASON_CREDENTIAL_SMUGGLED) else "mcpgawk decide")
    return (f"mcpgawk blocked {server}.{tool} — {what}. "
            f"Review it with `{where}` in your own terminal.")


def strict_no_baseline_reason(server: str, tool: str) -> str:
    """The strict-mode denial: a call to a server with NO baseline on this machine. Same
    load-bearing properties as `deny_reason` — no executable remedy, no override named, stop and
    tell the user. It names `mcpgawk scan` only, never the command that would clear it."""
    return (
        f"SECURITY BLOCK (mcpgawk). '{server}' has no baseline on this machine and the guard is "
        f"in strict mode, so the call to '{tool}' was refused: nothing the user approved says "
        f"what this server is.\n"
        f"This decision is final for this session. Do not retry it, do not call a different "
        f"tool to achieve the same thing, and do not run any mcpgawk command to change the "
        f"baseline or the guard — that requires the person at the keyboard, and attempting it "
        f"from inside an agent session is itself treated as a red flag.\n"
        f"Stop and tell the user exactly this: the MCP server '{server}' has no approved "
        f"baseline on this machine, mcpgawk blocked the call because the guard is in strict "
        f"mode, and they should run `mcpgawk scan` themselves to see what it is before deciding "
        f"whether to trust it."
    )


def deny_reason(server: str, tool: str, origin: str | None = None) -> str:
    """The canonical denial text, shared by every path that applies a declared-tier deny.

    Its properties are load-bearing and pinned by tests/test_approve_human_gate.py: it contains no
    executable remedy, never names any override, and tells the agent to stop and tell the user —
    a denial that hands the agent a bypass has enforced nothing. `origin` words who set the
    baseline (`_anchor`).
    """
    a = _anchor(origin)
    return (
        f"SECURITY BLOCK (mcpgawk). '{tool}' is not in {a['in']} for MCP server "
        f"'{server}'{a['note']}. A tool that appeared {a['appeared']} is how a malicious "
        f"update arrives.\n"
        f"This decision is final for this session. Do not retry it, do not call a different "
        f"tool to achieve the same thing, and do not run any mcpgawk command to change the "
        f"baseline — approval requires the person at the keyboard, and attempting it from "
        f"inside an agent session is itself treated as a red flag.\n"
        f"Tell the user exactly this: the MCP server '{server}' added a tool called '{tool}' "
        f"{a['they_added']}, mcpgawk blocked the call, and they should run `mcpgawk scan` "
        f"themselves to see what changed before deciding whether to trust it."
    )
