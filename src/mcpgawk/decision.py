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


def content_hash(description: str | None) -> str:
    """The approved-surface fingerprint of one tool's model-visible text.

    MUST stay byte-identical to `drift._hash`, which writes the `{tool: hash}` map into the trust
    store — comparing against a differently-computed hash would deny every call on every server.
    `tests/test_rugpull_runtime.py` pins the two together.
    """
    import hashlib
    return hashlib.sha256((description or "").encode()).hexdigest()[:12]


def declared_verdict(server: str, tool: str,
                     approved: dict[str, str] | None,
                     live_hash: str | None = None) -> tuple[str, str, str | None]:
    """The declared-tier decision: `(decision, basis, reason)`.

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

    The paid gateway is not in that position: it holds `listed.tools` and the approved map in the
    SAME process, and passed neither. `mcpgawk scan` reported the rug-pull signature while the
    gateway allowed the call silently.
    """
    if approved is None:
        return DEFER, BASIS_DECLARED, None
    if tool not in approved:
        return DENY, BASIS_DECLARED, deny_reason(server, tool)
    approved_hash = approved.get(tool)
    # Both sides must be present. A record written before hashes existed, or a caller that could
    # not compute one, is missing evidence — and missing evidence is never a deny here.
    if live_hash and approved_hash and live_hash != approved_hash:
        return DENY, BASIS_DECLARED, (
            f"{server}.{tool} has CHANGED since you approved it — same name, different content "
            f"(approved {approved_hash}, now {live_hash}). This is the rug-pull shape: a tool you "
            f"trusted rewritten to say something else. Re-read it, then `mcpgawk approve {server}`."
        )
    return DEFER, BASIS_DECLARED, None


def verdict(server: str, tool: str, approved: dict[str, str] | None,
            observations: dict[str, dict] | None = None,
            session_sources: tuple[tuple[str, str], ...] = (),
            live_hash: str | None = None) -> tuple[str, str, str | None]:
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
    decision, basis, reason = declared_verdict(server, tool, approved, live_hash)
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


def deny_reason(server: str, tool: str) -> str:
    """The canonical denial text, shared by every path that applies a declared-tier deny.

    Its properties are load-bearing and pinned by tests/test_approve_human_gate.py: it contains no
    executable remedy, never names any override, and tells the agent to stop and tell the user —
    a denial that hands the agent a bypass has enforced nothing.
    """
    return (
        f"SECURITY BLOCK (mcpgawk). '{tool}' is not in the approved baseline for MCP server "
        f"'{server}'. A tool that appeared after this server was approved is how a malicious "
        f"update arrives.\n"
        f"This decision is final for this session. Do not retry it, do not call a different "
        f"tool to achieve the same thing, and do not run any mcpgawk command to change the "
        f"baseline — approval requires the person at the keyboard, and attempting it from "
        f"inside an agent session is itself treated as a red flag.\n"
        f"Tell the user exactly this: the MCP server '{server}' added a tool called '{tool}' "
        f"since they approved it, mcpgawk blocked the call, and they should run `mcpgawk scan` "
        f"themselves to see what changed before deciding whether to trust it."
    )
