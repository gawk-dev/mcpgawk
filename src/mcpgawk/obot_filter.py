"""mcpgawk's verdict, delivered inside the Obot gateway's request-filter slot.

Obot (and Lasso, and every gateway that follows them) ships the plumbing for free: it already sits
in the request path and already calls out to a filter before forwarding a tool call. What it does
not have is a reason to say no. That is the whole of this module — the same decision core the
free hook and the paid proxy both run, wearing the shape Obot's hook runner expects.

THE CONTRACT (read from obot main @ 8da1870: pkg/mcp/hookrunner.go, pkg/mcp/hooks.go,
pkg/api/handlers/mcpgateway/proxy_hooks.go). Four properties of it drive most of the code below:

  1. Obot calls a filter with ONE argument, a serialized SessionMessageHook whose `message` is the
     raw JSON-RPC envelope. It does NOT say which server the call is headed for — backend.go calls
     that omission deliberate. Our verdicts are keyed server+tool, so the operator supplies the
     key (MCPGAWK_SERVER) and runs one filter instance per guarded server. We never guess: a
     missing key is reported as unevaluated, not treated as any particular server.
  2. `accept` must be explicit. Go decodes an absent field to false, so a verdict that forgets it
     REJECTS the call.
  3. A response Obot cannot parse — no structuredContent, text that is not a JSON object — is
     silently treated as accept. Their gateway is fail-CLOSED on our errors but fail-OPEN on our
     malformed answers, so this module never raises out of `evaluate`: it answers, always, in the
     shape, and says when it failed.
  4. `message` is discarded unless `mutated` is true, and the original bytes pass through. We
     never echo the payload back (the hook body cap is 10 MB) and we never mutate — v1 rules on
     calls, it does not rewrite them.
  5. THE PAYLOAD CARRIES NO SESSION IDENTITY, and this is a decision of theirs, not an oversight
     we can configure around. `SessionMessageHook` declares four fields and none is an identity
     (hooks.go:54-59); `hookrunner.go:56` passes the struct with no `Meta`; nothing per-request
     reaches the filter as a header, URL or query param either. Obot HAS the stable value — it
     resolves `Mcp-Session-Id` at proxy_hooks.go:108 — and routes it only to the audit recorder
     and the cross-replica correlation store. Measured on the pinned digest as well as read from
     source: scripts/e2e-obot/probe_session_identity.py, and the E2E fails if it ever changes.
     The consequence is property 6 below, and the reason `_sequence_gap` exists.
  6. A BEARER ON THE HOOK CALL IS NOT THE CALLER'S IDENTITY. Read from source: Obot can mint a JWT
     for the hook session (client.go:109-131) carrying `server.UserID`, and that session is cached
     across every user and every client session — the cache key deliberately blanks the user
     (manager.go:454-458, :479-481) and the scope is one constant string. MEASURED, and the two do
     not agree in the obvious way: at the pinned digest, in a local unauthenticated run, NO
     `authorization` header reached the filter at all (the dump carries accept, content-type,
     host, mcp-*, user-agent, x-forwarded-*, and nothing else) — presumably because `server.UserID`
     is empty there. So the honest statement is conditional: WHEN a bearer is presented it
     identifies whoever created the cached session, not the caller. Either way a filter must never
     read it as "who is calling". We do not read it, and principal-aware work must not start by
     trusting it.

WHAT WE DO NOT DO: the free decision core denies or defers, and never returns "allow" — a machine
that has approved nothing must not have every call blocked by a guard it never configured. Obot
needs a boolean, so a defer becomes accept — and the honesty moves into the reason, which
distinguishes "checked this against an approved baseline and found nothing adverse" from
"UNEVALUATED", every time. An accept that cannot tell those apart reads as protection that isn't
there.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import decision as decision_core, guard_hook, spool

#: The adapter name in the shared decision record. One name, so the panel, `status` and any
#: export can tell a gateway-side ruling from the client-side hook without inspecting anything.
ADAPTER = "obot-filter"

#: What Obot must call. Configured as the filter's "Filter Tool Name" when the operator registers
#: the server; named for the product (mcpgawk, never `gawk` — that binary is GNU AWK).
TOOL_NAME = "mcpgawk_guard"

_UNEVALUATED = "UNEVALUATED by mcpgawk"


def _verdict(accept: bool, reason: str) -> dict[str, Any]:
    """The wire shape, built in exactly one place so no path can omit `accept` (property 2) or
    drift into something Obot parses as a pass (property 3)."""
    return {"accept": accept, "mutated": False, "reason": reason}


def _out_of_scope(what: str) -> dict[str, Any]:
    # Accepted even under fail_closed: this traffic was never ours to rule on, and blocking it
    # would break the gateway for every client while gaining nothing. v1 judges request-direction
    # tools/call; operators are told to narrow the selector to that anyway.
    return _verdict(True, f"mcpgawk: {what} — out of scope for this filter, passed unjudged")


def _unevaluated(cause: str, *, fail_closed: bool) -> dict[str, Any]:
    return _verdict(not fail_closed, f"{_UNEVALUATED}: {cause}")


def evaluate(hook_input: dict[str, Any], *, server: str | None = None,
             store_path: str | Path | None = None, fail_closed: bool | None = None,
             record: bool = True, spool_path: str | None = None) -> dict[str, Any]:
    """Rule on one hook invocation. Returns Obot's `{accept, mutated, reason}`.

    `server` is the baseline key this filter instance guards (defaults to $MCPGAWK_SERVER).
    `fail_closed` defaults to $MCPGAWK_FILTER_FAIL_CLOSED: off, matching the free hook's stance
    that an unconfigured guard must not block a machine, and available for operators who would
    rather stop traffic than pass it unproven.
    """
    if fail_closed is None:
        fail_closed = os.environ.get("MCPGAWK_FILTER_FAIL_CLOSED", "").strip().lower() in (
            "1", "true", "yes", "on")
    try:
        return _evaluate(hook_input, server, store_path, fail_closed, record, spool_path)
    except Exception as exc:                       # noqa: BLE001 - property 3: never leak a raise
        # A raise would reach Obot as a filter error and block the call (their fail-closed path),
        # or worse, a partial write would hit the fail-open corner. Answer in the shape and name
        # the failure, so an operator reading the trail sees OUR breakage, not a verdict.
        return _verdict(not fail_closed,
                        f"mcpgawk filter failed to evaluate this call ({type(exc).__name__}: "
                        f"{exc}) — {'blocked' if fail_closed else 'passed unjudged'}")


def _evaluate(hook_input: dict[str, Any], server: str | None,
              store_path: str | Path | None, fail_closed: bool,
              record: bool, spool_path: str | None) -> dict[str, Any]:
    if not isinstance(hook_input, dict):
        return _out_of_scope("no hook payload")
    message = hook_input.get("message")
    if not isinstance(message, dict):
        return _out_of_scope("no JSON-RPC message in the hook payload")

    # Response-direction messages carry result/error instead of params. Obot re-attaches `method`
    # to responses, so the method alone does not tell the two apart.
    if "result" in message or "error" in message:
        return _out_of_scope("a response, not a request")
    if message.get("method") != "tools/call":
        return _out_of_scope(f"{message.get('method')!r} is not a tool call")

    params = message.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        return _out_of_scope("a tools/call with no tool name")
    tool = params["name"]
    arguments = params.get("arguments")

    if server is None:
        server = (os.environ.get("MCPGAWK_SERVER") or "").strip() or None
    if not server:
        # Property 1. Guessing from the tool name would attach some other server's baseline to
        # this traffic — a verdict computed against the wrong evidence is worse than none.
        return _unevaluated(
            "this filter instance is not mapped to a server. Obot does not tell a filter which "
            "server a call is headed for, so set MCPGAWK_SERVER to the baseline key this "
            "instance guards and attach it to that server with a server-name selector.",
            fail_closed=fail_closed)

    # The decision core takes an agent-shaped event, so the pair is encoded into the wire name the
    # agents use and parsed straight back out. Real store keys survive that trip (`mcp:vault-rag`,
    # `mcp:BrowserStack MCP Server#3cb4da84649c`, `stdio:local` — colons, spaces and # are all
    # fine), but `__` is the separator itself: a server named `a__b` calling `c` encodes to a name
    # that re-reads as server `a`, tool `b__c`. That silently consults a DIFFERENT server's
    # baseline and then reports "no approved baseline", which is both false and useless advice.
    # So the round-trip is verified, never assumed, and a name we cannot express says exactly that.
    tool_name = f"mcp__{server}__{tool}"
    if guard_hook.parse_mcp_tool_name(tool_name) != (server, tool):
        return _unevaluated(
            f"the pair (server {server!r}, tool {tool!r}) cannot be expressed unambiguously — "
            f"'__' separates the two halves, so this call was NOT looked up against any baseline. "
            f"Re-key the server without '__' (`mcpgawk scan` shows its key) and set MCPGAWK_SERVER "
            f"to that.", fail_closed=fail_closed)

    event = {"tool_name": tool_name,
             "tool_input": arguments if isinstance(arguments, dict) else {}}
    output, note, basis, checked, _reason = guard_hook._decide(
        event, Path(store_path) if store_path is not None else None, "claude")

    if output is not None:
        reason = _for_gateway(_deny_reason(output) or f"mcpgawk denied {server}/{tool}")
        return _record(_verdict(False, reason), server, tool, "deny", basis, reason,
                       record, spool_path)

    if checked:
        # WHICH TIERS ACTUALLY RAN. The declared tier (is this tool in the approved surface?) runs
        # here exactly as it does in the client hook. The behavioural SEQUENCE tier does not: it
        # needs to know which calls came earlier in the SAME session, and Obot hands a filter no
        # session identity at all. So a source→sink flow that the client hook denies on the
        # `observed` basis is invisible from inside the gateway — proven side by side, same
        # fixtures, 2026-08-26.
        #
        # That gap was then MEASURED rather than left as a reading (property 5): every field of
        # every invocation dumped off the pinned digest, and nothing is both stable within a
        # client session and different in the next. The nearest candidate, the JSON-RPC id, goes
        # 2 then 4 inside one session and resets to 2 in the following one, so keying on it would
        # both lose history and collide across callers. This sentence stays until the E2E's
        # tripwire goes red.
        #
        # Saying "no adverse finding" for that call would be the worst sentence this filter could
        # emit: our strongest reassurance, on precisely the attack our own engine catches. So an
        # accept states the tier it rests on, and names the one that could not run.
        gap = _sequence_gap(server, tool)
        reason = (f"mcpgawk: evaluated {server}/{tool} against the approved baseline — "
                  f"no adverse finding (basis: {basis})")
        if gap:
            reason = (f"mcpgawk: {server}/{tool} matches the approved baseline (basis: {basis}), "
                      f"but this is a PARTIAL check — {gap}")
        return _record(_verdict(True, reason), server, tool, "allow", basis, reason,
                       record, spool_path)

    # Deferred without checking anything. `note` is the core's own loud stand-down (a baseline it
    # cannot interpret, an ambiguous alias); when it is silent the cause is simply that this
    # machine holds no approved surface for the server.
    cause = note or (f"no approved baseline for {server!r} on this machine — run `mcpgawk scan` "
                     f"and approve it, or mount the operator's ~/.mcpgawk into this filter")
    verdict = _unevaluated(cause, fail_closed=fail_closed)
    return _record(verdict, server, tool, "defer", basis, verdict["reason"], record, spool_path)


#: The core's block text ends by telling the agent what to say to its user, and that instruction
#: assumes the CLIENT-side deployment, where the approval store sits on the caller's own machine.
#: Through a gateway it does not: the store lives on the gateway host, and neither the agent nor
#: the person driving it can run `mcpgawk scan` against it. The finding itself stays exactly as the
#: core wrote it — only the remedy is corrected, and by ADDITION, so nothing specific is lost.
_TELL_MARKER = "Tell the user exactly this:"

_GATEWAY_NOTE = (
    "\nWhere to act, in this deployment: the approval store is on the GATEWAY host, not on the "
    "machine running this agent. Running mcpgawk locally changes nothing here — the gateway "
    "operator is the one who reviews the change and re-approves the server.")


def _for_gateway(reason: str) -> str:
    """The core's deny, with its client-side remedy corrected for a gateway deployment."""
    return reason + _GATEWAY_NOTE if _TELL_MARKER in reason else reason


def _sequence_gap(server: str, tool: str) -> str | None:
    """The sentence naming the tier that could not run here, or None when nothing is missing.

    Two distinct absences, said differently, because the operator's next action differs:
      * a behavioural profile exists and THIS tool is a sink — the sequence check is the one that
        would have caught a source→sink flow, and it is blind here;
      * no behavioural profile on this host at all — the whole observed tier is absent, which is a
        `mcpgawk verify` away.
    """
    behaviour = guard_hook._load_behaviour()
    if behaviour is None:
        return ("no behavioural profile on this host, so ONLY the approved tool list was checked. "
                "Run `mcpgawk verify` where this filter runs to add the observed tier.")
    observations = behaviour.get(server)
    if not isinstance(observations, dict):
        return (f"no behavioural profile for {server!r} on this host, so ONLY its approved tool "
                f"list was checked. Run `mcpgawk verify {server}` where this filter runs.")
    if (observations.get(tool) or {}).get("sink") is True:
        return ("this tool is a known SINK and the behavioural sequence check could NOT run: the "
                "gateway gives the filter no session identity, so earlier calls in this agent's "
                "session are invisible here. A source-then-sink flow that the mcpgawk client hook "
                "denies would NOT be caught at this gateway.")
    return None


def _deny_reason(output: dict[str, Any]) -> str | None:
    """Pull the sentence out of the agent-shaped deny payload the core hands back."""
    specific = output.get("hookSpecificOutput")
    if isinstance(specific, dict):
        text = specific.get("permissionDecisionReason")
        if isinstance(text, str) and text:
            return text
    for key in ("permissionDecisionReason", "user_message", "agent_message", "message"):
        text = output.get(key)
        if isinstance(text, str) and text:
            return text
    return None


def _record(verdict: dict[str, Any], server: str, tool: str, decision: str, basis: str,
            reason: str, record: bool, spool_path: str | None) -> dict[str, Any]:
    """Every call we RULED on goes into the shared decision log; traffic we passed unjudged does
    not, because a gateway sees every method and burying the rulings would defeat the trail."""
    if record:
        spool.record_decision(server=server, tool=tool, decision=decision, adapter=ADAPTER,
                              reason=reason, basis=basis, path=spool_path,
                              reason_code=decision_core.reason_code(reason) if decision == "deny" else None)
    return verdict
