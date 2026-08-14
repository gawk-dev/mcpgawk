/**
 * Classify a tool as read / mutating / unknown to decide whether safe mode may INVOKE it.
 *
 * Safety design (this is the load-bearing part):
 *  - The decision to CALL a tool is name-driven — a leading/known read verb with NO mutating verb
 *    anywhere in the name. A server cannot make a tool *more* callable by lying.
 *  - Annotations (`readOnlyHint`/`destructiveHint`) are attacker-controlled, so they may only
 *    RESTRICT: `destructiveHint:true` forces mutating; `readOnlyHint:false` vetoes a read. They can
 *    never turn a mutating/unknown tool into a callable one.
 *  - RESTRICTION REQUIRES INFORMATION ([FOUNDER] 2026-08-14: "it is not what the kite server
 *    labels … it is our users security"): a server that stamps EVERY tool destructive (kite marks
 *    all 22 — get_ltp, get_profile, even search_instruments) is emitting noise, and blanket
 *    labels are exactly how a malicious server would evade behavioural verification while
 *    looking cautious. So a restricting annotation is honoured only when the server
 *    DISCRIMINATES — labels that never vary carry no information and no veto. Name-mutating
 *    tools stay uncallable regardless; this only stops noise from silencing name-reads.
 *  - Anything not confidently read is `unknown` and is NOT called in safe mode (default-deny).
 *
 * Residual risk (stated honestly): a tool with a deceptive read-looking name that actually mutates
 * would still be called. No purely client-side heuristic can rule that out — for a live account
 * with real funds, use a dedicated TEST/paper account. Safe mode reduces risk; it is not a proof.
 */
/** Verbs that change state or move money — if ANY appears in the name, the tool is mutating. */
const MUTATING = new Set([
    "place",
    "create",
    "update",
    "delete",
    "modify",
    "cancel",
    "remove",
    "buy",
    "sell",
    "transfer",
    "pay",
    "submit",
    "execute",
    "exec",
    "run",
    "drop",
    "purge",
    "kill",
    "revoke",
    "send",
    "post",
    "put",
    "patch",
    "write",
    "set",
    "edit",
    "deploy",
    "reset",
    "approve",
    "reject",
    "add",
    "insert",
    "upsert",
    "destroy",
    "terminate",
    "close",
    "open",
    "start",
    "stop",
    "enable",
    "disable",
    "move",
    "rename",
    "copy",
    "clone",
    "import",
    "upload",
    "trigger",
]);
/** Verbs that only read — a name needs one of these (and no mutating verb) to be callable. */
const READ = new Set([
    "get",
    "list",
    "search",
    "fetch",
    "read",
    "query",
    "describe",
    "show",
    "find",
    "lookup",
    "view",
    "status",
    "info",
    "count",
    "has",
    "is",
    "stat",
    "inspect",
    "peek",
    "preview",
    "check",
    "resolve",
]);
function tokens(name) {
    return name
        .split(/[^a-zA-Z0-9]+|(?<=[a-z0-9])(?=[A-Z])/)
        .filter(Boolean)
        .map((t) => t.toLowerCase());
}
/** Labels that never vary carry no information. Per SERVER, per axis: if every tool carries the
 * same restricting label (all `destructiveHint:true`, or all `readOnlyHint:false`), that axis is
 * noise and loses its veto. A single-tool server keeps its labels (nothing to vary against, and
 * caution costs one tool, not a fleet's coverage). Selective labels — a server that marks SOME
 * tools destructive — are real warnings and keep full force. */
export function annotationSignal(tools) {
    if (tools.length <= 1) {
        return { destructiveInformative: true, readOnlyVetoInformative: true };
    }
    const anns = tools.map((t) => t.annotations ?? {});
    return {
        destructiveInformative: !anns.every((a) => a.destructiveHint === true),
        readOnlyVetoInformative: !anns.every((a) => a.readOnlyHint === false),
    };
}
const FULLY_INFORMATIVE = {
    destructiveInformative: true,
    readOnlyVetoInformative: true,
};
export function classifyTool(tool, signal = FULLY_INFORMATIVE) {
    const a = tool.annotations ?? {};
    const ts = tokens(tool.name);
    // Restrict-only signals first — honoured only from a server whose labels discriminate.
    if (a.destructiveHint === true && signal.destructiveInformative) {
        return { klass: "mutating", callable: false };
    }
    if (ts.some((t) => MUTATING.has(t)))
        return { klass: "mutating", callable: false };
    // Callable only if a read verb is present AND an informative server did not veto the read.
    if (ts.some((t) => READ.has(t)) && !(a.readOnlyHint === false && signal.readOnlyVetoInformative)) {
        return { klass: "read", callable: true };
    }
    return { klass: "unknown", callable: false };
}
//# sourceMappingURL=classify.js.map