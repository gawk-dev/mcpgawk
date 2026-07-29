/**
 * Classify a tool as read / mutating / unknown to decide whether safe mode may INVOKE it.
 *
 * Safety design (this is the load-bearing part):
 *  - The decision to CALL a tool is name-driven — a leading/known read verb with NO mutating verb
 *    anywhere in the name. A server cannot make a tool *more* callable by lying.
 *  - Annotations (`readOnlyHint`/`destructiveHint`) are attacker-controlled, so they may only
 *    RESTRICT: `destructiveHint:true` forces mutating; `readOnlyHint:false` vetoes a read. They can
 *    never turn a mutating/unknown tool into a callable one.
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
export function classifyTool(tool) {
    const a = tool.annotations ?? {};
    const ts = tokens(tool.name);
    // Restrict-only signals first.
    if (a.destructiveHint === true)
        return { klass: "mutating", callable: false };
    if (ts.some((t) => MUTATING.has(t)))
        return { klass: "mutating", callable: false };
    // Callable only if a read verb is present AND the server did not veto with readOnlyHint:false.
    if (ts.some((t) => READ.has(t)) && a.readOnlyHint !== false) {
        return { klass: "read", callable: true };
    }
    return { klass: "unknown", callable: false };
}
//# sourceMappingURL=classify.js.map