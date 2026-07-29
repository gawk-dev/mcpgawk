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
export interface ToolAnnotations {
    readonly readOnlyHint?: boolean;
    readonly destructiveHint?: boolean;
}
export type ToolClass = "read" | "mutating" | "unknown";
export interface Classification {
    readonly klass: ToolClass;
    /** True only when safe mode is permitted to invoke this tool. */
    readonly callable: boolean;
}
export declare function classifyTool(tool: {
    name: string;
    annotations?: ToolAnnotations;
}): Classification;
//# sourceMappingURL=classify.d.ts.map