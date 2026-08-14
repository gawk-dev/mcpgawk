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
export interface AnnotationSignal {
    /** destructiveHint:true is honoured as a veto only when true. */
    readonly destructiveInformative: boolean;
    /** readOnlyHint:false is honoured as a veto only when true. */
    readonly readOnlyVetoInformative: boolean;
}
/** Labels that never vary carry no information. Per SERVER, per axis: if every tool carries the
 * same restricting label (all `destructiveHint:true`, or all `readOnlyHint:false`), that axis is
 * noise and loses its veto. A single-tool server keeps its labels (nothing to vary against, and
 * caution costs one tool, not a fleet's coverage). Selective labels — a server that marks SOME
 * tools destructive — are real warnings and keep full force. */
export declare function annotationSignal(tools: readonly {
    name: string;
    annotations?: ToolAnnotations;
}[]): AnnotationSignal;
export declare function classifyTool(tool: {
    name: string;
    annotations?: ToolAnnotations;
}, signal?: AnnotationSignal): Classification;
//# sourceMappingURL=classify.d.ts.map