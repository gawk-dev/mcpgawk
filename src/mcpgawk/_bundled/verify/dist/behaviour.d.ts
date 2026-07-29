import type { VerificationReport } from "./report.js";
/**
 * Behavioural source/sink profile (B4) — the bridge from VERIFY's observations to ENFORCE's
 * toxic-flow gate. VERIFY runs each tool in a no-egress sandbox and reproduces findings; this maps
 * those findings to the role they behaviourally evidence, so the enforce gate can classify a tool by
 * what it DID rather than its attacker-chosen name (see src/gawk_platform/detectors/behaviour.py,
 * which reads this exact `gawk.behaviour/1` shape):
 *
 *   - `undeclared-egress` / `server-side-request-forgery` → the tool can exfiltrate → **sink**
 *   - `output-prompt-injection` → the tool delivers injected content to the agent → **source**
 *
 * Positive-only: a role appears only when VERIFY REPRODUCED the finding. A tool with no finding is
 * absent, and its absence is not a claim of safety — the consumer falls back to the name heuristic.
 */
export interface BehaviourProfileDoc {
    readonly schema: "gawk.behaviour/1";
    readonly servers: Record<string, Record<string, {
        source?: true;
        sink?: true;
    }>>;
}
export declare function behaviourProfile(report: VerificationReport): BehaviourProfileDoc;
//# sourceMappingURL=behaviour.d.ts.map