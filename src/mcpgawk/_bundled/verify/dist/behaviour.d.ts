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
/**
 * What a run OBSERVED about one server, recorded whether or not anything was found.
 *
 * Separate from `servers` on purpose. `servers` is a record of CONVICTIONS; this is a record of
 * OBSERVATION. Conflating them made a clean server indistinguishable from an unvisited one.
 */
export interface ServerObservation {
    /** Tools actually exercised. 0 means this run is evidence of nothing. */
    readonly toolsChecked: number;
    /** Tools deliberately NOT invoked. Their absence from `servers` is not a claim of safety. */
    readonly skipped: readonly string[];
    /** Checks that never reached a verdict. >0 alongside 0 findings is NOT "verified clean". */
    readonly checkErrors: number;
    /** Vuln-class codes that ran (remote servers can only run output-based checks). */
    readonly checksRun: readonly string[];
    /** Which sandbox actually ran it. "none" is the honest value for an unisolated run. */
    readonly backend: string;
}
export interface BehaviourProfileDoc {
    readonly schema: "gawk.behaviour/1";
    readonly servers: Record<string, Record<string, {
        source?: true;
        sink?: true;
    }>>;
    /**
     * Observation record, added 2026-07-30. ADDITIVE: `servers` keeps its exact shape and meaning,
     * so every existing reader (including gawk_platform/detectors/behaviour.py) is unaffected.
     * Readers that want "was this server actually looked at?" must consult THIS map — membership of
     * `servers` answers "was it convicted?", which is a different question and was being used for
     * both.
     */
    readonly verified?: Record<string, ServerObservation>;
}
export declare function behaviourProfile(report: VerificationReport): BehaviourProfileDoc;
/**
 * Merge a fresh profile over an existing one, replacing only the servers THIS run verified.
 *
 * Why merge exists: until 2026-07-29 the writer replaced the whole file, so a remote-only
 * front-door run that observed nothing WIPED every other server's recorded behaviour — observed
 * evidence, the product's most expensive asset, destroyed by an unrelated run. A verified server
 * is replaced even to empty (its old convictions may describe a server that has since been
 * fixed); an unverified server's entry is retained untouched.
 */
export declare function mergeBehaviourProfiles(existing: unknown, fresh: BehaviourProfileDoc, verified: ReadonlySet<string>): BehaviourProfileDoc;
//# sourceMappingURL=behaviour.d.ts.map