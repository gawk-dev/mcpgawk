import type { Severity } from "@gawk/oracle";
import type { EgressRecord } from "@gawk/sandbox";
/** What one sandboxed tool invocation produced — the raw material each check decides on. */
export interface Observation {
    /** Non-allowlisted egress the tool attempted (blocked + recorded by the sandbox). */
    readonly egress: readonly EgressRecord[];
    /** The tool's returned text content, concatenated. */
    readonly resultText: string;
}
export interface CheckDecision {
    readonly reproduced: boolean;
    readonly detail: string;
    readonly evidence?: Record<string, unknown>;
}
/** A behavioural vulnerability class: how to probe a tool and how to decide it's vulnerable. */
export interface VulnCheck {
    readonly code: string;
    readonly findingClass: string;
    readonly severity: Severity;
    /** Short label for reports (e.g. "EXFIL"). */
    readonly label: string;
    /** One-line, plain-English description of what this check catches (shown in the audit UI). */
    readonly detects: string;
    /**
     * What the check observes. `sandboxed` needs the server in our no-egress sandbox (egress-based —
     * LOCAL servers only). `output` only inspects the tool's returned output, so it also works on
     * REMOTE hosted servers over HTTP/SSE (which cannot be sandboxed).
     */
    readonly applicability: "sandboxed" | "output";
    /** Probe args for this check, built from the tool's inputSchema. */
    args(inputSchema: unknown): Record<string, unknown>;
    /** Decide from one attempt's observation whether the vuln reproduced. */
    decide(obs: Observation): CheckDecision;
}
/** A non-allowlisted host we plant in tool inputs to detect input-driven fetches (SSRF). */
declare const SSRF_CANARY = "gawk-ssrf-canary.invalid";
/**
 * Agent-directed instructions that should never appear in a tool's OUTPUT — the payload of a
 * tool-poisoning / rug-pull attack (the description can be clean while the runtime output hijacks
 * the calling agent). Patterns follow the publicly documented MCP tool-poisoning techniques.
 */
declare const INJECTION_MARKERS: readonly RegExp[];
export declare const CHECKS: readonly VulnCheck[];
export { SSRF_CANARY, INJECTION_MARKERS };
//# sourceMappingURL=checks.d.ts.map