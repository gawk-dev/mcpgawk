import { type Severity } from "@gawk/oracle";
import { type Sandbox } from "@gawk/sandbox";
import { type ServerConfig, type ServerReport, type Transport, type VerifyOptions } from "./model.js";
/** A step in the behavioural audit, emitted live so a UI can show the work as it happens. */
export type AuditEvent = {
    type: "server";
    server: string;
    transport: Transport;
    mode: "safe" | "unsafe";
} | {
    type: "enumerated";
    server: string;
    tools: ReadonlyArray<{
        name: string;
        description: string;
    }>;
} | {
    type: "skip";
    server: string;
    tool: string;
    klass: string;
} | {
    /**
     * F4: how the hidden catalog was enumerated. `mode: "query"` means a query-driven discover
     * tool was probed with keyword queries — PARTIAL by nature (never exhaustive), so the server
     * stays incomplete however much is probed. `mode: "listing"` means an empty call returned the
     * full catalog. `found` is the number of hidden tools surfaced.
     */
    type: "dispatch-enumeration";
    server: string;
    discover: string;
    mode: "query" | "listing";
    queries: number;
    found: number;
} | {
    /**
     * Docker is the required-for-full-protection sandbox: this fires whenever a local server
     * fell back to the weaker proxy-only sandbox instead, so the degradation is never silent.
     */
    type: "sandbox-degraded";
    server: string;
    reason: string;
} | {
    type: "check";
    server: string;
    tool: string;
    code: string;
    label: string;
    severity: Severity;
    outcome: "reproduced" | "clean" | "error";
    attemptsOk: number;
    attemptsRun: number;
    detail: string;
    evidence?: Record<string, unknown>;
} | {
    /**
     * Fires for EVERY reproduction attempt (not just ones that produce a finding) — the raw
     * evidence a check's `decide()` looked at to make its call. Added 2026-07-14 after a real
     * gap: a "clean" result previously left NO trace of what the tool actually returned, so a
     * human reviewing a clean report had nothing to verify the tool's own claim against —
     * "trust the verdict" instead of "here's the evidence, judge it yourself." `resultText` is
     * truncated (not full response bodies — those can be large and may contain the target's own
     * data) to keep this a spot-check trail, not a full data mirror.
     */
    type: "raw-observation";
    server: string;
    tool: string;
    code: string;
    attempt: number;
    ok: boolean;
    resultTextExcerpt?: string;
    egress?: readonly {
        host: string;
        allowed: boolean;
    }[];
    infraDetail?: string;
};
/**
 * Verify one MCP server behaviourally: enumerate its tools, then for each callable one run every
 * applicable vulnerability check — each driving the tool and reproduction-verifying (N/N).
 *
 * LOCAL (stdio) servers run inside a fresh no-egress sandbox, so ALL checks apply (exfil, SSRF,
 * tool-poisoning). REMOTE (HTTP/SSE) servers run on the provider's infrastructure and cannot be
 * sandboxed, so only OUTPUT-based checks apply (tool-poisoning) — the egress-based checks are
 * reported as not-run rather than faked.
 */
export declare function verifyServer(server: ServerConfig, opts?: VerifyOptions & {
    sandbox?: Sandbox;
    onEvent?: (e: AuditEvent) => void;
}): Promise<ServerReport>;
//# sourceMappingURL=verify.d.ts.map