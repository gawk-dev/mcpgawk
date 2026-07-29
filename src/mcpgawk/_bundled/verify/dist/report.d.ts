import type { Severity } from "@gawk/oracle";
import type { CheckError, HiddenTool, ServerReport, Transport } from "./model.js";
import type { Drift } from "./pins.js";
import { type SuppressionsFile } from "./suppressions.js";
/** 1.2 (2026-07-14): added `checkErrors`/`summary.checkErrors` — see {@link CheckError}'s
 * docstring in model.ts for the incident that made this necessary. */
export declare const REPORT_SCHEMA_VERSION = "1.2";
/**
 * The honest coverage boundary of the current sandbox backend. Egress-based checks observe HTTP(S)
 * traffic routed through the proxy; a target that exfiltrates over a RAW socket / DNS / UDP is NOT
 * observed and will read as "no egress". Adversary-proof coverage needs an OS-level sandbox
 * (netns/gVisor) that denies all egress by default. We say this rather than overclaim "clean".
 */
export declare const EGRESS_COVERAGE: string;
/** The strong claim, only true when EVERY local server actually ran under the Docker backend. */
export declare const DOCKER_COVERAGE: string;
/** The ADR-0014 claim: isolation AND observation in the same run — the strongest coverage. */
export declare const PROXIED_COVERAGE: string;
/** Transparent, re-derivable status: worst severity present decides it — EXCEPT `incomplete`, which
 * means the server could not be fully verified (a dynamic-dispatch server whose hidden catalog was
 * not enumerated) and so must NOT read as `clean`. Precedence: vulnerable > at-risk > incomplete >
 * clean. `incomplete` is a coverage verdict, not a severity — it says "not proven wrong, but not
 * fully checked either", the same spirit as a run with checkErrors. */
export type Status = "clean" | "at-risk" | "vulnerable" | "incomplete";
export interface ReportFinding {
    readonly findingId: string;
    readonly code: string;
    readonly class: string;
    readonly severity: Severity;
    readonly tool: string;
    readonly reproOk: number;
    readonly reproTotal: number;
    readonly evidence: Record<string, unknown>;
    /** A reviewed, explicitly accepted finding — still REPORTED (never hidden), but excluded from
     * `status`/`bySeverity`/the CI exit code. See suppressions.ts. */
    readonly suppressed: boolean;
    readonly suppressionReason?: string;
}
export interface ReportServer {
    readonly server: string;
    readonly transport: Transport;
    readonly status: Status;
    readonly toolsChecked: number;
    readonly checksRun: readonly string[];
    readonly findings: readonly ReportFinding[];
    readonly skipped: ReadonlyArray<{
        readonly tool: string;
        readonly class: string;
    }>;
    /** Checks that hit infra noise on every attempt and never reached a verdict — NOT the same as
     * clean. See {@link CheckError}. */
    readonly checkErrors: readonly CheckError[];
    /** Inventory drift vs a baseline (rug-pull) — present only when a baseline was provided. */
    readonly drift?: Drift;
    /** Which sandbox actually enforced no-egress for this server's checks (see {@link ServerReport}). */
    readonly sandboxBackend: "proxied-container" | "docker" | "proxy" | "none";
    /** Set only when sandboxBackend is "proxy" because Docker was attempted and unavailable/unusable. */
    readonly sandboxDegradedReason?: string;
    /** Meta-tool name(s) that make this a dynamic-dispatch server — a larger real catalog is hidden
     * behind them and was NOT enumerated. Non-empty forces status `incomplete` (never `clean`). */
    readonly dynamicDispatch?: readonly string[];
    /** The hidden catalog enumerated via the discover meta-tool — the tools the static scan missed. */
    readonly hiddenCatalog?: readonly HiddenTool[];
    /** Which hidden tools were behaviourally probed through the executor (F4). The server is `clean`
     * only when this covers the whole {@link hiddenCatalog}; otherwise it stays `incomplete`. */
    readonly hiddenProbed?: readonly string[];
    /** True when the catalog came from a query-driven discover (partial, never exhaustive) — the
     * server can never be `clean`. See {@link ServerReport.hiddenCatalogPartial}. */
    readonly hiddenCatalogPartial?: boolean;
}
/** A server that couldn't be verified (unreachable, bad config, enumerate failed). */
export interface ReportError {
    readonly server: string;
    readonly message: string;
}
export interface VerificationReport {
    readonly schemaVersion: string;
    readonly tool: string;
    readonly generatedAt: string;
    readonly summary: {
        readonly servers: number;
        readonly toolsChecked: number;
        /** ACTIVE (non-suppressed) findings only — this is what decides `status` and the CI exit
         * code. Suppressed findings are never subtracted from the report, only from this count. */
        readonly findings: number;
        /** Reviewed, explicitly accepted findings — still visible in each server's `findings`
         * array, excluded from `findings`/`status`/`bySeverity`. See suppressions.ts. */
        readonly suppressed: number;
        readonly errors: number;
        /** Total checks (across all servers) that hit infra noise and never reached a verdict.
         * >0 here means the run is INCOMPLETE, not clean — check `status`/`findings` alongside this,
         * never in isolation. See {@link CheckError}. */
        readonly checkErrors: number;
        /** Number of servers hiding a larger tool catalog behind dynamic dispatch that was NOT
         * enumerated. >0 means the run is INCOMPLETE, not clean — same spirit as checkErrors. */
        readonly dynamicDispatch: number;
        readonly status: Status;
        readonly bySeverity: Record<Severity, number>;
    };
    readonly servers: readonly ReportServer[];
    /** Servers that could not be verified — the report is PARTIAL, not aborted. */
    readonly errors: readonly ReportError[];
    /** The honest coverage boundary of the egress checks (see {@link EGRESS_COVERAGE}). */
    readonly coverage: string;
}
/**
 * Cluster undeclared-egress findings by the host they reached, ordered ANOMALY-FIRST — a host
 * reached by the FEWEST tools ranks first. On a server with no `allowedHosts`, its own upstream
 * produces one finding per tool (16 tools → sentry.io); rendered as 16 separate HIGH lines that
 * buries the one host reached by a single hidden tool (the real outlier). Grouping by host with a
 * tool count, fewest-first, surfaces the outlier at the top. The individual findings are untouched
 * (machine formats keep them); this only drives the human report. Ties broken alphabetically.
 */
export declare function groupEgressByHost(egressFindings: readonly ReportFinding[]): Array<{
    host: string;
    tools: string[];
}>;
/** Worst severity → status. critical ⇒ vulnerable; high/medium ⇒ at-risk; else clean. */
export declare function statusOf(severities: readonly Severity[]): Status;
/** The three dispatch-coverage fields — shared by the raw {@link ServerReport} and the rendered
 * {@link ReportServer}, so the F4-4 rule is computed from one place on either shape. */
interface DispatchCoverage {
    readonly dynamicDispatch?: readonly string[];
    readonly hiddenCatalog?: readonly HiddenTool[];
    readonly hiddenProbed?: readonly string[];
    readonly hiddenCatalogPartial?: boolean;
}
/**
 * F4-4: would a would-be-clean dispatcher still be INCOMPLETE? True unless its WHOLE catalog was
 * enumerated AND behaviourally probed. Four honest cases:
 *   - not a dispatcher              → false (unaffected).
 *   - dispatcher, catalog empty     → true  (NOT-ENUMERABLE: no discover tool / unreadable listing).
 *   - dispatcher, catalog PARTIAL   → true  (query-driven semantic-search discover — never provably
 *                                     whole, so no amount of probing can clear it).
 *   - dispatcher, catalog complete  → true if ANY hidden tool went unprobed (no schema, or a
 *                                     safe-mode-skipped mutator).
 * Only a dispatcher whose entire, EXHAUSTIVELY-enumerated catalog was probed drops to a real clean.
 */
export declare function dispatchForcesIncomplete(s: DispatchCoverage): boolean;
/** Assemble the versioned report from the per-server results. Pure — pass the timestamp in.
 * `suppressions`, if given, marks reviewed findings as `suppressed` — still present in the
 * output (never hidden), excluded from status/severity-count/exit-code purposes only. */
export declare function buildReport(reports: readonly ServerReport[], generatedAt: string, driftByServer?: Record<string, Drift>, errors?: readonly ReportError[], suppressions?: SuppressionsFile): VerificationReport;
/** Flatten the report to CSV — one row per finding, suppressed included (empty but for the
 * header when clean). */
export declare function toCsv(report: VerificationReport): string;
export {};
//# sourceMappingURL=report.d.ts.map