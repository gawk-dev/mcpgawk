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
/** What replaces every coverage CLAIM when the run did not complete. Deliberately contains none of
 * the strong-claim wording (no "BLOCKED", no "is recorded") — an incomplete run has established
 * nothing to make a claim about. Followed by the specific reasons and {@link EGRESS_COVERAGE}. */
export declare const INCOMPLETE_COVERAGE: string;
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
    /** Every check this server's verification INTENDED to perform (see {@link Completeness}). */
    readonly checksPlanned: number;
    /** The subset that produced a verdict either way. `< checksPlanned` ⇒ the server is INCOMPLETE. */
    readonly checksCompleted: number;
    /** Derived, never decided locally: `checksCompleted === checksPlanned` AND a tool was exercised
     * AND (dispatcher) the hidden catalog was fully enumerated+probed. `status` can only be `clean`
     * when this is true. */
    readonly complete: boolean;
    /** Why not complete — empty iff `complete`. Rendered by every human surface. */
    readonly incompleteReasons: readonly string[];
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
    /** Set when this server's restricting annotations were ignored as uninformative (blanket
     * labels, kite-style: every tool stamped destructive). Rendered by human surfaces so a
     * label-evading server can never look cautiously verified. */
    readonly labelNoiseNote?: string;
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
        /** Every check the whole run intended to perform. */
        readonly checksPlanned: number;
        /** The subset that produced a verdict. `< checksPlanned` ⇒ the run is INCOMPLETE. */
        readonly checksCompleted: number;
        /** THE field: every renderer and the exit code derive from this and {@link status}. */
        readonly complete: boolean;
        /** Why the run is not complete — empty iff `complete`. */
        readonly incompleteReasons: readonly string[];
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
/** Worst severity → status. critical ⇒ vulnerable; high/medium ⇒ at-risk; else clean.
 *
 * NOTE: severity ALONE can never decide a status — it cannot see whether anything was actually
 * checked. Use {@link deriveStatus}, which folds this together with {@link Completeness}. This is
 * exported only for the severity half and for direct unit tests of it. */
export declare function statusOf(severities: readonly Severity[]): Status;
/**
 * The ONE completeness derivation (remediation plan 1A). Everything downstream — `status`, the exit
 * code, the coverage sentence, prose, JSON, HTML, SARIF, JUnit — is a function of this, so no two
 * surfaces can disagree the way they did before 2026-08-02.
 *
 * `checksPlanned` is every check the run INTENDED to perform; `checksCompleted` is the subset that
 * produced a verdict either way. A check that hit infra noise (see {@link CheckError}) is planned
 * but NOT completed, so it can never be silently absorbed into a clean pass.
 */
export interface Completeness {
    readonly checksPlanned: number;
    readonly checksCompleted: number;
    readonly complete: boolean;
    /** Human-readable, machine-stable reasons the run/server is not complete. Empty iff complete. */
    readonly reasons: readonly string[];
}
/** Completeness for ONE server. A server is complete only when every check it planned produced a
 * verdict, at least one tool was actually exercised, and (for a dispatcher) its whole hidden
 * catalog was enumerated AND probed. */
export declare function serverCompleteness(r: DispatchCoverage & {
    readonly toolsChecked: number;
    readonly checkErrors: readonly CheckError[];
    readonly checksPlanned?: number;
    readonly checksCompleted?: number;
    readonly authIncomplete?: string;
}): Completeness;
/** Completeness for the WHOLE run: every server complete, at least one server, at least one tool
 * anywhere, and no server that failed outright. */
export declare function runCompleteness(servers: readonly ReportServer[], errors: readonly ReportError[]): Completeness;
/**
 * The single status algebra. Precedence is unchanged (vulnerable > at-risk > incomplete > clean) —
 * a reproduced finding still outranks incompleteness — but `clean` is now UNREACHABLE unless the
 * run/server is complete. Before this, `clean` was decided by severity alone, so any number of
 * failed checks (1 or 1000) still read as a clean pass.
 */
export declare function deriveStatus(severity: Status, completeness: Completeness): Status;
/** The ONLY exit-code derivation: a pure function of {@link Status}. 1 = actionable (a reproduced
 * finding), 2 = incomplete (nothing can be claimed), 0 = clean and complete. Before 1A this was
 * computed independently of `summary.status`, so `incomplete` could exit 0 and `clean` exit 2. */
export declare function exitCodeForStatus(status: Status): number;
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