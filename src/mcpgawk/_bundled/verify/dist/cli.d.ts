#!/usr/bin/env node
import type { requireLicense } from "./license.js";
import { type ReportFinding, type VerificationReport, buildReport } from "./report.js";
export declare function run(argv: readonly string[], log?: (message?: any, ...optionalParams: any[]) => void, err?: (message?: any, ...optionalParams: any[]) => void, licenseOpts?: Parameters<typeof requireLicense>[1]): Promise<number>;
/** Exit: 1 = actionable (findings/drift), 2 = incomplete (servers errored, checks never completed,
 * nothing exercised, or a hidden catalog not fully probed — nothing can be claimed), 0 = clean.
 *
 * DERIVED from `summary.status` via {@link exitCodeForStatus} — never computed independently. Until
 * 2026-08-02 this function re-derived its own answer from a different set of fields, so `incomplete`
 * could exit 0 and `clean` could exit 2: no single output field was trustworthy alone. `actionable`
 * (findings OR baseline drift) is the one input `status` cannot see, and it only ever escalates. */
export declare function exitCode(report: VerificationReport, actionable: boolean): number;
/** The undeclared-egress cluster for the terminal, grouped by host and ordered ANOMALY-FIRST (a host
 * reached by the fewest tools ranks first). See {@link groupEgressByHost} for the rationale. */
export declare function egressClusterLines(egressFindings: readonly ReportFinding[]): string[];
/** The human-readable terminal report (default output when --json is not given). Exported so the
 * prose can be asserted against the other renderers in one cross-artefact agreement test — the
 * surfaces disagreeing with each other is the defect this file was fixed for. */
export declare function printText(report: ReturnType<typeof buildReport>, log: (s: string) => void): void;
//# sourceMappingURL=cli.d.ts.map