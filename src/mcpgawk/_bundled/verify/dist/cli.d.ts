#!/usr/bin/env node
import { requireLicense } from "./license.js";
import { type ReportFinding, type VerificationReport } from "./report.js";
export declare function run(argv: readonly string[], log?: (message?: any, ...optionalParams: any[]) => void, err?: (message?: any, ...optionalParams: any[]) => void, licenseOpts?: Parameters<typeof requireLicense>[1]): Promise<number>;
/** Exit: 1 = actionable (findings/drift), 2 = partial (servers errored OR checks never completed,
 * none convicted — checkErrors deliberately weighed the same as a whole-server error: a report
 * with 0 findings and >0 checkErrors is NOT a clean pass, see model.ts's CheckError docstring),
 * 0 = clean. Exported as a pure function so this decision is directly unit-testable without
 * spawning a real server process. */
export declare function exitCode(report: VerificationReport, actionable: boolean): number;
/** The undeclared-egress cluster for the terminal, grouped by host and ordered ANOMALY-FIRST (a host
 * reached by the fewest tools ranks first). See {@link groupEgressByHost} for the rationale. */
export declare function egressClusterLines(egressFindings: readonly ReportFinding[]): string[];
//# sourceMappingURL=cli.d.ts.map