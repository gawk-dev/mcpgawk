import { isSuppressed } from "./suppressions.js";
/** 1.2 (2026-07-14): added `checkErrors`/`summary.checkErrors` — see {@link CheckError}'s
 * docstring in model.ts for the incident that made this necessary. */
export const REPORT_SCHEMA_VERSION = "1.2";
/**
 * The honest coverage boundary of the current sandbox backend. Egress-based checks observe HTTP(S)
 * traffic routed through the proxy; a target that exfiltrates over a RAW socket / DNS / UDP is NOT
 * observed and will read as "no egress". Adversary-proof coverage needs an OS-level sandbox
 * (netns/gVisor) that denies all egress by default. We say this rather than overclaim "clean".
 */
export const EGRESS_COVERAGE = "egress checks observe HTTP(S) only; raw-socket / DNS / UDP exfiltration is NOT detected by this " +
    "backend (needs the OS-level sandbox). A clean egress result is 'no HTTP exfiltration observed', not proof.";
/** The strong claim, only true when EVERY local server actually ran under the Docker backend. */
export const DOCKER_COVERAGE = "egress is enforced at the OS level (--network none): raw-socket / DNS / UDP exfiltration is " +
    "BLOCKED, not merely unobserved. This backend trades away visibility into WHAT a tool tried to " +
    "reach in exchange for that guarantee.";
/** The ADR-0014 claim: isolation AND observation in the same run — the strongest coverage. */
export const PROXIED_COVERAGE = "egress is enforced at the OS level AND observed: the target runs on an internal container " +
    "network whose only route out is the verifying egress proxy, so raw-socket / DNS / UDP " +
    "exfiltration is BLOCKED while every HTTP(S) destination — including the npx/uvx install " +
    "fetch — is recorded. A non-allowlisted host in this report was seen by the only possible " +
    "way out, not by a bypassable observer.";
/**
 * Cluster undeclared-egress findings by the host they reached, ordered ANOMALY-FIRST — a host
 * reached by the FEWEST tools ranks first. On a server with no `allowedHosts`, its own upstream
 * produces one finding per tool (16 tools → sentry.io); rendered as 16 separate HIGH lines that
 * buries the one host reached by a single hidden tool (the real outlier). Grouping by host with a
 * tool count, fewest-first, surfaces the outlier at the top. The individual findings are untouched
 * (machine formats keep them); this only drives the human report. Ties broken alphabetically.
 */
export function groupEgressByHost(egressFindings) {
    const byHost = new Map();
    for (const f of egressFindings) {
        const hosts = Array.isArray(f.evidence.egress) ? f.evidence.egress : [];
        for (const host of hosts) {
            const set = byHost.get(host) ?? new Set();
            set.add(f.tool);
            byHost.set(host, set);
        }
    }
    return [...byHost.entries()]
        .map(([host, tools]) => ({ host, tools: [...tools].sort() }))
        .sort((a, b) => a.tools.length - b.tools.length || a.host.localeCompare(b.host));
}
/** Worst severity → status. critical ⇒ vulnerable; high/medium ⇒ at-risk; else clean. */
export function statusOf(severities) {
    if (severities.includes("critical"))
        return "vulnerable";
    if (severities.some((s) => s === "high" || s === "medium"))
        return "at-risk";
    return "clean";
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
export function dispatchForcesIncomplete(s) {
    if ((s.dynamicDispatch?.length ?? 0) === 0)
        return false;
    const catalog = s.hiddenCatalog ?? [];
    if (catalog.length === 0)
        return true;
    if (s.hiddenCatalogPartial)
        return true;
    const probed = new Set(s.hiddenProbed ?? []);
    return !catalog.every((h) => probed.has(h.name));
}
/** Assemble the versioned report from the per-server results. Pure — pass the timestamp in.
 * `suppressions`, if given, marks reviewed findings as `suppressed` — still present in the
 * output (never hidden), excluded from status/severity-count/exit-code purposes only. */
export function buildReport(reports, generatedAt, driftByServer = {}, errors = [], suppressions) {
    const servers = reports.map((r) => {
        const findings = r.findings.map((f) => {
            const entry = suppressions ? isSuppressed(f.findingId, suppressions) : undefined;
            return {
                findingId: f.findingId,
                code: f.candidate.code,
                class: f.candidate.findingClass,
                severity: f.candidate.severity,
                tool: f.candidate.toolName ?? "",
                reproOk: f.reproOk,
                reproTotal: f.reproTotal,
                evidence: f.evidence,
                suppressed: entry !== undefined,
                suppressionReason: entry?.reason,
            };
        });
        const active = findings.filter((f) => !f.suppressed);
        const base = statusOf(active.map((f) => f.severity));
        // A dispatcher is INCOMPLETE unless its WHOLE hidden catalog was enumerated AND behaviourally
        // probed (F4-4) — a partially-probed dispatcher must never read as a clean pass. Real findings
        // (at-risk/vulnerable) still take precedence over incompleteness.
        // ...and a server where NOTHING was checked cannot be clean either. Safe mode skips every
        // not-read-only tool, so an all-mutating server (a common shape — writers, senders, deployers)
        // connected fine, had all its tools skipped, and still wore a green "clean" over an empty
        // examination. Found live 2026-07-27 verifying mcpgawk's OWN server: `toolsChecked: 0`,
        // 2 skipped, `status: "clean"`. The whole-run guard below already refused to call an
        // all-errored run clean; this is the same rule at the per-server level, which it did not cover.
        const nothingChecked = r.toolsChecked === 0;
        const status = base === "clean" && (dispatchForcesIncomplete(r) || nothingChecked) ? "incomplete" : base;
        return {
            server: r.server,
            transport: r.transport,
            status,
            toolsChecked: r.toolsChecked,
            checksRun: [...r.checksRun],
            findings,
            skipped: r.skipped.map((s) => ({ tool: s.tool, class: s.klass })),
            checkErrors: [...r.checkErrors],
            drift: driftByServer[r.server],
            sandboxBackend: r.sandboxBackend,
            sandboxDegradedReason: r.sandboxDegradedReason,
            dynamicDispatch: r.dynamicDispatch,
            hiddenCatalog: r.hiddenCatalog,
            hiddenProbed: r.hiddenProbed,
            hiddenCatalogPartial: r.hiddenCatalogPartial,
        };
    });
    const allFindings = servers.flatMap((s) => s.findings);
    const activeFindings = allFindings.filter((f) => !f.suppressed);
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of activeFindings)
        bySeverity[f.severity] += 1;
    // How many servers ARE dispatchers (factual count), and how many of those are still INCOMPLETE
    // because their catalog wasn't fully enumerated+probed (F4-4). Only the latter folds the overall
    // status to `incomplete`: a fully-probed dispatcher is a real clean, not a hedge.
    const dispatchServers = servers.filter((s) => (s.dynamicDispatch?.length ?? 0) > 0).length;
    const dispatchIncompleteServers = servers.filter(dispatchForcesIncomplete).length;
    const severityStatus = statusOf(activeFindings.map((f) => f.severity));
    // A run where NOTHING was actually verified but a server errored is not "clean" — nothing was
    // proven. Read it as `incomplete` so an all-errored run never wears a green banner.
    const nothingVerified = servers.length === 0 && errors.length > 0;
    // A run in which no tool anywhere was actually examined is not a clean run, even when every
    // server connected happily. Without this, verifying a fleet of all-mutating servers in safe mode
    // returned a green summary having proven nothing at all.
    const noToolsAnywhere = servers.length > 0 && servers.every((s) => s.toolsChecked === 0);
    const summaryStatus = severityStatus === "clean" &&
        (dispatchIncompleteServers > 0 || nothingVerified || noToolsAnywhere)
        ? "incomplete"
        : severityStatus;
    return {
        schemaVersion: REPORT_SCHEMA_VERSION,
        tool: "gawk-verify",
        generatedAt,
        summary: {
            servers: servers.length,
            toolsChecked: servers.reduce((n, s) => n + s.toolsChecked, 0),
            findings: activeFindings.length,
            suppressed: allFindings.length - activeFindings.length,
            errors: errors.length,
            checkErrors: servers.reduce((n, s) => n + s.checkErrors.length, 0),
            dynamicDispatch: dispatchServers,
            status: summaryStatus,
            bySeverity,
        },
        servers,
        errors: [...errors],
        coverage: coverageOf(servers),
    };
}
/**
 * The honest, run-specific coverage line — reflects what backend(s) actually ran, not an
 * aspiration. A server on the plain "proxy" backend with no degradedReason simply never had
 * `isolate` requested (today's default) — that's not a degradation, just the normal mode.
 */
function coverageOf(servers) {
    const local = servers.filter((s) => s.sandboxBackend !== "none");
    if (local.length === 0)
        return EGRESS_COVERAGE; // all-remote run, no local sandbox involved
    const isolateRequested = local.filter((s) => s.sandboxBackend === "proxied-container" ||
        s.sandboxBackend === "docker" ||
        s.sandboxDegradedReason);
    if (isolateRequested.length === 0)
        return EGRESS_COVERAGE; // isolate not requested — normal default run
    const degraded = isolateRequested.filter((s) => Boolean(s.sandboxDegradedReason));
    if (degraded.length === 0) {
        // Every isolate-requested server ran contained. The claim depends on WHICH backend:
        // proxied-container both blocks and observes; plain docker only blocks.
        return isolateRequested.every((s) => s.sandboxBackend === "proxied-container")
            ? PROXIED_COVERAGE
            : isolateRequested.every((s) => s.sandboxBackend === "docker")
                ? DOCKER_COVERAGE
                : `${PROXIED_COVERAGE} NOTE: some server(s) ran under the older --network none backend instead (blocked but NOT observed) — see each server's sandboxBackend.`;
    }
    if (degraded.length === isolateRequested.length && isolateRequested.length === local.length) {
        return `${EGRESS_COVERAGE} Container isolation was requested and degraded for every local server this run — see each server's sandboxDegradedReason.`;
    }
    return `${EGRESS_COVERAGE} MIXED run: ${isolateRequested.length - degraded.length}/${local.length} local server(s) ran under an OS-level container sandbox; the rest are on the default proxy sandbox or degraded — see each server's sandboxBackend/sandboxDegradedReason.`;
}
function csvCell(v) {
    return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}
/** Flatten the report to CSV — one row per finding, suppressed included (empty but for the
 * header when clean). */
export function toCsv(report) {
    const header = "server,transport,status,class,severity,tool,repro,findingId,suppressed,suppressionReason,evidence";
    const rows = [header];
    for (const s of report.servers) {
        for (const f of s.findings) {
            const evidence = JSON.stringify(f.evidence);
            rows.push([
                s.server,
                s.transport,
                s.status,
                f.class,
                f.severity,
                f.tool,
                `${f.reproOk}/${f.reproTotal}`,
                f.findingId,
                f.suppressed ? "true" : "false",
                f.suppressionReason ?? "",
                evidence,
            ]
                .map((c) => csvCell(String(c)))
                .join(","));
        }
    }
    return `${rows.join("\n")}\n`;
}
//# sourceMappingURL=report.js.map