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
/** What replaces every coverage CLAIM when the run did not complete. Deliberately contains none of
 * the strong-claim wording (no "BLOCKED", no "is recorded") — an incomplete run has established
 * nothing to make a claim about. Followed by the specific reasons and {@link EGRESS_COVERAGE}. */
export const INCOMPLETE_COVERAGE = "NO COVERAGE CLAIM — this run did not complete, so nothing can be asserted about what was not " +
    "checked. Not clean, not proven: incomplete because";
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
/** Worst severity → status. critical ⇒ vulnerable; high/medium ⇒ at-risk; else clean.
 *
 * NOTE: severity ALONE can never decide a status — it cannot see whether anything was actually
 * checked. Use {@link deriveStatus}, which folds this together with {@link Completeness}. This is
 * exported only for the severity half and for direct unit tests of it. */
export function statusOf(severities) {
    if (severities.includes("critical"))
        return "vulnerable";
    if (severities.some((s) => s === "high" || s === "medium"))
        return "at-risk";
    return "clean";
}
/** The counts a {@link ServerReport} carries, plus the legacy fallback: when the runner did not
 * record explicit counts, a check that errored is by definition planned-but-not-completed, so
 * `complete ⟺ checkErrors.length === 0` still holds. */
function countsOf(r) {
    const planned = r.checksPlanned ?? (r.checksCompleted ?? 0) + r.checkErrors.length;
    const completed = r.checksCompleted ?? Math.max(planned - r.checkErrors.length, 0);
    return { planned, completed };
}
/** Completeness for ONE server. A server is complete only when every check it planned produced a
 * verdict, at least one tool was actually exercised, and (for a dispatcher) its whole hidden
 * catalog was enumerated AND probed. */
export function serverCompleteness(r) {
    const { planned, completed } = countsOf(r);
    const reasons = [];
    if (completed !== planned) {
        reasons.push(`${planned - completed} check(s) never completed (infra failure, not a verdict) — ${completed}/${planned} completed`);
    }
    if (r.toolsChecked === 0) {
        reasons.push("no tool was actually exercised, so nothing was proven about this server");
    }
    if (dispatchForcesIncomplete(r)) {
        reasons.push("a dynamic-dispatch catalog was not fully enumerated AND probed");
    }
    return {
        checksPlanned: planned,
        checksCompleted: completed,
        complete: reasons.length === 0,
        reasons,
    };
}
/** Completeness for the WHOLE run: every server complete, at least one server, at least one tool
 * anywhere, and no server that failed outright. */
export function runCompleteness(servers, errors) {
    const checksPlanned = servers.reduce((n, s) => n + s.checksPlanned, 0);
    const checksCompleted = servers.reduce((n, s) => n + s.checksCompleted, 0);
    const reasons = [];
    if (servers.length === 0)
        reasons.push("no server was verified at all");
    if (servers.length > 0 && servers.reduce((n, s) => n + s.toolsChecked, 0) === 0) {
        reasons.push("no tool anywhere was exercised");
    }
    if (errors.length > 0)
        reasons.push(`${errors.length} server(s) could not be verified`);
    for (const s of servers) {
        for (const reason of s.incompleteReasons)
            reasons.push(`${s.server}: ${reason}`);
    }
    return { checksPlanned, checksCompleted, complete: reasons.length === 0, reasons };
}
/**
 * The single status algebra. Precedence is unchanged (vulnerable > at-risk > incomplete > clean) —
 * a reproduced finding still outranks incompleteness — but `clean` is now UNREACHABLE unless the
 * run/server is complete. Before this, `clean` was decided by severity alone, so any number of
 * failed checks (1 or 1000) still read as a clean pass.
 */
export function deriveStatus(severity, completeness) {
    if (severity === "vulnerable" || severity === "at-risk")
        return severity;
    return completeness.complete ? "clean" : "incomplete";
}
/** The ONLY exit-code derivation: a pure function of {@link Status}. 1 = actionable (a reproduced
 * finding), 2 = incomplete (nothing can be claimed), 0 = clean and complete. Before 1A this was
 * computed independently of `summary.status`, so `incomplete` could exit 0 and `clean` exit 2. */
export function exitCodeForStatus(status) {
    switch (status) {
        case "vulnerable":
        case "at-risk":
            return 1;
        case "incomplete":
            return 2;
        default:
            return 0;
    }
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
        // ONE derivation (1A): severity decides only convicted-vs-not; completeness decides whether
        // `clean` is even sayable. A dispatcher whose hidden catalog was not fully enumerated+probed
        // (F4-4), a server where no tool was exercised (safe mode skips every mutator — found live
        // 2026-07-27 on mcpgawk's OWN server: `toolsChecked: 0`, `status: "clean"`), and a server with
        // ANY check that never completed all land in the same place: INCOMPLETE, never clean.
        const completeness = serverCompleteness(r);
        const status = deriveStatus(statusOf(active.map((f) => f.severity)), completeness);
        return {
            server: r.server,
            transport: r.transport,
            status,
            toolsChecked: r.toolsChecked,
            checksRun: [...r.checksRun],
            checksPlanned: completeness.checksPlanned,
            checksCompleted: completeness.checksCompleted,
            complete: completeness.complete,
            incompleteReasons: completeness.reasons,
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
    // The SAME derivation as each server, one level up: the run is complete only when every server
    // is, at least one server was verified, at least one tool anywhere was exercised, and no server
    // failed outright. A summary can no longer say `clean` above a server saying `incomplete`.
    const completeness = runCompleteness(servers, errors);
    const summaryStatus = deriveStatus(statusOf(activeFindings.map((f) => f.severity)), completeness);
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
            checksPlanned: completeness.checksPlanned,
            checksCompleted: completeness.checksCompleted,
            complete: completeness.complete,
            incompleteReasons: completeness.reasons,
            status: summaryStatus,
            bySeverity,
        },
        servers,
        errors: [...errors],
        // The coverage sentence is the strongest claim the product makes ("raw-socket / DNS / UDP
        // exfiltration is BLOCKED ... every HTTP(S) destination is recorded"). It is a statement about
        // what THIS run established, so it is unsayable on a run that did not complete — it used to be
        // printed unconditionally, including on runs where the target never started.
        coverage: coverageOf(servers, completeness),
    };
}
/**
 * The honest, run-specific coverage line — reflects what backend(s) actually ran, not an
 * aspiration. A server on the plain "proxy" backend with no degradedReason simply never had
 * `isolate` requested (today's default) — that's not a degradation, just the normal mode.
 */
function coverageOf(servers, completeness) {
    // No coverage CLAIM on an incomplete run. What we can honestly say is what was NOT established.
    if (!completeness.complete) {
        return `${INCOMPLETE_COVERAGE} ${completeness.reasons.join("; ")}. ${EGRESS_COVERAGE}`;
    }
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