#!/usr/bin/env node
import { appendFileSync, existsSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync, } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { behaviourProfile, mergeBehaviourProfiles } from "./behaviour.js";
import { serversOf, toConfig } from "./config.js";
import { readSharedBaseline } from "./fleet.js";
import { renderHtml } from "./html.js";
import { toJUnit } from "./junit.js";
import { LEGACY_PINS_SCHEMA_VERSIONS, PINS_SCHEMA_VERSION, diffPins, hasDrift, } from "./pins.js";
import { redactAuditEvent } from "./redact.js";
import { buildReport, exitCodeForStatus, groupEgressByHost, toCsv, } from "./report.js";
import { toSarif } from "./sarif.js";
import { serve } from "./serve.js";
import { loadSuppressions, saveSuppressions, withSuppression } from "./suppressions.js";
import { verifyServer } from "./verify.js";
const USAGE = `usage: mcpgawk verify <config.json> [--unsafe] [--isolate] [--json] [--html <file>] [--csv <file>]
                          [--sarif <file>] [--junit <file>] [--behaviour-profile <file>] [--suppress <file>]
                          [--baseline <file>] [--webhook <url>] [--audit-log <file>] [--out <file>]
                          [--audit-source] [--source-dir <path>]
       mcpgawk verify serve [--port <n>] [--host <addr>]   # local web UI
       mcpgawk verify suppress <findingId> --file <file> --reason "<why>" [--approved-by "<who>"]

config.json:
{
  "mcpServers": {
    "local":  { "command": "node", "args": ["server.js"], "allowedHosts": ["api.myservice.com"] },
    "remote": { "url": "https://mcp.example.com/mcp", "transport": "http", "headers": { "Authorization": "Bearer \${MCP_TOKEN}" } }
  }
}
Local (stdio) servers run in a no-egress sandbox — all checks apply.
Remote (http/sse) servers can't be sandboxed — only output-based checks (tool-poisoning) apply.
\${VAR_NAME} in "headers"/"env" values is substituted from the environment at load time — so a
config.json committed to a repo never needs to contain a literal secret (export MCP_TOKEN=... and
mcpgawk verify resolves it; a config that references an unset variable fails loudly at startup).
--isolate:         run local servers in an OS-level container sandbox whose ONLY route out is the
                   verifying egress proxy (ADR-0014). Blocks raw-socket/DNS/UDP exfil outright AND
                   still observes every HTTP(S) destination — allowlisted hosts stay reachable, so
                   SSRF-canary / undeclared-egress checks keep their signal. Covers node/python
                   scripts and install-on-launch commands (npx/uvx); the package install runs
                   contained too, observed against an explicit registry allowlist. Requires Docker;
                   degrades to the default proxy sandbox with a warning otherwise. Slower per probe
                   (a container network per call) — the default remains the everyday path.
--baseline <file>: first run records a fingerprint of each server's tools; later runs flag DRIFT
                   (added / removed / changed tools) — i.e. a rug-pull.
--behaviour-profile <file>: write a gawk.behaviour/1 profile (per-tool observed source/sink) — feed
                   it to \`mcpgawk enforce --behaviour-profile\` so toxic-flow blocks by BEHAVIOUR, not name.
--sarif <file>:    write a SARIF 2.1.0 report — GitHub code scanning / most CI security dashboards
                   ingest this natively. A suppressed finding is encoded as a SARIF suppression
                   (shows as "dismissed" on GitHub), not silently dropped from the file.
--junit <file>:    write a JUnit XML report — renders as a pass/fail test tree in most CI UIs.
                   A suppressed finding becomes a <skipped/> testcase, not a <failure> or nothing.
--suppress <file>: exclude REVIEWED findings (by deterministic findingId) from status/exit-code —
                   a legitimate, accepted finding no longer fails CI forever. Never auto-created;
                   use \`mcpgawk verify suppress\` to add an entry after actually reviewing a finding.
                   Suppressed findings still APPEAR in every output format, marked, never hidden.
--webhook <url>:   POST the JSON report to <url> when there are findings or drift (alert sink).
--audit-log <file>: append ONE JSONL line per reproduction attempt (every attempt, not just ones
                   that produce a finding) — server/tool/check/attempt, whether it completed, the
                   raw response text (truncated to 2000 chars) and egress observed, or the infra
                   failure detail. A "clean" report on its own is a verdict to trust; this is the
                   evidence to check that verdict against. Off by default (raw tool output may
                   contain the target's own data — opt in deliberately).
--out <file>:      write the JSON report incrementally as each server finishes, not only once
                   at the very end (atomic tmp-file-then-rename, same pattern as never leaving a
                   half-written file). A killed/timed-out run (a slow OAuth-fronted remote, a
                   hung server) leaves the last-known-good snapshot on disk instead of losing
                   every server that already finished cleanly. --json still controls whether the
                   full report also prints to stdout at the end; --out is independent of it.
--audit-source:    ALSO statically audit each server's SOURCE CODE (AST + semgrep, handled by the
                   Python side before this CLI runs — you won't see these flags again in errors from
                   here). Local script paths are audited in place; npm/pypi launch specs (npx/uvx)
                   are fetched from the public registry — a network call, fetch-only, nothing
                   executed. Remote (url) servers have no local source: reported not-applicable.
--source-dir <path>: with --audit-source, skip resolution and audit exactly this directory
                   (single-server configs only).
serve:             open a local web UI (default http://127.0.0.1:7878) to paste a config and verify in the browser.
suppress:          record that a specific findingId (from a prior run's output) has been reviewed
                   and accepted — appends to --file, creating it if it doesn't exist yet.`;
export async function run(argv, log = console.log, err = console.error, 
// Injectable so the gate's own tests can drive it without a network call or a real key — the
// same pattern licensing.py uses for `post`. Production callers pass nothing.
licenseOpts = {}) {
    const flagValue = (flag) => {
        const i = argv.indexOf(flag);
        return i !== -1 ? argv[i + 1] : undefined;
    };
    // NO LICENCE GATE. Behavioural verification became FREE on 2026-07-28 (founder decision, Task 0
    // in BUILD_PLAN.md): the product's own sentence — "every call verified against expected
    // behaviour" — is unreachable on a free install without it, because every other free check reads
    // what a server DECLARES and cannot see a tool that keeps its name and changes what it does.
    //
    // The gate that stood here was correct while verify was paid, and it was the LAST thing holding
    // the paywall: the engine had already moved into the free package, so a free install shipped the
    // engine and refused to run it. Removing it here matters more than removing the Python one,
    // because this binary is standalone-runnable (`gawk-verify`, and the wheel ships dist/cli.js).
    //
    // What stays paid: ENFORCE (the live proxy), MONITOR (the continuous layer) and BUILD — each
    // gated in its own entry point, not here.
    // `serve` subcommand: start the local web UI and block until the process is killed.
    if (argv[0] === "serve") {
        const port = Number(flagValue("--port") ?? 7878);
        const host = flagValue("--host") ?? "127.0.0.1";
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            err(`mcpgawk verify serve: invalid --port '${flagValue("--port")}'`);
            return 2;
        }
        await serve({ port, host, unsafeAllowed: argv.includes("--unsafe"), log });
        return await new Promise(() => { }); // run until the process is terminated
    }
    // `suppress` subcommand: record a reviewed, accepted finding — never auto-generated.
    if (argv[0] === "suppress") {
        const findingId = argv[1];
        const filePath = flagValue("--file");
        const reason = flagValue("--reason");
        const approvedBy = flagValue("--approved-by");
        if (!findingId || findingId.startsWith("--")) {
            err('mcpgawk verify suppress: a findingId is required, e.g. mcpgawk verify suppress F-abc123... --file suppressions.json --reason "..."');
            return 2;
        }
        if (!filePath) {
            err("mcpgawk verify suppress: --file <path> is required");
            return 2;
        }
        if (!reason) {
            err('mcpgawk verify suppress: --reason "..." is required — a suppression with no recorded reason defeats the point of a review trail');
            return 2;
        }
        let existing;
        try {
            existing = loadSuppressions(filePath);
        }
        catch (e) {
            err(`cannot read '${filePath}': ${e.message}`);
            return 2;
        }
        saveSuppressions(filePath, withSuppression(existing, findingId, reason, approvedBy));
        log(`mcpgawk verify: suppressed ${findingId} → ${filePath}`);
        return 0;
    }
    const unsafe = argv.includes("--unsafe");
    const isolate = argv.includes("--isolate");
    const asJson = argv.includes("--json");
    const htmlPath = flagValue("--html");
    const csvPath = flagValue("--csv");
    const sarifPath = flagValue("--sarif");
    const behaviourPath = flagValue("--behaviour-profile") ?? flagValue("--behavior-profile");
    const junitPath = flagValue("--junit");
    const suppressPath = flagValue("--suppress");
    const baselinePath = flagValue("--baseline");
    const webhookUrl = flagValue("--webhook");
    const auditLogPath = flagValue("--audit-log");
    const outPath = flagValue("--out");
    const valueFlags = new Set([
        "--html",
        "--csv",
        "--sarif",
        "--junit",
        "--suppress",
        "--baseline",
        "--webhook",
        "--audit-log",
        "--out",
    ]);
    const configPath = argv.find((a, i) => !a.startsWith("--") && !valueFlags.has(argv[i - 1] ?? ""));
    if (!configPath) {
        err(USAGE);
        return 2;
    }
    let servers;
    try {
        servers = serversOf(JSON.parse(readFileSync(configPath, "utf8")));
    }
    catch (e) {
        err(`cannot read config '${configPath}': ${e.message}`);
        return 2;
    }
    let suppressions;
    if (suppressPath) {
        try {
            suppressions = loadSuppressions(suppressPath);
        }
        catch (e) {
            err(`cannot read suppressions '${suppressPath}': ${e.message}`);
            return 2;
        }
    }
    if (unsafe) {
        err("⚠  --unsafe: every tool will be invoked, including mutating ones. Use only against a server you control or a TEST account.");
    }
    if (auditLogPath) {
        // Truncate/create fresh at the start of this run -- an audit log from a stale prior run
        // silently mixed into a new one would be worse than no audit log at all.
        writeFileSync(auditLogPath, "");
    }
    // Writes the report built from whatever has completed SO FAR, atomically (tmp file + rename,
    // same pattern as the Trust Index crawler's incremental flush) -- a killed/timed-out process
    // (confirmed live 2026-07-14: a real 7-server run got killed at minute 50 with the whole
    // report, including servers that finished cleanly minutes earlier, lost -- --json only ever
    // printed once, at the very end) now leaves the last-known-good snapshot on disk instead of
    // nothing.
    const writeIncremental = (currentReports, currentErrors) => {
        if (!outPath)
            return;
        const snapshot = buildReport(currentReports, new Date().toISOString(), {}, [...currentErrors]);
        const tmpPath = `${outPath}.tmp`;
        writeFileSync(tmpPath, `${JSON.stringify(snapshot, null, 2)}\n`);
        renameSync(tmpPath, outPath);
    };
    // Partial reports: a server that can't be verified is recorded as an error, not an abort.
    const reports = [];
    const errors = [];
    for (const [name, raw] of Object.entries(servers)) {
        try {
            reports.push(await verifyServer(toConfig(name, raw), {
                mode: unsafe ? "unsafe" : "safe",
                isolate,
                onEvent: (e) => {
                    if (e.type === "sandbox-degraded") {
                        err(`⚠  ${e.server}: ${e.reason}`);
                    }
                    if (e.type === "raw-observation" && auditLogPath) {
                        // Masked AT THE WRITE. `resultTextExcerpt` is 2000 chars of whatever the tool
                        // returned, and on 2026-08-13 a fixture this engine CONVICTED for credential-exposure
                        // had its key written here in cleartext. Truncation was never a redaction.
                        appendFileSync(auditLogPath, `${JSON.stringify(redactAuditEvent(e))}\n`);
                    }
                },
            }));
        }
        catch (e) {
            errors.push({ server: name, message: e.message });
        }
        writeIncremental(reports, errors);
    }
    // Drift / rug-pull: establish or compare a baseline of each server's tool inventory.
    const driftByServer = {};
    let drifted = false;
    // THE SHARED BASELINE. With no --baseline file, compare against what the operator has already
    // approved in the engine (`mcpgawk approve`) instead of holding a private opinion. This is the
    // hop that used to be manual: you approved a server in scan, and verify still called it drift.
    if (!baselinePath) {
        const shared = await readSharedBaseline();
        if (shared) {
            for (const r of reports) {
                const entry = shared.servers[r.server];
                const priorTools = entry?.tools;
                if (!priorTools || Object.keys(priorTools).length === 0)
                    continue;
                const prior = Object.entries(priorTools).map(([name, hash]) => ({ name, hash }));
                const d = diffPins(prior, r.pins.tools);
                driftByServer[r.server] = d;
                if (hasDrift(d))
                    drifted = true;
            }
            const compared = Object.keys(driftByServer).length;
            if (compared > 0) {
                log(`\nBaseline: comparing ${compared} server(s) against what you approved with \`mcpgawk approve\`.`);
            }
        }
    }
    if (baselinePath) {
        if (existsSync(baselinePath)) {
            let base;
            try {
                base = JSON.parse(readFileSync(baselinePath, "utf8"));
            }
            catch (e) {
                err(`cannot read baseline '${baselinePath}': ${e.message}`);
                return 2;
            }
            // A baseline written before the fingerprint included annotations cannot be compared against
            // current hashes: EVERY tool would read as changed. Emitting that storm would teach the
            // operator that drift means nothing, which is worse than reporting no drift at all.
            if (LEGACY_PINS_SCHEMA_VERSIONS.includes(base.schemaVersion)) {
                err([
                    `baseline '${baselinePath}' is schema ${base.schemaVersion}; the fingerprint now includes `,
                    "tool annotations (a tool flipping readOnlyHint->destructiveHint used to hash identically ",
                    "and pass as unchanged). Its hashes are not comparable — delete it and re-run to re-baseline ",
                    "this fleet.",
                ].join(""));
                return 2;
            }
            const priorByServer = new Map(base.pins.map((p) => [p.server, p.tools]));
            for (const r of reports) {
                const prior = priorByServer.get(r.server);
                if (prior) {
                    const d = diffPins(prior, r.pins.tools);
                    driftByServer[r.server] = d;
                    if (hasDrift(d))
                        drifted = true;
                }
            }
        }
        else {
            const baseline = {
                schemaVersion: PINS_SCHEMA_VERSION,
                pins: reports.map((r) => r.pins),
            };
            writeFileSync(baselinePath, `${JSON.stringify(baseline, null, 2)}\n`);
            err(`mcpgawk verify: baseline established → ${baselinePath}`);
        }
    }
    const report = buildReport(reports, new Date().toISOString(), driftByServer, errors, suppressions);
    if (outPath) {
        // Final write: the complete report (drift + suppressions included), replacing the
        // in-progress incremental snapshots.
        const tmpPath = `${outPath}.tmp`;
        writeFileSync(tmpPath, `${JSON.stringify(report, null, 2)}\n`);
        renameSync(tmpPath, outPath);
    }
    const actionable = report.summary.findings > 0 || drifted;
    // Alert sink: on any finding or drift, POST the report to a webhook (Monitor notification).
    if (webhookUrl && actionable) {
        try {
            const res = await fetch(webhookUrl, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(report),
            });
            err(`mcpgawk verify: alerted ${webhookUrl} (${res.status})`);
        }
        catch (e) {
            err(`mcpgawk verify: webhook failed: ${e.message}`);
        }
    }
    if (asJson)
        log(JSON.stringify(report, null, 2));
    if (htmlPath) {
        try {
            writeFileSync(htmlPath, renderHtml(report));
            err(`mcpgawk verify: wrote HTML report → ${htmlPath}`);
        }
        catch (e) {
            err(`cannot write '${htmlPath}': ${e.message}`);
            return 2;
        }
    }
    if (csvPath) {
        try {
            writeFileSync(csvPath, toCsv(report));
            err(`mcpgawk verify: wrote CSV → ${csvPath}`);
        }
        catch (e) {
            err(`cannot write '${csvPath}': ${e.message}`);
            return 2;
        }
    }
    if (sarifPath) {
        try {
            writeFileSync(sarifPath, toSarif(report));
            err(`mcpgawk verify: wrote SARIF → ${sarifPath}`);
        }
        catch (e) {
            err(`cannot write '${sarifPath}': ${e.message}`);
            return 2;
        }
    }
    {
        // B4 — the bridge to ENFORCE: toxic-flow classification follows what a tool was OBSERVED to do,
        // not its attacker-chosen name. `sync_workspace` is a sink that matches no name pattern, and
        // the name is written by whoever wrote the server — the attacker, in this threat model.
        //
        // ALWAYS written, to a shared well-known path, in addition to any explicit --behaviour-profile.
        // Until 2026-07-27 this only happened when the operator passed the flag AND then passed the
        // same file to enforce — so the strongest control in the product was opt-in on BOTH sides, and
        // opt-in security defaults to off. Same one-shared-file spine as the approved baseline: the
        // pillar that can observe writes it, the pillar that enforces reads it, neither needs a flag.
        // Path constant is duplicated in enforce/cli.py (DEFAULT_BEHAVIOUR_PROFILE) and pinned by a
        // cross-language test — the two runtimes must agree on it or the loop silently never closes.
        // GAWK_BEHAVIOUR_PROFILE overrides the shared default, and MUST be honoured here as well as in
        // Python. Until 2026-07-31 only the Python side could be redirected, so every run of the test
        // suite that invoked this engine wrote to the developer's REAL ~/.gawk/behaviour.json and
        // stripped its `verified` map. It was diagnosed as a "mystery writer" twice. Two runtimes share
        // this file; an override only one of them respects is not an override.
        const targets = [
            process.env.GAWK_BEHAVIOUR_PROFILE || join(homedir(), ".gawk", "behaviour.json"),
        ];
        if (behaviourPath && !targets.includes(behaviourPath))
            targets.push(behaviourPath);
        const freshProfile = behaviourProfile(report);
        const verifiedNames = new Set(report.servers.map((s) => s.server));
        for (const target of targets) {
            const isExplicit = target === behaviourPath;
            try {
                mkdirSync(dirname(target), { recursive: true });
                // MERGE, never replace the file: only the servers THIS run verified are rewritten.
                // A remote-only run must not wipe the recorded behaviour of servers it never touched.
                let existing = null;
                try {
                    existing = JSON.parse(readFileSync(target, "utf-8"));
                }
                catch {
                    existing = null; // absent or corrupt — the merge treats both as nothing to retain
                }
                const merged = mergeBehaviourProfiles(existing, freshProfile, verifiedNames);
                writeFileSync(target, `${JSON.stringify(merged, null, 2)}\n`);
                if (isExplicit)
                    err(`mcpgawk verify: wrote behavioural profile → ${target}`);
            }
            catch (e) {
                // An explicit path the operator named is a hard failure; the shared default is
                // best-effort — a read-only HOME must not fail a verify run that otherwise succeeded.
                if (isExplicit) {
                    err(`cannot write '${target}': ${e.message}`);
                    return 2;
                }
                err(`mcpgawk verify: could not update the shared behavioural profile at ${target} ` +
                    `(${e.message}) — enforce will fall back to NAME-ONLY toxic-flow.`);
            }
        }
    }
    if (junitPath) {
        try {
            writeFileSync(junitPath, toJUnit(report));
            err(`mcpgawk verify: wrote JUnit XML → ${junitPath}`);
        }
        catch (e) {
            err(`cannot write '${junitPath}': ${e.message}`);
            return 2;
        }
    }
    if (!asJson)
        printText(report, log);
    return exitCode(report, actionable);
}
/** Exit: 1 = actionable (findings/drift), 2 = incomplete (servers errored, checks never completed,
 * nothing exercised, or a hidden catalog not fully probed — nothing can be claimed), 0 = clean.
 *
 * DERIVED from `summary.status` via {@link exitCodeForStatus} — never computed independently. Until
 * 2026-08-02 this function re-derived its own answer from a different set of fields, so `incomplete`
 * could exit 0 and `clean` could exit 2: no single output field was trustworthy alone. `actionable`
 * (findings OR baseline drift) is the one input `status` cannot see, and it only ever escalates. */
export function exitCode(report, actionable) {
    if (actionable)
        return 1;
    return exitCodeForStatus(report.summary.status);
}
/** Render a finding's evidence into a short human line, whatever check produced it. */
function summarise(evidence) {
    if (Array.isArray(evidence.egress))
        return `→ ${evidence.egress.join(", ")}`;
    if (typeof evidence.canary === "string")
        return `fetched input URL (${evidence.canary})`;
    if (typeof evidence.snippet === "string")
        return `output: “${evidence.snippet}”`;
    return JSON.stringify(evidence);
}
/** The undeclared-egress cluster for the terminal, grouped by host and ordered ANOMALY-FIRST (a host
 * reached by the fewest tools ranks first). See {@link groupEgressByHost} for the rationale. */
export function egressClusterLines(egressFindings) {
    const groups = groupEgressByHost(egressFindings);
    if (groups.length === 0)
        return [];
    const toolTotal = new Set(egressFindings.map((f) => f.tool)).size;
    const hint = "Declare expected upstreams in allowedHosts; a host reached by MANY tools is usually the " +
        "server's own backend, one reached by a SINGLE tool is the outlier to verify:";
    const lines = [
        `  ⚠ EGRESS — ${toolTotal} tool(s) contacted ${groups.length} undeclared host(s). ${hint}`,
    ];
    for (const g of groups) {
        const shown = g.tools.slice(0, 8).join(", ");
        const more = g.tools.length > 8 ? `, +${g.tools.length - 8} more` : "";
        lines.push(`    ✗ ${g.host} ← ${g.tools.length} tool(s): ${shown}${more}`);
    }
    return lines;
}
/** The human-readable terminal report (default output when --json is not given). Exported so the
 * prose can be asserted against the other renderers in one cross-artefact agreement test — the
 * surfaces disagreeing with each other is the defect this file was fixed for. */
export function printText(report, log) {
    for (const s of report.servers) {
        log(`\n${s.server} [${s.transport}]: checked ${s.toolsChecked} tool(s)`);
        if (s.transport !== "stdio") {
            log(`  (remote — can't sandbox; egress checks N/A, ran: ${s.checksRun.join(", ")})`);
        }
        if (s.dynamicDispatch && s.dynamicDispatch.length > 0) {
            const catalog = s.hiddenCatalog ?? [];
            const probed = new Set(s.hiddenProbed ?? []);
            if (catalog.length === 0) {
                // NOT-ENUMERABLE: we know a catalog is hidden but couldn't list it.
                log(`  ⚠ INCOMPLETE — dynamic dispatch via ${s.dynamicDispatch.join(", ")}: a larger tool catalog is hidden behind these and could NOT be enumerated (no readable discover tool). A clean result on the visible tools is NOT proof of a clean server.`);
            }
            else {
                const unprobed = catalog.filter((h) => !probed.has(h.name)).map((h) => h.name);
                const fully = unprobed.length === 0 && !s.hiddenCatalogPartial;
                const head = fully
                    ? `  dynamic dispatch via ${s.dynamicDispatch.join(", ")}: all ${catalog.length} hidden tool(s) enumerated AND probed through the executor.`
                    : s.hiddenCatalogPartial
                        ? `  ⚠ INCOMPLETE — dynamic dispatch via ${s.dynamicDispatch.join(", ")}: the discover tool is query-driven, so only a PARTIAL catalog could be surfaced (${catalog.length - unprobed.length}/${catalog.length} of what was found were probed) — there may be hidden tools no query returned.`
                        : `  ⚠ INCOMPLETE — dynamic dispatch via ${s.dynamicDispatch.join(", ")}: ${catalog.length - unprobed.length}/${catalog.length} hidden tool(s) probed; the rest keep this incomplete.`;
                log(head);
                const shown = catalog
                    .slice(0, 12)
                    .map((h) => `${h.name}${probed.has(h.name) ? "" : "*"}`)
                    .join(", ");
                const more = catalog.length > 12 ? `, +${catalog.length - 12} more` : "";
                log(`    hidden tool(s): ${shown}${more}`);
                if (!fully) {
                    const shownUnprobed = unprobed.slice(0, 12).join(", ");
                    log(`    * NOT probed (no schema to synthesise args, or a safe-mode-skipped mutator): ${shownUnprobed}`);
                }
            }
        }
        if (s.skipped.length > 0) {
            const shown = s.skipped
                .slice(0, 8)
                .map((k) => `${k.tool}(${k.class})`)
                .join(", ");
            const more = s.skipped.length > 8 ? `, +${s.skipped.length - 8} more` : "";
            log(`  - skipped ${s.skipped.length} not-read-only tool(s): ${shown}${more}`);
        }
        const d = s.drift;
        if (d && (d.changed.length || d.removed.length || d.added.length)) {
            const parts = [];
            if (d.changed.length)
                parts.push(`changed: ${d.changed.join(", ")}`);
            if (d.removed.length)
                parts.push(`removed: ${d.removed.join(", ")}`);
            if (d.added.length)
                parts.push(`added: ${d.added.join(", ")}`);
            log(`  ⚠ DRIFT since baseline — ${parts.join("; ")} (possible rug-pull)`);
        }
        if (s.checkErrors.length > 0) {
            const shown = s.checkErrors
                .slice(0, 8)
                .map((c) => `${c.tool}::${c.code}`)
                .join(", ");
            const more = s.checkErrors.length > 8 ? `, +${s.checkErrors.length - 8} more` : "";
            log(`  ⚠ ${s.checkErrors.length} check(s) never completed (infra failure, NOT clean): ${shown}${more}`);
        }
        if (s.findings.length === 0) {
            // "Nothing was reproduced" only means something if something was TRIED. A server whose every
            // tool was skipped (safe mode skips not-read-only tools, so an all-mutating server checks
            // nothing) printed the same green tick as a genuinely exercised one — found live 2026-07-27
            // against mcpgawk's own server, 0 checked and still ticked.
            if (s.toolsChecked === 0) {
                log("  ⊘ INCONCLUSIVE — no tool was actually exercised, so nothing was proven about this " +
                    "server. Safe mode skips tools that are not read-only; re-run with --unsafe in a " +
                    "throwaway environment to exercise them.");
                continue;
            }
            // The green tick belongs ONLY to a server that completed. Anything else says incomplete
            // first — it is the same derived field the JSON/HTML/SARIF/JUnit and the exit code use.
            log(s.complete
                ? "  ✓ no HTTP exfiltration / SSRF / poisoning / secret-leak reproduced"
                : `  ⊘ INCOMPLETE (${s.checksCompleted}/${s.checksPlanned} check(s) completed) — nothing reproduced in the checks that DID complete, which is not a clean result: ${s.incompleteReasons.join("; ")}`);
            continue;
        }
        // Undeclared-egress findings are clustered BY HOST here (not one line per tool): on a server
        // with no allowedHosts, its own upstream shows up as one finding per tool — expected traffic
        // that buries the real outlier. Grouping by host, anomaly-first, surfaces "one host reached by
        // a single (hidden) tool" above "one host reached by many". The individual findings are intact
        // in --json/--sarif/--csv for CI; this is the human digest. Non-egress findings render as before.
        const activeEgress = s.findings.filter((f) => f.class === "undeclared-egress" && !f.suppressed);
        const rest = s.findings.filter((f) => !(f.class === "undeclared-egress" && !f.suppressed));
        for (const line of egressClusterLines(activeEgress))
            log(line);
        for (const f of rest) {
            const mark = f.suppressed ? "~" : "✗";
            const suffix = f.suppressed ? `  [suppressed: ${f.suppressionReason}]` : "";
            log(`  ${mark} [${f.class}] ${f.tool}: ${summarise(f.evidence)}  (${f.reproOk}/${f.reproTotal}, ${f.findingId})${suffix}`);
        }
    }
    for (const e of report.errors) {
        log(`\n${e.server}: ⚠ could not verify — ${e.message}`);
    }
    const partialBits = [];
    if (report.errors.length > 0)
        partialBits.push(`${report.errors.length} server(s) could not be verified`);
    if (report.summary.checkErrors > 0)
        partialBits.push(`${report.summary.checkErrors} check(s) never completed`);
    const partial = partialBits.length > 0 ? ` (${partialBits.join("; ")})` : "";
    const suppressedNote = report.summary.suppressed > 0
        ? ` (${report.summary.suppressed} suppressed, marked ~ above)`
        : "";
    // The prose verdict is the SAME derived field as the JSON, the HTML banner, SARIF and the exit
    // code (1A) — never a separately-worded judgement. A run that did not complete says so first:
    // "no findings reproduced" over an examination that never happened is the central lie this fixes.
    if (report.summary.findings > 0) {
        log(`\nmcpgawk verify: CONVICTED ${report.summary.findings} finding(s) — status ${report.summary.status}.${partial}${suppressedNote}`);
    }
    else if (!report.summary.complete) {
        const why = report.summary.incompleteReasons.slice(0, 6).join("; ");
        const more = report.summary.incompleteReasons.length > 6
            ? `; +${report.summary.incompleteReasons.length - 6} more`
            : "";
        log(`\nmcpgawk verify: INCOMPLETE — status ${report.summary.status}. ` +
            `${report.summary.checksCompleted}/${report.summary.checksPlanned} check(s) completed. ` +
            `NOT a clean pass: ${why}${more}.${suppressedNote}`);
    }
    else {
        log(`\nmcpgawk verify: no findings reproduced — status ${report.summary.status} ` +
            `(${report.summary.checksCompleted}/${report.summary.checksPlanned} check(s) completed).${suppressedNote}`);
    }
    log(`\nCoverage: ${report.coverage}`);
}
// Compare REAL paths, not raw ones: on macOS /var is a symlink to /private/var, so a CLI invoked
// through a symlinked path (any temp dir, and the wheel's own install path under it) has an
// import.meta.url that does not string-match process.argv[1]. The naive comparison made the binary
// exit 0 having silently done nothing — a no-op that reads exactly like a clean run. Found while
// mutation-testing the licence gate, which this same no-op was masking.
const isMain = (() => {
    const invoked = process.argv[1];
    if (!invoked)
        return false;
    try {
        return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(invoked);
    }
    catch {
        return import.meta.url === `file://${invoked}`;
    }
})();
if (isMain) {
    run(process.argv.slice(2)).then((code) => process.exit(code));
}
//# sourceMappingURL=cli.js.map