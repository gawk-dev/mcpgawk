import { execFile } from "node:child_process";
/** How to invoke mcpgawk. Override with `GAWK_MCPGAWK_CMD` (e.g. ".venv/bin/python -m mcpgawk");
 * default assumes `mcpgawk` is on PATH (the normal `pip install mcpgawk` case). */
function resolveCommand(launchLocal = false) {
    // `--with-spec` so the local UI can verify a fleet server by click. The spec may carry secrets;
    // `serve` keeps it server-side and never forwards it to the browser (see serve.ts /api/fleet).
    //
    // `--yes` is NEVER the default: scanning a local (stdio) server means launching it, which runs
    // its code on this machine. Without it those rows come back SKIPPED — which is correct, but the
    // UI previously reported that state with no way to act on it, so the fleet view could not finish
    // its own job. The flag is now reachable through one explicitly-labelled control.
    const scan = ["scan", "--fleet-json", "--with-spec"];
    if (launchLocal)
        scan.push("--yes");
    const parts = (process.env.GAWK_MCPGAWK_CMD ?? "").trim().split(/\s+/).filter(Boolean);
    if (parts.length > 0) {
        return { command: parts[0], args: [...parts.slice(1), ...scan] };
    }
    return { command: "mcpgawk", args: scan };
}
/**
 * Read the ONE approved baseline instead of keeping a private one.
 *
 * verify used to hold its own pins file, so a server the operator had already approved in `mcpgawk`
 * was still reported as drifted here — three pillars, three memories, three verdicts about the same
 * machine. This asks the engine what has been approved; `mcpgawk baseline --json` is the contract.
 *
 * Never throws: an engine too old to know the subcommand, or a machine with nothing approved yet,
 * must degrade to "no shared baseline" and let the caller fall back — not fail the verification the
 * user actually asked for.
 */
export function readSharedBaseline(timeoutMs = 20_000) {
    const { command, args } = resolveBaselineCommand();
    return new Promise((resolve) => {
        execFile(command, args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
            if (err)
                return resolve(null);
            try {
                const parsed = JSON.parse(stdout);
                resolve(parsed && typeof parsed.schema === "string" ? parsed : null);
            }
            catch {
                resolve(null);
            }
        });
    });
}
function resolveBaselineCommand() {
    const sub = ["baseline", "--json"];
    const parts = (process.env.GAWK_MCPGAWK_CMD ?? "").trim().split(/\s+/).filter(Boolean);
    if (parts.length > 0)
        return { command: parts[0], args: [...parts.slice(1), ...sub] };
    return { command: "mcpgawk", args: sub };
}
export function discoverFleet(timeoutMs = 60_000, launchLocal = false) {
    const { command, args } = resolveCommand(launchLocal);
    const scannedAt = new Date().toISOString();
    return new Promise((resolve) => {
        execFile(command, args, { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
            if (err && err.code === "ENOENT") {
                resolve({
                    available: false,
                    servers: [],
                    scannedAt,
                    reason: "mcpgawk isn't installed — run `pip install mcpgawk` (or set GAWK_MCPGAWK_CMD) to " +
                        "discover the MCP servers configured on this machine.",
                });
                return;
            }
            // Version skew: an OLDER mcpgawk on PATH doesn't know --with-spec and argparse-rejects it.
            // Hit for real (a uv-cached pre-0.1.7 CLI beside a fresh serve): without this branch the
            // user sees a raw "Command failed" with no way to know the fix is an upgrade.
            if (err && /unrecognized arguments/.test(stderr ?? "")) {
                resolve({
                    available: false,
                    servers: [],
                    scannedAt,
                    reason: "the mcpgawk on PATH is older than this UI (it doesn't support --with-spec) — " +
                        "upgrade it: `pip install -U mcpgawk` (or point GAWK_MCPGAWK_CMD at a current one).",
                });
                return;
            }
            try {
                const doc = JSON.parse(stdout);
                if (!Array.isArray(doc.servers))
                    throw new Error("unexpected fleet output shape");
                resolve({ available: true, servers: doc.servers, scannedAt });
            }
            catch (parseErr) {
                // Lead with mcpgawk's own last stderr line when there is one — "Command failed: …" tells
                // the user nothing; the engine's actual complaint usually does.
                const detail = (stderr ?? "").trim().split("\n").filter(Boolean).pop();
                resolve({
                    available: false,
                    servers: [],
                    scannedAt,
                    reason: err
                        ? `fleet discovery failed: ${detail || err.message.split("\n")[0]}`
                        : `fleet output was not readable: ${parseErr.message}`,
                });
            }
        });
    });
}
/** Every fleet state this maps deliberately. Exported so the browser's copy can be GENERATED from
 * `stateStatus` rather than hand-written — serve.ts held a second, already-drifted transcription
 * of this table, and a table maintained twice is a table that disagrees with itself. */
export const FLEET_STATES = [
    "CLEAN",
    "REVIEW",
    "VULNERABLE",
    "AUTH",
    "SKIPPED",
    "UNREACHABLE",
    "NOT-SCANNABLE",
];
/** mcpgawk state → the report's status vocabulary + a colour role, so the fleet and a verify report
 * speak the same visual language. */
export function stateStatus(state) {
    switch (state.toUpperCase()) {
        case "CLEAN":
            return { label: "clean", role: "clean" };
        case "REVIEW":
            return { label: "review", role: "risk" };
        case "VULNERABLE":
            return { label: "vulnerable", role: "vuln" };
        case "AUTH":
            return { label: "needs auth", role: "muted" };
        case "SKIPPED":
            return { label: "skipped", role: "incomplete" };
        case "UNREACHABLE":
            return { label: "unreachable", role: "muted" };
        case "NOT-SCANNABLE":
            return { label: "remote", role: "muted" };
        default:
            // A state we do not recognise is UNKNOWN, which is `incomplete` — not `muted`. `muted` is
            // the deliberate "we chose not to scan this" role (auth needed, unreachable, remote); using
            // it as the fallback quietly filed anything new or unexpected under "nothing to see here".
            return { label: state.toLowerCase(), role: "incomplete" };
    }
}
//# sourceMappingURL=fleet.js.map