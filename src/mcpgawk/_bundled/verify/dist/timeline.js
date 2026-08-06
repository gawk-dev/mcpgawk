import { execFile } from "node:child_process";
function resolveCommand(limit) {
    const sub = ["runs", "--json", "--limit", String(limit)];
    const parts = (process.env.GAWK_MCPGAWK_CMD ?? "").trim().split(/\s+/).filter(Boolean);
    if (parts.length > 0) {
        return { command: parts[0], args: [...parts.slice(1), ...sub] };
    }
    return { command: "mcpgawk", args: sub };
}
/** Read the local run registry. Never throws, never invents. */
export async function loadTimeline(limit = 100) {
    const { command, args } = resolveCommand(Math.max(1, Math.min(limit, 1000)));
    return await new Promise((resolve) => {
        execFile(command, args, { timeout: 15_000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
            if (err) {
                const missing = err.code === "ENOENT";
                resolve({
                    available: false,
                    runs: [],
                    reason: missing
                        ? `\`${command}\` is not on PATH — install mcpgawk, or set GAWK_MCPGAWK_CMD.`
                        : stderr.trim().split("\n").pop() || err.message,
                });
                return;
            }
            try {
                const parsed = JSON.parse(stdout);
                if (!Array.isArray(parsed))
                    throw new Error("expected a JSON array of runs");
                resolve({ available: true, runs: parsed });
            }
            catch (e) {
                // A parse failure is NOT an empty history. Say so rather than rendering "no runs yet".
                resolve({
                    available: false,
                    runs: [],
                    reason: `could not read the run registry: ${e.message}`,
                });
            }
        });
    });
}
/** Whole seconds between start and end, or null while a run is still open. */
export function durationSeconds(run) {
    if (!run.ended_at)
        return null;
    const started = Date.parse(run.started_at);
    const ended = Date.parse(run.ended_at);
    if (Number.isNaN(started) || Number.isNaN(ended))
        return null;
    return Math.max(0, Math.round((ended - started) / 1000));
}
/** "4s" / "2m 10s" / "1h 3m". Compact because it sits in a dense column. */
export function formatDuration(seconds) {
    if (seconds === null)
        return "—";
    if (seconds < 60)
        return `${seconds}s`;
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    if (m < 60)
        return s ? `${m}m ${s}s` : `${m}m`;
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m`;
}
/**
 * The counts worth showing inline, per pillar, in a stable order. Only keys that carry meaning to
 * a reader — `session_id` is a join key, not a fact about the run, so it is deliberately excluded.
 */
const SUMMARY_KEYS = [
    "findings",
    "alerts",
    "blocked",
    "calls",
    "tools",
    "servers",
    "failed_backends",
    "exit_code",
];
export function summaryChips(run) {
    const out = [];
    for (const key of SUMMARY_KEYS) {
        const value = run.summary?.[key];
        if (value === undefined || value === null)
            continue;
        // exit_code 0 is noise; a non-zero one is already conveyed by the status.
        if (key === "exit_code" && value === 0)
            continue;
        out.push({ label: key.replace(/_/g, " "), value: String(value) });
    }
    return out;
}
/**
 * Shorten a target for display, keeping the END.
 *
 * A target is a path or a URL, and the distinguishing part is the tail: every Python-based stdio
 * server shares the same "/Users/me/devtools/…" prefix, so right-truncation renders them all
 * identically — the same failure the run LABEL had before it appended args. Done here rather than
 * in CSS because `text-overflow` truncates at the end, and the `direction:rtl` workaround is
 * defeated by `unicode-bidi:plaintext` resolving a Latin path back to LTR (observed, not assumed).
 * As data it is also deterministic and testable.
 */
export function shortenTarget(target, max = 46) {
    if (target.length <= max)
        return target;
    const tail = target.slice(-(max - 1));
    // Prefer cutting at a separator so the result starts at a readable boundary.
    const boundary = tail.search(/[/\\ ]/);
    const cut = boundary >= 0 && boundary < 16 ? tail.slice(boundary + 1) : tail;
    return `…${cut}`;
}
/** Group runs under YYYY-MM-DD, newest day first, preserving the newest-first order within a day. */
export function groupByDay(runs) {
    const days = new Map();
    for (const run of runs) {
        const day = (run.started_at || "").slice(0, 10) || "unknown";
        const bucket = days.get(day);
        if (bucket)
            bucket.push(run);
        else
            days.set(day, [run]);
    }
    return [...days.entries()]
        .sort((a, b) => (a[0] < b[0] ? 1 : -1))
        .map(([day, dayRuns]) => ({ day, runs: dayRuns }));
}
/** Counts for the header strip. `open` is called out because an open run is not a result. */
export function timelineTotals(runs) {
    let findings = 0;
    let errors = 0;
    let open = 0;
    for (const r of runs) {
        if (r.status === "findings")
            findings++;
        else if (r.status === "error")
            errors++;
        if (r.status === "running" || r.status === "incomplete")
            open++;
    }
    return { total: runs.length, findings, errors, open };
}
//# sourceMappingURL=timeline.js.map