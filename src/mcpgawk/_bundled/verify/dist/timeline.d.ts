/**
 * Local run timeline — what has actually happened on THIS machine, across all four pillars.
 *
 * Like `fleet.ts`, this shells out to the canonical Python engine (`mcpgawk runs --json`) rather
 * than opening `~/.mcpgawk/runs.db` from Node. Two reasons, and the second is the load-bearing one:
 * a TS SQLite dependency would be a second reader of a schema Python owns (the exact drift this
 * project has spent whole sessions chasing between the two languages), and the registry's honesty
 * rules — an unfinished run is reconciled to `incomplete`, never to `ok` — live in `runlog.py`.
 * Re-implementing those here would mean re-implementing the part that makes the data trustworthy.
 *
 * Local-only, same posture as the rest of `serve`: it reads a file in the user's own home and
 * sends nothing anywhere.
 */
/** Terminal + non-terminal run states, exactly as runlog.py defines them. */
export type RunStatus = "running" | "ok" | "findings" | "error" | "incomplete";
export interface Run {
    readonly run_id: string;
    /** scan | verify | enforce | monitor | guard */
    readonly kind: string;
    /** What it was pointed at. Null for a fleet-wide scan — genuinely no single target. */
    readonly target: string | null;
    readonly started_at: string;
    readonly ended_at: string | null;
    readonly status: RunStatus;
    /** Pillar-specific counts, plus the join keys (enforce carries `session_id`). */
    readonly summary: Record<string, unknown>;
}
export interface Timeline {
    /** False when mcpgawk isn't installed or the registry couldn't be read — never a fabricated
     * empty history. An empty timeline and an unreadable one mean very different things, and
     * showing "no runs yet" for the second is a lie the user cannot detect. */
    readonly available: boolean;
    readonly runs: readonly Run[];
    readonly reason?: string;
}
/** Read the local run registry. Never throws, never invents. */
export declare function loadTimeline(limit?: number): Promise<Timeline>;
/** Whole seconds between start and end, or null while a run is still open. */
export declare function durationSeconds(run: Run): number | null;
/** "4s" / "2m 10s" / "1h 3m". Compact because it sits in a dense column. */
export declare function formatDuration(seconds: number | null): string;
export declare function summaryChips(run: Run): {
    label: string;
    value: string;
}[];
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
export declare function shortenTarget(target: string, max?: number): string;
/** Group runs under YYYY-MM-DD, newest day first, preserving the newest-first order within a day. */
export declare function groupByDay(runs: readonly Run[]): {
    day: string;
    runs: Run[];
}[];
/** Counts for the header strip. `open` is called out because an open run is not a result. */
export declare function timelineTotals(runs: readonly Run[]): {
    total: number;
    findings: number;
    errors: number;
    open: number;
};
//# sourceMappingURL=timeline.d.ts.map