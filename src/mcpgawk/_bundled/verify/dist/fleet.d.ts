/**
 * Fleet discovery — the servers actually configured on THIS machine, across every AI tool
 * (Claude Desktop, Cursor, Claude Code, Codex, Gemini CLI, …). This deliberately shells out to the
 * canonical Python engine (`mcpgawk scan --fleet-json`) rather than re-implementing config
 * discovery in TS: `mcpgawk/discover.py` already knows every client's config path and shape across
 * platforms, and a second copy would silently drift from the one the CLI and the VS Code panel use.
 * Local-only, same as the rest of `serve` — it reads local config files, spawns nothing untrusted.
 */
/** A server's launch spec — command/args/env for local stdio, url/headers for remote. Whatever the
 * user's own config carries; it can include secrets (an `env` API key), so it stays SERVER-SIDE in
 * `serve` and is never sent to the browser. */
export type FleetSpec = Record<string, unknown>;
export interface FleetServer {
    readonly name: string;
    /** REVIEW / CLEAN / SKIPPED / UNREACHABLE / AUTH / NOT-SCANNABLE — mcpgawk's own state vocabulary. */
    readonly state: string;
    readonly detail: string;
    readonly url: string | null;
    readonly clients: readonly string[];
    readonly can_authenticate: boolean;
    /** Present only when discovery was asked for specs (`--with-spec`). Lets the UI verify by click. */
    readonly spec?: FleetSpec | null;
    /** True iff a launch spec is available — the safe, secret-free "can verify by click" signal. */
    readonly scannable?: boolean;
}
export interface Fleet {
    /** False when mcpgawk isn't installed or discovery couldn't run — never a fabricated empty fleet. */
    readonly available: boolean;
    readonly servers: readonly FleetServer[];
    readonly scannedAt: string;
    /** Present iff `available` is false — the honest reason, shown to the user. */
    readonly reason?: string;
}
/**
 * Discover the machine's MCP fleet. Never throws and never invents: if mcpgawk is missing or its
 * output can't be read, returns `available: false` with a reason the UI shows, rather than an empty
 * list that would read as "you have no servers".
 */
/** The shared baseline, read from the free engine — see src/mcpgawk/baseline.py. */
export interface SharedBaseline {
    readonly schema: string;
    readonly servers: Record<string, {
        pin?: string;
        tools?: Record<string, string>;
        approved_at?: string;
        aliases?: string[];
    }>;
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
export declare function readSharedBaseline(timeoutMs?: number): Promise<SharedBaseline | null>;
export declare function discoverFleet(timeoutMs?: number, launchLocal?: boolean): Promise<Fleet>;
/** Every fleet state this maps deliberately. Exported so the browser's copy can be GENERATED from
 * `stateStatus` rather than hand-written — serve.ts held a second, already-drifted transcription
 * of this table, and a table maintained twice is a table that disagrees with itself. */
export declare const FLEET_STATES: readonly ["CLEAN", "REVIEW", "VULNERABLE", "AUTH", "FAILED", "TIMED-OUT", "SKIPPED", "UNREACHABLE", "NOT-SCANNABLE"];
/** mcpgawk state → the report's status vocabulary + a colour role, so the fleet and a verify report
 * speak the same visual language. */
export declare function stateStatus(state: string): {
    label: string;
    role: string;
};
//# sourceMappingURL=fleet.d.ts.map