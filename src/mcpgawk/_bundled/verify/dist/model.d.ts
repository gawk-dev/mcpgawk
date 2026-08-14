import type { Verdict } from "@gawk/oracle";
import type { ToolClass } from "./classify.js";
import type { ServerPins } from "./pins.js";
export type Transport = "stdio" | "http" | "sse";
/**
 * How to reach an MCP server to be verified. Either LOCAL stdio (`command`/`args` — spawned inside
 * the no-egress sandbox, all checks apply) or REMOTE over HTTP/SSE (`url` — cannot be sandboxed, so
 * only output-based checks apply).
 */
export interface ServerConfig {
    readonly name: string;
    readonly command?: string;
    readonly args?: readonly string[];
    readonly env?: Readonly<Record<string, string>>;
    /** The server's declared, legitimate upstreams (host or host:port). Everything else is exfil. */
    readonly allowedHosts?: readonly string[];
    readonly url?: string;
    readonly transport?: Transport;
    readonly headers?: Readonly<Record<string, string>>;
}
export declare function isRemote(server: ServerConfig): boolean;
/** A tool that was NOT invoked, and why (safe mode skips anything not confidently read-only). */
export interface SkippedTool {
    readonly tool: string;
    readonly klass: ToolClass;
}
/**
 * A check that could not be completed — the reproduction runner hit infra noise (spawn failure,
 * timeout, sandbox crash, a flaky `npx` registry fetch, ...) on every attempt, not a real verdict
 * either way. Confirmed live 2026-07-14: an `npx`-launched server hitting npm registry 403s mid-run
 * produced infra-failures that were emitted as live events but never reached `findings`, `skipped`,
 * or any summary count — the JSON report read "clean, 0 errors" while some checks had never
 * actually completed. This field exists so that specific silent-drop can't happen again: every
 * check that isn't a verdict and isn't a pre-classification skip MUST land here.
 */
export interface CheckError {
    readonly tool: string;
    readonly code: string;
    readonly detail: string;
}
/** The result of verifying one server: what was checked, skipped, and convicted. */
export interface ServerReport {
    readonly server: string;
    readonly transport: Transport;
    readonly toolsChecked: number;
    /** Reproduced, evidence-bearing verdicts (empty = the server is clean under this check). */
    readonly findings: readonly Verdict[];
    /** Tools not invoked (safe mode) — coverage the caller should know was NOT behaviourally tested. */
    readonly skipped: readonly SkippedTool[];
    /** Checks that never reached a verdict either way — infra noise, NOT a clean result. See
     * {@link CheckError}. A server can show 0 findings and >0 checkErrors: that combination means
     * "nothing was proven wrong, AND some checks never actually ran" — not "verified clean". */
    readonly checkErrors: readonly CheckError[];
    /** Vuln-class codes that RAN (remote servers can only run output-based checks). */
    readonly checksRun: readonly string[];
    /** Every check this run INTENDED to perform for this server (tools × applicable checks, plus the
     * dispatched hidden-tool probes). Counted where the checks are actually driven, not inferred. */
    readonly checksPlanned?: number;
    /** The subset of `checksPlanned` that produced a verdict either way (finding or clean). A check
     * that ended in a {@link CheckError} is planned but NOT completed. `checksCompleted <
     * checksPlanned` makes the server INCOMPLETE — it is the single fact that makes `clean`
     * unreachable when anything failed. Optional only so older fixtures still build: when absent,
     * report.ts falls back to "a check that errored never completed", which is the same rule. */
    readonly checksCompleted?: number;
    /** Fingerprint of the server's tool inventory — for drift / rug-pull detection over time. */
    readonly pins: ServerPins;
    /**
     * Which sandbox backend actually ran this server's checks: "proxied-container" (ADR-0014 — an
     * `--internal` container network whose only route out is our egress proxy: raw-socket/DNS/UDP
     * exfil is BLOCKED at the OS level AND HTTP(S) egress is OBSERVED, in the same run), "docker"
     * (OS-level `--network none`: blocked but nothing observed), "proxy" (HTTP-proxy only, the
     * older and weaker boundary), or "none" (remote server, can't be sandboxed at all).
     */
    readonly sandboxBackend: "proxied-container" | "docker" | "proxy" | "none";
    /** Set only when `isolate` was requested but Docker was unavailable/unusable for this command. */
    readonly sandboxDegradedReason?: string;
    /** Set when this server's restricting annotations were IGNORED as uninformative — every tool
     * carried the same restricting label (kite stamps all 22 destructive, get_ltp included).
     * Labels that never vary carry no information, and honouring them lets a server evade
     * behavioural verification by labelling; name-mutating tools stayed skipped regardless. */
    readonly labelNoiseNote?: string;
    /** Meta-tool name(s) that make this a dynamic-DISPATCH server (see dispatch.ts). Non-empty means
     * a larger real tool catalog is hidden behind them and was NOT enumerated by the static tools/list
     * — the verification is INCOMPLETE, and a "clean" result on the visible tools is not proof of a
     * clean server. Empty/absent for an ordinary server. */
    readonly dynamicDispatch?: readonly string[];
    /** The hidden catalog enumerated by CALLING the discover meta-tool (present only when dispatch was
     * detected AND the discover tool's listing could be read). Names the tools the static scan missed. */
    readonly hiddenCatalog?: readonly HiddenTool[];
    /** Which hidden tools were actually PROBED behaviourally through the executor (F4). A dispatcher
     * earns `clean` ONLY when this covers the WHOLE enumerated catalog — any hidden tool that was
     * unprobeable (no schema) or skipped (safe-mode mutator) keeps the server INCOMPLETE. */
    readonly hiddenProbed?: readonly string[];
    /** True when the catalog was enumerated via a QUERY-DRIVEN discover tool (keyword queries, never
     * exhaustive) — so the server can NEVER earn `clean`, however much was probed, because there may
     * be hidden tools no query surfaced. False/absent for a listing discover that returns the whole
     * catalog. */
    readonly hiddenCatalogPartial?: boolean;
}
/** One tool discovered inside a dynamic-dispatch server's hidden catalog (see dispatch.ts). */
export interface HiddenTool {
    readonly name: string;
    readonly description: string;
    /** The hidden tool's own input schema, WHEN the discover tool provides it (F4). Absent when the
     * discover tool returns only names/descriptions — that tool is then enumerated-but-unprobeable
     * (no schema to synthesise args against), which keeps the server INCOMPLETE, never a false clean. */
    readonly inputSchema?: unknown;
}
export interface VerifyOptions {
    /** N in the N/N reproduction gate (default 3). */
    readonly attempts?: number;
    /**
     * "safe" (default) invokes ONLY tools classified read-only — never anything that could mutate
     * state or move money. "unsafe" invokes every tool: use only against servers you control or a
     * dedicated test account.
     */
    readonly mode?: "safe" | "unsafe";
    /**
     * Opt in to OS-level container isolation. Selects the ProxiedContainerSandbox (ADR-0014):
     * the target runs on an `--internal` network whose only way out is our egress proxy, so
     * raw-socket/DNS/UDP exfil is BLOCKED at the OS level while HTTP(S) egress — including an
     * npx/uvx install fetch — stays fully OBSERVED, in the same run. Covers node/python scripts
     * AND install-on-launch commands (npx/uvx). Degrades to the proxy sandbox with a clear warning
     * if Docker is unavailable or the command can't be containerized.
     */
    readonly isolate?: boolean;
}
//# sourceMappingURL=model.d.ts.map