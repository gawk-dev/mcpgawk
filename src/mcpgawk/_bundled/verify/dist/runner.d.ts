import type { Candidate, ReproResult, ReproRunner } from "@gawk/oracle";
import type { Sandbox } from "@gawk/sandbox";
import type { Observation, VulnCheck } from "./checks.js";
import type { ToolAnnotations } from "./classify.js";
import { type ExecutorEnvelope } from "./dispatch.js";
import { type ServerConfig } from "./model.js";
export interface ToolInfo {
    readonly name: string;
    readonly description: string;
    readonly inputSchema: unknown;
    readonly annotations?: ToolAnnotations;
}
/** The captured tail for a transport, trimmed — empty string when the child said nothing. */
export declare function stderrTailOf(transport: object): string;
/**
 * The one line worth showing a human out of a crash dump. Relocating a 4 KB stack trace from the
 * terminal into a report field is not a fix — it is the same noise in a different place. A runtime
 * announces the cause on a line of its own ("Error: Cannot find module ..."), which is what the
 * user needs; the frames below it are for us, and stay in the audit log.
 */
export declare function explainChildFailure(stderrTail: string): string;
/** Connect once and enumerate the server's tools (works for stdio and remote). */
export declare function listTools(server: ServerConfig): Promise<ToolInfo[]>;
/** Call ONE tool once and return its text output — for enumerating a dynamic-dispatch server's
 * hidden catalog via its (read-only) discover tool. Best-effort: bounded by the probe timeout and
 * returns "" on any failure, so a server that can't be enumerated degrades to the correctness floor
 * rather than throwing. NOT a behavioural probe (no sandbox/egress observation) — only used to read
 * a discover tool's listing. */
export declare function callToolText(server: ServerConfig, toolName: string, args: Record<string, unknown>): Promise<string>;
type ProbeResult = {
    ok: true;
    obs: Observation;
} | {
    ok: false;
    detail: string;
};
/** Invoke a tool once and observe (egress + output). Implementations differ by transport.
 * `dispose`, when present, MUST be called once the caller is done making calls through this probe
 * -- probes that keep a connection/process alive across calls (remoteProbe, sandboxedProbeReused)
 * need it to avoid leaking a live child process or open socket past the end of verification. */
export type Probe = ((toolName: string, args: Record<string, unknown>) => Promise<ProbeResult>) & {
    dispose?: () => Promise<void>;
};
/**
 * A local stdio command that's actually a proxy to a remote server (`npx mcp-remote <url>`), not
 * untrusted code running locally. This is the case Bug 3 (2026-07-14) actually broke: reconnecting
 * per attempt meant opening a brand-new OAuth session with the REAL remote server every single
 * time, since `mcp-remote` re-does its own auth negotiation on every fresh spawn.
 */
export declare function isMcpRemoteProxy(server: ServerConfig): boolean;
/** LOCAL probe: spawn the server in a fresh no-egress sandbox; observe egress AND output. */
export declare function sandboxedProbe(server: ServerConfig, sandbox: Sandbox): Probe;
/**
 * Bug 3 fix (2026-07-14): for an `mcp-remote` proxy specifically, `mcp-remote` itself is OUR OWN
 * trusted tooling, not the untrusted target -- the actual target is the REAL remote server it
 * proxies to, which was never being isolated by respawning anyway (same reasoning as
 * {@link remoteProbe}). Reuses one sandbox session + one spawned `mcp-remote` process + one MCP
 * client connection across every call, reconnecting once on failure. Confirmed live: Supabase got
 * 3-4 real findings with full 3/3 reproduction alongside ~80% checkErrors elsewhere under the OLD
 * per-attempt-respawn design -- an inconsistent failure rate, not the ~100% a genuine protocol
 * misuse would produce, pointing at session-creation-rate throttling from spawning a brand-new
 * OAuth session on every attempt.
 *
 * Egress correctness: the sandbox's gateway records egress cumulatively for the session's whole
 * lifetime, not per-call -- reusing one session means a naive `nonAllowlistedEgress()` read would
 * leak an EARLIER call's violation into every LATER call's observation. Tracked via a
 * high-water-mark index into the cumulative record list, so each call's `Observation.egress` is
 * only the NEW records since the previous call, same isolation the fresh-per-attempt design gave
 * for free.
 */
export declare function sandboxedProbeReused(server: ServerConfig, sandbox: Sandbox): Probe;
/**
 * REMOTE probe: connect over HTTP/SSE; observe OUTPUT only (a hosted server can't be sandboxed).
 *
 * Reuses ONE connection across every call this probe makes (all tools, all checks, all
 * reproduction attempts for this server) instead of reconnecting per attempt. Confirmed live
 * 2026-07-14: reconnecting per attempt against real OAuth-fronted servers (Vercel, Supabase)
 * produced a wall of connection timeouts indistinguishable from what a rate-limited/abuse-flagged
 * client would see -- because redoing a full OAuth handshake for every single tool call is not
 * something any real MCP client does, and looks exactly like automated abuse to the provider.
 * There's no isolation trade-off in dropping it: unlike the local sandboxed path, a remote server
 * was never isolated between attempts in the first place (no local execution to contain), so
 * reconnecting per attempt bought zero extra safety -- only chatter.
 *
 * Disclosed, not hidden, residual risk: a target that deliberately alters its behavior when it
 * detects repeated calls on the same session (to evade testing) could in principle behave
 * differently under one persistent connection than it would across fully independent ones. This
 * doesn't change what a reproduction attempt MEASURES (each call's response is still judged
 * independently by the check's own pass/fail logic) -- it only changes the transport underneath.
 * The prior per-attempt-reconnect design wasn't a defense against this either: IP-level
 * correlation makes "fresh TCP connection" trivial to detect as the same caller anyway.
 */
export declare function remoteProbe(server: ServerConfig): Probe;
/**
 * F4: turn a base probe into one that reaches a HIDDEN tool THROUGH a dispatcher's executor. The
 * checks synthesise args against the hidden tool's own schema and call `dispatched(hiddenTool,
 * innerArgs)`; this wraps that into the executor envelope (`execute_tool({tool, args})`, shape
 * discovered by {@link inferExecutorEnvelope}) and delegates to the base probe — so the sandbox,
 * egress observation and N/N reproduction all work exactly as for a visible tool, and the SSRF
 * canary lands in the hidden tool's arg, not the executor's. The base probe still connects to and
 * spawns the SAME server; only the tool name + arguments it sends change.
 */
export declare function dispatchedProbe(base: Probe, executorName: string, envelope: ExecutorEnvelope): Probe;
/** One fresh reproduction attempt for a specific {@link VulnCheck} against a tool, via a {@link Probe}. */
export declare class CheckRunner implements ReproRunner {
    private readonly tool;
    private readonly check;
    private readonly probe;
    constructor(tool: ToolInfo, check: VulnCheck, probe: Probe);
    attempt(_candidate: Candidate): Promise<ReproResult>;
}
export {};
//# sourceMappingURL=runner.d.ts.map