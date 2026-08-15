import { type Severity } from "@gawk/oracle";
import { type Sandbox } from "@gawk/sandbox";
import { type ServerConfig, type ServerReport, type Transport, type VerifyOptions } from "./model.js";
/** A step in the behavioural audit, emitted live so a UI can show the work as it happens. */
export type AuditEvent = {
    type: "server";
    server: string;
    transport: Transport;
    mode: "safe" | "unsafe";
} | {
    type: "enumerated";
    server: string;
    tools: ReadonlyArray<{
        name: string;
        description: string;
    }>;
} | {
    type: "skip";
    server: string;
    tool: string;
    klass: string;
} | {
    /**
     * The server's sign-in is IN ITS OWN TOOLS and this session is not authenticated: the
     * engine called the server's login tool and got a URL for the human. Session-bound auth
     * (kite's model) only works because mcp-remote proxies get ONE persistent session
     * (sandboxedProbeReused) — the login and every later read share it. The run now WAITS
     * (up to 5 minutes) for the human to authorise.
     */
    type: "auth-needed";
    server: string;
    tool: string;
    url: string;
} | {
    type: "auth-ok";
    server: string;
} | {
    type: "auth-timeout";
    server: string;
} | {
    /**
     * F4: how the hidden catalog was enumerated. `mode: "query"` means a query-driven discover
     * tool was probed with keyword queries — PARTIAL by nature (never exhaustive), so the server
     * stays incomplete however much is probed. `mode: "listing"` means an empty call returned the
     * full catalog. `found` is the number of hidden tools surfaced.
     */
    type: "dispatch-enumeration";
    server: string;
    discover: string;
    mode: "query" | "listing";
    queries: number;
    found: number;
} | {
    /**
     * Docker is the required-for-full-protection sandbox: this fires whenever a local server
     * fell back to the weaker proxy-only sandbox instead, so the degradation is never silent.
     */
    type: "sandbox-degraded";
    server: string;
    reason: string;
} | {
    type: "check";
    server: string;
    tool: string;
    code: string;
    label: string;
    severity: Severity;
    outcome: "reproduced" | "clean" | "error";
    attemptsOk: number;
    attemptsRun: number;
    detail: string;
    evidence?: Record<string, unknown>;
} | {
    /**
     * Fires for EVERY reproduction attempt (not just ones that produce a finding) — the raw
     * evidence a check's `decide()` looked at to make its call. Added 2026-07-14 after a real
     * gap: a "clean" result previously left NO trace of what the tool actually returned, so a
     * human reviewing a clean report had nothing to verify the tool's own claim against —
     * "trust the verdict" instead of "here's the evidence, judge it yourself." `resultText` is
     * truncated (not full response bodies — those can be large and may contain the target's own
     * data) to keep this a spot-check trail, not a full data mirror.
     */
    type: "raw-observation";
    server: string;
    tool: string;
    code: string;
    attempt: number;
    ok: boolean;
    resultTextExcerpt?: string;
    egress?: readonly {
        host: string;
        allowed: boolean;
    }[];
    infraDetail?: string;
};
/**
 * `--isolate` (opt-in, NOT the default): Docker is required for full protection. When it's
 * reachable and the server's command maps onto a known runtime — plain `node`/`python` AND the
 * install-on-launch commands (`npx`/`uvx`) — the {@link ProxiedContainerSandbox} runs: OS-level
 * isolation whose only route out is our egress proxy, so exfil over ANY channel is blocked while
 * HTTP(S) egress (including the package install fetch) stays fully observed, in the same run
 * (ADR-0014). Otherwise this degrades to the proxy-only sandbox and says so via the returned
 * reason — never silently claims stronger coverage than what ran.
 *
 * Still not the default: the container spin-up (network + sidecar per probe) costs real seconds
 * per call, so the fast host-proxy sandbox remains the everyday path and `--isolate` is the
 * deliberate stronger pass. Unlike the old `--network none` backend, isolation no longer costs
 * the SSRF-canary/undeclared-egress signal — allowlisted hosts stay reachable through the proxy.
 */
/** The server's own sign-in tool, when auth lives IN-BAND (kite's `login` returns a broker
 * URL bound to the calling session). Name-driven and deliberately narrow: `login`, `log_in`,
 * `login_url` shapes match; anything containing `out` (logout) never does. */
export declare function findInbandLoginTool<T extends {
    name: string;
}>(tools: readonly T[]): T | undefined;
/** The first URL in a login tool's prose, stripped of trailing punctuation — servers wrap the
 * link in sentences ("Click here: https://… to continue."). Null when there is none. */
export declare function firstUrlIn(text: string): string | null;
/**
 * Verify one MCP server behaviourally: enumerate its tools, then for each callable one run every
 * applicable vulnerability check — each driving the tool and reproduction-verifying (N/N).
 *
 * LOCAL (stdio) servers run inside a fresh no-egress sandbox, so ALL checks apply (exfil, SSRF,
 * tool-poisoning). REMOTE (HTTP/SSE) servers run on the provider's infrastructure and cannot be
 * sandboxed, so only OUTPUT-based checks apply (tool-poisoning) — the egress-based checks are
 * reported as not-run rather than faked.
 */
export declare function verifyServer(server: ServerConfig, opts?: VerifyOptions & {
    sandbox?: Sandbox;
    onEvent?: (e: AuditEvent) => void;
}): Promise<ServerReport>;
//# sourceMappingURL=verify.d.ts.map