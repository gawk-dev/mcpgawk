import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { buildDispatchEnvelope } from "./dispatch.js";
import { isRemote } from "./model.js";
/** Untrusted tools must not be able to stall the verifier — bound every tool call. */
function probeTimeoutMs() {
    const parsed = Number(process.env.GAWK_PROBE_TIMEOUT_MS);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 10_000;
}
/** Delay before a reused-session probe retries a connection, in ms. Configurable for tests. */
function reconnectBackoffMs() {
    const parsed = Number(process.env.GAWK_RECONNECT_BACKOFF_MS);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 1_500;
}
/**
 * A session-creation throttle (e.g. Supabase's `ThrottlerException`) rejects a reconnect attempt
 * made immediately after the failure that triggered it, since zero time has passed since the
 * previous session-creation call that got throttled. Found live 2026-07-14: once one reconnect hit
 * this, every later probe call retried the same dead connection instantly and failed the same way
 * for the rest of the run (27 checkErrors on 7 tools, all "Connection closed" on attempt 1/3).
 * Waiting briefly before reconnecting gives a rate-limit window a chance to clear.
 */
function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
/**
 * Tail of each spawned server's stderr, so a failure can be EXPLAINED rather than dumped.
 *
 * The SDK defaults a stdio child's stderr to `inherit`, which sent the child's output straight to
 * whatever terminal was running us. A server that fails to start therefore printed a raw Node stack
 * trace into the operator's console — during `serve`, that made a perfectly healthy web UI look
 * like it had crashed, while the actual cause ("Cannot find module ...") was never attached to the
 * per-server error the user could see. We now pipe it, keep a bounded tail, and surface it.
 */
const STDERR_TAIL_LIMIT = 4000;
const childStderr = new WeakMap();
/** The captured tail for a transport, trimmed — empty string when the child said nothing. */
export function stderrTailOf(transport) {
    return (childStderr.get(transport)?.text ?? "").trim();
}
/**
 * The one line worth showing a human out of a crash dump. Relocating a 4 KB stack trace from the
 * terminal into a report field is not a fix — it is the same noise in a different place. A runtime
 * announces the cause on a line of its own ("Error: Cannot find module ..."), which is what the
 * user needs; the frames below it are for us, and stay in the audit log.
 */
export function explainChildFailure(stderrTail) {
    const lines = stderrTail
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
    const cause = lines.find((l) => /^[A-Za-z_$][\w.]*Error\b/.test(l)) ??
        lines.find((l) => /error|cannot|not found|refused|denied/i.test(l)) ??
        lines[0] ??
        "";
    return cause.length > 300 ? `${cause.slice(0, 297)}…` : cause;
}
function stdioTransport(server, extraEnv = {}, spawnOverride) {
    const transport = new StdioClientTransport({
        command: spawnOverride?.command ?? server.command ?? "",
        args: spawnOverride?.args ?? [...(server.args ?? [])],
        env: { ...process.env, ...server.env, ...extraEnv },
        // Capture instead of inherit. Without this the child owns the operator's terminal.
        stderr: "pipe",
    });
    const sink = { text: "" };
    childStderr.set(transport, sink);
    // `transport.stderr` exists only once the child is spawned; the SDK exposes it as a stream when
    // stderr is piped. Bounded so a chatty or looping server cannot grow this without limit.
    const attach = () => {
        const stream = transport.stderr;
        if (!stream)
            return false;
        stream.on("data", (chunk) => {
            sink.text = (sink.text + String(chunk)).slice(-STDERR_TAIL_LIMIT);
        });
        return true;
    };
    if (!attach()) {
        // Not spawned yet — try again once the event loop has run the SDK's start().
        setTimeout(attach, 0);
    }
    return transport;
}
function remoteTransport(server) {
    const url = new URL(server.url ?? "");
    const requestInit = server.headers ? { headers: { ...server.headers } } : undefined;
    return server.transport === "sse"
        ? new SSEClientTransport(url, { requestInit })
        : new StreamableHTTPClientTransport(url, { requestInit });
}
function connectTransport(server, extraEnv = {}) {
    return isRemote(server) ? remoteTransport(server) : stdioTransport(server, extraEnv);
}
/** Connect once and enumerate the server's tools (works for stdio and remote). */
export async function listTools(server) {
    const client = new Client({ name: "gawk-verify", version: "1.0.0" });
    const transport = connectTransport(server);
    try {
        await client.connect(transport);
    }
    catch (e) {
        // A server that cannot start produces a useless protocol-level message ("MCP error -32000:
        // Connection closed"). The reason is in the child's stderr — attach it, so the user is told
        // "Cannot find module ..." instead of being left to find a stack trace in a terminal they may
        // not even be looking at.
        const cause = explainChildFailure(stderrTailOf(transport));
        const base = e?.message ?? String(e);
        throw new Error(cause ? `${base} — the server failed to start: ${cause}` : base);
    }
    try {
        const res = await client.listTools();
        return res.tools.map((t) => ({
            name: t.name,
            description: t.description ?? "",
            inputSchema: t.inputSchema,
            annotations: t.annotations,
        }));
    }
    finally {
        await client.close();
    }
}
/** Call ONE tool once and return its text output — for enumerating a dynamic-dispatch server's
 * hidden catalog via its (read-only) discover tool. Best-effort: bounded by the probe timeout and
 * returns "" on any failure, so a server that can't be enumerated degrades to the correctness floor
 * rather than throwing. NOT a behavioural probe (no sandbox/egress observation) — only used to read
 * a discover tool's listing. */
export async function callToolText(server, toolName, args) {
    const client = new Client({ name: "gawk-verify", version: "1.0.0" });
    try {
        await client.connect(connectTransport(server));
        const res = await client.callTool({ name: toolName, arguments: args }, undefined, {
            timeout: probeTimeoutMs(),
        });
        return resultText(res);
    }
    catch {
        return "";
    }
    finally {
        await client.close().catch(() => { });
    }
}
function resultText(res) {
    const content = res?.content;
    if (!Array.isArray(content))
        return "";
    return content
        .filter((c) => c?.type === "text" && typeof c.text === "string")
        .map((c) => c.text)
        .join("\n");
}
const MCP_REMOTE_LAUNCHERS = new Set(["npx", "npm", "pnpm", "yarn", "bunx"]);
/**
 * A local stdio command that's actually a proxy to a remote server (`npx mcp-remote <url>`), not
 * untrusted code running locally. This is the case Bug 3 (2026-07-14) actually broke: reconnecting
 * per attempt meant opening a brand-new OAuth session with the REAL remote server every single
 * time, since `mcp-remote` re-does its own auth negotiation on every fresh spawn.
 */
export function isMcpRemoteProxy(server) {
    const base = (server.command ?? "").split("/").pop() ?? "";
    if (!MCP_REMOTE_LAUNCHERS.has(base))
        return false;
    return (server.args ?? []).some((a) => a === "mcp-remote" || a.startsWith("mcp-remote@"));
}
/** LOCAL probe: spawn the server in a fresh no-egress sandbox; observe egress AND output. */
export function sandboxedProbe(server, sandbox) {
    return isMcpRemoteProxy(server)
        ? sandboxedProbeReused(server, sandbox)
        : sandboxedProbeFresh(server, sandbox);
}
/** The original behaviour: a fresh sandbox + fresh spawn for EVERY call. Correct and unchanged for
 * genuinely untrusted local execution (an arbitrary npx/uvx-launched third-party server, a Finix-
 * generated server, ...) -- isolating one attempt's egress/output from contaminating the next
 * matters when the thing running is untrusted code. */
function sandboxedProbeFresh(server, sandbox) {
    return async (toolName, args) => {
        const session = await sandbox.enter(server.allowedHosts ?? [], {
            command: server.command ?? "",
            args: server.args ?? [],
        });
        try {
            const client = new Client({ name: "gawk-verify", version: "1.0.0" });
            let text = "";
            // server.env goes through wrapSpawn too: a containerized target does NOT inherit the host
            // spawn env, so merging env only into stdioTransport would silently strip it in-container.
            const spawnOverride = session.wrapSpawn?.(server.command ?? "", server.args ?? [], server.env);
            // Hold the transport: on a startup failure its stderr tail is the ONLY place the real
            // cause exists. `listTools` has always attached it; this path did not, so every
            // containerized probe failure was reported as the bare protocol message.
            const transport = stdioTransport(server, session.envOverrides, spawnOverride);
            try {
                await client.connect(transport);
            }
            catch (e) {
                const cause = explainChildFailure(stderrTailOf(transport));
                const base = e?.message ?? String(e);
                throw new Error(cause ? `${base} — the server failed to start: ${cause}` : base);
            }
            try {
                text = resultText(await client.callTool({ name: toolName, arguments: args }, undefined, {
                    timeout: probeTimeoutMs(),
                }));
            }
            finally {
                await client.close();
            }
            await session.settle?.(); // backends with an async record pipe: let in-flight egress land
            const obs = { egress: session.nonAllowlistedEgress(), resultText: text };
            await session.dispose();
            return { ok: true, obs };
        }
        catch (e) {
            await session.dispose();
            return { ok: false, detail: e?.message ?? String(e) };
        }
    };
}
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
export function sandboxedProbeReused(server, sandbox) {
    let session;
    let client;
    let egressSeen = 0;
    const connect = async () => {
        session = await sandbox.enter(server.allowedHosts ?? [], {
            command: server.command ?? "",
            args: server.args ?? [],
        });
        egressSeen = 0;
        const c = new Client({ name: "gawk-verify", version: "1.0.0" });
        const spawnOverride = session.wrapSpawn?.(server.command ?? "", server.args ?? [], server.env);
        await c.connect(stdioTransport(server, session.envOverrides, spawnOverride));
        return c;
    };
    const callOnce = async (c, toolName, args) => resultText(await c.callTool({ name: toolName, arguments: args }, undefined, {
        timeout: probeTimeoutMs(),
    }));
    const probe = async (toolName, args) => {
        try {
            if (!client)
                client = await connect();
            let text;
            try {
                text = await callOnce(client, toolName, args);
            }
            catch (callErr) {
                // Stale session (provider-side idle close, token expiry) -- tear down and reconnect once,
                // rather than assuming every failure is the tool's own misbehavior.
                try {
                    await client.close();
                }
                catch {
                    // already dead
                }
                try {
                    await session?.dispose();
                }
                catch {
                    // already gone
                }
                session = undefined;
                await delay(reconnectBackoffMs());
                client = await connect();
                text = await callOnce(client, toolName, args);
            }
            await session?.settle?.(); // backends with an async record pipe: let in-flight egress land
            const allEgress = session?.egress() ?? [];
            const newEgress = allEgress.slice(egressSeen);
            egressSeen = allEgress.length;
            const obs = {
                egress: newEgress.filter((r) => !r.allowed),
                resultText: text,
            };
            return { ok: true, obs };
        }
        catch (e) {
            return { ok: false, detail: e?.message ?? String(e) };
        }
    };
    probe.dispose = async () => {
        try {
            await client?.close();
        }
        catch {
            // already dead
        }
        try {
            await session?.dispose();
        }
        catch {
            // already gone
        }
    };
    return probe;
}
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
export function remoteProbe(server) {
    let client;
    const connect = async () => {
        const c = new Client({ name: "gawk-verify", version: "1.0.0" });
        await c.connect(remoteTransport(server));
        return c;
    };
    const callOnce = async (c, toolName, args) => resultText(await c.callTool({ name: toolName, arguments: args }, undefined, {
        timeout: probeTimeoutMs(),
    }));
    const probe = async (toolName, args) => {
        try {
            if (!client)
                client = await connect();
            let text;
            try {
                text = await callOnce(client, toolName, args);
            }
            catch (callErr) {
                // The cached connection may have gone stale (token expiry, idle timeout, provider-side
                // close) -- reconnect once and retry rather than assuming every failure is the tool's own
                // misbehavior. Only ONE retry: a second failure is real, not a stale-connection artifact.
                try {
                    await client.close();
                }
                catch {
                    // already dead -- nothing to close
                }
                await delay(reconnectBackoffMs());
                client = await connect();
                text = await callOnce(client, toolName, args);
            }
            return { ok: true, obs: { egress: [], resultText: text } };
        }
        catch (e) {
            return { ok: false, detail: e?.message ?? String(e) };
        }
    };
    probe.dispose = async () => {
        try {
            await client?.close();
        }
        catch {
            // already dead
        }
    };
    return probe;
}
/**
 * F4: turn a base probe into one that reaches a HIDDEN tool THROUGH a dispatcher's executor. The
 * checks synthesise args against the hidden tool's own schema and call `dispatched(hiddenTool,
 * innerArgs)`; this wraps that into the executor envelope (`execute_tool({tool, args})`, shape
 * discovered by {@link inferExecutorEnvelope}) and delegates to the base probe — so the sandbox,
 * egress observation and N/N reproduction all work exactly as for a visible tool, and the SSRF
 * canary lands in the hidden tool's arg, not the executor's. The base probe still connects to and
 * spawns the SAME server; only the tool name + arguments it sends change.
 */
export function dispatchedProbe(base, executorName, envelope) {
    const probe = (hiddenToolName, innerArgs) => base(executorName, buildDispatchEnvelope(envelope, hiddenToolName, innerArgs));
    probe.dispose = base.dispose;
    return probe;
}
/** One fresh reproduction attempt for a specific {@link VulnCheck} against a tool, via a {@link Probe}. */
export class CheckRunner {
    tool;
    check;
    probe;
    constructor(tool, check, probe) {
        this.tool = tool;
        this.check = check;
        this.probe = probe;
    }
    async attempt(_candidate) {
        const args = this.check.args(this.tool.inputSchema);
        const probe = await this.probe(this.tool.name, args);
        if (!probe.ok)
            return { outcome: "infra-failure", detail: probe.detail };
        const d = this.check.decide(probe.obs);
        return d.reproduced
            ? { outcome: "reproduced", detail: d.detail, evidence: d.evidence ?? {} }
            : { outcome: "not-reproduced", detail: d.detail };
    }
}
//# sourceMappingURL=runner.js.map