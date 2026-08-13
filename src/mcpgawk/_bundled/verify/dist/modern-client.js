/**
 * A minimal MCP 2026-07-28 ("modern") client — because the official TypeScript SDK does not have
 * one yet (`@modelcontextprotocol/sdk` dist-tags end at 1.30.0, checked 2026-08-13), and "the
 * verifier cannot check post-upgrade servers" is not an acceptable answer during the ecosystem's
 * upgrade wave.
 *
 * The modern revision is deliberately simple, which is what makes this feasible and safe:
 * stateless request/response, no session, no initialize — `server/discover` states what the
 * server supports, then plain `tools/list` / `tools/call` with the cacheable result envelope
 * (`resultType`/`cacheScope`/`ttlMs`). Wire shapes were driven against a real modern-only server
 * (tests/fixtures/mcp2_only_server.py) before this was written, not read out of the spec.
 *
 * Implements exactly the surface runner.ts uses of the SDK client: listTools / callTool / close.
 * When the SDK ships v2 this file is deleted and the callers keep working — that is the exit
 * criterion, recorded here so it happens.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
export const MODERN_REVISION = "2026-07-28";
const HEADER = "MCP-Protocol-Version";
/** stdio: newline-delimited JSON-RPC to a child process, one in-flight request at a time —
 * verify's checks are sequential, so a queue is complexity without a customer. */
class StdioRpc {
    child;
    pending = new Map();
    nextId = 1;
    stderrTail = [];
    constructor(command, args, env) {
        this.child = spawn(command, args, { env: { ...process.env, ...env }, stdio: "pipe" });
        createInterface({ input: this.child.stdout }).on("line", (line) => {
            let msg;
            try {
                msg = JSON.parse(line);
            }
            catch {
                return; // servers may log non-JSON to stdout; a strict parser would turn noise into failure
            }
            const id = msg.id;
            if (id === undefined)
                return;
            const waiter = this.pending.get(id);
            if (!waiter)
                return;
            this.pending.delete(id);
            if (msg.error) {
                const err = msg.error;
                waiter.reject(new Error(`MCP error ${err.code}: ${err.message}`));
            }
            else {
                waiter.resolve((msg.result ?? {}));
            }
        });
        createInterface({ input: this.child.stderr }).on("line", (line) => {
            this.stderrTail.push(line);
            if (this.stderrTail.length > 20)
                this.stderrTail.shift();
        });
        // BOTH terminal signals. "exit" fires for a process that ran and stopped; "error" fires for
        // one that never started (ENOENT and friends) — and an unhandled "error" event crashes the
        // whole node process. Missing the second made an unverifiable server HANG the CLI for the
        // full request timeout instead of failing in milliseconds (caught by the engine's own
        // partial-report test, not by reasoning).
        const die = (why) => {
            this.dead = new Error(why);
            for (const [, w] of this.pending)
                w.reject(this.dead);
            this.pending.clear();
        };
        this.child.on("error", (e) => die(`server could not start: ${e.message}`));
        this.child.on("exit", () => die(`server process exited${this.stderrTail.length ? `: ${this.stderrTail.join(" | ").slice(0, 300)}` : ""}`));
    }
    dead = null;
    request(method, params) {
        if (this.dead)
            return Promise.reject(this.dead);
        const id = this.nextId++;
        const p = new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            // A hung server must be a diagnosis, not a hang: verify's whole posture.
            setTimeout(() => {
                if (this.pending.delete(id))
                    reject(new Error(`timeout waiting for ${method} (30s)`));
            }, 30_000).unref();
        });
        this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params: params ?? {} })}\n`);
        return p;
    }
    async close() {
        this.child.kill();
    }
}
/** HTTP: one POST per request — the stateless core is the POINT of the modern revision, so a
 * request/response client IS the faithful implementation, not a shortcut. Answers may arrive as
 * plain JSON or as a single SSE event; both are real server behaviours, both are handled. */
class HttpRpc {
    url;
    headers;
    nextId = 1;
    constructor(url, headers) {
        this.url = url;
        this.headers = headers;
    }
    async request(method, params) {
        const res = await fetch(this.url, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                accept: "application/json, text/event-stream",
                [HEADER]: MODERN_REVISION,
                ...this.headers,
            },
            body: JSON.stringify({ jsonrpc: "2.0", id: this.nextId++, method, params: params ?? {} }),
            signal: AbortSignal.timeout(30_000),
        });
        if (!res.ok)
            throw new Error(`HTTP ${res.status} from ${method}`);
        const text = await res.text();
        const payload = (res.headers.get("content-type") ?? "").includes("event-stream")
            ? (text
                .split("\n")
                .find((l) => l.startsWith("data:"))
                ?.slice(5) ?? "")
            : text;
        const msg = JSON.parse(payload);
        if (msg.error) {
            const err = msg.error;
            throw new Error(`MCP error ${err.code}: ${err.message}`);
        }
        return (msg.result ?? {});
    }
    async close() { }
}
export class ModernClient {
    rpc;
    protocolVersion;
    constructor(rpc, protocolVersion) {
        this.rpc = rpc;
        this.protocolVersion = protocolVersion;
    }
    /** Connect by probing `server/discover`. Throws if the server does not speak the modern
     * revision — the caller's legacy path owns that case, mirroring the Python probe's policy. */
    static async connect(rpc) {
        // The spec-faithful envelope: the version travels in params._meta under the
        // io.modelcontextprotocol keys — the server-side era router classifies the request by THAT,
        // not by the method name. A bare {protocolVersion} probe gets "Method not found" from real
        // SDK servers (measured against the SDK's own server before this was fixed).
        const disc = await rpc.request("server/discover", {
            _meta: {
                "io.modelcontextprotocol/protocolVersion": MODERN_REVISION,
                "io.modelcontextprotocol/clientInfo": { name: "gawk-verify", version: "1.0.0" },
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        });
        const versions = disc.supportedVersions ?? [];
        if (!versions.includes(MODERN_REVISION)) {
            await rpc.close();
            throw new Error(`server/discover answered but without ${MODERN_REVISION} (got: ${versions.join(", ") || "none"})`);
        }
        return new ModernClient(rpc, MODERN_REVISION);
    }
    static stdio(command, args, env = {}) {
        return ModernClient.connect(new StdioRpc(command, args, env));
    }
    static http(url, headers = {}) {
        return ModernClient.connect(new HttpRpc(url, headers));
    }
    async listTools() {
        const r = await this.rpc.request("tools/list");
        return { tools: r.tools ?? [] };
    }
    async callTool(params) {
        const r = await this.rpc.request("tools/call", params);
        return {
            content: r.content ?? [],
            isError: r.isError ?? false,
        };
    }
    async close() {
        await this.rpc.close();
    }
}
//# sourceMappingURL=modern-client.js.map