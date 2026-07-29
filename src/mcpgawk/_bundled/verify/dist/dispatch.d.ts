import type { HiddenTool } from "./model.js";
import type { ToolInfo } from "./runner.js";
/** The discover meta-tool (`search_tools` / `mcp-find` / …) — the one to CALL to enumerate the
 * hidden catalog. Undefined for a single-executor dispatcher with no discover tool. */
export declare function discoverToolOf(tools: readonly ToolInfo[]): string | undefined;
/** The executor meta-tool (`execute_tool` / `mcp-exec` / …) — the one to DRIVE to probe a hidden
 * tool (F4). Returns the tool itself (its schema is needed to infer the envelope), or undefined if
 * there is no executor to dispatch through. */
export declare function executorToolOf(tools: readonly ToolInfo[]): ToolInfo | undefined;
/**
 * If the discover tool REQUIRES a free-text query (a semantic search like sentry's
 * `search_sentry_tools` or docker/mcp-gateway's BM25 `mcp-find`), return that param's name;
 * otherwise `null`. Confirmed live 2026-07-22: sentry's discover has `required: ["query"]` and
 * returns ≤20 of 54 tools — such a tool CANNOT be exhaustively enumerated, so a caller must run
 * keyword queries for PARTIAL coverage and keep the server INCOMPLETE (never a false clean).
 */
export declare function discoverQueryParam(discoverSchema: unknown): string | null;
/**
 * Keyword queries for enumerating a query-driven discover tool. Biased toward the CAPABILITY words
 * that surface the hidden tools most worth probing — exfiltration, fetch/SSRF, file/secret access,
 * and state mutation — because a semantic search can never return the whole catalog anyway, so the
 * goal is coverage of the DANGEROUS surface, not completeness. Deliberately small and fixed.
 */
export declare const DISCOVERY_QUERIES: readonly string[];
/** Parse a discover tool's response into the hidden catalog. DEFENSIVE and best-effort: the wire
 * shape is server-specific, so we accept a bare array or a `{tools|results|data: [...]}` envelope of
 * `{name, description}` objects, and return [] on anything we can't read rather than throwing. Real
 * dispatchers (Sentry / Docker mcp-gateway) will each need their response shape confirmed against
 * this — validated here only against the paired fixture. */
export declare function parseHiddenCatalog(text: string): HiddenTool[];
/** How an executor wraps a dispatched call: which property names the inner tool, which carries its
 * args, and whether those args go as an object or a JSON string. Discovered from the executor's
 * OWN input schema — never assumed — so `{tool, args}`, `{tool_name, arguments}` and the real
 * sentry `{name, arguments}` all work, and a schema we can't read degrades honestly to `null`
 * (caller reports INCOMPLETE, F4-3). */
export interface ExecutorEnvelope {
    readonly toolNameParam: string;
    readonly argsParam: string | null;
    readonly argsKind: "object" | "string";
}
/** Infer the executor's envelope from its input schema, or `null` if it has no free-text tool
 * selector (then it isn't a dispatchable executor we can drive). `argsParam` is null when the
 * executor exposes no recognised args slot — a name-only dispatcher we can call but not inject
 * args into. */
export declare function inferExecutorEnvelope(executorSchema: unknown): ExecutorEnvelope | null;
/** Construct the arguments for a dispatched call: `execute_tool(<this>)` invokes `hiddenTool` with
 * `innerArgs`. Pure — the transport/probe wiring that USES it is F4 Phase 2. */
export declare function buildDispatchEnvelope(env: ExecutorEnvelope, hiddenTool: string, innerArgs: Record<string, unknown>): Record<string, unknown>;
/** Returns the meta-tool name(s) that make this a dispatcher, or [] if it isn't one. */
export declare function detectDynamicDispatch(tools: readonly ToolInfo[]): string[];
//# sourceMappingURL=dispatch.d.ts.map