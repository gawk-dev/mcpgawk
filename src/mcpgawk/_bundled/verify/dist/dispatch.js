/**
 * Dynamic tool-dispatch detection — the TS mirror of the Python scanner's
 * `mcpgawk.signals.detect_dynamic_dispatch`. A server can expose a small set of visible tools via
 * tools/list while hiding a much larger real catalog behind a meta-tool (getsentry/sentry-mcp's
 * `search_sentry_tools` + `execute_sentry_tool`; docker/mcp-gateway's `mcp-find` + `mcp-exec`). A
 * single static tools/list — all verify enumerates today — CANNOT see that catalog, so a "clean"
 * result on the visible tools is not proof of a clean server. This detector lets verify say so.
 *
 * Narrow by design (0-FP, matching the scanner): fires only on (a) a paired discover+execute name
 * match, or (b) a single execute-shaped tool whose input schema takes a free-text tool/action
 * selector — NOT an ordinary `execute_workflow(id)` with a fixed, non-dispatching argument.
 */
const DISCOVER_TOOL_NAME = /(?:search|find|discover|list)[-_]?\w*tools?\b|tools?[-_]?(?:search|find|discover|list)\b|^mcp[-_]?find$/i;
const EXEC_TOOL_NAME = /(?:execute|exec|invoke|dispatch|call|run)[-_]?\w*tools?\b|tools?[-_]?(?:execute|exec|invoke|dispatch)\b|^mcp[-_]?(?:exec|add)$|^code[-_]?mode$/i;
const DISPATCH_PARAM_NAMES = new Set(["tool", "tool_name", "toolname", "target_tool", "action"]);
/** The discover meta-tool (`search_tools` / `mcp-find` / …) — the one to CALL to enumerate the
 * hidden catalog. Undefined for a single-executor dispatcher with no discover tool. */
export function discoverToolOf(tools) {
    return tools.find((t) => DISCOVER_TOOL_NAME.test(t.name))?.name;
}
/** The executor meta-tool (`execute_tool` / `mcp-exec` / …) — the one to DRIVE to probe a hidden
 * tool (F4). Returns the tool itself (its schema is needed to infer the envelope), or undefined if
 * there is no executor to dispatch through. */
export function executorToolOf(tools) {
    return tools.find((t) => EXEC_TOOL_NAME.test(t.name));
}
/** Param names a discover tool uses for its free-text query. */
const QUERY_PARAM_NAMES = new Set(["query", "q", "search", "keywords", "term", "text", "prompt"]);
/**
 * If the discover tool REQUIRES a free-text query (a semantic search like sentry's
 * `search_sentry_tools` or docker/mcp-gateway's BM25 `mcp-find`), return that param's name;
 * otherwise `null`. Confirmed live 2026-07-22: sentry's discover has `required: ["query"]` and
 * returns ≤20 of 54 tools — such a tool CANNOT be exhaustively enumerated, so a caller must run
 * keyword queries for PARTIAL coverage and keep the server INCOMPLETE (never a false clean).
 */
export function discoverQueryParam(discoverSchema) {
    const schema = (discoverSchema ?? {});
    const required = Array.isArray(schema.required) ? schema.required : [];
    for (const name of required) {
        const key = name.toLowerCase().replace(/-/g, "_");
        const type = schema.properties?.[name]?.type;
        if (QUERY_PARAM_NAMES.has(key) && type === "string")
            return name;
    }
    return null;
}
/**
 * Keyword queries for enumerating a query-driven discover tool. Biased toward the CAPABILITY words
 * that surface the hidden tools most worth probing — exfiltration, fetch/SSRF, file/secret access,
 * and state mutation — because a semantic search can never return the whole catalog anyway, so the
 * goal is coverage of the DANGEROUS surface, not completeness. Deliberately small and fixed.
 */
export const DISCOVERY_QUERIES = [
    "fetch url http request",
    "read file path",
    "download attachment image",
    "get resource secret token",
    "list search query",
    "create update delete",
    "execute run command",
    "export upload send",
];
/** Parse a discover tool's response into the hidden catalog. DEFENSIVE and best-effort: the wire
 * shape is server-specific, so we accept a bare array or a `{tools|results|data: [...]}` envelope of
 * `{name, description}` objects, and return [] on anything we can't read rather than throwing. Real
 * dispatchers (Sentry / Docker mcp-gateway) will each need their response shape confirmed against
 * this — validated here only against the paired fixture. */
export function parseHiddenCatalog(text) {
    let data;
    try {
        data = JSON.parse(text);
    }
    catch {
        return [];
    }
    const env = data;
    const arr = Array.isArray(data)
        ? data
        : Array.isArray(env?.tools)
            ? env.tools
            : Array.isArray(env?.results)
                ? env.results
                : Array.isArray(env?.data)
                    ? env.data
                    : [];
    const out = [];
    for (const item of arr) {
        const rec = item;
        if (typeof rec?.name !== "string" || rec.name.length === 0)
            continue;
        const description = typeof rec.description === "string" ? rec.description : "";
        // Capture the hidden tool's own schema under whichever key this server uses, so F4 can
        // synthesise valid args and probe it THROUGH the executor. Only attach when actually present
        // — absence is meaningful (enumerated-but-unprobeable), not an empty object to guess against.
        const schema = rec.inputSchema ?? rec.input_schema ?? rec.schema ?? rec.parameters;
        out.push(schema !== undefined && schema !== null
            ? { name: rec.name, description, inputSchema: schema }
            : { name: rec.name, description });
    }
    return out;
}
/** Param names an executor uses to carry the INNER tool's arguments (F4). Strict, known-names
 * only: guessing an unrecognised object param risks landing the SSRF canary in the wrong field and
 * reporting a false clean — better to treat args as un-injectable and stay honest about it. */
const ARGS_PARAM_NAMES = new Set([
    "args",
    "arguments",
    "params",
    "parameters",
    "input",
    "payload",
    "tool_args",
    "tool_input",
    "tool_arguments",
]);
/** Params an executor uses to name the inner tool, for ENVELOPE INFERENCE (which runs only AFTER
 * dispatch is already detected). Broader than {@link DISPATCH_PARAM_NAMES}: it also accepts a param
 * literally named `name`, because the real getsentry/sentry-mcp executor is
 * `execute_sentry_tool({name, arguments})` (captured live 2026-07-22 — see test/sentry-mcp-sample.json).
 * `name` is deliberately kept OUT of DISPATCH_PARAM_NAMES, which drives 0-FP DETECTION, since a bare
 * `name` string param is far too generic to flag an unknown tool as a dispatcher on its own. */
const EXECUTOR_TOOLNAME_PARAMS = new Set([...DISPATCH_PARAM_NAMES, "name"]);
/** Infer the executor's envelope from its input schema, or `null` if it has no free-text tool
 * selector (then it isn't a dispatchable executor we can drive). `argsParam` is null when the
 * executor exposes no recognised args slot — a name-only dispatcher we can call but not inject
 * args into. */
export function inferExecutorEnvelope(executorSchema) {
    const schema = (executorSchema ?? {});
    const props = schema.properties ?? {};
    let toolNameParam = null;
    for (const [pname, pschema] of Object.entries(props)) {
        const key = pname.toLowerCase().replace(/-/g, "_");
        if (EXECUTOR_TOOLNAME_PARAMS.has(key) && pschema?.type === "string") {
            toolNameParam = pname;
            break;
        }
    }
    if (toolNameParam === null)
        return null;
    for (const [pname, pschema] of Object.entries(props)) {
        if (pname === toolNameParam)
            continue;
        const key = pname.toLowerCase().replace(/-/g, "_");
        const type = pschema?.type;
        if (ARGS_PARAM_NAMES.has(key) && (type === "object" || type === "string")) {
            return { toolNameParam, argsParam: pname, argsKind: type === "string" ? "string" : "object" };
        }
    }
    return { toolNameParam, argsParam: null, argsKind: "object" };
}
/** Construct the arguments for a dispatched call: `execute_tool(<this>)` invokes `hiddenTool` with
 * `innerArgs`. Pure — the transport/probe wiring that USES it is F4 Phase 2. */
export function buildDispatchEnvelope(env, hiddenTool, innerArgs) {
    const payload = { [env.toolNameParam]: hiddenTool };
    if (env.argsParam !== null) {
        payload[env.argsParam] = env.argsKind === "string" ? JSON.stringify(innerArgs) : innerArgs;
    }
    return payload;
}
/** Returns the meta-tool name(s) that make this a dispatcher, or [] if it isn't one. */
export function detectDynamicDispatch(tools) {
    const names = tools.map((t) => t.name);
    const discover = [...new Set(names.filter((n) => DISCOVER_TOOL_NAME.test(n)))].sort();
    const executor = [...new Set(names.filter((n) => EXEC_TOOL_NAME.test(n)))].sort();
    if (discover.length > 0 && executor.length > 0) {
        return [...discover, ...executor];
    }
    // Single execute-shaped tool with a free-text dispatch selector param.
    const out = [];
    for (const t of tools) {
        if (!EXEC_TOOL_NAME.test(t.name))
            continue;
        const schema = (t.inputSchema ?? {});
        const props = schema.properties ?? {};
        for (const [pname, pschema] of Object.entries(props)) {
            const key = pname.toLowerCase().replace(/-/g, "_");
            const type = pschema?.type;
            if (DISPATCH_PARAM_NAMES.has(key) && type === "string") {
                out.push(t.name);
                break;
            }
        }
    }
    return out;
}
//# sourceMappingURL=dispatch.js.map