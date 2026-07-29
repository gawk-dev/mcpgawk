/**
 * Synthesise minimal, valid probe arguments for a tool from its JSON-Schema inputSchema, so the
 * verifier can actually invoke the tool (and thus observe its behaviour). Deterministic. A probe
 * string is provided so exfiltrated data is identifiable; checks may override it (e.g. the SSRF
 * check passes a canary URL so it can tell whether the tool fetches attacker-controlled input).
 */
const PROBE = "gawk-probe-canary";
function firstType(schema) {
    const t = schema.type;
    if (Array.isArray(t))
        return typeof t[0] === "string" ? t[0] : "string";
    return typeof t === "string" ? t : "";
}
function isSchema(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
function synthValue(schema, opts) {
    const enumVals = schema.enum;
    if (Array.isArray(enumVals) && enumVals.length > 0)
        return enumVals[0];
    switch (firstType(schema)) {
        case "integer":
        case "number":
            return 1;
        case "boolean":
            return true;
        case "array": {
            const items = schema.items;
            return isSchema(items) ? [synthValue(items, opts)] : [];
        }
        case "object":
            return synthObject(schema, opts);
        default:
            return opts.stringValue ?? PROBE;
    }
}
function synthObject(schema, opts) {
    const out = {};
    const props = isSchema(schema.properties) ? schema.properties : {};
    const required = new Set(Array.isArray(schema.required) ? schema.required.filter((r) => typeof r === "string") : []);
    for (const [key, sub] of Object.entries(props)) {
        // Include required fields; if none are marked required, include all (maximise triggering).
        if ((required.size === 0 || required.has(key)) && isSchema(sub)) {
            out[key] = synthValue(sub, opts);
        }
    }
    return out;
}
/** Build a probe argument object for a tool's inputSchema. */
export function synthesizeArgs(inputSchema, opts = {}) {
    return synthObject(isSchema(inputSchema) ? inputSchema : {}, opts);
}
export const PROBE_TOKEN = PROBE;
//# sourceMappingURL=synth.js.map