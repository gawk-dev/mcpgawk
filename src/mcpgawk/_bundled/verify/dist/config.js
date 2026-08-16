const record = (v) => v && typeof v === "object" ? v : undefined;
/**
 * `${VAR_NAME}` in a config string is substituted from `process.env.VAR_NAME` — so a committed
 * config.json can reference `"Authorization": "Bearer ${MY_TOKEN}"` instead of the literal
 * secret. Throws if the referenced variable isn't set: a silently-empty/literal-"${...}" secret
 * that fails auth downstream is a worse failure mode than refusing to start.
 */
function interpolateEnv(value) {
    return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (match, name) => {
        const v = process.env[name];
        if (v === undefined) {
            throw new Error(`config references \${${name}}, but that environment variable is not set`);
        }
        return v;
    });
}
function interpolateRecord(r) {
    if (!r)
        return undefined;
    const out = {};
    for (const [k, v] of Object.entries(r))
        out[k] = interpolateEnv(v);
    return out;
}
/** Normalise one raw server block into a typed {@link ServerConfig}. Throws on an unusable block
 * (including an unresolved `${VAR}` reference in `headers`/`env` — see {@link interpolateEnv}). */
export function toConfig(name, raw) {
    if (typeof raw.url === "string" && raw.url) {
        const t = raw.transport === "sse" ? "sse" : "http";
        return {
            name,
            url: raw.url,
            transport: t,
            headers: interpolateRecord(record(raw.headers)),
            // Through-gateway routing: which backend of the gateway endpoint this entry addresses.
            backendPrefix: typeof raw.backendPrefix === "string" ? raw.backendPrefix : undefined,
        };
    }
    if (typeof raw.command !== "string") {
        throw new Error(`server '${name}': needs either "command" (local) or "url" (remote)`);
    }
    return {
        name,
        command: raw.command,
        args: Array.isArray(raw.args) ? raw.args.map(String) : [],
        env: interpolateRecord(record(raw.env)),
        allowedHosts: Array.isArray(raw.allowedHosts) ? raw.allowedHosts.map(String) : [],
    };
}
/** Pull the `mcpServers` map out of a parsed config document (tolerant of a missing/blank map). */
export function serversOf(doc) {
    return doc?.mcpServers ?? {};
}
//# sourceMappingURL=config.js.map