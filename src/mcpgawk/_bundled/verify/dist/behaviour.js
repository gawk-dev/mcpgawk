const SINK_CLASSES = new Set(["undeclared-egress", "server-side-request-forgery"]);
const SOURCE_CLASSES = new Set(["output-prompt-injection"]);
export function behaviourProfile(report) {
    const servers = {};
    for (const s of report.servers) {
        for (const f of s.findings) {
            if (f.suppressed || !f.tool)
                continue; // only real, reproduced, un-suppressed convictions
            const role = SINK_CLASSES.has(f.class)
                ? "sink"
                : SOURCE_CLASSES.has(f.class)
                    ? "source"
                    : null;
            if (!role)
                continue;
            const tools = servers[s.server] ?? {};
            servers[s.server] = tools;
            const sig = tools[f.tool] ?? {};
            tools[f.tool] = sig;
            sig[role] = true;
        }
    }
    return { schema: "gawk.behaviour/1", servers };
}
/**
 * Merge a fresh profile over an existing one, replacing only the servers THIS run verified.
 *
 * Why merge exists: until 2026-07-29 the writer replaced the whole file, so a remote-only
 * front-door run that observed nothing WIPED every other server's recorded behaviour — observed
 * evidence, the product's most expensive asset, destroyed by an unrelated run. A verified server
 * is replaced even to empty (its old convictions may describe a server that has since been
 * fixed); an unverified server's entry is retained untouched.
 */
export function mergeBehaviourProfiles(existing, fresh, verified) {
    const out = {};
    const prior = existing && typeof existing === "object" && !Array.isArray(existing)
        ? (existing.servers ?? {})
        : {};
    if (prior && typeof prior === "object" && !Array.isArray(prior)) {
        for (const [srv, tools] of Object.entries(prior)) {
            if (verified.has(srv))
                continue; // this run's observation of srv wins, even when empty
            if (tools && typeof tools === "object" && !Array.isArray(tools)) {
                out[srv] = tools;
            }
        }
    }
    for (const [srv, tools] of Object.entries(fresh.servers))
        out[srv] = tools;
    return { schema: "gawk.behaviour/1", servers: out };
}
//# sourceMappingURL=behaviour.js.map