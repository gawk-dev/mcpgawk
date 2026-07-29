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
//# sourceMappingURL=behaviour.js.map