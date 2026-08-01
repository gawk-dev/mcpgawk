const SINK_CLASSES = new Set(["undeclared-egress", "server-side-request-forgery"]);
const SOURCE_CLASSES = new Set(["output-prompt-injection"]);
export function behaviourProfile(report) {
    const servers = {};
    // A CLEAN RUN IS A RESULT. `servers` only ever gains an entry when a tool is CONVICTED, so a
    // server that verified with nothing wrong produced no entry at all — and every consumer that
    // asks "was this observed?" by testing membership therefore read a clean server as one that had
    // never been run. Measured on the founder's fleet 2026-07-30: the engine verified five servers,
    // `behaviour.json` held two, and the panel reported "Unverified 9" after a successful run.
    // The cleaner the fleet, the emptier the evidence — exactly backwards.
    //
    // `verified` records the OBSERVATION, separately from the convictions, for every server this run
    // actually exercised. It deliberately carries what makes a clean result honest:
    //   * toolsChecked  — 0 means nothing was exercised, so this is not evidence of anything;
    //   * skipped       — tools NOT invoked. Absence of a finding for those is not a claim of safety;
    //   * checkErrors   — >0 with 0 findings means "nothing proven wrong AND some checks never ran";
    //   * backend       — which sandbox actually ran it ("none" is the truth for an unisolated run).
    const verified = {};
    for (const s of report.servers) {
        verified[s.server] = {
            toolsChecked: s.toolsChecked,
            skipped: s.skipped.map((t) => t.tool),
            checkErrors: s.checkErrors.length,
            checksRun: [...s.checksRun],
            backend: s.sandboxBackend,
        };
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
    return { schema: "gawk.behaviour/1", servers, verified };
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
    // `verified` merges by the SAME rule as `servers`: this run's observation of a server it verified
    // wins; every other server's prior observation is retained. Without this, verifying one server
    // would erase the record that any other had ever been looked at — the same data-loss bug the
    // comment above describes for convictions, which was fixed on 2026-07-29.
    const outVerified = {};
    const priorVerified = existing && typeof existing === "object" && !Array.isArray(existing)
        ? (existing.verified ?? {})
        : {};
    if (priorVerified && typeof priorVerified === "object" && !Array.isArray(priorVerified)) {
        for (const [srv, obs] of Object.entries(priorVerified)) {
            if (verified.has(srv))
                continue;
            if (obs && typeof obs === "object" && !Array.isArray(obs)) {
                outVerified[srv] = obs;
            }
        }
    }
    for (const [srv, obs] of Object.entries(fresh.verified ?? {}))
        outVerified[srv] = obs;
    return { schema: "gawk.behaviour/1", servers: out, verified: outVerified };
}
//# sourceMappingURL=behaviour.js.map