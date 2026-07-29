/**
 * SARIF 2.1.0 — the format GitHub code scanning (and most CI security dashboards) natively
 * ingest. A suppressed finding is encoded with SARIF's own `suppressions` array (kind:
 * "external", the correct SARIF-native way to say "reviewed, accepted") rather than dropped —
 * GitHub renders that as "dismissed", not "passing", so the review trail survives the format
 * conversion instead of disappearing into it.
 */
const SEVERITY_TO_LEVEL = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "note",
};
function ruleFor(code, klass) {
    return { id: code, shortDescription: { text: `${klass} (${code})` } };
}
/** Render a finding's evidence into one line, mirroring cli.ts's own `summarise`. */
function summarise(evidence) {
    if (Array.isArray(evidence.egress))
        return `sent data to ${evidence.egress.join(", ")}`;
    if (typeof evidence.canary === "string")
        return "fetched an attacker-controlled URL from input";
    if (typeof evidence.snippet === "string")
        return `output: "${evidence.snippet}"`;
    return JSON.stringify(evidence);
}
export function toSarif(report) {
    const rules = new Map();
    const results = [];
    for (const server of report.servers) {
        for (const f of server.findings) {
            if (!rules.has(f.code))
                rules.set(f.code, ruleFor(f.code, f.class));
            results.push({
                ruleId: f.code,
                level: SEVERITY_TO_LEVEL[f.severity] ?? "warning",
                message: {
                    text: `[${f.class}] ${f.tool}: ${summarise(f.evidence)} (reproduced ${f.reproOk}/${f.reproTotal}, ${f.findingId})`,
                },
                locations: [
                    {
                        physicalLocation: {
                            artifactLocation: { uri: `mcp-server:${server.server}/${f.tool}` },
                        },
                    },
                ],
                partialFingerprints: { findingId: f.findingId },
                properties: { severity: f.severity, server: server.server },
                ...(f.suppressed
                    ? {
                        suppressions: [
                            {
                                kind: "external",
                                justification: f.suppressionReason ?? "reviewed and accepted",
                            },
                        ],
                    }
                    : {}),
            });
        }
    }
    // toolExecutionNotifications: SARIF's own place for "the tool itself hit an error running a
    // check" — distinct from `results` (findings). A checkError rendered as a `result` would read
    // as a vulnerability; rendered here it correctly reads as "this check didn't complete", which
    // is what it is. See model.ts's CheckError docstring for why this exists.
    const toolExecutionNotifications = report.servers.flatMap((server) => server.checkErrors.map((c) => ({
        descriptor: { id: c.code },
        message: { text: `${server.server}/${c.tool}: check did not complete — ${c.detail}` },
        level: "error",
    })));
    const sarif = {
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "gawk-verify",
                        informationUri: "https://github.com/gawk-dev/mcpgawk",
                        version: report.schemaVersion,
                        rules: [...rules.values()],
                    },
                },
                results,
                ...(toolExecutionNotifications.length > 0
                    ? { invocations: [{ executionSuccessful: true, toolExecutionNotifications }] }
                    : {}),
            },
        ],
    };
    return `${JSON.stringify(sarif, null, 2)}\n`;
}
//# sourceMappingURL=sarif.js.map