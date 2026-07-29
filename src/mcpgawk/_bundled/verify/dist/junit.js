/**
 * JUnit XML — the format most CI test-result UIs render natively (a red/green test tree, not
 * just a log). One `<testsuite>` per server; one `<testcase>` per finding. A suppressed finding
 * becomes a JUnit `<skipped/>` testcase (most CI systems render skips distinctly from failures —
 * "reviewed, not run against", which is close enough to "reviewed and accepted" to read
 * correctly at a glance) rather than a `<failure>`, so CI goes green without the finding
 * disappearing from the test tree entirely. A server with zero (active) findings gets one
 * synthetic passing testcase so the suite isn't empty — an empty `<testsuite>` reads as
 * "nothing ran" in most renderers, not "checked, clean".
 *
 * A checkError (see model.ts) becomes a JUnit `<error>` testcase — the element JUnit itself
 * reserves for "this test could not run", distinct from `<failure>` ("this test ran and found a
 * problem"). Before this existed, a run where every check infra-failed produced ONLY the
 * synthetic "no findings" passing testcase — a fully green suite for a server nothing was
 * actually checked on. The synthetic pass is now only added when there are truly zero cases of
 * any kind, so it can never paper over a checkError.
 */
function esc(s) {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
function summarise(evidence) {
    if (Array.isArray(evidence.egress))
        return `sent data to ${evidence.egress.join(", ")}`;
    if (typeof evidence.canary === "string")
        return "fetched an attacker-controlled URL from input";
    if (typeof evidence.snippet === "string")
        return `output: "${evidence.snippet}"`;
    return JSON.stringify(evidence);
}
export function toJUnit(report) {
    const suites = [];
    let totalTests = 0;
    let totalFailures = 0;
    let totalErrors = 0;
    for (const server of report.servers) {
        const active = server.findings.filter((f) => !f.suppressed);
        const suppressed = server.findings.filter((f) => f.suppressed);
        const cases = [];
        for (const f of active) {
            cases.push(`    <testcase name="${esc(`${f.tool} :: ${f.code}`)}" classname="${esc(server.server)}">\n      <failure message="${esc(summarise(f.evidence))}">reproduced ${f.reproOk}/${f.reproTotal}, ${esc(f.findingId)}</failure>\n    </testcase>`);
        }
        for (const f of suppressed) {
            cases.push(`    <testcase name="${esc(`${f.tool} :: ${f.code}`)}" classname="${esc(server.server)}">\n      <skipped message="${esc(f.suppressionReason ?? "reviewed and accepted")}"/>\n    </testcase>`);
        }
        for (const c of server.checkErrors) {
            cases.push(`    <testcase name="${esc(`${c.tool} :: ${c.code}`)}" classname="${esc(server.server)}">\n      <error message="${esc(c.detail)}">check did not complete — infra failure, not a verdict</error>\n    </testcase>`);
        }
        if (cases.length === 0) {
            cases.push(`    <testcase name="no findings" classname="${esc(server.server)}"/>`);
        }
        totalTests += Math.max(cases.length, 1);
        totalFailures += active.length;
        totalErrors += server.checkErrors.length;
        suites.push(`  <testsuite name="${esc(server.server)}" tests="${cases.length || 1}" failures="${active.length}" errors="${server.checkErrors.length}" skipped="${suppressed.length}">\n${cases.join("\n")}\n  </testsuite>`);
    }
    return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="gawk-verify" tests="${totalTests}" failures="${totalFailures}" errors="${totalErrors}">\n${suites.join("\n")}\n</testsuites>\n`;
}
//# sourceMappingURL=junit.js.map