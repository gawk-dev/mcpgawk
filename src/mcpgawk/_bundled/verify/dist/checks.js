import { INVARIANT_SECRET_MARKERS } from "./adapters/pulled/invariant-secrets.js";
import { synthesizeArgs } from "./synth.js";
/** A non-allowlisted host we plant in tool inputs to detect input-driven fetches (SSRF). */
const SSRF_CANARY = "gawk-ssrf-canary.invalid";
/**
 * Agent-directed instructions that should never appear in a tool's OUTPUT — the payload of a
 * tool-poisoning / rug-pull attack (the description can be clean while the runtime output hijacks
 * the calling agent). Patterns follow the publicly documented MCP tool-poisoning techniques.
 */
const INJECTION_MARKERS = [
    /ignore\s+(all\s+|the\s+)?(previous|prior|above)\s+instructions?/i,
    /disregard\s+(all\s+|the\s+)?(previous|prior|above)/i,
    /<\/?(important|system|secret|instructions?|assistant)>/i,
    /do\s+not\s+(tell|inform|mention|reveal)\s+(the\s+)?user/i,
    /you\s+(must|should|are required to)\s+(now\s+)?(call|use|send|forward|email|exfiltrate)/i,
    /\bBEGIN\s+SYSTEM\b/i,
];
/**
 * Class 1 — undeclared egress: the tool sends a request to a host NOT in the declared allowlist.
 * From egress alone we cannot distinguish data exfiltration from benign telemetry/CDN/update-checks,
 * so this is reported as HIGH ("verify these are legitimate upstreams") rather than a false CRITICAL.
 */
const undeclaredEgress = {
    code: "undeclared-egress",
    findingClass: "undeclared-egress",
    severity: "high",
    label: "EGRESS",
    detects: "the tool sends data to a host you did not declare (data exfiltration or undisclosed telemetry)",
    applicability: "sandboxed",
    args: (schema) => synthesizeArgs(schema), // benign inputs — the egress is the tool's own doing
    decide: (obs) => {
        // Ignore the SSRF canary here; this class is about the tool's OWN destinations.
        const hosts = [
            ...new Set(obs.egress.filter((e) => e.hostname !== SSRF_CANARY).map((e) => e.hostname)),
        ];
        return hosts.length > 0
            ? {
                reproduced: true,
                detail: `contacted ${hosts.join(", ")} (not in allowedHosts — verify these are legitimate upstreams, else exfiltration)`,
                evidence: {
                    egress: hosts,
                    note: "undeclared HTTP egress — verify or it is data exfiltration",
                },
            }
            : { reproduced: false, detail: "no undeclared HTTP egress" };
    },
};
/** Class 2 — SSRF: the tool fetches a URL taken from its input (reaches attacker-chosen hosts). */
const ssrf = {
    code: "ssrf",
    findingClass: "server-side-request-forgery",
    severity: "high",
    label: "SSRF ",
    detects: "the tool fetches a URL taken from its own input, so an attacker can make it reach internal or attacker-chosen hosts",
    applicability: "sandboxed",
    args: (schema) => synthesizeArgs(schema, { stringValue: `http://${SSRF_CANARY}/probe` }),
    decide: (obs) => {
        const hit = obs.egress.some((e) => e.hostname === SSRF_CANARY);
        return hit
            ? {
                reproduced: true,
                detail: `fetched an attacker-controlled URL from input (${SSRF_CANARY})`,
                evidence: { canary: SSRF_CANARY },
            }
            : { reproduced: false, detail: "did not fetch input URLs" };
    },
};
/** Class 3 — tool poisoning: the tool's OUTPUT carries instructions aimed at the calling agent. */
const toolPoisoning = {
    code: "tool-poisoning",
    findingClass: "output-prompt-injection",
    severity: "high",
    label: "POISON",
    detects: "the tool's output smuggles instructions aimed at the calling AI agent (tool poisoning / prompt injection)",
    applicability: "output",
    args: (schema) => synthesizeArgs(schema), // benign inputs; the payload is in the output
    decide: (obs) => {
        const marker = INJECTION_MARKERS.find((m) => m.test(obs.resultText));
        if (!marker)
            return { reproduced: false, detail: "output carried no agent-directed instructions" };
        const match = obs.resultText.match(marker)?.[0] ?? "";
        return {
            reproduced: true,
            detail: "tool output contains agent-directed instructions (tool poisoning)",
            evidence: { snippet: match.slice(0, 120) },
        };
    },
};
/** Precise, structural signatures for well-known secret formats (low false-positive). */
const SECRET_MARKERS = [
    { name: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
    { name: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
    { name: "github-token", re: /ghp_[A-Za-z0-9]{36}/ },
    { name: "slack-token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
    { name: "openai-key", re: /\bsk-[A-Za-z0-9]{20,}\b/ },
    ...INVARIANT_SECRET_MARKERS,
];
/** Class 4 — credential exposure: the tool's OUTPUT leaks a secret (API key, private key, token). */
const secretLeak = {
    code: "secret-leak",
    findingClass: "credential-exposure",
    severity: "high",
    label: "SECRET",
    detects: "the tool's output leaks a credential — API key, token, or private key",
    applicability: "output",
    args: (schema) => synthesizeArgs(schema),
    decide: (obs) => {
        const hit = SECRET_MARKERS.find((m) => m.re.test(obs.resultText));
        return hit
            ? { reproduced: true, detail: `output leaked a ${hit.name}`, evidence: { leaked: hit.name } } // value redacted
            : { reproduced: false, detail: "no credentials in output" };
    },
};
export const CHECKS = [undeclaredEgress, ssrf, toolPoisoning, secretLeak];
export { SSRF_CANARY, INJECTION_MARKERS };
//# sourceMappingURL=checks.js.map