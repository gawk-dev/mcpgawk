/**
 * Credential masking for the audit log — the deepest record this engine writes.
 *
 * `--audit-log` appends one JSONL line per reproduction attempt, and each carries
 * `resultTextExcerpt`: 2000 characters of whatever the tool returned. The AuditEvent docstring
 * already conceded those responses "may contain the target's own data" and treated truncation as
 * the mitigation. It is not one. Measured 2026-08-13: verifying a fixture whose `get_config`
 * returns `api_key: sk-…` CONVICTED it for credential-exposure and then wrote that same key,
 * in cleartext, into `~/.gawk/verify-runs/<run>/audit.jsonl`. The detector was storing the
 * evidence it exists to warn about.
 *
 * Shape-preserving on purpose. The audit log is a spot-check trail: a human reading it has to be
 * able to see WHAT the tool returned and judge the verdict. Masking a credential SHAPE leaves the
 * surrounding response intact, and for a credential-exposure finding `[REDACTED]` in the excerpt
 * is exactly the right record — the conviction already says a key was leaked; the trail should
 * show where it appeared without storing it a second time.
 *
 * Deliberately a separate copy of the shapes rather than a shared package: this engine ships as a
 * standalone bundled CLI with its own dependency closure, the same reason `mcpgawk/redact.py` and
 * `gawk_platform/enforce/redact.py` are separate. Drift between the copies is the standing risk,
 * so the tests assert the SHAPES, not just the outcomes.
 */
const SECRETS = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    /\bAKIA[0-9A-Z]{16}\b/g,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    // Vendor-prefixed keys: `sk-live-…`, `sk_test_…`. Hyphens/underscores allowed inside the body.
    /\b(?:sk|pk|rk)[-_][A-Za-z0-9][A-Za-z0-9_-]{18,}\b/g,
    // key = value / token: value. The noun may carry a vendor prefix (`fetch_apiKey=`,
    // `BROWSERSTACK_ACCESS_KEY=`) — the bare-word form cannot match those, because `_` is a word
    // character, and that exact gap let a live key past the platform copy of these patterns.
    /(?:[\w.-]+[_.\-])?(?:api[_-]?key|access[_-]?key|secret[_-]?key|key|secret|token|password|passwd|bearer|credential)s?["']?\s*[:=]\s*["']?\S{8,}/gi,
    /\bauthorization\s*:\s*(?:bearer|basic)\s+\S+/gi,
];
/** A URL's credential-bearing query values and any userinfo, masked but still identifiable. */
function redactUrls(text) {
    return text.replace(/https?:\/\/[^\s'"<>)\]}]+/g, (raw) => {
        try {
            const url = new URL(raw);
            let changed = false;
            if (url.password) {
                url.password = "***";
                changed = true;
            }
            for (const [name] of [...url.searchParams]) {
                if (/(key|token|secret|pass|pwd|auth|sig|credential)/i.test(name)) {
                    url.searchParams.set(name, "***");
                    changed = true;
                }
            }
            return changed ? decodeURIComponent(url.toString()) : raw;
        }
        catch {
            return raw; // not parseable as a URL: leave the text alone rather than mangle it
        }
    });
}
export function redactText(text) {
    let out = redactUrls(text);
    for (const pattern of SECRETS)
        out = out.replace(pattern, "[REDACTED]");
    return out;
}
/**
 * Mask every free-text field of one audit event, leaving identity and measurement fields alone.
 * Applied at the WRITE in cli.ts, so any field added to the event later inherits it only if it is
 * listed here — which is deliberate: silently redacting an unknown field could destroy evidence.
 */
export function redactAuditEvent(event) {
    const out = { ...event };
    for (const field of ["resultTextExcerpt", "infraDetail", "tool", "server"]) {
        const value = out[field];
        if (typeof value === "string")
            out[field] = redactText(value);
    }
    return out;
}
/**
 * Mask credential shapes anywhere in a document that is about to be written to disk, leaving its
 * structure and every ordinary string untouched.
 *
 * Used for the two documents the engine persists whole — `last-verify.json` (`--out`) and the
 * behaviour profile (`--behaviour-profile`). Neither embeds tool OUTPUT (measured 2026-08-13: a
 * convicted `credential-exposure` finding records the classification `{"leaked":"openai-key"}`,
 * not the value), but both record TOOL NAMES, and a name is chosen by the server: a tool called
 * `send_apiKey=…` put a credential into the profile's `skipped` list and the report's tool table.
 *
 * A blanket walk is safe HERE precisely because `redactText` needs a credential SHAPE to fire —
 * an assignment, a vendor prefix, a known key format. Ordinary names (`ordinary_tool`,
 * `create_api_key`), enum labels, ISO timestamps and finding ids pass through unchanged, which the
 * tests pin. It is not safe as a general rule and is not used as one: the audit log still masks
 * named fields only.
 */
export function redactDocument(value) {
    if (typeof value === "string")
        return redactText(value);
    if (Array.isArray(value))
        return value.map((v) => redactDocument(v));
    if (value && typeof value === "object") {
        const out = {};
        for (const [k, v] of Object.entries(value))
            out[k] = redactDocument(v);
        return out;
    }
    return value;
}
//# sourceMappingURL=redact.js.map