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
export declare function redactText(text: string): string;
/**
 * Mask every free-text field of one audit event, leaving identity and measurement fields alone.
 * Applied at the WRITE in cli.ts, so any field added to the event later inherits it only if it is
 * listed here — which is deliberate: silently redacting an unknown field could destroy evidence.
 */
export declare function redactAuditEvent<T extends Record<string, unknown>>(event: T): T;
//# sourceMappingURL=redact.d.ts.map