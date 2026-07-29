import { existsSync, readFileSync, writeFileSync } from "node:fs";
export const SUPPRESSIONS_SCHEMA_VERSION = "1.0";
const EMPTY = { schemaVersion: SUPPRESSIONS_SCHEMA_VERSION, suppressed: {} };
/**
 * A missing file means "nothing suppressed yet" — NOT auto-created on first run the way
 * `--baseline` is. Suppression is an explicit, reviewed operator action (a real finding, looked
 * at, and accepted) — auto-writing "accept everything currently found" on first run would
 * silently accept real vulnerabilities with no review at all. Use `gawk-verify suppress` to add
 * an entry.
 */
export function loadSuppressions(path) {
    if (!existsSync(path))
        return EMPTY;
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return {
        schemaVersion: parsed.schemaVersion ?? SUPPRESSIONS_SCHEMA_VERSION,
        suppressed: parsed.suppressed ?? {},
    };
}
export function isSuppressed(findingId, file) {
    return file.suppressed[findingId];
}
/** Add (or overwrite) one suppression entry and persist it — pure, the caller writes the file. */
export function withSuppression(file, findingId, reason, approvedBy, approvedAt = new Date().toISOString()) {
    return {
        schemaVersion: file.schemaVersion,
        suppressed: { ...file.suppressed, [findingId]: { reason, approvedBy, approvedAt } },
    };
}
export function saveSuppressions(path, file) {
    writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`);
}
//# sourceMappingURL=suppressions.js.map