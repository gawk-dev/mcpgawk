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
/** The hosts a finding reached that its suppression never accepted. Empty when it is covered. */
export function unreviewedHosts(entry, evidence) {
    const reached = evidence?.egress;
    if (entry.hosts === undefined || !Array.isArray(reached))
        return [];
    const accepted = new Set(entry.hosts.map((h) => String(h).toLowerCase()));
    return reached.map((h) => String(h)).filter((h) => !accepted.has(h.toLowerCase()));
}
/**
 * The suppression that covers this finding, or undefined.
 *
 * A finding's id is the server, the tool and the kind of finding, so by id alone a suppression
 * for "fetch reaches api.github.com" also covered the same tool reaching anywhere else, for good
 * (review P5, 2026-11-13). When the entry names the hosts that were accepted and `evidence`
 * carries the hosts this run reached, any host outside the list means the entry does not cover it.
 */
export function isSuppressed(findingId, file, evidence) {
    const entry = file.suppressed[findingId];
    if (entry === undefined)
        return undefined;
    return unreviewedHosts(entry, evidence).length > 0 ? undefined : entry;
}
/** Add (or overwrite) one suppression entry and persist it — pure, the caller writes the file. */
export function withSuppression(file, findingId, reason, approvedBy, approvedAt = new Date().toISOString(), hosts) {
    const entry = hosts === undefined
        ? { reason, approvedBy, approvedAt }
        : { reason, approvedBy, approvedAt, hosts: [...hosts] };
    return {
        schemaVersion: file.schemaVersion,
        suppressed: { ...file.suppressed, [findingId]: entry },
    };
}
export function saveSuppressions(path, file) {
    writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`);
}
//# sourceMappingURL=suppressions.js.map