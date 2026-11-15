export declare const SUPPRESSIONS_SCHEMA_VERSION = "1.0";
/** One reviewed, explicitly accepted finding — never auto-generated, always an operator action. */
export interface SuppressionEntry {
    readonly reason: string;
    readonly approvedBy?: string;
    readonly approvedAt: string;
    /**
     * The hosts that were reviewed and accepted, for a finding whose evidence is a list of hosts
     * (undeclared egress). Present: the suppression covers the finding only while every host it
     * reaches is in this list (review P5). Absent: the suppression is by finding id alone, as
     * every suppression was before this field existed.
     */
    readonly hosts?: readonly string[];
}
export interface SuppressionsFile {
    readonly schemaVersion: string;
    readonly suppressed: Readonly<Record<string, SuppressionEntry>>;
}
/**
 * A missing file means "nothing suppressed yet" — NOT auto-created on first run the way
 * `--baseline` is. Suppression is an explicit, reviewed operator action (a real finding, looked
 * at, and accepted) — auto-writing "accept everything currently found" on first run would
 * silently accept real vulnerabilities with no review at all. Use `gawk-verify suppress` to add
 * an entry.
 */
export declare function loadSuppressions(path: string): SuppressionsFile;
/** The hosts a finding reached that its suppression never accepted. Empty when it is covered. */
export declare function unreviewedHosts(entry: SuppressionEntry, evidence?: Readonly<Record<string, unknown>>): string[];
/**
 * The suppression that covers this finding, or undefined.
 *
 * A finding's id is the server, the tool and the kind of finding, so by id alone a suppression
 * for "fetch reaches api.github.com" also covered the same tool reaching anywhere else, for good
 * (review P5, 2026-11-13). When the entry names the hosts that were accepted and `evidence`
 * carries the hosts this run reached, any host outside the list means the entry does not cover it.
 */
export declare function isSuppressed(findingId: string, file: SuppressionsFile, evidence?: Readonly<Record<string, unknown>>): SuppressionEntry | undefined;
/** Add (or overwrite) one suppression entry and persist it — pure, the caller writes the file. */
export declare function withSuppression(file: SuppressionsFile, findingId: string, reason: string, approvedBy?: string, approvedAt?: string, hosts?: readonly string[]): SuppressionsFile;
export declare function saveSuppressions(path: string, file: SuppressionsFile): void;
//# sourceMappingURL=suppressions.d.ts.map