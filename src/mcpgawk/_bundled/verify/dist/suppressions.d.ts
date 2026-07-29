export declare const SUPPRESSIONS_SCHEMA_VERSION = "1.0";
/** One reviewed, explicitly accepted finding — never auto-generated, always an operator action. */
export interface SuppressionEntry {
    readonly reason: string;
    readonly approvedBy?: string;
    readonly approvedAt: string;
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
export declare function isSuppressed(findingId: string, file: SuppressionsFile): SuppressionEntry | undefined;
/** Add (or overwrite) one suppression entry and persist it — pure, the caller writes the file. */
export declare function withSuppression(file: SuppressionsFile, findingId: string, reason: string, approvedBy?: string, approvedAt?: string): SuppressionsFile;
export declare function saveSuppressions(path: string, file: SuppressionsFile): void;
//# sourceMappingURL=suppressions.d.ts.map