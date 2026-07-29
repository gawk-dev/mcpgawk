/**
 * Structured secret-detection patterns, ported from Invariant's `secrets.py`.
 *
 * Upstream credits its own patterns to https://github.com/Yelp/detect-secrets (also permissively
 * licensed). The value over gawk's prior list is the CONTEXTUAL pattern below — the AWS generic
 * secret only fires near a key/token/password keyword, unlike a bare 40-char-base64 regex alone.
 */
export declare const INVARIANT_SECRET_MARKERS: ReadonlyArray<{
    name: string;
    re: RegExp;
}>;
//# sourceMappingURL=invariant-secrets.d.ts.map