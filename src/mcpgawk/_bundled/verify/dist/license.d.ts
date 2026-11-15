export type LicenseReason = "not-set" | "invalid" | "ok" | "ok-cached" | "ok-cached-offline" | "unreachable-no-cache";
export interface LicenseResult {
    ok: boolean;
    reason: LicenseReason;
}
interface LicenseState {
    license_key: string;
    instance_id: string | null;
    valid: boolean;
    checked_at: number;
}
export declare const cachePath: () => string;
/**
 * Byte-identical to licensing.py::_canonical — sorted keys, no whitespace, no \uXXXX escaping.
 * `checked_at` is an integer on both sides: Python renders an integral float as "1000.0" and
 * JavaScript renders it as "1000", which would silently break the shared signature.
 */
export declare function canonical(payload: LicenseState): string;
export declare function loadCache(): LicenseState | null;
export declare function saveCache(state: LicenseState): void;
export declare function readKey(): string;
type PostFn = (url: string, body: Record<string, string>) => Promise<Record<string, unknown>>;
/**
 * WHOSE licence is this? (review P12, 2026-11-12). Lemon Squeezy's validate endpoint answers for
 * every store, so valid + active only proves the key is real SOMEWHERE: anyone can open a store and
 * mint one. The same pin as the Python engine (src/gawk_platform/licensing.py _provenance_ok) and
 * the site (site/api/_lib/products.js); tests/test_license_pins_agree.py keeps all three equal.
 * store_id/product_id are read from `meta`, falling back to `license_key`, as licensing.py does.
 * A response that cannot name its store is refused, never passed.
 */
export declare const EXPECTED_STORE_ID = 431133;
export declare const EXPECTED_PRODUCT_ID = 1377799;
/**
 * Mirrors licensing.py::check_license_detailed, including its offline policy: fail OPEN inside a
 * fresh same-key cache window (a paying customer on flaky wifi is not blocked), fail CLOSED once
 * the cache is stale, missing, or unsigned.
 */
export declare function checkLicense(key: string, opts?: {
    now?: number;
    post?: PostFn;
}): Promise<LicenseResult>;
/**
 * THE gate. Returns 0 when licensed, else prints one actionable line and returns 3 — the same
 * "not licensed" exit code the Python pillars use, so CI treats every pillar identically.
 */
export declare function requireLicense(err?: (msg: string) => void, opts?: {
    now?: number;
    post?: PostFn;
    key?: string;
}): Promise<number>;
export {};
//# sourceMappingURL=license.d.ts.map