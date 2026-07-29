/**
 * Licence gate for the standalone `gawk-verify` binary.
 *
 * Why this file exists: verify is a gawk Platform capability, but its gate used to live only in the
 * Python dispatcher (`gawk_platform.cli.require_license`). package.json exposes a `gawk-verify` bin
 * and the wheel ships `_bundled/verify/dist/cli.js`, so anyone holding the file ran the strongest
 * paid pillar unlicensed — the same standalone-entry-point class of hole that was already found and
 * closed for gawk-enforce / gawk-monitor / finix on the Python side.
 *
 * The cache format and its HMAC are deliberately byte-compatible with
 * src/gawk_platform/licensing.py — one file, two readers, one signature. See the honest-scope note
 * there: this is tamper-evidence (a hand-written or copied cache is rejected), not DRM.
 *
 * Unlike the Python path this never calls Lemon Squeezy's *activate* endpoint. Activation consumes
 * a seat against the licence's activation_limit, and a verify run must not silently burn one; it
 * validates the key (with the cached instance id when there is one) and leaves seat allocation to
 * `gawk login`.
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { dirname, join } from "node:path";
const VALIDATE_URL = "https://api.lemonsqueezy.com/v1/licenses/validate";
const CACHE_FORMAT_VERSION = 2;
const SIGNING_CONTEXT = "gawk.license-cache.v2";
const PRODUCT_SALT = "gawk-platform/nativerse-ventures/license-cache-integrity";
const CACHE_TTL_SECONDS = 24 * 60 * 60;
const TIMEOUT_MS = 5000;
export const cachePath = () => process.env.GAWK_LICENSE_CACHE || join(homedir(), ".gawk", "license-cache.json");
const configPath = () => join(homedir(), ".gawk", "config.json");
/**
 * Must match licensing.py::_machine_binding exactly - sha256 of hostname and home directory joined
 * by a NUL byte. Same rationale: no privileged lookups, no MAC address (which changes on VPNs and
 * docks), and it changes when the cache is moved to another machine or user - which is exactly the
 * copy we want to reject.
 */
const machineBinding = () => createHash("sha256").update(`${hostname()}\0${homedir()}`, "utf8").digest();
const signingKey = () => createHmac("sha256", PRODUCT_SALT)
    .update(Buffer.concat([Buffer.from(SIGNING_CONTEXT, "utf8"), machineBinding()]))
    .digest();
/**
 * Byte-identical to licensing.py::_canonical — sorted keys, no whitespace, no \uXXXX escaping.
 * `checked_at` is an integer on both sides: Python renders an integral float as "1000.0" and
 * JavaScript renders it as "1000", which would silently break the shared signature.
 */
export function canonical(payload) {
    const keys = Object.keys(payload).sort();
    const parts = keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(payload[k])}`);
    return `{${parts.join(",")}}`;
}
const sign = (payload) => createHmac("sha256", signingKey()).update(canonical(payload), "utf8").digest("hex");
function signaturesMatch(a, b) {
    const ab = Buffer.from(a, "utf8");
    const bb = Buffer.from(b, "utf8");
    return ab.length === bb.length && timingSafeEqual(ab, bb);
}
export function loadCache() {
    let doc;
    try {
        doc = JSON.parse(readFileSync(cachePath(), "utf8"));
    }
    catch {
        return null;
    }
    if (typeof doc !== "object" || doc === null)
        return null;
    const d = doc;
    // A v1 (unsigned) cache from an older install is ignored rather than migrated — migrating would
    // sign whatever an attacker had already written. Cost to an honest customer: one revalidation.
    if (d.v !== CACHE_FORMAT_VERSION)
        return null;
    const payload = d.payload;
    const sig = d.sig;
    if (typeof payload !== "object" || payload === null || typeof sig !== "string")
        return null;
    if (typeof payload.license_key !== "string" ||
        typeof payload.valid !== "boolean" ||
        typeof payload.checked_at !== "number" ||
        (payload.instance_id !== null && typeof payload.instance_id !== "string"))
        return null;
    const clean = {
        license_key: payload.license_key,
        instance_id: payload.instance_id,
        valid: payload.valid,
        checked_at: payload.checked_at,
    };
    if (!signaturesMatch(sig, sign(clean)))
        return null; // forged, edited, or copied from another machine
    return clean;
}
export function saveCache(state) {
    const payload = { ...state, checked_at: Math.floor(state.checked_at) };
    const p = cachePath();
    try {
        mkdirSync(dirname(p), { recursive: true });
        writeFileSync(p, JSON.stringify({ v: CACHE_FORMAT_VERSION, payload, sig: sign(payload) }));
        chmodSync(p, 0o600);
    }
    catch {
        // A cache we cannot write is a performance loss, never a correctness one — the next run
        // revalidates against Lemon Squeezy rather than silently trusting anything.
    }
}
export function readKey() {
    const fromEnv = (process.env.GAWK_LICENSE_KEY || "").trim();
    if (fromEnv)
        return fromEnv;
    try {
        const cfg = JSON.parse(readFileSync(configPath(), "utf8"));
        return typeof cfg.license_key === "string" ? cfg.license_key.trim() : "";
    }
    catch {
        return "";
    }
}
const postForm = async (url, body) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
        const resp = await fetch(url, {
            method: "POST",
            headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams(body).toString(),
            signal: controller.signal,
        });
        return (await resp.json());
    }
    finally {
        clearTimeout(timer);
    }
};
/** true/false on a real answer from Lemon Squeezy; null if it could not be reached. */
async function validate(key, instanceId, post) {
    const body = { license_key: key };
    if (instanceId)
        body.instance_id = instanceId;
    let resp;
    try {
        resp = await post(VALIDATE_URL, body);
    }
    catch {
        return null;
    }
    if (resp.valid !== true)
        return false;
    const lk = resp.license_key;
    return (lk?.status ?? null) === "active";
}
/**
 * Mirrors licensing.py::check_license_detailed, including its offline policy: fail OPEN inside a
 * fresh same-key cache window (a paying customer on flaky wifi is not blocked), fail CLOSED once
 * the cache is stale, missing, or unsigned.
 */
export async function checkLicense(key, opts = {}) {
    const k = (key || "").trim();
    if (!k)
        return { ok: false, reason: "not-set" };
    const now = opts.now ?? Date.now() / 1000;
    const post = opts.post ?? postForm;
    const cached = loadCache();
    const sameKey = cached && cached.license_key === k ? cached : null;
    const fresh = sameKey !== null && now - sameKey.checked_at < CACHE_TTL_SECONDS;
    if (fresh && sameKey.valid)
        return { ok: true, reason: "ok-cached" };
    const result = await validate(k, sameKey?.instance_id ?? null, post);
    if (result === null) {
        if (fresh)
            return { ok: sameKey.valid, reason: sameKey.valid ? "ok-cached-offline" : "invalid" };
        return { ok: false, reason: "unreachable-no-cache" };
    }
    saveCache({
        license_key: k,
        instance_id: sameKey?.instance_id ?? null,
        valid: result,
        checked_at: now,
    });
    return { ok: result, reason: result ? "ok" : "invalid" };
}
const REMEDY = {
    "not-set": "no licence key found. Run `gawk login <key>` (your key is in your purchase email), or export GAWK_LICENSE_KEY=... for CI — see https://mcp.gawk.dev/activate.html",
    invalid: "your licence key was rejected by Lemon Squeezy — check for a typo, or your subscription may have expired or been cancelled. See https://mcp.gawk.dev/activate.html",
    "unreachable-no-cache": "couldn't reach Lemon Squeezy to verify your key, and there's no recent successful check to fall back on. Check your connection and try again.",
    ok: "",
    "ok-cached": "",
    "ok-cached-offline": "",
};
/**
 * THE gate. Returns 0 when licensed, else prints one actionable line and returns 3 — the same
 * "not licensed" exit code the Python pillars use, so CI treats every pillar identically.
 */
export async function requireLicense(err = console.error, opts = {}) {
    const result = await checkLicense(opts.key ?? readKey(), opts);
    if (result.ok)
        return 0;
    err(`mcpgawk verify: verify is a gawk Platform capability — ${REMEDY[result.reason]}`);
    return 3;
}
//# sourceMappingURL=license.js.map