import { createHash } from "node:crypto";
/**
 * Schema 2.0 — the fingerprint is now byte-identical to the Python engine's
 * (src/mcpgawk/fingerprint.py::_tool_basis), and includes ANNOTATIONS.
 *
 * 1.0 hashed only {name, description, inputSchema}. A server that flipped
 * `readOnlyHint: true -> false` with `destructiveHint: true` — a tool silently becoming
 * destructive, which is the rug-pull that matters most — produced the IDENTICAL hash, so
 * `--baseline` reported no drift. The Python engine has caught that since B2; verify never did.
 *
 * A 1.0 baseline cannot be compared against 2.0 hashes: every tool would read as changed. Loading
 * one is detected and reported as "re-baseline needed" rather than silently emitting a false-alarm
 * storm that trains the operator to ignore drift.
 */
export const PINS_SCHEMA_VERSION = "2.0";
export const LEGACY_PINS_SCHEMA_VERSIONS = ["1.0"];
/**
 * Order-independent JSON, reproducing Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)` BYTE FOR BYTE.
 *
 * Python is canonical: every stored baseline was written by it, and the release differential pins
 * its output as unchanged. JSON.stringify differs from it in three places, each one a different
 * 12-hex pin for the same tool depending on which pillar looked:
 *   - strings: Python escapes every code unit outside 0x20-0x7E (ensure_ascii) as a lowercase
 *     \uXXXX — an astral character becomes its surrogate pair — where JS emits it raw;
 *   - key order: Python sorts by CODE POINT, JS's default sort by UTF-16 code unit (they disagree
 *     when an astral character meets one in U+E000-U+FFFF);
 *   - floats: Python prints `repr(float)` — exponent form below 1e-4 with a signed, 2-digit
 *     exponent (`1e-05`), where JS prints `0.00001`.
 *
 * ONE INPUT CAN NEVER MATCH, by construction: an INTEGRAL float (`1.0`, `100.0`, `-0.0`, `1e20`).
 * Python keeps it a float and prints `1.0`; in JS it is the same number as the integer `1`. The MCP
 * SDK's transports (stdio, SSE, streamable HTTP) all `JSON.parse` the wire bytes before verify sees
 * a tool, so the source text is gone; verify prints the integer form, which is right for the far
 * more common `maximum: 1`. pydantic / FastMCP servers emit `1.0`/`0.0` for float constraints and
 * defaults, so a basis-2 comparison of such a tool reads as changed. Integers beyond 2^53 lose
 * precision in JS for the same reason.
 */
export function canonical(value) {
    if (value === null || value === undefined)
        return "null";
    if (typeof value === "string")
        return pyString(value);
    if (typeof value === "number")
        return pyNumber(value);
    if (typeof value === "boolean")
        return value ? "true" : "false";
    if (typeof value === "bigint")
        return value.toString();
    if (Array.isArray(value))
        return `[${value.map(canonical).join(",")}]`;
    const obj = value;
    const keys = Object.keys(obj).sort(byCodePoint);
    return `{${keys.map((k) => `${pyString(k)}:${canonical(obj[k])}`).join(",")}}`;
}
const SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\b": "\\b",
    "\f": "\\f",
};
/** `json.dumps(s, ensure_ascii=True)`: by UTF-16 code unit, so astral = surrogate pair. */
function pyString(s) {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
        const ch = s[i];
        const short = SHORT_ESCAPES[ch];
        if (short !== undefined)
            out += short;
        else {
            const code = s.charCodeAt(i);
            out += code >= 0x20 && code <= 0x7e ? ch : `\\u${code.toString(16).padStart(4, "0")}`;
        }
    }
    return `${out}"`;
}
/** Python's json number: an int prints its digits; a float prints `float.__repr__`. */
function pyNumber(n) {
    if (Number.isNaN(n))
        return "NaN";
    if (!Number.isFinite(n))
        return n > 0 ? "Infinity" : "-Infinity";
    // Integral: the int/float distinction is gone (see `canonical`); print the integer form.
    if (Number.isInteger(n))
        return Math.abs(n) < 1e21 ? String(n === 0 ? 0 : n) : BigInt(n).toString();
    // Non-integral ⇒ |n| < 2^52 < 1e16, so Python's only exponent case is |n| < 1e-4. Both runtimes
    // print the SHORTEST round-trip digits; only the layout differs.
    if (Math.abs(n) >= 1e-4)
        return String(n);
    const [mantissa, exp] = n.toExponential().split("e");
    const sign = exp.startsWith("-") ? "-" : "+";
    return `${mantissa}e${sign}${exp.replace(/^[+-]/, "").padStart(2, "0")}`;
}
function byCodePoint(a, b) {
    let i = 0;
    let j = 0;
    while (i < a.length && j < b.length) {
        const ca = a.codePointAt(i);
        const cb = b.codePointAt(j);
        if (ca !== cb)
            return ca - cb;
        i += ca > 0xffff ? 2 : 1;
        j += cb > 0xffff ? 2 : 1;
    }
    return a.length - i - (b.length - j);
}
/** Python's `str(x)` for the scalar values a tool's name/description can hold. */
function pyStr(v) {
    if (v === undefined)
        return "";
    if (v === null)
        return "None";
    if (typeof v === "boolean")
        return v ? "True" : "False";
    if (typeof v === "number")
        return Number.isInteger(v) ? String(v) : pyNumber(v);
    return String(v);
}
/** Python truthiness, for `x or {}`: None, False, 0, "", [] and {} are all falsy. */
function pyOr(v) {
    if (v === null || v === undefined || v === false || v === 0 || v === "")
        return {};
    if (Array.isArray(v) && v.length === 0)
        return {};
    if (typeof v === "object" && Object.keys(v).length === 0)
        return {};
    return v;
}
/**
 * The full comparable surface of one tool: what a model READS (name, description), what it can be
 * made to SEND (input schema), and what it CLAIMS about itself (annotations).
 *
 * Byte-identical to src/mcpgawk/fingerprint.py::_tool_basis — including the \x1f separators, the
 * `str()` of a missing or null field and the `or {}` of an empty schema — so a baseline written by
 * any pillar is readable by every other one.
 */
export function toolBasis(t) {
    const raw = t;
    return [
        pyStr(raw.name),
        pyStr(raw.description),
        canonical(pyOr(raw.inputSchema)),
        canonical(pyOr(raw.annotations)),
    ].join("\x1f");
}
/** `drift._hash(description)`: sha256 of the UTF-8 description, None → "". Basis 1. */
export function contentHash(description) {
    const text = typeof description === "string" ? description : "";
    return createHash("sha256").update(text, "utf8").digest("hex").slice(0, 12);
}
export function pinTool(t) {
    return {
        name: t.name,
        hash: createHash("sha256").update(toolBasis(t), "utf8").digest("hex").slice(0, 12),
        content: contentHash(t.description),
    };
}
export function pinInventory(server, tools) {
    return { server, tools: tools.map(pinTool) };
}
/** Diff a baseline inventory against the current one: added / removed / mutated tools. */
export function diffPins(baseline, current) {
    const before = new Map(baseline.map((p) => [p.name, p.hash]));
    const now = new Map(current.map((p) => [p.name, p.hash]));
    const added = [];
    const removed = [];
    const changed = [];
    for (const name of now.keys())
        if (!before.has(name))
            added.push(name);
    for (const [name, hash] of before) {
        if (!now.has(name))
            removed.push(name);
        else if (now.get(name) !== hash)
            changed.push(name);
    }
    return { added, removed, changed };
}
export function hasDrift(d) {
    return d.added.length > 0 || d.removed.length > 0 || d.changed.length > 0;
}
// ------------------------------------------------------------------------------------------------
// The shared baseline — what the operator approved in the engine (`mcpgawk baseline --json`).
// ------------------------------------------------------------------------------------------------
/** `drift.TOOLS_BASIS_*`: which rule minted an approved `tools` map. */
export const TOOLS_BASIS_CONTENT = 1;
export const TOOLS_BASIS_SURFACE = 2;
/**
 * The approved entry for the server verify knows by its CONFIG name — through the engine's own
 * `names` index, which it resolves with `history.resolve` (exact key, bare asserted name, alias;
 * ambiguous or unapproved ⇒ absent). verify never guesses a key itself: `servers[configName]`
 * could never hit, because the engine keys by `mcp:<asserted name>`, and a guess here would be a
 * second resolution rule that disagrees with approve, scan and the guard.
 */
export function sharedEntryFor(shared, configName) {
    const names = shared.names;
    if (!names || !Object.hasOwn(names, configName))
        return undefined;
    const key = names[configName];
    return Object.hasOwn(shared.servers ?? {}, key) ? shared.servers[key] : undefined;
}
/**
 * Compare ONE approved entry with the pins verify just computed — like basis with like basis only.
 * A scan-approved map is description-only (basis 1) and is compared on description hashes; a
 * monitor-published map (basis 2) on surface hashes. Any other basis, or an engine too old to say,
 * is NOT COMPARABLE: tool names are still compared (membership needs no hash), `changed` is not —
 * reporting every tool as changed would be a false alarm the operator learns to ignore.
 */
export function compareShared(entry, current) {
    const prior = Object.entries(entry.tools ?? {}).map(([name, hash]) => ({ name, hash }));
    const basis = typeof entry.tools_basis === "number" ? entry.tools_basis : null;
    if (basis === TOOLS_BASIS_SURFACE) {
        return { comparable: true, basis, drift: diffPins(prior, current) };
    }
    if (basis === TOOLS_BASIS_CONTENT) {
        const byContent = current.map((p) => ({ name: p.name, hash: p.content ?? "" }));
        return {
            comparable: true,
            basis,
            reason: "approved after a scan: description-only hashes, so a schema or annotation change is " +
                "not visible against this approval",
            drift: diffPins(prior, byContent),
        };
    }
    const membership = diffPins(prior, current);
    return {
        comparable: false,
        basis,
        reason: basis === null
            ? "not comparable: the engine did not say which rule minted the approved hashes " +
                "(too old to export tools_basis) — compared tool names only"
            : `not comparable: the approved hashes use rule ${basis}, which this verify does not compute — compared tool names only`,
        drift: { added: membership.added, removed: membership.removed, changed: [] },
    };
}
/** Every verified server that has an approval in the engine → its comparison. Others are absent. */
export function compareSharedBaseline(shared, servers) {
    const out = {};
    for (const s of servers) {
        const entry = sharedEntryFor(shared, s.server);
        if (!entry?.tools || Object.keys(entry.tools).length === 0)
            continue;
        out[s.server] = compareShared(entry, s.tools);
    }
    return out;
}
//# sourceMappingURL=pins.js.map