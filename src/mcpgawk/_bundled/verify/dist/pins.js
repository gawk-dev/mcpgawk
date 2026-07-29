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
 * Order-independent JSON, matching Python's `json.dumps(sort_keys=True, separators=(",", ":"))`.
 * A schema's key order is not semantic and must not read as a change — and the two runtimes must
 * agree byte for byte, or the same server fingerprints differently depending on which pillar looked
 * at it. (Same cross-runtime discipline as the signed licence cache.)
 */
export function canonical(value) {
    if (value === null || typeof value !== "object")
        return JSON.stringify(value ?? null);
    if (Array.isArray(value))
        return `[${value.map(canonical).join(",")}]`;
    const obj = value;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}
/**
 * The full comparable surface of one tool: what a model READS (name, description), what it can be
 * made to SEND (input schema), and what it CLAIMS about itself (annotations).
 *
 * Byte-identical to src/mcpgawk/fingerprint.py::_tool_basis — including the \x1f separators and
 * the 12-hex digest — so a baseline written by any pillar is readable by every other one.
 */
export function toolBasis(t) {
    const ann = t.annotations;
    return [
        t.name ?? "",
        t.description ?? "",
        canonical(t.inputSchema ?? {}),
        canonical(ann ?? {}),
    ].join("\x1f");
}
export function pinTool(t) {
    return {
        name: t.name,
        hash: createHash("sha256").update(toolBasis(t)).digest("hex").slice(0, 12),
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
//# sourceMappingURL=pins.js.map