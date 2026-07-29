import type { ToolInfo } from "./runner.js";
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
export declare const PINS_SCHEMA_VERSION = "2.0";
export declare const LEGACY_PINS_SCHEMA_VERSIONS: string[];
/** A fingerprint of one tool (name + description + input schema). A change ⇒ the tool mutated. */
export interface ToolPin {
    readonly name: string;
    readonly hash: string;
}
export interface ServerPins {
    readonly server: string;
    readonly tools: readonly ToolPin[];
}
/** A baseline file — the pinned inventory of a set of servers at a known-good moment. */
export interface Baseline {
    readonly schemaVersion: string;
    readonly pins: readonly ServerPins[];
}
/** What changed between a baseline and the current inventory — the rug-pull signal. */
export interface Drift {
    readonly added: readonly string[];
    readonly removed: readonly string[];
    readonly changed: readonly string[];
}
/**
 * Order-independent JSON, matching Python's `json.dumps(sort_keys=True, separators=(",", ":"))`.
 * A schema's key order is not semantic and must not read as a change — and the two runtimes must
 * agree byte for byte, or the same server fingerprints differently depending on which pillar looked
 * at it. (Same cross-runtime discipline as the signed licence cache.)
 */
export declare function canonical(value: unknown): string;
/**
 * The full comparable surface of one tool: what a model READS (name, description), what it can be
 * made to SEND (input schema), and what it CLAIMS about itself (annotations).
 *
 * Byte-identical to src/mcpgawk/fingerprint.py::_tool_basis — including the \x1f separators and
 * the 12-hex digest — so a baseline written by any pillar is readable by every other one.
 */
export declare function toolBasis(t: ToolInfo): string;
export declare function pinTool(t: ToolInfo): ToolPin;
export declare function pinInventory(server: string, tools: readonly ToolInfo[]): ServerPins;
/** Diff a baseline inventory against the current one: added / removed / mutated tools. */
export declare function diffPins(baseline: readonly ToolPin[], current: readonly ToolPin[]): Drift;
export declare function hasDrift(d: Drift): boolean;
//# sourceMappingURL=pins.d.ts.map