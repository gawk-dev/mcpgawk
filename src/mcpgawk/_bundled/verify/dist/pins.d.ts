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
/**
 * A fingerprint of one tool. `hash` is the SURFACE hash (basis 2: name + description + input schema +
 * annotations). `content` is the DESCRIPTION-ONLY hash (basis 1, `drift._hash`) — what a server
 * approved after a scan carries in the shared baseline, so verify can compare like with like.
 */
export interface ToolPin {
    readonly name: string;
    readonly hash: string;
    readonly content?: string;
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
export declare function canonical(value: unknown): string;
/**
 * The full comparable surface of one tool: what a model READS (name, description), what it can be
 * made to SEND (input schema), and what it CLAIMS about itself (annotations).
 *
 * Byte-identical to src/mcpgawk/fingerprint.py::_tool_basis — including the \x1f separators, the
 * `str()` of a missing or null field and the `or {}` of an empty schema — so a baseline written by
 * any pillar is readable by every other one.
 */
export declare function toolBasis(t: ToolInfo): string;
/** `drift._hash(description)`: sha256 of the UTF-8 description, None → "". Basis 1. */
export declare function contentHash(description: unknown): string;
export declare function pinTool(t: ToolInfo): ToolPin;
export declare function pinInventory(server: string, tools: readonly ToolInfo[]): ServerPins;
/** Diff a baseline inventory against the current one: added / removed / mutated tools. */
export declare function diffPins(baseline: readonly ToolPin[], current: readonly ToolPin[]): Drift;
export declare function hasDrift(d: Drift): boolean;
/** `drift.TOOLS_BASIS_*`: which rule minted an approved `tools` map. */
export declare const TOOLS_BASIS_CONTENT = 1;
export declare const TOOLS_BASIS_SURFACE = 2;
/** One exported server, as src/mcpgawk/baseline.py::export writes it. */
export interface SharedBaselineEntry {
    readonly pin?: string | null;
    readonly tools?: Record<string, string>;
    readonly tools_basis?: number | null;
    readonly approved_at?: string | null;
    readonly aliases?: readonly string[];
}
/** The export: servers keyed by STORE IDENTITY, plus `names`, config name → that key. */
export interface SharedBaselineShape {
    readonly schema: string;
    readonly servers: Record<string, SharedBaselineEntry>;
    readonly names?: Record<string, string>;
}
/** One server's comparison against its approval. `comparable: false` ⇒ `changed` is not judged. */
export interface SharedComparison {
    readonly comparable: boolean;
    readonly basis: number | null;
    readonly reason?: string;
    readonly drift: Drift;
}
/**
 * The approved entry for the server verify knows by its CONFIG name — through the engine's own
 * `names` index, which it resolves with `history.resolve` (exact key, bare asserted name, alias;
 * ambiguous or unapproved ⇒ absent). verify never guesses a key itself: `servers[configName]`
 * could never hit, because the engine keys by `mcp:<asserted name>`, and a guess here would be a
 * second resolution rule that disagrees with approve, scan and the guard.
 */
export declare function sharedEntryFor(shared: SharedBaselineShape, configName: string): SharedBaselineEntry | undefined;
/**
 * Compare ONE approved entry with the pins verify just computed — like basis with like basis only.
 * A scan-approved map is description-only (basis 1) and is compared on description hashes; a
 * monitor-published map (basis 2) on surface hashes. Any other basis, or an engine too old to say,
 * is NOT COMPARABLE: tool names are still compared (membership needs no hash), `changed` is not —
 * reporting every tool as changed would be a false alarm the operator learns to ignore.
 */
export declare function compareShared(entry: SharedBaselineEntry, current: readonly ToolPin[]): SharedComparison;
/** Every verified server that has an approval in the engine → its comparison. Others are absent. */
export declare function compareSharedBaseline(shared: SharedBaselineShape, servers: readonly ServerPins[]): Record<string, SharedComparison>;
//# sourceMappingURL=pins.d.ts.map