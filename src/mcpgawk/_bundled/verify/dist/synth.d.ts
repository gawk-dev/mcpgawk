/**
 * Synthesise minimal, valid probe arguments for a tool from its JSON-Schema inputSchema, so the
 * verifier can actually invoke the tool (and thus observe its behaviour). Deterministic. A probe
 * string is provided so exfiltrated data is identifiable; checks may override it (e.g. the SSRF
 * check passes a canary URL so it can tell whether the tool fetches attacker-controlled input).
 */
export interface SynthOptions {
    /** Value to use for string leaves (default: a recognisable probe token). */
    readonly stringValue?: string;
}
/** Build a probe argument object for a tool's inputSchema. */
export declare function synthesizeArgs(inputSchema: unknown, opts?: SynthOptions): Record<string, unknown>;
export declare const PROBE_TOKEN = "gawk-probe-canary";
//# sourceMappingURL=synth.d.ts.map