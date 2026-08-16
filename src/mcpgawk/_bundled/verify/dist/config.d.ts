import type { ServerConfig } from "./model.js";
/** A server block as it appears in a user-supplied config (untrusted shape). */
export interface RawServer {
    command?: unknown;
    args?: unknown;
    env?: unknown;
    allowedHosts?: unknown;
    url?: unknown;
    transport?: unknown;
    headers?: unknown;
    backendPrefix?: unknown;
}
/** Normalise one raw server block into a typed {@link ServerConfig}. Throws on an unusable block
 * (including an unresolved `${VAR}` reference in `headers`/`env` — see {@link interpolateEnv}). */
export declare function toConfig(name: string, raw: RawServer): ServerConfig;
/** Pull the `mcpServers` map out of a parsed config document (tolerant of a missing/blank map). */
export declare function serversOf(doc: unknown): Record<string, RawServer>;
//# sourceMappingURL=config.d.ts.map