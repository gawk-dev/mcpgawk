export declare const MODERN_REVISION = "2026-07-28";
type Json = Record<string, unknown>;
export interface ModernToolsResult {
    tools: {
        name: string;
        description?: string;
        inputSchema?: Json;
        annotations?: Json;
    }[];
}
export interface ModernCallResult {
    content: {
        type: string;
        text?: string;
    }[];
    isError?: boolean;
}
interface Rpc {
    request(method: string, params?: Json): Promise<Json>;
    close(): Promise<void>;
}
export declare class ModernClient {
    private rpc;
    readonly protocolVersion: string;
    private constructor();
    /** Connect by probing `server/discover`. Throws if the server does not speak the modern
     * revision — the caller's legacy path owns that case, mirroring the Python probe's policy. */
    static connect(rpc: Rpc): Promise<ModernClient>;
    static stdio(command: string, args: string[], env?: Record<string, string>): Promise<ModernClient>;
    static http(url: string, headers?: Record<string, string>): Promise<ModernClient>;
    listTools(): Promise<ModernToolsResult>;
    callTool(params: {
        name: string;
        arguments?: Json;
    }): Promise<ModernCallResult>;
    close(): Promise<void>;
}
export {};
//# sourceMappingURL=modern-client.d.ts.map