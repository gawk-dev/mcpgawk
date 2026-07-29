import { type Server } from "node:http";
import { type VerificationReport } from "./report.js";
import { type AuditEvent } from "./verify.js";
export interface ServeOptions {
    readonly port: number;
    readonly host?: string;
    /** Whether the UI is allowed to request unsafe mode (invokes mutating tools). Default false. */
    readonly unsafeAllowed?: boolean;
    readonly log?: (s: string) => void;
}
/**
 * Verify every server in a parsed config document. A server that can't be reached is recorded as an
 * error, never thrown — the caller always gets one {@link VerificationReport}.
 */
export declare function verifyDoc(doc: unknown, unsafe: boolean, now?: string, isolate?: boolean): Promise<{
    report: VerificationReport;
    audit: AuditEvent[];
}>;
/** Build the HTTP server (exposed for tests). Does not call `.listen()`. */
export declare function createVerifyServer(opts: ServeOptions): Server;
export declare function serve(opts: ServeOptions): Promise<Server>;
//# sourceMappingURL=serve.d.ts.map