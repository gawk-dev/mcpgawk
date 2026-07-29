import { Verifier } from "@gawk/oracle";
import { DockerProcessSandbox, ProcessSandbox, ProxiedContainerSandbox, canProxyContainerize, } from "@gawk/sandbox";
import { CHECKS } from "./checks.js";
import { classifyTool } from "./classify.js";
import { DISCOVERY_QUERIES, detectDynamicDispatch, discoverQueryParam, discoverToolOf, executorToolOf, inferExecutorEnvelope, parseHiddenCatalog, } from "./dispatch.js";
import { isRemote, } from "./model.js";
import { pinInventory } from "./pins.js";
import { CheckRunner, callToolText, dispatchedProbe, listTools, remoteProbe, sandboxedProbe, sandboxedProbeReused, } from "./runner.js";
/**
 * `--isolate` (opt-in, NOT the default): Docker is required for full protection. When it's
 * reachable and the server's command maps onto a known runtime — plain `node`/`python` AND the
 * install-on-launch commands (`npx`/`uvx`) — the {@link ProxiedContainerSandbox} runs: OS-level
 * isolation whose only route out is our egress proxy, so exfil over ANY channel is blocked while
 * HTTP(S) egress (including the package install fetch) stays fully observed, in the same run
 * (ADR-0014). Otherwise this degrades to the proxy-only sandbox and says so via the returned
 * reason — never silently claims stronger coverage than what ran.
 *
 * Still not the default: the container spin-up (network + sidecar per probe) costs real seconds
 * per call, so the fast host-proxy sandbox remains the everyday path and `--isolate` is the
 * deliberate stronger pass. Unlike the old `--network none` backend, isolation no longer costs
 * the SSRF-canary/undeclared-egress signal — allowlisted hosts stay reachable through the proxy.
 */
async function selectIsolatedSandbox(server) {
    if (!canProxyContainerize(server.command ?? "")) {
        return {
            sandbox: new ProcessSandbox(),
            backend: "proxy",
            degradedReason: `command "${server.command}" can't be containerized (supported: node/python invocations of a local script, and install-on-launch commands npx/uvx) — falling back to the proxy-only sandbox, which does not see raw-socket/DNS/UDP exfiltration.`,
        };
    }
    if (!(await ProxiedContainerSandbox.isAvailable())) {
        return {
            sandbox: new ProcessSandbox(),
            backend: "proxy",
            degradedReason: "Docker daemon unreachable — falling back to the proxy-only sandbox, which does not see " +
                "raw-socket/DNS/UDP exfiltration.",
        };
    }
    return { sandbox: new ProxiedContainerSandbox(), backend: "proxied-container" };
}
/**
 * Run every applicable check against one tool via `probe`, reproduction-verifying (N/N) and
 * emitting the live audit events. Extracted so a HIDDEN tool reached through a dispatcher
 * (`attributionName` = "tool via executor", probe = a {@link dispatchedProbe}) is verified by the
 * exact same path as a visible one — no second, drifting copy of the check loop.
 */
async function runToolChecks(tool, checks, probe, ctx, attributionName = tool.name) {
    const findings = [];
    const checkErrors = [];
    for (const check of checks) {
        const candidate = {
            code: check.code,
            findingClass: check.findingClass,
            serverId: ctx.serverName,
            toolName: attributionName,
            severity: check.severity,
        };
        // Emits a `raw-observation` for EVERY attempt (not just ones that end up in a finding) — the
        // actual evidence, not just the decided verdict. See the AuditEvent variant's docstring.
        let attemptNum = 0;
        const auditingProbe = async (toolName, args) => {
            attemptNum += 1;
            const result = await probe(toolName, args);
            ctx.emit({
                type: "raw-observation",
                server: ctx.serverName,
                tool: attributionName,
                code: check.code,
                attempt: attemptNum,
                ok: result.ok,
                resultTextExcerpt: result.ok ? result.obs.resultText.slice(0, 2000) : undefined,
                egress: result.ok ? result.obs.egress : undefined,
                infraDetail: result.ok ? undefined : result.detail,
            });
            return result;
        };
        const outcome = await new Verifier(new CheckRunner(tool, check, auditingProbe)).verify(candidate, { attempts: ctx.attempts });
        if (outcome.kind === "verdict")
            findings.push(outcome.verdict);
        const isInfra = outcome.kind !== "verdict" && /infra/i.test(outcome.reason);
        if (outcome.kind !== "verdict" && isInfra) {
            checkErrors.push({ tool: attributionName, code: check.code, detail: outcome.reason });
        }
        ctx.emit({
            type: "check",
            server: ctx.serverName,
            tool: attributionName,
            code: check.code,
            label: check.label.trim(),
            severity: check.severity,
            outcome: outcome.kind === "verdict" ? "reproduced" : isInfra ? "error" : "clean",
            attemptsOk: outcome.attemptsOk,
            attemptsRun: outcome.attemptsRun,
            detail: outcome.kind === "verdict"
                ? `reproduced ${outcome.verdict.reproOk}/${outcome.verdict.reproTotal}`
                : outcome.reason,
            evidence: outcome.kind === "verdict" ? outcome.verdict.evidence : undefined,
        });
    }
    return { findings, checkErrors };
}
/**
 * Verify one MCP server behaviourally: enumerate its tools, then for each callable one run every
 * applicable vulnerability check — each driving the tool and reproduction-verifying (N/N).
 *
 * LOCAL (stdio) servers run inside a fresh no-egress sandbox, so ALL checks apply (exfil, SSRF,
 * tool-poisoning). REMOTE (HTTP/SSE) servers run on the provider's infrastructure and cannot be
 * sandboxed, so only OUTPUT-based checks apply (tool-poisoning) — the egress-based checks are
 * reported as not-run rather than faked.
 */
export async function verifyServer(server, opts = {}) {
    const attempts = opts.attempts ?? 3;
    const mode = opts.mode ?? "safe";
    const emit = opts.onEvent ?? (() => { });
    const remote = isRemote(server);
    const transport = remote ? (server.transport ?? "http") : "stdio";
    let sandboxBackend = "none";
    let sandboxDegradedReason;
    let sandbox;
    if (remote) {
        sandbox = new ProcessSandbox(); // unused for remote (remoteProbe doesn't sandbox at all)
    }
    else if (opts.sandbox) {
        sandbox = opts.sandbox;
        sandboxBackend =
            opts.sandbox instanceof ProxiedContainerSandbox
                ? "proxied-container"
                : opts.sandbox instanceof DockerProcessSandbox
                    ? "docker"
                    : "proxy";
    }
    else if (opts.isolate) {
        const picked = await selectIsolatedSandbox(server);
        sandbox = picked.sandbox;
        sandboxBackend = picked.backend;
        sandboxDegradedReason = picked.degradedReason;
        if (sandboxDegradedReason) {
            emit({ type: "sandbox-degraded", server: server.name, reason: sandboxDegradedReason });
        }
    }
    else {
        sandbox = new ProcessSandbox(); // default: fast, HTTP(S)-visible — pass `isolate: true` for OS-level containment
        sandboxBackend = "proxy";
    }
    const probe = remote ? remoteProbe(server) : sandboxedProbe(server, sandbox);
    const checks = remote ? CHECKS.filter((c) => c.applicability === "output") : CHECKS;
    emit({ type: "server", server: server.name, transport, mode });
    const tools = await listTools(server);
    emit({
        type: "enumerated",
        server: server.name,
        tools: tools.map((t) => ({ name: t.name, description: t.description })),
    });
    // Dynamic dispatch: this server hides a larger catalog behind a meta-tool, so the static
    // tools/list above is INCOMPLETE. We still verify the visible tools, and the report must never read
    // as a clean pass on the hidden catalog (F4). When a discover meta-tool is present we go one step
    // further and ENUMERATE the hidden catalog by calling it (read-only, best-effort) — turning
    // "incomplete, unknown" into "incomplete, and here are the N hidden tools". Behaviourally probing
    // each hidden tool THROUGH the executor is the remaining follow-on (server-specific arg shapes).
    const dynamicDispatch = detectDynamicDispatch(tools);
    let hiddenCatalog = [];
    // Partial = we know the enumeration is NOT the whole catalog (a query-driven semantic-search
    // discover can never be exhaustive), so the server can never earn `clean` no matter how many we
    // probe. Only a listing discover (returns the full catalog on an empty call) can be complete.
    let hiddenCatalogPartial = false;
    if (dynamicDispatch.length > 0) {
        const discover = discoverToolOf(tools);
        const discoverTool = discover ? tools.find((t) => t.name === discover) : undefined;
        if (discover && discoverTool) {
            const queryParam = discoverQueryParam(discoverTool.inputSchema);
            if (queryParam) {
                // Query-driven (sentry `search_sentry_tools`, docker `mcp-find`): an empty call is rejected
                // and no single query returns everything, so run a fixed set of capability-keyword queries
                // and UNION the results — PARTIAL by nature. The server stays incomplete regardless.
                const byName = new Map();
                for (const q of DISCOVERY_QUERIES) {
                    const cat = parseHiddenCatalog(await callToolText(server, discover, { [queryParam]: q }));
                    for (const h of cat)
                        if (!byName.has(h.name))
                            byName.set(h.name, h);
                }
                hiddenCatalog = [...byName.values()];
                hiddenCatalogPartial = true;
                emit({
                    type: "dispatch-enumeration",
                    server: server.name,
                    discover,
                    mode: "query",
                    queries: DISCOVERY_QUERIES.length,
                    found: hiddenCatalog.length,
                });
            }
            else {
                // Listing discover: an empty call returns the whole catalog. callToolText is bounded +
                // swallows failures, so a server we can't read simply stays at the correctness floor.
                hiddenCatalog = parseHiddenCatalog(await callToolText(server, discover, {}));
                emit({
                    type: "dispatch-enumeration",
                    server: server.name,
                    discover,
                    mode: "listing",
                    queries: 0,
                    found: hiddenCatalog.length,
                });
            }
        }
    }
    const findings = [];
    const skipped = [];
    const checkErrors = [];
    // F4: what we can probe THROUGH the executor. Present only for a dispatcher with a readable
    // executor schema; hidden tools WITH a captured schema are probed, those without stay
    // enumerated-but-unprobeable (recorded so Phase 3's status logic never calls the server clean
    // unless the WHOLE catalog was probed).
    const executor = remote ? undefined : executorToolOf(tools);
    const envelope = executor ? inferExecutorEnvelope(executor.inputSchema) : null;
    const hiddenProbed = [];
    try {
        for (const tool of tools) {
            // Safe mode (default): NEVER invoke a tool that could mutate state or move money.
            if (mode === "safe") {
                const { klass, callable } = classifyTool(tool);
                if (!callable) {
                    skipped.push({ tool: tool.name, klass });
                    emit({ type: "skip", server: server.name, tool: tool.name, klass });
                    continue;
                }
            }
            const res = await runToolChecks(tool, checks, probe, {
                serverName: server.name,
                attempts,
                emit,
            });
            findings.push(...res.findings);
            checkErrors.push(...res.checkErrors);
        }
        // F4: drive the executor to probe each hidden tool the same way — synthesise args against the
        // HIDDEN tool's own schema, wrapped into the executor envelope by `dispatchedProbe`, so the
        // sandbox/egress/N-N reproduction all apply and the SSRF canary lands in the hidden tool's arg.
        //
        // The probes here all drive the SAME dispatcher server through the SAME executor, so they run on
        // ONE reused session (spawned once, torn down after the loop) rather than a fresh spawn per
        // probe — a real catalog is hundreds of calls, and respawning the backend each time was the cost
        // the 2026-07-22 live run flagged (minutes on real sentry-mcp). `sandboxedProbeReused` windows
        // egress per call via a high-water-mark, so each probe still sees only its OWN egress — the same
        // isolation the fresh-per-attempt path gives for free.
        if (executor && envelope) {
            const dispatchBase = sandboxedProbeReused(server, sandbox);
            const dprobe = dispatchedProbe(dispatchBase, executor.name, envelope);
            try {
                for (const hidden of hiddenCatalog) {
                    if (hidden.inputSchema === undefined)
                        continue; // no schema → can't build args → skip, stays incomplete
                    const hiddenTool = {
                        name: hidden.name,
                        description: hidden.description,
                        inputSchema: hidden.inputSchema,
                    };
                    if (mode === "safe") {
                        const { klass, callable } = classifyTool(hiddenTool);
                        if (!callable) {
                            skipped.push({ tool: hidden.name, klass });
                            emit({ type: "skip", server: server.name, tool: hidden.name, klass });
                            continue;
                        }
                    }
                    const attribution = `${hidden.name} via ${executor.name}`;
                    const res = await runToolChecks(hiddenTool, checks, dprobe, { serverName: server.name, attempts, emit }, attribution);
                    findings.push(...res.findings);
                    checkErrors.push(...res.checkErrors);
                    hiddenProbed.push(hidden.name);
                }
            }
            finally {
                await dispatchBase.dispose?.(); // tear down the one reused dispatcher session
            }
        }
    }
    finally {
        // remoteProbe / the mcp-remote-reuse sandboxedProbe keep a connection or child process alive
        // across every call in the loop above -- must be torn down once verification for this server
        // is done, success or failure, or it leaks past the end of the run.
        await probe.dispose?.();
    }
    return {
        server: server.name,
        transport,
        toolsChecked: tools.length - skipped.length,
        findings,
        skipped,
        checkErrors,
        checksRun: checks.map((c) => c.code),
        pins: pinInventory(server.name, tools),
        sandboxBackend,
        sandboxDegradedReason,
        dynamicDispatch: dynamicDispatch.length > 0 ? dynamicDispatch : undefined,
        hiddenCatalog: hiddenCatalog.length > 0 ? hiddenCatalog : undefined,
        hiddenProbed: hiddenProbed.length > 0 ? hiddenProbed : undefined,
        hiddenCatalogPartial: hiddenCatalogPartial ? true : undefined,
    };
}
//# sourceMappingURL=verify.js.map