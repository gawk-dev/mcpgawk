import { Verifier } from "@gawk/oracle";
import { DockerProcessSandbox, ProcessSandbox, ProxiedContainerSandbox, canProxyContainerize, } from "@gawk/sandbox";
import { CHECKS } from "./checks.js";
import { annotationSignal, classifyTool } from "./classify.js";
import { DISCOVERY_QUERIES, detectDynamicDispatch, discoverQueryParam, discoverToolOf, executorToolOf, inferExecutorEnvelope, parseHiddenCatalog, } from "./dispatch.js";
import { isRemote, } from "./model.js";
import { pinInventory } from "./pins.js";
import { CheckRunner, isMcpRemoteProxy, callToolText, dispatchedProbe, listTools, remoteProbe, sandboxedProbe, sandboxedProbeReused, } from "./runner.js";
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
/** The server's own sign-in tool, when auth lives IN-BAND (kite's `login` returns a broker
 * URL bound to the calling session). Name-driven and deliberately narrow: `login`, `log_in`,
 * `login_url` shapes match; anything containing `out` (logout) never does. */
export function findInbandLoginTool(tools) {
    return tools.find((t) => /(^|[._-])log[_-]?in($|[._-])/i.test(t.name) && !/out/i.test(t.name));
}
/** Wait between two "has the human signed in yet?" reads, in ms. Configurable for tests, like
 * the probe and connect timeouts in runner.ts; 30 reads at the default is the five-minute wait. */
function signInPollMs() {
    const parsed = Number(process.env.GAWK_SIGNIN_POLL_MS);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 10_000;
}
/** An answer that still reads as "you are not signed in", whatever the ok-flag says — kite
 * reports auth failures as ok:true "Failed to execute <tool>". One regex for the preflight
 * and the post-sign-in retry, so the two ends of the dance cannot drift apart. */
export function authFailureShaped(text) {
    return /not (logged in|authenticated)|login|forbidden|unauthorized|failed to execute/i.test(text);
}
/** Signed-in means the answer CHANGED **into one that no longer reads as an auth failure**.
 * Change alone was the entire signal until 2026-08-15, and the first through-gateway kite run
 * proved it insufficient: one transient variance in the still-failing answer flipped auth-ok
 * ten seconds in, the human was never asked, and every later read still failed.
 *
 * The shape comparison uses the truncated normalisation; the failure test gets the retry's
 * FULL text — the same input the preflight's test gets. Running it on the 120-char shape
 * would let a long answer whose failure phrase sits past the truncation flip auth-ok. */
export function signInComplete(firstShape, againShape, againOk, againFullText) {
    return againOk && againShape !== firstShape && !authFailureShaped(againFullText);
}
/** The first URL in a login tool's prose, stripped of trailing punctuation — servers wrap the
 * link in sentences ("Click here: https://… to continue."). Null when there is none. */
export function firstUrlIn(text) {
    const m = text.match(/https?:\/\/\S+/);
    return m ? m[0].replace(/[)\]}"',.]+$/, "") : null;
}
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
async function runToolChecks(tool, checks, probe, ctx, attributionName = tool.name) {
    const findings = [];
    const checkErrors = [];
    const rejectedChecks = [];
    let rejectedDetail;
    let answers = 0;
    let errorAnswers = 0;
    let startupFailed = false;
    let startupDetail;
    // 1A: count what was PLANNED and what actually reached a verdict, at the only place that knows.
    // Everything downstream (status, exit code, coverage claim, every renderer) derives from these.
    let checksPlanned = 0;
    let checksCompleted = 0;
    for (const check of checks) {
        checksPlanned += 1;
        if (ctx.budget && Date.now() >= ctx.budget.deadlineAt) {
            // The server's wall clock is spent. Start nothing more: planned, not completed, and said so.
            if (!ctx.budget.announced) {
                ctx.budget.announced = true;
                ctx.emit({
                    type: "server-timeout",
                    server: ctx.serverName,
                    tool: attributionName,
                    budgetMs: ctx.budget.budgetMs,
                    elapsedMs: Date.now() - ctx.budget.startedAt,
                });
            }
            const detail = `not attempted — server budget of ${Math.round(ctx.budget.budgetMs / 1000)} s exhausted`;
            checkErrors.push({ tool: attributionName, code: check.code, detail });
            ctx.emit({
                type: "check",
                server: ctx.serverName,
                tool: attributionName,
                code: check.code,
                label: check.label.trim(),
                severity: check.severity,
                outcome: "error",
                attemptsOk: 0,
                attemptsRun: 0,
                detail,
            });
            continue;
        }
        if (startupFailed) {
            // The process did not come up for the previous check of THIS tool. Probing again would be
            // another spawn and another 45 s for the same answer. Every remaining check is an error,
            // not a skip and not a pass: planned, not completed.
            checkErrors.push({ tool: attributionName, code: check.code, detail: startupDetail ?? "" });
            ctx.emit({
                type: "check",
                server: ctx.serverName,
                tool: attributionName,
                code: check.code,
                label: check.label.trim(),
                severity: check.severity,
                outcome: "error",
                attemptsOk: 0,
                attemptsRun: 0,
                detail: `not attempted — ${startupDetail ?? "the server failed to start"}`,
            });
            continue;
        }
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
        let checkErrorAnswer;
        const auditingProbe = async (toolName, args) => {
            attemptNum += 1;
            const result = await probe(toolName, args);
            if (!result.ok && result.startup) {
                startupFailed = true;
                startupDetail = result.detail;
            }
            if (result.ok) {
                answers += 1;
                if (result.obs.errorAnswer !== undefined) {
                    errorAnswers += 1;
                    checkErrorAnswer ??= result.obs.errorAnswer;
                }
            }
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
                errorAnswer: result.ok ? result.obs.errorAnswer : undefined,
            });
            return result;
        };
        const outcome = await new Verifier(new CheckRunner(tool, check, auditingProbe)).verify(candidate, { attempts: ctx.attempts });
        if (outcome.kind === "verdict")
            findings.push(outcome.verdict);
        const isInfra = outcome.kind !== "verdict" && /infra/i.test(outcome.reason);
        // J1 narrowed: ANY attempt of this check answered with the tool's own error and nothing was
        // convicted. "Did not reproduce" against a refusal is not a clean check, so it is counted as
        // neither planned nor completed, and the tool is listed. A conviction read out of the error
        // text itself (a secret in the message) still stands and is counted like any other.
        const isRejected = outcome.kind !== "verdict" && !isInfra && checkErrorAnswer !== undefined;
        if (outcome.kind !== "verdict" && isInfra) {
            checkErrors.push({ tool: attributionName, code: check.code, detail: outcome.reason });
        }
        else if (isRejected) {
            checksPlanned -= 1;
            rejectedChecks.push(check.code);
            rejectedDetail ??= checkErrorAnswer;
        }
        else {
            // A verdict, or a non-infra "did not reproduce" — either way this check reached a conclusion.
            checksCompleted += 1;
        }
        ctx.emit({
            type: "check",
            server: ctx.serverName,
            tool: attributionName,
            code: check.code,
            label: check.label.trim(),
            severity: check.severity,
            outcome: outcome.kind === "verdict" ? "reproduced" : isInfra ? "error" : isRejected ? "rejected" : "clean",
            attemptsOk: outcome.attemptsOk,
            attemptsRun: outcome.attemptsRun,
            detail: outcome.kind === "verdict"
                ? `reproduced ${outcome.verdict.reproOk}/${outcome.verdict.reproTotal}`
                : isRejected
                    ? `the tool answered the test input with an error, so this check concluded nothing (${checkErrorAnswer})`
                    : outcome.reason,
            evidence: outcome.kind === "verdict" ? outcome.verdict.evidence : undefined,
        });
    }
    return {
        findings,
        checkErrors,
        checksPlanned,
        checksCompleted,
        startupFailed,
        startupDetail,
        rejected: rejectedChecks.length > 0
            ? { checks: rejectedChecks, detail: rejectedDetail ?? "" }
            : undefined,
        answers,
        errorAnswers,
    };
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
    const budget = opts.serverTimeoutMs !== undefined && opts.serverTimeoutMs > 0
        ? {
            startedAt: Date.now(),
            deadlineAt: Date.now() + opts.serverTimeoutMs,
            budgetMs: opts.serverTimeoutMs,
            announced: false,
        }
        : undefined;
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
    // An mcp-remote proxy's upstream IS the server — the sandbox blocking it killed every
    // probe call (kite: mcp-remote exited the moment a tools/call needed the network, so even
    // the server's own login tool answered "Connection closed"; measured 2026-08-15). The
    // proxied URL's host is first-party by construction and joins the allowlist; genuinely
    // undeclared egress to anywhere ELSE stays observed and blocked exactly as before.
    let effectiveServer = server;
    if (!remote && isMcpRemoteProxy(server)) {
        const upstream = (server.args ?? []).find((a) => /^https?:\/\//.test(a));
        if (upstream) {
            try {
                const host = new URL(upstream).host;
                const allowed = new Set([...(server.allowedHosts ?? []), host]);
                effectiveServer = { ...server, allowedHosts: [...allowed] };
            }
            catch {
                /* an unparseable arg is not a URL; nothing to allow */
            }
        }
    }
    const probe = remote ? remoteProbe(server) : sandboxedProbe(effectiveServer, sandbox);
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
    // 1A: the run's own accounting of planned-vs-completed checks (see report.ts's Completeness).
    let checksPlanned = 0;
    let checksCompleted = 0;
    // F4: what we can probe THROUGH the executor. Present only for a dispatcher with a readable
    // executor schema; hidden tools WITH a captured schema are probed, those without stay
    // enumerated-but-unprobeable (recorded so Phase 3's status logic never calls the server clean
    // unless the WHOLE catalog was probed).
    const executor = remote ? undefined : executorToolOf(tools);
    const envelope = executor ? inferExecutorEnvelope(executor.inputSchema) : null;
    const hiddenProbed = [];
    // J9 (2026-11-12): tools that actually ran their checks, counted, never derived by subtraction.
    let visibleExercised = 0;
    // J3 follow-up (2026-11-13): the tools whose every planned check reached a conclusion, collected
    // here for the same reason. The behaviour profile clears a conviction only for these.
    const settledTools = [];
    // A tool that answered ANY check with its own error is not settled, even when its other checks
    // concluded: a convicted tool must not clear itself by refusing the one probe that convicted it.
    const settles = (r) => r.checksPlanned > 0 && r.checksCompleted === r.checksPlanned && r.rejected === undefined;
    // J1 narrowed (2026-11-15): tools that answered the made-up test input with their own error,
    // collected where the calls were made, under the name the report uses for the tool.
    const rejectedInput = [];
    let answersTotal = 0;
    let errorAnswersTotal = 0;
    let firstErrorAnswer;
    const noteAnswers = (name, r) => {
        answersTotal += r.answers;
        errorAnswersTotal += r.errorAnswers;
        if (r.rejected) {
            rejectedInput.push({ tool: name, checks: r.rejected.checks, detail: r.rejected.detail });
            firstErrorAnswer ??= r.rejected.detail;
        }
    };
    /** A probe that got a real answer: the call worked AND the tool did not answer with an error. */
    const answered = (r) => r.ok && r.obs.errorAnswer === undefined;
    // Per-server, once: do this server's restricting labels DISCRIMINATE? Kite stamps every tool
    // destructiveHint:true (get_ltp included) — blanket labels are noise, and honouring them let
    // kite sit "verified-looking" with 0 of 22 tools exercised for two weeks ([FOUNDER]
    // 2026-08-14: the user's security outranks the server's labels).
    const labelSignal = annotationSignal(tools);
    // IN-BAND SIGN-IN ([FOUNDER] 2026-08-15 "go ahead with kite"): a server whose auth lives in
    // its own tools (kite: `login` returns a broker URL bound to THIS session) has never had a
    // tool genuinely exercised — the reads fail until a human authorises the session. When a
    // login-shaped tool exists and a probe read fails, call the server's own login tool in the
    // SAME session, hand the URL out as an audit event, and wait for the human (bounded).
    // Only for safe-mode local runs on a persistent session; everything else is unchanged.
    const loginTool = findInbandLoginTool(tools);
    // Fire for a session-bound sign-in over ANY persistent session: the direct mcp-remote proxy
    // (local, one reused spawn) OR through a running gateway (remote, one reused client). Both
    // keep a single session so the login and the later reads share it — the whole point.
    const persistentSession = isMcpRemoteProxy(server) || Boolean(server.backendPrefix);
    let authIncomplete;
    if (mode === "safe" && loginTool && persistentSession) {
        const preflight = tools.find((t) => classifyTool(t, labelSignal).callable);
        if (preflight) {
            const first = await probe(preflight.name, {});
            // The unauthenticated answer, normalised — kite says "Failed to execute get_gtts" with
            // ok=true, so phrase-lists misread it (the first cut called that signed-in and burned a
            // run: 0/60 with the human never asked). Auth is COMPLETE only when the same read's
            // answer CHANGES from this shape.
            const unauthedShape = (r) => (r.ok ? r.obs.resultText : r.detail ?? "").trim().slice(0, 120);
            const firstShape = unauthedShape(first);
            // An error answer is a failed read here, exactly as it was when the probe reported it as a
            // failed call (J1 narrowed): this is where "the server answers errors until signed in" is
            // decided, and an error whose text varies must never read as a completed sign-in below.
            const failed = !answered(first) || authFailureShaped(first.obs.resultText);
            if (failed) {
                const login = await probe(loginTool.name, {});
                const url = answered(login) ? firstUrlIn(login.obs.resultText) : null;
                if (url) {
                    emit({ type: "auth-needed", server: server.name, tool: loginTool.name, url });
                    let authed = false;
                    for (let i = 0; i < 30; i++) {
                        await new Promise((r) => setTimeout(r, signInPollMs()));
                        const again = await probe(preflight.name, {});
                        if (signInComplete(firstShape, unauthedShape(again), answered(again), again.ok ? again.obs.resultText : "")) {
                            authed = true;
                            break;
                        }
                    }
                    emit(authed ? { type: "auth-ok", server: server.name }
                        : { type: "auth-timeout", server: server.name });
                    if (!authed) {
                        authIncomplete =
                            "sign-in never completed (auth-timeout) — every read answered as " +
                                "unauthenticated, so nothing behavioural was proven";
                    }
                }
                else {
                    authIncomplete =
                        "reads answer as unauthenticated and the server has a login tool, but no " +
                            "sign-in URL could be obtained from it — nothing behavioural was proven";
                }
            }
        }
    }
    const noisyAxes = [
        ...(labelSignal.destructiveInformative ? [] : ["destructiveHint:true on every tool"]),
        ...(labelSignal.readOnlyVetoInformative ? [] : ["readOnlyHint:false on every tool"]),
    ];
    const labelNoiseNote = noisyAxes.length > 0
        ? `blanket labels ignored as uninformative (${noisyAxes.join("; ")}) — a label that never ` +
            `varies carries no information and would let a server evade behavioural verification; ` +
            `name-read tools were exercised, name-mutating tools stayed skipped`
        : undefined;
    try {
        // Consecutive tools whose PROCESS failed to start. Two in a row with nothing on this server
        // completed means the server is not going to come up; stop spending a container per check.
        let startupFailures = 0;
        for (const [toolIndex, tool] of tools.entries()) {
            // Safe mode (default): NEVER invoke a tool that could mutate state or move money.
            if (mode === "safe") {
                const { klass, callable } = classifyTool(tool, labelSignal);
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
                budget,
            });
            noteAnswers(tool.name, res);
            // A tool whose every check was answered with an error was not exercised: nothing was
            // learnt about what it does. It is listed in `rejectedInput`, not counted as checked.
            if (res.checksPlanned > 0 || !res.rejected)
                visibleExercised += 1;
            if (settles(res))
                settledTools.push(tool.name);
            findings.push(...res.findings);
            checkErrors.push(...res.checkErrors);
            checksPlanned += res.checksPlanned;
            checksCompleted += res.checksCompleted;
            if (res.startupFailed) {
                startupFailures += 1;
                if (startupFailures >= 2 && checksCompleted === 0) {
                    const reason = res.startupDetail ?? "the server failed to start";
                    emit({
                        type: "server-abandoned",
                        server: server.name,
                        tool: tool.name,
                        failedToStart: startupFailures,
                        toolsRemaining: tools.length - toolIndex - 1,
                        reason,
                    });
                    throw new Error(`abandoned after ${startupFailures} tools in a row could not start the server and ` +
                        `no check completed — ${reason}`);
                }
            }
            else if (res.checksCompleted > 0) {
                startupFailures = 0;
            }
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
                        const { klass, callable } = classifyTool(hiddenTool, labelSignal);
                        if (!callable) {
                            skipped.push({ tool: hidden.name, klass });
                            emit({ type: "skip", server: server.name, tool: hidden.name, klass });
                            continue;
                        }
                    }
                    const attribution = `${hidden.name} via ${executor.name}`;
                    // J6 (2026-11-12): an executor with no arguments slot cannot deliver this tool's inputs
                    // (the SSRF canary among them). Dispatching it anyway "probed" a tool that received
                    // nothing and counted it clean. Not probed; a check error says why; the server stays
                    // incomplete. A hidden tool that declares no inputs loses nothing and is still probed.
                    const declared = Object.keys(hidden.inputSchema?.properties ?? {});
                    if (envelope.argsParam === null && declared.length > 0) {
                        checkErrors.push({
                            tool: attribution,
                            code: "dispatch-no-args-slot",
                            detail: `the executor ${executor.name} has no arguments parameter, so ${hidden.name}'s ` +
                                `inputs (${declared.join(", ")}) could not be delivered; not probed`,
                        });
                        continue;
                    }
                    const res = await runToolChecks(hiddenTool, checks, dprobe, { serverName: server.name, attempts, emit, budget }, attribution);
                    findings.push(...res.findings);
                    checkErrors.push(...res.checkErrors);
                    checksPlanned += res.checksPlanned;
                    checksCompleted += res.checksCompleted;
                    noteAnswers(attribution, res);
                    // Deliberately stricter than a visible tool: an error through the executor is as likely
                    // OUR envelope as the tool's input check, so a hidden tool that answered any check with
                    // an error is not "probed" and the dispatcher stays incomplete, as it did before.
                    if (!res.rejected)
                        hiddenProbed.push(hidden.name);
                    if (settles(res))
                        settledTools.push(hidden.name);
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
    // "At least one call got an answer, and none of them was anything but an error": the server
    // ran nothing for us (an expired credential, a missing key), so nothing was proven about it.
    const allCallsErrored = answersTotal > 0 && errorAnswersTotal === answersTotal
        ? `every call answered with an error, so nothing was proven about this server (first: ${firstErrorAnswer ?? "no error text"})`
        : undefined;
    return {
        server: server.name,
        transport,
        // Visible tools that ran + hidden tools probed through the executor. `tools.length -
        // skipped.length` subtracted HIDDEN skips from VISIBLE tools: 2 visible and 5 skipped hidden
        // mutators read -3, and a probed hidden tool never counted (review J9).
        toolsChecked: visibleExercised + hiddenProbed.length,
        findings,
        skipped,
        checkErrors,
        checksRun: checks.map((c) => c.code),
        checksPlanned,
        checksCompleted,
        pins: pinInventory(server.name, tools),
        sandboxBackend,
        sandboxDegradedReason,
        labelNoiseNote,
        authIncomplete,
        rejectedInput: rejectedInput.length > 0 ? rejectedInput : undefined,
        allCallsErrored,
        // A run that never signed in proved nothing behavioural, so it settles nothing. (A run that
        // got nothing but errors settles nothing either, by construction: a tool that answered any
        // check with an error is never in `settledTools`.)
        toolsSettled: authIncomplete ? [] : settledTools,
        dynamicDispatch: dynamicDispatch.length > 0 ? dynamicDispatch : undefined,
        hiddenCatalog: hiddenCatalog.length > 0 ? hiddenCatalog : undefined,
        hiddenProbed: hiddenProbed.length > 0 ? hiddenProbed : undefined,
        hiddenCatalogPartial: hiddenCatalogPartial ? true : undefined,
    };
}
//# sourceMappingURL=verify.js.map