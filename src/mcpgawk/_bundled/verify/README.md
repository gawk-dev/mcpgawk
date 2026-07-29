# @gawk/verify — behavioural MCP verifier

Static scanners (mc-scan, Invariant) read a tool's **description** and guess. `gawk-verify`
**runs** your MCP server: it drives every tool inside a no-egress sandbox and convicts the ones
that actually misbehave — with **reproduced evidence**, not a heuristic.

A malicious tool with a perfectly innocent description ("Store a note.") is invisible to a static
scan. It is not invisible to a tool that watches what it does.

## What it checks (behavioural vuln classes)

| Class | Caught when a tool… |
| --- | --- |
| **data-exfiltration** | sends data over **HTTP** to a host outside its declared upstreams |
| **SSRF** | fetches a URL taken from its input (reaches attacker-chosen hosts) |
| **tool-poisoning** | returns OUTPUT carrying instructions aimed at the calling agent |
| **secret-leak** | returns OUTPUT containing a credential (API key, private key, token) |

Each is reproduced N/N in a fresh sandbox before it's reported.

> **Coverage, stated plainly:** by default the sandbox observes **HTTP(S) egress via a proxy**. A
> tool that exfiltrates over a **raw socket / DNS / UDP is NOT detected** by this backend — a clean
> egress result means "no HTTP exfiltration observed", *not* proof of safety.
>
> Pass **`--isolate`** for the adversary-proof backend (ADR-0014): the tool runs in a container on
> an **internal network whose only route out is the verifying egress proxy**. Raw-socket/DNS/UDP
> exfiltration is **blocked outright** at the OS level, while every HTTP(S) destination is still
> **observed and allowlist-enforced** — the SSRF-canary and undeclared-egress checks keep their
> signal, because allowlisted hosts stay reachable through the proxy. A non-allowlisted host in an
> `--isolate` report was seen by the only possible way out, not by a bypassable observer.
> `npx`/`uvx` servers run contained too: the package install happens **through the same proxy**
> against an explicit registry allowlist (`registry.npmjs.org`, `pypi.org`, …), so install-time
> egress to anything else is blocked *and recorded* — a supply-chain signal the default path
> (which pre-warms the cache on the host) structurally cannot see. gVisor (`runsc`) is used
> automatically when the daemon offers it. Requires Docker; degrades to the default proxy sandbox
> with a clear warning otherwise, never silently claiming more coverage than what ran. It costs
> real seconds per probe (a container network per call), which is why it's opt-in rather than the
> default.

## Usage

```
npx @gawk/verify config.json
```

```json
{
  "mcpServers": {
    "notes-pro": {
      "command": "node",
      "args": ["server.js"],
      "env": { "API_TOKEN": "..." },
      "allowedHosts": ["api.notes-pro.com"]
    }
  }
}
```

`allowedHosts` are the server's legitimate upstreams. Any egress elsewhere, reproduced across N
runs, is convicted:

```
notes-pro: checked 1 tool(s)
  ✗ EXFIL [storeNote] → attacker.example  (3/3, F-b9231fda012adf7fc450)

gawk-verify: CONVICTED 1 tool(s) for data exfiltration.
```

Exit code is non-zero when anything is convicted, so it gates CI.

## CI-native output and suppressing a reviewed finding

`--sarif <file>` writes SARIF 2.1.0 (GitHub code scanning and most security dashboards ingest
this natively); `--junit <file>` writes JUnit XML (renders as a pass/fail test tree in most CI
UIs). Both are additive to `--json`/`--html`/`--csv`, not a replacement.

A finding you've actually reviewed and decided is fine (a known, accepted risk — not every
finding blocks shipping forever) can be suppressed so it stops failing CI, without disappearing
from the record:

```
gawk-verify config.json --json   # find the findingId (F-...) in the output
gawk-verify suppress F-b9231fda012adf7fc450 --file suppressions.json --reason "internal telemetry, reviewed 2026-07-12" --approved-by alice
gawk-verify config.json --suppress suppressions.json   # now exits 0 for this finding
```

`suppressions.json` is never auto-created — suppression is an explicit, reviewed action, unlike
`--baseline`'s auto-establish-on-first-run. A suppressed finding still appears in every output
format (JSON, HTML, CSV, SARIF, JUnit), marked as suppressed with its reason — SARIF encodes it
with SARIF's own `suppressions` field (shows as "dismissed" on GitHub, not "passing"); JUnit
renders it as `<skipped/>`, not `<failure>`. Suppression is keyed on the finding's deterministic
id (`server|class|tool|code`, stable across runs) — it does not silently widen to cover a
different finding on the same tool.

## Safe by default

`gawk-verify` invokes tools to observe them, so by default it runs in **safe mode**: it only calls
tools it can confidently classify as **read-only** and never calls anything that could mutate state
or move money (`place_order`, `cancel_order`, `transfer_*`, …). Skipped tools are reported so you
know what was not tested. Two design rules make this trustworthy:

- The decision to call is **name-driven** (a read verb, no mutating verb) — a server cannot make a
  tool *more* callable by lying.
- Tool annotations may only **restrict** (`destructiveHint`/`readOnlyHint:false` skip a tool), never
  enable one.

Residual risk, stated plainly: a tool with a deceptive read-looking name that actually mutates would
still be called. For a live account with real funds, use a **dedicated test/paper account**. Pass
`--unsafe` to invoke every tool (only against a server you control or a test account).

## How it works

`spec/target → enumerate tools → for each: N× { fresh no-egress sandbox → invoke tool → observe
egress } → N/N + evidence → verdict`. Built on `@gawk/sandbox` (the disposable, allowlisting
egress boundary) and `@gawk/oracle` (the N/N reproduction gate: an infra failure never convicts).

## Honest scope

- **Runtimes:** the default sandbox intercepts outbound HTTP(S) for **Go, Python, and Node**
  servers you run locally (tested with real child processes). A target using raw sockets, an HTTP
  client that ignores proxy env, or a non-HTTP protocol can evade the proxy-level boundary — that
  is exactly what `--isolate`'s ProxiedContainerSandbox closes (ADR-0014): those channels are
  dropped at the OS boundary while HTTP(S) stays observed. Under `--isolate`, non-HTTP protocols
  are BLOCKED but not parsed (blocking is a guarantee; parsing them is a later capability).
- **Transports:** local **stdio** (sandboxed — all checks apply) and **remote HTTP/SSE**. A remote
  hosted server can't be sandboxed, so only the output-based check (**tool-poisoning**) runs against
  it; the egress checks are reported as not-applicable, not faked.

See `docs/spec/adr-0010-verification-substance.md`.
