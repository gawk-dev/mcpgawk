# mcpgawk — what it checks, and what it does *not* claim

mcpgawk measures an MCP server's **cost** and **trust surface** locally, before you connect it to a
model. This document states exactly what it reports, how confident each signal is, and its limits —
because a security tool that overstates itself is worse than none.

## The three confidence tiers (kept separate in code and output)

| Tier | What | Trust it as |
|---|---|---|
| **EXACT** | structural capability facts (write/mutating verb, exfil-capable param, declared annotations), and the integrity pin (a hash of the tool set) | facts |
| **INDEX** | token cost at connect, via a **named** tokenizer (cl100k) | a *comparable ranking*, not an absolute Claude count |
| **BOUNDED** | heuristic signals (injection-shaped descriptions, cross-server name shadowing, server-card under-declaration) | *pointers for a human to review* — never verdicts |

EXACT facts, the INDEX, and BOUNDED signals never mix. mcpgawk never emits a risk "score" or declares a
server "insecure."

## What each signal means
- **Cost index** — how many tokens a tool's definition adds to your context at connect. High totals are
  a real, measurable tax (and degrade tool selection). It's an *index* because the exact count depends
  on the model's tokenizer, which isn't public; cl100k is a fair relative proxy.
- **Capability facts** — whether a tool can mutate state or reach the network (a URL/fetch parameter),
  and what safety annotations (`readOnlyHint`/`destructiveHint`) it declares. Facts, not judgements.
- **Integrity pin** — a hash of the server's tool names + descriptions. With `--track`, a changed pin
  means the server silently rewrote its tools since you last trusted it (a rug-pull).
- **Bounded signals** — precise, low-false-positive pointers: descriptions that contain instructions
  aimed at the *model* rather than the caller (tool poisoning), a tool name exposed by more than one
  connected server (shadowing), or a public Server Card that hides tools the server actually exposes.

## Privacy / egress model
The only network mcpgawk performs is the protocol client talking to the **server you point it at**. The
measurement layers import no network library — they cannot exfiltrate what they saw by construction
(enforced by a test). Public Server Card discovery is fetched with **no auth headers and no
redirect-following**, so a discovery endpoint can never capture your credentials.

## Beyond the scan — what else is in the trust boundary

The sections above describe `scan`, which reads what a server claims. Three other capabilities
change what is being trusted, so each states its own limit here.

### `verify` — behaviour, observed
Runs the server in a sandbox and reports what it did: data exfiltration, SSRF, tool poisoning,
secret leaks. A finding is reproduced in a fresh sandbox before it is reported. **Safe mode is the
default**: only tools provably read-only are driven, and every tool it skips is named as skipped —
never counted as clean. Egress is watched through a proxy; `--isolate` adds a stricter pass on top
rather than replacing it.

### `guard` — the call, checked before it runs
A single pre-execution hook checks every MCP tool call against the surface you approved, locally,
before the call reaches the server. **It works on 6 of the 21 supported clients** — the others
expose no hook point, and are named rather than silently omitted. A client with no hook point is
not protected in place; route it through the gateway instead.

### `enforce` — the gateway
One endpoint in front of the fleet. Each caller gets its own key, so a blocked call has a name
against it. Scope enforcement is **deny-by-default**. Both the call and the response are evaluated.
Whether an evaluator error fails open or closed is **explicit and set by your config** — it is not
guessed.

### `monitor` — after you approved it
Re-checks approved servers on a schedule and raises an alert when a surface moves. This is the
post-approval drift case: a server you already trusted changing later.

## The audit log, stated precisely
Every guard decision is written synchronously and **hash-chained**: each row is
`sha256(prev_hash || canonical(fields))`, so an in-place edit, a reorder or a mid-deletion breaks
the link and `verify_chain()` names the first broken row.

What the chain alone **cannot** catch, and we do not pretend it can: a local party who holds the
database can truncate the tail or recompute a fresh, internally-valid chain. Only an **off-box
anchor** closes that — ship the chain head somewhere you do not control, and truncation or a
wholesale rewrite is then detectable at the anchored count. The guarantee is therefore:
**tamper-evident up to the last anchored head**; rows after it are chain-consistent and
crash-integral but still rewritable locally. Do not read it as more than that.

**Tool arguments are never recorded.** The log is metadata — when, which agent, which server.tool,
the decision and its basis — so it cannot become the richest secret on your disk.

## Honest limits
- **Bounded signals are heuristics.** They are tuned for zero false positives on the (non-adversarial)
  corpus they were tested against — they are **not** a guarantee against a crafted evasion.
- mcpgawk **cannot** determine a description's true *intent*, or judge whether a capability is
  dangerous *in your context*. It surfaces; you decide.
- Static scanning alone cannot see behaviour. That is why `verify` exists: it runs the server in a
  sandbox and reports what it actually did. Read the two apart — a scan is what a server *claims*,
  a verify run is what it *did*.
- The token number is an **index**, not a billing-exact Claude count.

If you can reproduce a finding, it's real — every number is reproducible by re-running the command.
