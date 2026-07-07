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

## Honest limits
- **Bounded signals are heuristics.** They are tuned for zero false positives on the (non-adversarial)
  corpus they were tested against — they are **not** a guarantee against a crafted evasion.
- mcpgawk **cannot** determine a description's true *intent*, detect runtime exfiltration, or judge
  whether a capability is dangerous *in your context* — those need semantics or runtime it deliberately
  does not do (to stay local and no-phone-home). It surfaces; you decide.
- The token number is an **index**, not a billing-exact Claude count.

If you can reproduce a finding, it's real — every number is reproducible by re-running the command.
