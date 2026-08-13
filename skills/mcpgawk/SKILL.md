---
name: mcpgawk
description: Check what an MCP server can actually do BEFORE trusting it, and catch it changing afterwards. Use whenever the user adds, installs, updates or upgrades an MCP server; asks what their MCP servers can do, cost or risk; mentions MCP 2 / protocol upgrade; or asks whether a server changed. Runs locally — nothing leaves the machine.
---

# mcpgawk — measure, approve, and watch MCP servers

A local CLI. Install once: `uv tool install mcpgawk` (or `pipx install mcpgawk && pipx ensurepath`).
Verify with `mcpgawk --version`. Nothing is uploaded anywhere; state lives in `~/.mcpgawk` and `~/.gawk`.

## When the user ADDS or INSTALLS an MCP server

Before they wire it into their agent config, measure it:

    mcpgawk scan --stdio "<command the server runs with>"     # or --http <url>

Read the report to the user honestly: how many tools, the token cost per message, which tools can
write or reach the network, and any findings. If the server is already in their agent's config, a
bare `mcpgawk` scans the whole fleet — it will ASK before launching local servers; relay that
consent question to the user, never answer it for them.

Then pin what they accepted:

    mcpgawk scan --track        # records the baseline
    mcpgawk approve <server>    # marks THIS surface as the trusted one

## When a server UPDATES — including the MCP-2 (2026-07-28) upgrade wave

An upgraded server re-presents its whole surface while claiming to be the same server. That is
exactly the shape of a rug-pull, so audit the upgrade instead of re-trusting it blind:

    mcpgawk scan --track        # BEFORE upgrading: baseline
    # ... user upgrades the server ...
    mcpgawk scan --track        # AFTER: mcpgawk diffs against the approved baseline

Anything that changed is reported as drift — new tools, changed descriptions, changed schemas.
Walk the user through the diff; `mcpgawk decide` records their verdict. Only `approve` moves the
baseline; a drifted server stays flagged until a human decides.

## When the user asks "what can my MCP servers do / what do they cost?"

    mcpgawk               # fleet report in the terminal
    mcpgawk panel         # local web panel (tokened 127.0.0.1 URL)

## When the user wants behavioural proof, not just declarations

    mcpgawk verify        # launches each server in a sandbox and watches what it actually does

Verify launches servers (it says so and asks). Report its coverage statements verbatim — it
distinguishes "clean" from "not checked", and that distinction is the point. Note: servers that
speak ONLY the 2026-07-28 revision cannot be behaviourally verified yet (upstream TypeScript SDK);
`verify` reports this as no-coverage rather than pretending.

## Ongoing protection

    mcpgawk protect       # installs a pre-call guard hook into the user's agent

After this, a tool that appears post-approval is blocked at call time with a clear reason.

## Rules for the agent using this skill

- Never launch a server without relaying mcpgawk's consent prompt to the user first.
- Never summarise a finding away: report tool counts, token costs and drift verbatim.
- `mcpgawk demo` shows the whole story in a throwaway sandbox (`mcpgawk demo --clean` removes it) —
  offer it when the user wants to see the point before trusting their own fleet to it.
