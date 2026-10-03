---
name: mcpgawk
description: Check what an MCP server can actually do before trusting it, record the tool surface you approved, and catch it changing afterwards. Use whenever the user adds, installs, updates or upgrades an MCP server, asks what their MCP servers can do or cost, or wants a changed tool refused until they have looked. Local-first; nothing is uploaded.
---

# /mcpgawk — measure, approve, and watch the MCP servers your agent calls

mcpgawk is a local CLI. It records what each MCP tool said when the user approved it, reports any
change after that, and with the guard installed it refuses a call to a changed tool before it runs.
State lives in `~/.mcpgawk` and `~/.gawk`. Nothing leaves the machine.

Install once (ask before running an installer):

    uv tool install --force mcpgawk      # or: pipx install --force mcpgawk
    mcpgawk --version

## Rules for you, the agent

1. **Never run `mcpgawk approve` or `mcpgawk decide`.** Both refuse to run inside an agent session,
   on purpose: accepting a changed tool surface is the person's decision. Print the exact command
   and let the user run it in their own terminal.
2. Relay consent questions verbatim. A bare `mcpgawk` asks before it launches a local server;
   `mcpgawk verify` launches servers in a sandbox and says so. Do not answer for the user.
3. Report coverage statements exactly as printed. mcpgawk distinguishes "clean" from "not checked";
   that distinction is the point. Never summarise a partial picture as a clean one.
4. If a call is refused with a `[mcpgawk guard] SECURITY BLOCK` message: stop, do not retry, do not
   reach the same result through another tool, and do not run any mcpgawk command to change the
   baseline. Tell the user what was blocked and that `mcpgawk decide` in their own terminal shows
   the change.

## When the user adds or installs an MCP server

Measure it before it goes into any agent config:

    mcpgawk scan --http <url>                    # a remote server
    mcpgawk scan --stdio "<command the server runs with>"

Read the report to the user plainly: how many tools, the token cost at connect, which tools can
write or reach the network, and any findings. The first scan records the server's baseline. Then
hand over the approval:

    mcpgawk approve <server>                     # the USER runs this, not you

## When the user asks what their servers can do, or what they cost

    mcpgawk                                      # every server in every agent config on this machine
    mcpgawk panel                                # the local control panel (a tokened 127.0.0.1 URL)

## When a server updates, or the user suspects it changed

    mcpgawk scan                                 # re-scans; prints DRIFT against the approved baseline
    mcpgawk changes <server>                     # what the server's tools did over time

A changed description, a changed input schema, a tool added or removed: each is printed with the
old and new text. Walk the user through the diff. Only `mcpgawk approve` moves the baseline, and
only the user runs it. A drifted server stays flagged until a person decides.

## When the user wants the refusal to happen automatically

    mcpgawk guard install                        # one pre-execution hook; checks every MCP tool call
    mcpgawk guard status

Six clients expose a hook point today (Claude Code, Codex, Cursor, Gemini CLI, Windsurf, Kimi); the
docs list the rest and what covers them. After install, a tool that changed since approval, or a
tool that appeared after approval, is refused at call time with a reason the agent can read.

## When the user wants behaviour, not declarations

    mcpgawk verify <config.json>                 # runs local servers in a no-egress sandbox and watches

Remote (http/sse) servers cannot be sandboxed; verify says so and runs output checks only. Report
that limit as printed.

## Try it on a server that changes on purpose

A public test server flips its tool surface every ten minutes, harmless by construction:

    mcpgawk scan --http https://mcpgawk-testserver.vercel.app/rugpull/mcp

Scan, let the user approve, wait for the flip, scan again, and the change is reported. With the
guard installed, the changed tool's call is refused. Walkthrough: https://mcp.gawk.dev/docs/rugpull.html

## Run mcpgawk as an MCP server

Any MCP client can call mcpgawk's own scan tools: `mcpgawk-mcp` over stdio (from 0.1.68 also
`mcpgawk mcp`). Useful when the agent should audit the servers it is sitting next to.

Docs: https://mcp.gawk.dev/docs/ · Source: https://github.com/gawk-dev/mcpgawk (Apache-2.0)
