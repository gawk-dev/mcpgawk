---
name: mcpgawk
description: Be told when an MCP server changes after you approved it, and refuse the changed tool until the user decides; check what a server can actually do before trusting it. Use whenever the user adds, installs, updates or upgrades an MCP server, asks what their MCP servers can do or cost, or wants a changed tool refused until they decide. Your inventory stays on your machine.
---

# /mcpgawk — measure, approve, and watch the MCP servers your agent calls

mcpgawk is a local CLI. It records what each MCP tool said when the user approved it, reports any
change after that, and with the guard installed it refuses a call to a changed tool before it runs.
State lives in `~/.mcpgawk` and `~/.gawk`, on this machine. mcpgawk connects out only to: the
servers it scans (and their sign-in pages, when the user asks to sign in), each scanned server's
public Server Card, PyPI about once a day for a version check (`MCPGAWK_NO_UPDATE_CHECK=1` turns it
off), the npm registry or PyPI with `--supply-chain`, nodejs.org with `install-node`, mcp.gawk.dev
with `login` (which also downloads the paid engine from a short-lived signed link), Lemon Squeezy
to check a paid key (at login, then about once a day), your hosted fleet view with `push`, and a
URL you pass to `verify --webhook`. Those are the free CLI's connections; the paid engine's
gateway and monitor also reach the servers and destinations you configure for them.

Install once (ask before running an installer):

    uv tool install --force mcpgawk      # or: pipx install --force mcpgawk
    mcpgawk --version

## Rules for you, the agent

1. **Never run `mcpgawk approve` or `mcpgawk decide`.** Both refuse when they can see an agent
   running them, on purpose: accepting a changed tool surface is the person's decision. Print the
   exact command and let the user run it in their own terminal.
2. Relay consent questions verbatim. A bare `mcpgawk` asks before it launches a local server;
   `mcpgawk verify` launches local servers too, and says what its sandbox covers. Do not answer for
   the user, and never add `--yes` (it skips that prompt; scanning a stdio server runs its code) unless the user
   has told you to in this conversation.
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

    mcpgawk scan --fleet-json                    # every server in every agent config on this machine
    mcpgawk panel                                # the local control panel (a tokened 127.0.0.1 URL)

`scan --fleet-json` answers the question and installs no hooks. Do not run a bare `mcpgawk` for a
read-only question: it also writes the guard hook into each agent's config (next section).

## When a server updates, or the user suspects it changed

    mcpgawk scan                                 # re-scans; prints DRIFT against the approved baseline
    mcpgawk changes <server>                     # what the server's tools did over time

A changed description, a changed input schema, a tool added or removed: each is printed with the
old and new text. Walk the user through the diff. `mcpgawk approve` (or `decide`) moves the baseline.
It refuses when it can see an agent running it, so print the command for the user. A drifted server
stays flagged until the user decides.

## When the user wants the refusal to happen automatically

    mcpgawk                                      # scans, then adds the guard hook to each agent it finds
    mcpgawk guard status

Six clients expose a hook point today (Claude Code, Codex, Cursor, Gemini CLI, Windsurf, Kimi). A
bare `mcpgawk` writes a pre-execution hook into the config of each of those it finds on this
machine (`~/.claude/settings.json`, `~/.cursor/hooks.json`, `~/.codex/hooks.json`,
`~/.gemini/settings.json`, `~/.kimi/config.toml`, `~/.codeium/windsurf/hooks.json`), keeping any
hooks already there. Say that before you run it. `mcpgawk guard install` adds the hook to Claude
Code only. The docs list the other clients and what covers them. With the hook in place, a tool
that changed since approval, or a tool that appeared after approval, is refused at call time with a
reason the agent can read.

## When the user wants behaviour, not declarations

    mcpgawk verify <config.json>                 # drives the tools and reports what they did

By default verify watches local servers' outbound HTTP(S) through a proxy; raw-socket, DNS and UDP
traffic is not observed. `--isolate` runs the checks in a Docker container that blocks raw-socket,
DNS and UDP traffic; it needs Docker and falls back to the proxy, with a warning, without it. In
every mode, `--isolate` included, each local server is first started once outside the sandbox, to
list its tools.
Remote (http/sse) servers cannot be sandboxed; verify says so and runs output checks only. Report
every limit as printed in the run's coverage lines.

## Try it on a server that changes on purpose

A public test server flips its tool surface every ten minutes, harmless by construction:

    mcpgawk scan --http https://mcpgawk-testserver.vercel.app/rugpull/mcp

Scan, let the user approve, wait for the flip, scan again, and the change is reported. With the
guard installed, the changed tool's call is refused. Walkthrough: https://mcp.gawk.dev/docs/rugpull.html

## Reading results as data

Use the CLI with JSON output rather than parsing tables:

    mcpgawk scan --fleet-json                    # one row per server, grouped by the client it lives in
    mcpgawk scan --http <url> --json             # one server
    mcpgawk changes <server> --json
    mcpgawk status --json

`baseline`, `skills` and `runs` take `--json` too. Run without a terminal, as you are, mcpgawk
skips local (stdio) servers rather than launching them, and the output says so; to include them the
user runs it in their own terminal, or tells you to add `--yes` (rule 2). If that leaves nothing
measured, the scan fails rather than passing: report it as not checked.

## Optional: mcpgawk as an MCP server

This plugin does not load mcpgawk's own MCP server; the CLI above covers everything it does. For a
client with no shell (Zed, for example), add it yourself: `mcpgawk mcp` over stdio. Its two tools,
`scan_mcp_fleet` and `scan_mcp_server`, can launch local servers when asked to, so they are not
read-only.

Docs: https://mcp.gawk.dev/docs/ · Source: https://github.com/gawk-dev/mcpgawk (Apache-2.0)
