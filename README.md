<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/gawk-dev/mcpgawk/main/assets/brand/wordmark-dark.png">
    <img alt="mcpgawk by nativerse" src="https://raw.githubusercontent.com/gawk-dev/mcpgawk/main/assets/brand/wordmark-light.png" width="320">
  </picture>
</p>
<p align="center"><em>Make MCP lean and honest.</em></p>

# mcpgawk

[![PyPI](https://img.shields.io/pypi/v/mcpgawk.svg)](https://pypi.org/project/mcpgawk/)
[![Python](https://img.shields.io/pypi/pyversions/mcpgawk.svg)](https://pypi.org/project/mcpgawk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/gawk-dev/mcpgawk/actions/workflows/ci.yml/badge.svg)](https://github.com/gawk-dev/mcpgawk/actions/workflows/ci.yml)
[![Open VSX](https://img.shields.io/open-vsx/v/gawk-dev/mcpgawk?label=VS%20Code%20%2F%20Cursor)](https://open-vsx.org/extension/gawk-dev/mcpgawk)
[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-Action-blue?logo=github)](https://github.com/marketplace/actions/mcpgawk-mcp-hygiene-gate)
[![No egress](https://img.shields.io/badge/inventory-never%20uploaded-brightgreen.svg)](#guarantees)

A local-first command that measures what a [Model Context Protocol](https://modelcontextprotocol.io)
server costs and what it can do. It runs on your machine and uploads nothing.

<p align="center">
  <img src="https://raw.githubusercontent.com/gawk-dev/mcpgawk/main/assets/brand/demo.gif" alt="mcpgawk scanning an MCP server — tools, token cost, and capability flags, locally" width="760">
</p>
<p align="center"><sub>Real output. Reproducible on your machine — no account, nothing uploaded.</sub></p>

## Why

Connect an MCP server and it loads all its tools into your AI's context. Every request. Used or not.
You pay for those tokens, and you haven't checked what the tools can do. mcpgawk shows you both, locally.

## How it's different

- **vs. cloud scanners** (e.g. Snyk/Invariant `mcp-scan`) — they upload your inventory to a server and
  gate the verdict. mcpgawk runs entirely on your machine; nothing is uploaded, ever.
- **vs. lazy-load gateways** — they cut tokens but tell you nothing about the *risk* surface.
- **mcpgawk does both** — cost **and** trust — locally, reproducibly, in one command.

## Features

- 🔌 **Any transport** — stdio, streamable-HTTP, SSE, and OAuth remotes (via the `mcp-remote` bridge).
- 💸 **Token cost index** — exactly what each tool adds to your context at connect.
- 🧾 **Capability facts** — write / exfil-capable / declared annotations, straight from the schema.
- 📌 **Integrity pin + drift** — catch a server that silently rewrites its tools (`--track`).
- 🚩 **Bounded signals** — injection-shaped descriptions, cross-server shadowing, under-declaring Server Cards — pointers for a human, never verdicts.
- 🔒 **Zero egress, by construction** — the measurement layers import no network library. Enforced by a test.

## Get it — three ways

**CLI** (any terminal):
```bash
pip install mcpgawk        # or: uv tool install mcpgawk
mcpgawk scan mcp.json
```

**Editor** (VS Code / Cursor): install **mcpgawk** from the marketplace ([Open VSX](https://open-vsx.org/extension/gawk-dev/mcpgawk)). It scans your workspace `mcp.json` and shows cost + capability flags inline.

**CI** (GitHub Action): gate every PR on token budget / drift ([Marketplace](https://github.com/marketplace/actions/mcpgawk-mcp-hygiene-gate)):
```yaml
- uses: gawk-dev/mcpgawk@v1
  with: { config: mcp.json, max-tokens: 8000, fail-on-flagged: true }
```

## When to run it

- **Before you add a server** — see what it costs and what it can do, before you trust it.
- **When your agent feels slow or picks the wrong tool** — it's often MCP bloat (too many / too-heavy tools).
- **On every PR** — the CI gate catches drift and creeping token cost.
- **If you *publish* an MCP server** — see what it costs your users and how it reads to a client, and fix it (usually one line per tool). Lean + well-annotated is a differentiator.

## Use

```bash
mcpgawk scan mcp.json                                              # a whole config
mcpgawk scan --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp"
mcpgawk scan --http https://host/mcp --header "Authorization: Bearer $TOKEN"
mcpgawk scan --sse  https://host/sse
mcpgawk scan mcp.json --track                                     # record + detect rug-pulls over time
mcpgawk scan mcp.json --json                                      # machine-readable labels
```

## What it reports

- **Cost index** — tokens each tool adds at connect (named tokenizer; a comparable index, not an
  absolute Claude count).
- **Capability facts** — write/mutating, exfil-capable, declared annotations.
- **Integrity pin** — a hash that changes if the server silently rewrites its tools; `--track`
  turns it into rug-pull detection over time.
- **Bounded signals** — precise, low-false-positive pointers *for a human to review*, never verdicts:
  injection-shaped descriptions (tools **and** prompts), cross-server name shadowing, and public
  Server Cards that under-declare what the server actually exposes.

## Guarantees

- **No inventory egress.** The only network is the protocol client talking to the server you point
  it at. The measurement layers import no network library — they *cannot* egress by construction
  (enforced by a test). Public Server Card discovery is fetched with no auth and no redirect-following.
- **Facts ≠ heuristics.** Exact capability facts and the token index never mix with the bounded
  heuristic signals — separate in code, separate in output.
- **Reproducible.** One command, identical numbers.
- **Tracks the protocol.** Built on the official `mcp` SDK, which negotiates the protocol version.

## Develop

```bash
uv run --extra dev --with mcp --with tiktoken --with httpx python -m pytest -q
```

## CI gate — GitHub Action

Scan your MCP servers on every pull request and fail the build if one gets too heavy or trips a signal.
It runs entirely in your runner — nothing is uploaded — and posts a per-server cost/flag table to the job summary.

```yaml
- uses: gawk-dev/mcpgawk@v1
  with:
    config: mcp.json        # or: stdio / http / sse — a single server
    max-tokens: 8000        # fail if any server loads more than this at connect
    fail-on-flagged: true   # fail if any bounded signal fires
```

Available on the [GitHub Marketplace](https://github.com/marketplace/actions/mcpgawk-mcp-hygiene-gate).

## Contributing

Issues and PRs welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first, and see the design
boundaries in [THREAT-MODEL.md](THREAT-MODEL.md). Security reports go through [SECURITY.md](SECURITY.md)
(privately, not a public issue).

## License

**Apache-2.0** — see [LICENSE](LICENSE). Part of the **nativerse** · gawk.dev family. The value is in the
repo, not a cloud.
