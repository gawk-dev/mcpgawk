# mcpgawk

**gawk at an MCP server before you trust it.** A single, local-first command that connects to any
[Model Context Protocol](https://modelcontextprotocol.io) server and measures what it will cost and
expose — **without the server's inventory ever leaving your machine.**

```
● example-server         [stdio]  proto=2025-11-25
     14 tools     1890 tok@connect   pin:b5ba075b025f
      · write_file                     108 tok   write, destructive-declared
      · fetch_url                      120 tok   exfil-capable
      ...
```

## Why

Every MCP server you connect dumps *all* its tool definitions into your model's context at connect
time — whether you use one tool or none. That's a hidden **token tax** and an unvetted **trust
surface**. mcpgawk measures both, **locally**, and never phones home about what it saw.

## Install

```bash
pip install mcpgawk        # or: uv tool install mcpgawk
```

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
- **Rides protocol evolution.** Built on the official `mcp` SDK, which negotiates the protocol version.

## Develop

```bash
uv run --extra dev --with mcp --with tiktoken --with httpx python -m pytest -q
```

Apache-2.0. The value is in the repo, not a cloud.
