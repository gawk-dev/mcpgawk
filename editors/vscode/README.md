# mcpgawk — MCP cost & hygiene

See what your MCP servers cost and expose, right in your editor. **Local — nothing leaves your machine.**

Every MCP server you connect loads all its tools into your AI's context, on every request. This extension
runs the [mcpgawk](https://mcp.gawk.dev) CLI on your workspace's `mcp.json` and shows, per server, the tokens
loaded at connect, the write / network-capable tools, and any bounded signals.

## Use

1. Install the CLI once: `pip install mcpgawk`
2. Open a folder with an `mcp.json` (also detects `.cursor/mcp.json`, `.vscode/mcp.json`).
3. Run **mcpgawk: Scan MCP servers** from the command palette — or click the token count in the status bar.

## Settings

- `mcpgawk.configPath` — path to a specific config (default: auto-detect).
- `mcpgawk.command` — how to invoke the CLI (`mcpgawk`, `uvx mcpgawk`, or an absolute path).

## Privacy

The scan runs entirely on your machine via the local CLI. No inventory is uploaded. Apache-2.0 · part of nativerse · gawk.dev
