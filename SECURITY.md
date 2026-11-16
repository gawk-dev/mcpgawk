# Security

mcpgawk is a **local-first** tool: your servers, approvals and call log stay on your machine. Nothing
about them is sent unless you ask for it (`mcpgawk push`, `--supply-chain`). The design and its boundaries are documented in [THREAT-MODEL.md](THREAT-MODEL.md).

## Reporting a vulnerability

If you find a security issue **in mcpgawk itself** (e.g. a way it could leak inventory, follow a redirect
with credentials, or execute untrusted content), please report it privately rather than opening a public issue:

- Open a [GitHub security advisory](../../security/advisories/new), or
- email **hello@nativerse-ventures.com** with "security" in the subject.

Please include: what you did, what you expected, what happened, and a minimal reproduction. We aim to
acknowledge within a few days.

## Scope

- **In scope:** inventory egress, credential handling (Server Card fetch is deliberately unauthenticated and
  does not follow redirects), the EXACT / BOUNDED / INDEX separation, and any way the tool could be made to
  act on content from a scanned server.
- **Out of scope:** findings *about a third-party MCP server* that mcpgawk reports on. mcpgawk's signals are
  **bounded pointers for a human to review, never verdicts** — a flagged tool is not a vulnerability report.
