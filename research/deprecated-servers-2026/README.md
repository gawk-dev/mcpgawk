# Archived MCP servers, still installed (snapshot 2026-10-22)

Five reference servers the Model Context Protocol project archived on 2025-05-29 (commit d53d6cc75c,
"Archive unmaintained servers") are still among the 30 most-downloaded MCP server packages on npm. Plus
CircleCI's npm package, deprecated in favour of its hosted server.

| Package | latest | published | npm deprecation message |
|---|---|---|---|
| @modelcontextprotocol/server-github | 2025.4.8 | 2025-04-08 | "Package no longer supported. Contact Support at https://www.npmjs.com/support for more info." |
| @modelcontextprotocol/server-slack | 2025.4.25 | 2025-04-25 | same |
| @modelcontextprotocol/server-postgres | 0.6.2 | 2024-12-04 | same |
| @modelcontextprotocol/server-puppeteer | 2025.5.12 | 2025-05-12 | same |
| @modelcontextprotocol/server-brave-search | 0.6.2 | 2024-12-04 | same |
| @circleci/mcp-server-circleci | 0.20.0 | 2026-08-06 | "Deprecated: use CircleCI's hosted MCP server or CircleCI CLI MCP instead…" |

All five npm READMEs still show an `"npx", "-y"` install line. Only server-github's carries a deprecation
notice (pointing at github/github-mcp-server).

## Downloads
- The five reference servers, per month: 407,645 in June 2025, 1,794,602 in July 2026 (npm has backfilled July
  since our 22 Oct snapshot, which read 1,738,924). 17,163,025 from 2025-06-01 to 2026-11-03. That total is a floor:
  npm reports some whole days as zero (see `zero_days`).
- Rechecked 9 Nov 2026: npm backfilled more October days. 2025-06-01 to 2026-11-03 now reads 17,312,978; to
  2026-11-08 it reads 17,695,421 (the "about 17.7 million" in the write-up). Still a floor: 9 zero days per
  package remain in that range. Every other figure on this page was unchanged on 9 Nov.
- Week 26 Oct–1 Nov 2026 (no zero days), all six packages: 632,516. server-postgres alone: 164,787.
  The earlier figure, week 21–27 Sep 2026: 455,402 and 109,622.
- Do not use October 2026 as a month, or the week 12–18 Oct: both contain zero days across every package, a stats gap.
- For comparison, maintained reference servers, June 2025 → July 2026: server-filesystem 174,541 → 2,499,106
  (backfilled; read 2,399,054 on 22 Oct); server-memory 93,023 → 535,816 (22 Oct reading).
- Downloads count CI jobs and mirrors as well as people. They are not users.

## server-postgres: a known bug, fix merged, never published
Datadog Security Labs, 2025-08-21: a query starting `COMMIT;` ends the server's read-only transaction, and
later statements run with the database role's full rights
(https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/).
The fix, modelcontextprotocol/servers PR #1889, was merged to main on 2025-05-29, the day of the archive. npm
still serves 0.6.2 from 2024-12-04. Datadog counted about 21,000 weekly downloads then.

## Is the warning visible?
With a fresh npm cache, `npx -y @modelcontextprotocol/server-postgres <url>` prints `npm warn deprecated …` to
stderr on the first start. A second start, from npx's cache, prints nothing.

## Rerun
`python scripts/fetch.py > data/snapshot-$(date +%F).json` (standard library only). `data/snapshot-2026-11-04.json` (current) and `data/snapshot-2026-10-22.json`
holds this snapshot: version, deprecation text, monthly and daily downloads, zero days.
