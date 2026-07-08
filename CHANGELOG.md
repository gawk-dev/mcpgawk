# Changelog

All notable changes to mcpgawk. Format: [Keep a Changelog](https://keepachangelog.com/); versioning: [SemVer](https://semver.org/).

## [0.1.2] — 2026-07-08

### Changed
- Plain, reader-first README and package description.
- README images use absolute URLs so they render on PyPI (relative paths only work on GitHub).

## [0.1.1] — 2026-07-08

### Fixed
- A tool declaring `destructiveHint: true` is now counted as write/mutating even when its name isn't a
  write-verb (e.g. a `pause_job` tool). Previously the verb heuristic could leave a declared-destructive
  tool unflagged.

## [0.1.0] — 2026-07-08

Initial release. Local-first MCP measurement.

### Added
- `mcpgawk scan` over stdio, streamable-HTTP, and SSE via the official `mcp` SDK (protocol-version negotiated).
- Cost **index** (named tokenizer) + **EXACT** capability facts (write / exfil-capable / annotations) + **integrity pin**.
- **Bounded** heuristic signals (0-FP on the tested corpus, never verdicts): injection-shaped descriptions
  (tools and prompts), cross-server name shadowing, Server-Card under-declaration.
- `--track` rug-pull / drift monitor with a local history store.
- Server Card reader (`/.well-known/mcp/server-card.json`) — reads the card when present, checks
  declared-vs-measured, falls back to live-connect. Fetched with no auth and no redirect-following.
- Label output as a Server-Card extension (`x-mcpgawk`); `--json` for machine consumption.

### Security
- Measurement layers import no network library — cannot egress by construction (enforced by test).
- Per-server timeout so a hung server degrades to one error row.
