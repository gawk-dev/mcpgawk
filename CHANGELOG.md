# Changelog

All notable changes to mcpgawk. Format: [Keep a Changelog](https://keepachangelog.com/); versioning: [SemVer](https://semver.org/).

## [0.1.3] — 2026-07-12

### Added
- Report now covers 5 axes: cost (+ top-3 heaviest tools), trust surface (% write, % exfil-capable,
  destructive-declared count), annotation completeness (score — was computed but never surfaced),
  coverage (prompts/resources, previously `--json`-only), and bounded signals (unchanged).
- `--verbose` — full per-tool table in CLI text output (previously only the write/exfil-flagged subset
  was shown; the full list existed only via `--json`).
- `--supply-chain` (opt-in) — checks the launched package against the public npm registry / PyPI JSON
  API for deprecation (npm) / yanked (PyPI, PEP 592) status. Makes a real network call — only the package
  name and version are sent, never the tool inventory. Off by default.
- `--oauth-scopes` (opt-in) — locally decodes a supplied `Authorization: Bearer <jwt>` header's `scope`/
  `scp` claim. No network call; the signature is not verified (reading a declared claim, not
  authenticating). Opaque (non-JWT) tokens are reported as not locally inspectable, never guessed at.

### Changed
- `x-mcpgawk` label schema gains `top_heavy_tools`, `trust_surface`, `annotation_completeness`, and
  (only when the corresponding flag is passed) `supply_chain`/`oauth_scopes`. All additive — no existing
  key renamed or removed.

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
