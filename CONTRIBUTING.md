# Contributing to mcpgawk

Thanks for helping. mcpgawk is small on purpose. Two rules are non-negotiable — a PR that breaks
either will not be merged.

## The two invariants

1. **No inventory egress.** The measurement layers (`measure`, `label`, `signals`, `drift`, `history`)
   must never import a network library or send anything anywhere. Network lives only in `probe.py` (the
   protocol client talking to the scanned server) and `servercard.py` (public, unauthenticated card
   fetch — no auth headers, no redirect-following). A test enforces this; don't weaken it.

2. **Zero false positives, or the signal is cut.** Any new BOUNDED signal must be *precise* (it fires on
   language aimed at the model, never on legitimate capability keywords) and must score **0 false
   positives** on the test corpus before it ships. A capability keyword (`url`, `delete`, `base64`) is a
   *fact* (`measure.py`), never a signal. A signal is a pointer for a human, never a verdict.

## Also
- Keep the EXACT / INDEX / BOUNDED tiers separate — never let a heuristic contaminate a fact.
- Cost is a **named tokenizer index**, not an absolute count — keep it labelled honestly.
- Add a test with every change. Run: `uv run --extra dev --with mcp --with tiktoken --with httpx python -m pytest -q`.
- No telemetry, no account, no "phone home" — ever. That is the whole point of the tool.

## Dev setup
```bash
git clone <repo> && cd mcpgawk
uv run --with mcp --with tiktoken --with httpx python -m mcpgawk scan examples/mcp.json
```

By contributing you agree your contribution is licensed under Apache-2.0.
