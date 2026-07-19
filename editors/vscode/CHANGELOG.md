## 0.1.4
- Version sync with CLI 0.1.4 (`--login` OAuth scanning, dynamic tool-dispatch detection, typed
  error handling so a failed probe never reads CLEAN, faster remote-scan timeout, corrected signal
  labels). No extension code change — the panel reads `tool_count`, `cost_index_tokens`,
  `tools[].write/exfil_capable`, and `bounded_signals`, all unchanged additive fields in the label schema.

## 0.1.3
- Version sync with CLI 0.1.3 (5-axis report, `--verbose`, opt-in `--supply-chain`/`--oauth-scopes`). No
  extension code change — the panel reads `tool_count`, `cost_index_tokens`, `tools[].write/exfil_capable`,
  and `bounded_signals`, all of which are unchanged, additive-only fields in the 0.1.3 label schema.

## 0.1.1
- Robust CLI resolution: auto-detect mcpgawk (tries `mcpgawk`, `uvx mcpgawk`, `python -m mcpgawk`) and augment PATH with common install dirs, so it works even when the editor's GUI process doesn't see your shell PATH. Clearer 'not found' recovery (offers uvx, needs no install).

# Changelog

## 0.1.0
- First release: scan the workspace `mcp.json`, per-server cost + capability panel, status-bar token total.
