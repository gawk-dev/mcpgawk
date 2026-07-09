## 0.1.1
- Robust CLI resolution: auto-detect mcpgawk (tries `mcpgawk`, `uvx mcpgawk`, `python -m mcpgawk`) and augment PATH with common install dirs, so it works even when the editor's GUI process doesn't see your shell PATH. Clearer 'not found' recovery (offers uvx, needs no install).

# Changelog

## 0.1.0
- First release: scan the workspace `mcp.json`, per-server cost + capability panel, status-bar token total.
