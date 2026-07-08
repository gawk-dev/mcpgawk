#!/usr/bin/env python3
"""mcpgawk CI gate — scan MCP servers locally and fail the build on hygiene thresholds.

Reads its inputs from MCPGAWK_* env vars (set by action.yml), runs `mcpgawk scan --json`,
writes a Markdown summary to the GitHub job summary, and exits non-zero if a gate fails.
Nothing is uploaded; the scan runs entirely in the runner.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


def main() -> int:
    config = _env("MCPGAWK_CONFIG")
    stdio = _env("MCPGAWK_STDIO")
    http = _env("MCPGAWK_HTTP")
    sse = _env("MCPGAWK_SSE")
    try:
        max_tokens = int(_env("MCPGAWK_MAX_TOKENS", "0") or "0")
    except ValueError:
        max_tokens = 0
    fail_on_flagged = _env("MCPGAWK_FAIL_ON_FLAGGED", "false").lower() == "true"

    cmd = ["mcpgawk", "scan", "--json"]
    if stdio:
        cmd += ["--stdio", stdio]
    elif http:
        cmd += ["--http", http]
    elif sse:
        cmd += ["--sse", sse]
    elif config:
        cmd += [config]
    else:
        print("::error::mcpgawk-action: provide one of `config`, `stdio`, `http`, or `sse`.")
        return 2

    proc = subprocess.run(cmd, capture_output=True, text=True)
    match = re.search(r"(\[.*\]|\{.*\})", proc.stdout, re.S)
    if not match:
        print("::error::mcpgawk-action: no JSON label produced by the scan.")
        sys.stderr.write(proc.stdout[-2000:] + "\n" + proc.stderr[-2000:] + "\n")
        return 2
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        print(f"::error::mcpgawk-action: could not parse scan JSON ({exc}).")
        return 2
    servers = data if isinstance(data, list) else [data]

    rows = []
    failures = []
    for server in servers:
        x = server.get("x-mcpgawk", {}) or {}
        name = server.get("name", "?")
        tokens = int(x.get("cost_index_tokens", 0) or 0)
        tools = int(x.get("tool_count", 0) or 0)
        signals = x.get("bounded_signals") or []
        nsig = len(signals)
        status = "ok"
        if max_tokens and tokens > max_tokens:
            failures.append(f"{name}: {tokens:,} tokens at connect exceeds the {max_tokens:,} budget")
            status = "over budget"
        if fail_on_flagged and nsig:
            failures.append(f"{name}: {nsig} bounded signal(s) — review them")
            status = "flagged" if status == "ok" else status
        rows.append((name, tools, tokens, nsig, status))

    lines = [
        "## mcpgawk — MCP hygiene gate",
        "",
        "| Server | Tools | Tokens @ connect | Signals | Status |",
        "|---|---:|---:|---:|---|",
    ]
    for name, tools, tokens, nsig, status in rows:
        icon = "✅" if status == "ok" else "❌"
        lines.append(f"| {name} | {tools} | {tokens:,} | {nsig} | {icon} {status} |")
    if max_tokens:
        lines.append(f"\nToken budget: **{max_tokens:,}** per server.")
    lines.append("\n_Measured locally by mcpgawk — nothing left the runner._")
    summary = "\n".join(lines)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(summary + "\n")
    print(summary)

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print("\nmcpgawk gate: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
