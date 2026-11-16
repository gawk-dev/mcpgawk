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
import shutil
import subprocess
import sys
import tempfile


#: The drift fields that mean the server moved since its baseline (the scan JSON's `drift`).
_CHANGE_KEYS = ("added", "removed", "changed", "schema_changed", "annotation_changed",
                "extensions_changed", "transport_changed", "login_changed")


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
    # The approvals to compare against (review B7, 2026-11-12): a fresh runner has no baseline, so
    # "fail when a server changes" was a promise with nothing behind it. A committed approvals file
    # (what `mcpgawk approve` writes) makes it checkable.
    baseline = _env("MCPGAWK_BASELINE")

    cmd = ["mcpgawk", "scan", "--json"]
    if stdio:
        cmd += ["--stdio", stdio]
    elif http:
        cmd += ["--http", http]
    elif sse:
        cmd += ["--sse", sse]
    elif config:
        # `--yes`: a non-interactive scan does not launch a config's local servers without
        # consent, and naming the config as this step's input IS that consent. Without it the
        # scan measured nothing and this gate printed an empty table and "passed" (real drive,
        # 2026-11-14).
        cmd += [config, "--yes"]
    else:
        print("::error::mcpgawk-action: provide one of `config`, `stdio`, `http`, or `sse`.")
        return 2

    env = dict(os.environ)
    if baseline and not os.path.isfile(baseline):
        # Left alone, the scan CREATES the file it was told to compare against, and passes.
        print(f"::error::mcpgawk-action: the baseline file `{baseline}` does not exist. "
              "Commit a copy of your ~/.mcpgawk/history.json and point `baseline` at it.")
        return 2
    with tempfile.TemporaryDirectory(prefix="mcpgawk-baseline-") as work:
        approved_before: set[str] = set()
        copy = os.path.join(work, "history.json")
        if baseline:
            # The scan compares against a COPY. Pointed at the committed file it rewrote it on
            # every run, left its lock and state files in the checkout, and tightened the
            # checkout directory's permissions (real drive, 2026-11-14).
            shutil.copyfile(baseline, copy)
            approved_before = _server_keys(copy)
            env["MCPGAWK_HISTORY"] = copy
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        # A server the baseline has never held reads exactly like one that matches it (no drift
        # either way). The scan records what it sees, so a key that is new afterwards is a server
        # nobody approved.
        unapproved = sorted(_server_keys(copy) - approved_before) if baseline else []
        # Read the names each new key answers to while the copy still exists: the scan keys a
        # server by the name it asserts (`mcp:toy-fixture`), the summary table by its config name
        # (`mail`). Without this the gate failed the build and still showed that row as ok
        # (real drive, 2026-11-16).
        aliases = _aliases(copy, unapproved)
    return _judge(proc, unapproved, max_tokens, fail_on_flagged, aliases)


def _server_keys(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            servers = json.load(fh).get("servers")
    except (OSError, ValueError, AttributeError):
        return set()
    return set(servers) if isinstance(servers, dict) else set()


def _aliases(path: str, keys: list[str]) -> dict[str, set[str]]:
    """Every name each key answers to: its recorded aliases, and the asserted name after `mcp:`."""
    try:
        with open(path, encoding="utf-8") as fh:
            servers = json.load(fh).get("servers")
    except (OSError, ValueError, AttributeError):
        servers = None
    servers = servers if isinstance(servers, dict) else {}
    out: dict[str, set[str]] = {}
    for key in keys:
        names = {key, key.split(":", 1)[1] if ":" in key else key}
        entry = servers.get(key)
        if isinstance(entry, dict):
            names.update(a for a in (entry.get("aliases") or []) if isinstance(a, str))
        out[key] = names
    return out


def _judge(proc, unapproved: list[str], max_tokens: int, fail_on_flagged: bool,
           aliases: dict[str, set[str]] | None = None) -> int:
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
    # The scan's own exit code (review B7): 0 = clean, 1 = something to review, anything else = the
    # scan itself did not complete. It was ignored, so only the two opt-in thresholds could fail.
    if proc.returncode not in (0, 1):
        failures.append(f"the scan did not complete (exit {proc.returncode}); nothing below is a pass")
    if not servers:
        # An empty table is not a clean fleet (real drive, 2026-11-14).
        failures.append("nothing was scanned: the scan returned no servers, so there is nothing "
                        "here to pass")
    if unapproved:
        failures.append(f"{len(unapproved)} server(s) are not in your baseline and have never "
                        f"been approved: {', '.join(unapproved)}")
    aliases = aliases if aliases is not None else {k: {k} for k in unapproved}
    unmatched = set(unapproved)
    for server in servers:
        x = server.get("x-mcpgawk", {}) or {}
        name = server.get("name", "?")
        info = server.get("serverInfo") if isinstance(server.get("serverInfo"), dict) else {}
        asserted = info.get("name")
        not_approved = [k for k in unapproved
                        if name in aliases.get(k, {k}) or (asserted and f"mcp:{asserted}" == k)]
        unmatched.difference_update(not_approved)
        tokens = int(x.get("cost_index_tokens", 0) or 0)
        tools = int(x.get("tool_count", 0) or 0)
        signals = x.get("bounded_signals") or []
        nsig = len(signals)
        status = "ok"
        if x.get("is_failure"):
            # A server nobody scanned rendered "ok" with 0 tools (review B7). Fails by default.
            why = "; ".join([str(x.get("error_kind") or "")] + [str(c) for c in (x.get("caveats") or [])])
            failures.append(f"{name}: not scanned ({why.strip('; ') or 'no reason given'})")
            rows.append((name, tools, tokens, nsig, "not scanned"))
            continue
        drift = x.get("drift") or {}
        if drift.get("compared") is False:
            failures.append(f"{name}: its baseline could not be compared — treat as unreviewed")
            status = "not compared"
        elif any(drift.get(k) for k in _CHANGE_KEYS):
            moved = [k for k in _CHANGE_KEYS if drift.get(k)]
            failures.append(f"{name}: changed since its baseline ({', '.join(moved)})")
            status = "changed"
        if max_tokens and tokens > max_tokens:
            failures.append(f"{name}: {tokens:,} tokens at connect exceeds the {max_tokens:,} budget")
            status = "over budget"
        if fail_on_flagged and nsig:
            failures.append(f"{name}: {nsig} bounded signal(s) — review them")
            status = "flagged" if status == "ok" else status
        if not_approved and status == "ok":
            status = "not in baseline"
        rows.append((name, tools, tokens, nsig, status))
    for key in sorted(unmatched):
        # A server the baseline check failed that no row above names: it still gets a red row.
        rows.append((key, "?", "?", "?", "not in baseline"))

    lines = [
        "## mcpgawk — MCP hygiene gate",
        "",
        "| Server | Tools | Tokens @ connect | Signals | Status |",
        "|---|---:|---:|---:|---|",
    ]
    for name, tools, tokens, nsig, status in rows:
        icon = "✅" if status == "ok" else "❌"
        shown = f"{tokens:,}" if isinstance(tokens, int) else tokens
        lines.append(f"| {name} | {tools} | {shown} | {nsig} | {icon} {status} |")
    if max_tokens:
        lines.append(f"\nToken budget: **{max_tokens:,}** per server.")
    if failures:
        # The reasons go in the summary too: a run-level failure (a scan that did not complete)
        # leaves every row green, and the log is not what a reviewer reads.
        lines.append("\n**mcpgawk gate: failed**\n")
        lines.extend(f"- {failure}" for failure in failures)
    lines.append("\n_Measured on the runner by mcpgawk; no scan result was uploaded._")
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
