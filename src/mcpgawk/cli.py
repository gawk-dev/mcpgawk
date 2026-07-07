"""mcpgawk CLI — one command, zero config.

    mcpgawk scan <mcp.json> [--only a,b] [--json]
    mcpgawk scan --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp"
    mcpgawk scan --http https://host/mcp [--header "Authorization: Bearer ..."]
    mcpgawk scan --sse  https://host/sse

Local-first: the only network is the SDK talking to the server you point it at.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import sys
from datetime import datetime, timezone

from . import drift, history
from .label import build_label, render_cli, render_summary
from .measure import measure
from .probe import ServerSnapshot, probe, probe_http, probe_sse, probe_stdio
from .signals import as_dicts, detect, detect_card_mismatch, detect_shadowing


def _load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("mcpServers", data)


async def _scan_config(cfg: dict, only: set[str] | None) -> list[ServerSnapshot]:
    targets = [(n, e) for n, e in cfg.items() if not only or n in only]
    return await asyncio.gather(*(probe(e, n) for n, e in targets))


def _headers(pairs: list[str] | None) -> dict[str, str]:
    out = {}
    for p in pairs or []:
        k, _, v = p.partition(":")
        out[k.strip()] = v.strip()
    return out


async def _run(args) -> list[ServerSnapshot]:
    if args.stdio:
        parts = shlex.split(args.stdio)
        return [await probe_stdio("cli-stdio", parts[0], parts[1:])]
    if args.http:
        return [await probe_http("cli-http", args.http, _headers(args.header))]
    if args.sse:
        return [await probe_sse("cli-sse", args.sse, _headers(args.header))]
    only = set(args.only.split(",")) if args.only else None
    return await _scan_config(_load_config(args.config), only)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcpgawk", description="gawk at an MCP server before you trust it")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="measure MCP server(s) locally")
    s.add_argument("config", nargs="?", help="path to an mcp.json config")
    s.add_argument("--stdio", help='one stdio server, e.g. "npx -y @modelcontextprotocol/server-filesystem /tmp"')
    s.add_argument("--http", help="one streamable-HTTP server URL")
    s.add_argument("--sse", help="one SSE server URL")
    s.add_argument("--header", action="append", help='HTTP header, e.g. "Authorization: Bearer XYZ" (repeatable)')
    s.add_argument("--only", help="comma-separated server names to scan from the config")
    s.add_argument("--no-signals", action="store_true", help="skip BOUNDED heuristic signals (facts only)")
    s.add_argument("--track", action="store_true",
                   help="record this scan locally and report DRIFT vs the last sighting (rug-pull detection)")
    s.add_argument("--json", action="store_true", help="emit JSON labels instead of a table")
    args = p.parse_args(argv)

    if args.cmd == "scan" and not (args.config or args.stdio or args.http or args.sse):
        p.error("give a config path or one of --stdio/--http/--sse")

    snaps = asyncio.run(_run(args))
    measurements = [measure(sn) for sn in snaps]
    # Cross-server shadowing needs all snapshots together; merge into each involved server's signals.
    shadow = {} if args.no_signals else detect_shadowing(snaps)
    labels = []
    for sn, m in zip(snaps, measurements):
        sigs = None
        if not args.no_signals:
            sigs = (as_dicts(detect(sn)) + as_dicts(shadow.get(sn.name, []))
                    + as_dicts(detect_card_mismatch(sn)))
        labels.append(build_label(sn, m, bounded_signals=(sigs or None)))

    # --track: record locally and diff against the last sighting (rug-pull detection).
    drift_reports: dict[str, drift.DriftReport] = {}
    if args.track:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        store = history.load()
        for sn, m in zip(snaps, measurements):
            if sn.error:
                continue
            key = history.key_for(sn)
            record = drift.build_record(sn, m, measured_at=now)
            rep = drift.compare(history.last(store, key), record)
            if rep and rep.any:
                drift_reports[sn.name] = rep
            history.append(store, key, record)
        history.save(store)

    if args.json:
        print(json.dumps(labels, indent=2))
        return 0

    print(f"\n{'='*70}\nmcpgawk 0.1 — LOCAL scan (no inventory uploaded)\n{'='*70}")
    any_error = False
    for lab in labels:
        print("\n" + render_cli(lab))
        rep = drift_reports.get(lab["name"])
        if rep:
            print(drift.render(lab["name"], rep))
        any_error = any_error or bool(lab["x-mcpgawk"].get("caveats"))
    print("\n" + render_summary(labels) + "\n")
    return 1 if any_error else 0


if __name__ == "__main__":
    sys.exit(main())
