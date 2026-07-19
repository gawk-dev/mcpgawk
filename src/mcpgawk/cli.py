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
from dataclasses import asdict
from datetime import datetime, timezone

from . import drift, history
from .label import build_label, render_cli, render_summary
from .measure import measure
from .oauth_scopes import inspect as inspect_oauth_scopes
from .probe import ServerSnapshot, probe, probe_http, probe_sse, probe_stdio
from .signals import as_dicts, detect, detect_card_mismatch, detect_dynamic_dispatch, detect_shadowing
from .supplychain import check as check_supply_chain


def _load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("mcpServers", data)


def _headers(pairs: list[str] | None) -> dict[str, str]:
    out = {}
    for p in pairs or []:
        k, _, v = p.partition(":")
        out[k.strip()] = v.strip()
    return out


async def _run(args) -> tuple[list[ServerSnapshot], dict[str, dict]]:
    """Returns snapshots alongside the raw entry (command/args/headers) each came from — the
    opt-in supply-chain/oauth-scopes checks need that, but it's never part of the core scan."""
    if args.stdio:
        parts = shlex.split(args.stdio)
        entry = {"command": parts[0], "args": parts[1:]}
        return [await probe_stdio("cli-stdio", parts[0], parts[1:])], {"cli-stdio": entry}
    if args.http or args.sse:
        url = args.http or args.sse
        transport = "http" if args.http else "sse"
        entry = {"url": url, "headers": _headers(args.header)}
        auth = server = None
        # A remote endpoint that isn't MCP (a pasted docs/repo URL) must fail fast, not hang — so
        # the default here is the short HTTP budget, not the 90s stdio one. --login is the one case
        # that legitimately waits: the user has 5 min to approve the OAuth flow in the browser.
        from .probe import HTTP_TIMEOUT
        timeout = HTTP_TIMEOUT
        if getattr(args, "login", False):
            from .oauth_login import build_login_provider
            auth, server = build_login_provider(url)
            timeout = 330.0
        probe_fn = probe_http if transport == "http" else probe_sse
        try:
            snap = await probe_fn(f"cli-{transport}", url, entry["headers"], timeout, auth)
        finally:
            if server is not None:
                server.shutdown()
        return [snap], {f"cli-{transport}": entry}
    only = set(args.only.split(",")) if args.only else None
    cfg = _load_config(args.config)
    targets = [(n, e) for n, e in cfg.items() if not only or n in only]
    snaps = await asyncio.gather(*(probe(e, n) for n, e in targets))
    return list(snaps), {n: e for n, e in targets}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcpgawk", description="gawk at an MCP server before you trust it")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="measure MCP server(s) locally")
    s.add_argument("config", nargs="?", help="path to an mcp.json config")
    s.add_argument("--stdio", help='one stdio server, e.g. "npx -y @modelcontextprotocol/server-filesystem /tmp"')
    s.add_argument("--http", help="one streamable-HTTP server URL")
    s.add_argument("--sse", help="one SSE server URL")
    s.add_argument("--header", action="append", help='HTTP header, e.g. "Authorization: Bearer XYZ" (repeatable)')
    s.add_argument("--login", action="store_true",
                   help="for a remote --http/--sse server that needs OAuth: open the browser, sign "
                        "in once, and scan (token stored locally in ~/.gawk/oauth)")
    s.add_argument("--only", help="comma-separated server names to scan from the config")
    s.add_argument("--no-signals", action="store_true", help="skip BOUNDED heuristic signals (facts only)")
    s.add_argument("--track", action="store_true",
                   help="record this scan locally and report DRIFT vs the last sighting (rug-pull detection)")
    s.add_argument("--json", action="store_true", help="emit JSON labels instead of a table")
    s.add_argument("--verbose", action="store_true", help="show the full per-tool table, not just flagged tools")
    s.add_argument("--supply-chain", action="store_true",
                   help="opt-in: query the public npm/PyPI registry for the launched package's "
                        "deprecation/yank status (network egress — package name+version only)")
    s.add_argument("--oauth-scopes", action="store_true",
                   help="opt-in: locally decode a supplied Bearer JWT's scope claim (no network; "
                        "reads a credential you already provided)")
    args = p.parse_args(argv)

    if args.cmd == "scan" and not (args.config or args.stdio or args.http or args.sse):
        p.error("give a config path or one of --stdio/--http/--sse")

    snaps, entries = asyncio.run(_run(args))
    measurements = [measure(sn) for sn in snaps]
    # Cross-server shadowing needs all snapshots together; merge into each involved server's signals.
    shadow = {} if args.no_signals else detect_shadowing(snaps)
    labels = []
    for sn, m in zip(snaps, measurements):
        sigs = None
        if not args.no_signals:
            sigs = (as_dicts(detect(sn)) + as_dicts(shadow.get(sn.name, []))
                    + as_dicts(detect_card_mismatch(sn)) + as_dicts(detect_dynamic_dispatch(sn)))
        label = build_label(sn, m, bounded_signals=(sigs or None))
        entry = entries.get(sn.name) or {}
        # Both opt-in: supply-chain hits a public registry (egress), oauth-scopes reads a
        # credential the user already supplied (no egress, but still consent-gated).
        if args.supply_chain and entry.get("command"):
            finding = check_supply_chain(entry["command"], entry.get("args") or [])
            label["x-mcpgawk"]["supply_chain"] = (
                asdict(finding) if finding else {"checked": False,
                                                  "reason": "package not recognised from the launch command"})
        if args.oauth_scopes:
            label["x-mcpgawk"]["oauth_scopes"] = inspect_oauth_scopes(entry.get("headers"))
        labels.append(label)

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

    # Show the REAL installed version, not a hardcoded string. `__version__` is now single-sourced
    # from the installed package metadata in __init__ (see there), so this banner can no longer go
    # stale or disagree with pyproject/PyPI. A version banner that lies erodes trust in a measurement
    # tool.
    from . import __version__ as _ver
    print(f"\n{'='*70}\nmcpgawk {_ver} — LOCAL scan (no inventory uploaded)\n{'='*70}")
    any_error = False
    for lab in labels:
        print("\n" + render_cli(lab, verbose=args.verbose))
        rep = drift_reports.get(lab["name"])
        if rep:
            print(drift.render(lab["name"], rep))
        any_error = any_error or bool(lab["x-mcpgawk"].get("caveats"))
    print("\n" + render_summary(labels) + "\n")
    return 1 if any_error else 0


if __name__ == "__main__":
    sys.exit(main())
