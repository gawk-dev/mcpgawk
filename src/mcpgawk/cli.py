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

from . import drift, fleet, history
from .fleet import FleetRow
from .consent import gate_stdio_consent
from .discover import detect_unscannable, discover_servers
from .label import build_label, render_cli, render_summary
from .measure import measure
from .oauth_scopes import inspect as inspect_oauth_scopes
from .probe import ServerSnapshot, probe, probe_stdio, probe_url
from .signals import (as_dicts, detect, detect_card_mismatch, detect_cross_server_reference,
                      detect_dynamic_dispatch, detect_shadowing)
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


async def _run(args) -> tuple[list[ServerSnapshot], dict[str, dict], list[tuple[str, dict]]]:
    """Returns snapshots, the raw entry (command/args/headers) each came from, and the targets we
    deliberately did NOT scan (consent withheld). The entries feed the opt-in supply-chain/
    oauth-scopes checks and the fleet view's auth step; the skipped list keeps unscanned servers
    VISIBLE, so the summary can never imply coverage it doesn't have."""
    if args.stdio:
        parts = shlex.split(args.stdio)
        entry = {"command": parts[0], "args": parts[1:]}
        return [await probe_stdio("cli-stdio", parts[0], parts[1:])], {"cli-stdio": entry}, []
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
        # `--http`/`--sse` orders the attempts; it does not decide what we believe. The one case we
        # do NOT permute is --login: an OAuth provider would re-run its browser flow per candidate
        # and offer the token to URLs the user never named (see probe_url).
        try:
            snap = await probe_url(f"cli-{transport}", url, entry["headers"], timeout, auth,
                                   declared=transport, permute=auth is None)
        finally:
            if server is not None:
                server.shutdown()
        return [snap], {f"cli-{transport}": entry}, []
    only = set(args.only.split(",")) if args.only else None
    # Zero-config: with no path given, DISCOVER every MCP server configured across the machine's IDE
    # clients (Claude Desktop/Code, Cursor, VS Code, Windsurf, …), deduped. `mcpgawk scan` just works.
    is_discovery = not args.config
    cfg = _load_config(args.config) if args.config else discover_servers()
    targets = [(n, e) for n, e in cfg.items() if not only or n in only]
    if is_discovery and not targets:
        print("mcpgawk: no MCP servers found in your IDE configs "
              "(Claude Desktop/Code, Cursor, VS Code, Windsurf, …).\n"
              "  Point it at a config:  mcpgawk scan path/to/mcp.json\n"
              "  Or scan one server:    mcpgawk scan --stdio \"npx -y <server>\"  |  --http <url>",
              file=sys.stderr)
        return [], {}, []
    # Default-deny consent before LAUNCHING any discovered/configured stdio server (spawning runs its
    # code). Explicit --stdio never reaches here; remote servers aren't spawned so they always pass.
    approved = gate_stdio_consent(targets, assume_yes=getattr(args, "yes", False))
    # A server we chose NOT to launch must stay VISIBLE in the fleet view. Dropping it silently
    # would let the summary imply coverage we don't have.
    ok_names = {n for n, _ in approved}
    skipped = [(n, e) for n, e in targets if n not in ok_names]
    snaps = await asyncio.gather(*(probe(e, n) for n, e in approved))
    return list(snaps), {n: e for n, e in approved}, skipped


def _label_for(sn: ServerSnapshot, m, entry: dict, args, shadow: dict | None = None) -> dict:
    """Build one server's label. Extracted so the post-sign-in re-scan produces an IDENTICAL label
    to the original pass — a second, drifting definition of "what a label is" is exactly how the
    refreshed row would start disagreeing with the row it replaced."""
    sigs = None
    if not args.no_signals:
        sigs = (as_dicts(detect(sn)) + as_dicts((shadow or {}).get(sn.name, []))
                + as_dicts(detect_card_mismatch(sn)) + as_dicts(detect_dynamic_dispatch(sn)))
    label = build_label(sn, m, bounded_signals=(sigs or None))
    # Both opt-in: supply-chain hits a public registry (egress), oauth-scopes reads a credential the
    # user already supplied (no egress, but still consent-gated).
    if args.supply_chain and entry.get("command"):
        finding = check_supply_chain(entry["command"], entry.get("args") or [])
        label["x-mcpgawk"]["supply_chain"] = (
            asdict(finding) if finding else {"checked": False,
                                             "reason": "package not recognised from the launch command"})
    if args.oauth_scopes:
        label["x-mcpgawk"]["oauth_scopes"] = inspect_oauth_scopes(entry.get("headers"))
    return label


def build_parser() -> argparse.ArgumentParser:
    """The CLI surface, separated from `main` so the argument CONTRACT can be tested directly.

    Whether tracking defaults on is a product invariant (ADR-0012 N2), not a detail — asserting it
    needs a parser you can build without running a scan."""
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
    s.add_argument("--yes", "-y", action="store_true",
                   help="launch discovered/configured local (stdio) servers WITHOUT the consent "
                        "prompt (scanning a stdio server runs its code) — for CI / non-interactive use")
    s.add_argument("--no-signals", action="store_true", help="skip BOUNDED heuristic signals (facts only)")
    # ON BY DEFAULT (ADR-0012 N2). As an opt-in flag this produced no state for the users who never
    # thought to pass it — and drift is the one capability a general-purpose agent cannot reproduce,
    # precisely because it needs state captured before the question was asked. A moat you have to
    # remember to switch on is not a moat.
    s.add_argument("--no-track", dest="track", action="store_false",
                   help="do NOT record this scan locally (drift/rug-pull detection is on by default; "
                        "history stays on this machine, at ~/.mcpgawk/history.json)")
    s.add_argument("--track", dest="track", action="store_true",
                   help=argparse.SUPPRESS)   # kept so existing scripts and CI jobs keep working
    s.set_defaults(track=True)
    s.add_argument("--json", action="store_true", help="emit JSON labels instead of a table")
    s.add_argument("--fleet-json", action="store_true",
                   help="emit the FLEET STATUS as JSON (one row per server, grouped by the tool it "
                        "lives in) — what the IDE extension renders, so state is computed once here")
    s.add_argument("--with-spec", action="store_true",
                   help="with --fleet-json, include each server's launch spec (command/args/env or "
                        "url) so a local front-end can verify it by click — MAY carry secrets from "
                        "your config; kept off by default and never printed without this flag")
    s.add_argument("--verbose", action="store_true", help="show the full per-tool table, not just flagged tools")
    s.add_argument("--detail", action="store_true",
                   help="print the full narrative report for EVERY server instead of the fleet "
                        "status list (the list is the default when more than one server is scanned)")
    s.add_argument("--supply-chain", action="store_true",
                   help="opt-in: query the public npm/PyPI registry for the launched package's "
                        "deprecation/yank status (network egress — package name+version only)")
    s.add_argument("--oauth-scopes", action="store_true",
                   help="opt-in: locally decode a supplied Bearer JWT's scope claim (no network; "
                        "reads a credential you already provided)")

    # The other half of a sticky alarm. Drift now re-reports on every scan until acknowledged
    # (ADR-0012 N1), so there MUST be an obvious way to acknowledge it — an alarm a user cannot
    # clear is one they will silence with --no-track, which costs them the baseline entirely.
    a = sub.add_parser("approve",
                       help="accept a server's current tools as the trusted baseline (clears DRIFT)")
    a.add_argument("server", nargs="?",
                   help="the server name as it appears in your config, or its asserted identity")
    a.add_argument("--all", action="store_true", help="approve every server with pending drift")
    a.add_argument("--list", action="store_true",
                   help="show which servers have changes you have not approved, and change nothing")
    return p


def _approve(args) -> int:
    """`mcpgawk approve` — move the trusted baseline forward, deliberately."""
    path = history.default_path()
    store = history.load(path)
    waiting = history.pending(store)

    if args.list or (not args.server and not args.all):
        if not waiting:
            print("Nothing to approve — every tracked server matches its approved baseline.")
            return 0
        print(f"{len(waiting)} server(s) changed since you approved them:\n")
        for key in waiting:
            entry = store["servers"][key]
            names = ", ".join(entry.get("aliases", [])) or key
            print(f"    {names}  ({key})")
        print("\nReview the change first — `mcpgawk scan` shows what moved.")
        print("Then: mcpgawk approve <name>    (or --all)")
        return 0 if args.list else 1

    targets = waiting if args.all else [k for k in [history.resolve(store, args.server)] if k]
    if not targets:
        print(f"No tracked server matches {args.server!r}. "
              f"Try `mcpgawk approve --list`.", file=sys.stderr)
        return 2

    for key in targets:
        rec = history.approve(key, path=path)
        if rec is None:
            print(f"Nothing recorded for {key} yet — scan it first.", file=sys.stderr)
            return 2
        names = ", ".join(store["servers"][key].get("aliases", [])) or key
        # Name what was approved. "Approved." alone leaves a user unsure WHAT they just trusted.
        print(f"✓ approved {names} — {rec.get('tool_count', '?')} tools, "
              f"as seen {rec.get('measured_at') or 'just now'}. Future drift is measured from here.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    if args.cmd == "approve":
        return _approve(args)

    # No args at all is VALID: it means "discover and scan everything on this machine". _run handles
    # the nothing-found message and default-deny consent before launching any discovered stdio server.
    snaps, entries, skipped = asyncio.run(_run(args))
    measurements = [measure(sn) for sn in snaps]
    # Cross-server signals need all snapshots together; merge into each involved server's signals.
    # Two DISTINCT techniques, both requiring the whole inventory:
    #   name-collision      — two servers expose the same tool name (one shadows the other)
    #   cross-server-ref    — a server's description instructs the agent about ANOTHER server's tool
    #                         (Invariant E002). The names differ; the danger is server A rewriting how
    #                         the agent uses server B's trusted tool.
    shadow: dict = {}
    if not args.no_signals:
        shadow = detect_shadowing(snaps)
        for srv, fs in detect_cross_server_reference(snaps).items():
            shadow.setdefault(srv, []).extend(fs)
    labels = [_label_for(sn, m, entries.get(sn.name) or {}, args, shadow)
              for sn, m in zip(snaps, measurements)]

    # --track: record locally and diff against the last sighting (rug-pull detection).
    drift_reports: dict[str, drift.DriftReport] = {}
    new_baselines: list[str] = []
    reidentified: dict[str, str] = {}
    if args.track:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        # Keying on the server's asserted identity (so a rename can't orphan a baseline) means two
        # config entries for the SAME server collapse onto one key. Left alone they overwrite each
        # other's history every scan and drift flaps forever — and a false alarm that fires every
        # run trains the user to ignore the one signal that matters. Where a scan sees a collision,
        # keep those entries distinct by their config identity instead.
        recordable = [sn for sn in snaps if history.should_record(sn)]
        seen: dict[str, int] = {}
        for sn in recordable:
            seen[history.key_for(sn)] = seen.get(history.key_for(sn), 0) + 1
        collided = {k for k, n in seen.items() if n > 1}
        for sn, m in zip(snaps, measurements):
            if not history.should_record(sn):
                continue          # an errored probe would record an empty tool list as the truth
            # Read-the-baseline and write-the-current under ONE lock (history.record). Split across
            # a load()/save() pair, two concurrent scans each diff against a baseline the other has
            # already replaced, and one server's drift history is silently lost.
            #
            # `migrate_from` carries every legacy `transport:name` key (B3), so both switching to the
            # server-asserted identity AND switching transport on a nameless server adopt an existing
            # baseline instead of orphaning it — the fix for silent baseline resets must not itself
            # cause one, in either direction.
            current = drift.build_record(sn, m, measured_at=now)
            asserted = history.key_for(sn)
            key = history.legacy_key_for(sn) if asserted in collided else asserted
            # C2 — a server that changes the name it ASSERTS gets a new key, and a new key is a
            # first sighting, which is silence. Check before recording, or the entry we would be
            # comparing against is the one we just created.
            was = history.identity_change(history.load(), key, sn.name)
            if was:
                reidentified[sn.name] = was
            previous = history.record(key, current,
                                      migrate_from=history.transport_variant_keys(sn),
                                      alias=sn.name)
            if previous is None:
                new_baselines.append(sn.name)
            rep = drift.compare(previous, current)
            if rep and rep.any:
                drift_reports[sn.name] = rep

    # Drift must reach the MACHINE-READABLE output and the exit code, not only the pretty print.
    # A rug-pull that a CI job can't see is a rug-pull that ships: `--json` consumers and pipeline
    # gates were previously blind to it.
    for lab in labels:
        rep = drift_reports.get(lab["name"])
        if rep:
            d = asdict(rep)
            d["rug_pull"] = bool(rep.changed)   # same item, rewritten description — the signature
            d["hostile"] = rep.hostile          # injection signature or capability escalation
            lab["x-mcpgawk"]["drift"] = d
        if lab["name"] in reidentified:
            # No DriftReport exists for a re-identification, so a JSON consumer would see nothing
            # at all — the same blindness the exit code had.
            lab["x-mcpgawk"]["reidentified_from"] = reidentified[lab["name"]]

    # ONE exit code for both output modes. `--json` used to `return 0` unconditionally — so a failed
    # probe or a detected rug-pull reported success to CI, the same class of lie as a false CLEAN.
    # A re-identification must fail too. It produces no DriftReport — there is nothing to diff
    # against — so without this a server that renames itself passes CI silently, which is exactly
    # the evasion C2 exists to close. "Nothing to compare" is not "nothing wrong".
    failed = (any(lab["x-mcpgawk"].get("caveats") for lab in labels)
              or bool(drift_reports) or bool(reidentified))

    if args.json:
        print(json.dumps(labels, indent=2))
        return 1 if failed else 0

    if getattr(args, "fleet_json", False):
        # Front-ends get the SAME rows the terminal view renders — never raw labels to re-interpret.
        unscannable = detect_unscannable() if not (args.stdio or args.http or args.sse) else []
        payload = fleet.to_json(fleet.build_rows(labels, entries, skipped, unscannable,
                                                 with_spec=getattr(args, "with_spec", False)))
        print(json.dumps(payload, indent=2))
        return 1 if failed else 0

    # Show the REAL installed version, not a hardcoded string. `__version__` is now single-sourced
    # from the installed package metadata in __init__ (see there), so this banner can no longer go
    # stale or disagree with pyproject/PyPI. A version banner that lies erodes trust in a measurement
    # tool.
    from . import __version__ as _ver
    print(f"\n{'='*70}\nmcpgawk {_ver} — LOCAL scan (no inventory uploaded)\n{'='*70}")

    # THE FLEET VIEW. A machine has a fleet of MCP servers, not one — handing the reader seven
    # full narrative reports in a row means the third onwards goes unread, which is the same as not
    # scanning. So multiple servers get one status line each, needs-you-first, and the per-server
    # narrative stays a deliberate `--detail` (or --only <name>) away. One server always renders in
    # full: there is nothing to summarise.
    # Capabilities that exist but no local scan can reach (account-hosted connectors, browser
    # hosts) are LISTED, never silently omitted — see discover.detect_unscannable.
    unscannable = detect_unscannable() if not (args.stdio or args.http or args.sse) else []
    rows = fleet.build_rows(labels, entries, skipped, unscannable)
    if len(rows) > 1 and not args.detail:
        # DRIFT LEADS. It used to print after the fleet list, so the one finding a general-purpose
        # agent cannot reproduce arrived last, beneath a wall of token counts. Inventory and cost are
        # commodities; "this server changed after you approved it" is the product. Order says which
        # is which.
        # A re-identification is not drift — there is nothing to diff — but it is the one event that
        # LOOKS like a clean first sighting while meaning the opposite. It must never be silent.
        if reidentified:
            print()
            for name, was in sorted(reidentified.items()):
                print(f"  ⛔ {name} now identifies itself as a DIFFERENT server "
                      f"(was {was}). Its baseline does not carry over — this scan starts a new one.")
            print("     A server that renames itself is not diffed against what you approved. "
                  "Treat this as unreviewed.")
        if drift_reports:
            print()
            hostile = sorted(n for n, r in drift_reports.items() if r.hostile)
            print(drift.render_headline(sorted(drift_reports), hostile))
            for name in sorted(drift_reports):
                print(drift.render(name, drift_reports[name]))
        print()
        print(fleet.render_fleet(rows))
        # Trust-on-first-use was silent, so the single most valuable thing a first scan does — start
        # a record — happened invisibly. Say it once, only for servers actually seen for the first
        # time, so it teaches the idea and then gets out of the way.
        if new_baselines:
            n = len(new_baselines)
            print(f"\n  ✓ Baseline recorded for {n} server{'s' if n > 1 else ''}: "
                  f"{', '.join(sorted(new_baselines))}")
            print("    From now on a scan reports what CHANGED — the one thing looking at your "
                  "machine today can never tell you.")
        print()
        refreshed = _offer_batched_auth(rows, args, entries)
        any_error = any(lab["x-mcpgawk"].get("caveats") for lab in labels)
        if refreshed:
            # Redraw with the signed-in servers now MEASURED, rather than sending the user back to
            # the shell to run the same command again. The whole point of the batched step is that
            # you finish where you started.
            rows = [refreshed.get(r.name, r) for r in rows]
            print("\n  Updated:\n")
            print(fleet.render_fleet(fleet.sort_rows(rows)))
            print()
            # A server that only became measurable after sign-in can carry findings — those must
            # count towards the exit code exactly as if the first pass had seen them.
            any_error = any_error or any(r.state in ("REVIEW", "INCOMPLETE", "UNREACHABLE")
                                         for r in refreshed.values())
        return 1 if (any_error or failed) else 0

    any_error = False
    for lab in labels:
        print("\n" + render_cli(lab, verbose=args.verbose))
        rep = drift_reports.get(lab["name"])
        if rep:
            print(drift.render(lab["name"], rep))
        any_error = any_error or bool(lab["x-mcpgawk"].get("caveats"))
    # Local (stdio) servers — launched this run or merely configured. Both inherit the same
    # ambient credentials the moment anything starts them, so both count towards that warning.
    local_servers = (sum(1 for e in entries.values() if e.get("command"))
                     + sum(1 for _, e in skipped if e.get("command")))
    print("\n" + render_summary(labels, local_servers=local_servers) + "\n")
    return 1 if (any_error or failed) else 0


def _offer_batched_auth(rows: list, args, entries: dict) -> dict:
    """ONE prompt for every server that needs credentials — never one prompt per server, which the
    founder rejected outright as the painpoint this view exists to remove.

    Returns {name: refreshed FleetRow} for servers that signed in successfully, so the caller can
    redraw the list in place instead of telling the user to run the command again. Default-deny in
    spirit: a blank or unparseable answer authenticates nothing, and a non-interactive run never
    opens a browser at all."""
    pending = [r for r in rows if r.needs_auth]
    if not pending:
        return {}
    if not sys.stdin.isatty():
        print(f"  {len(pending)} server(s) need credentials. Re-run in a terminal, or: "
              f"mcpgawk scan --http <url> --login\n", file=sys.stderr)
        return {}

    print("  These need credentials:")
    for i, r in enumerate(pending, 1):
        print(f"    {i}. {r.name}  {r.url}")
    sys.stderr.write("  Sign in to which? [all / 1,2 / N] ")
    sys.stderr.flush()
    picked = fleet.parse_auth_selection(input(), len(pending))
    if not picked:
        print("  → skipped. Nothing was authenticated.\n", file=sys.stderr)
        return {}

    from .oauth_login import build_login_provider
    refreshed: dict[str, FleetRow] = {}
    for i in picked:
        row = pending[i]
        print(f"\n  Signing in to {row.name} — approve in the browser…", file=sys.stderr)
        auth, server = build_login_provider(row.url)
        try:
            snap = asyncio.run(probe_url(row.name, row.url, None, 330.0, auth,
                                         declared="http", permute=False))
        finally:
            server.shutdown()               # always release the local callback port
        if snap.is_failure:
            print(f"  {row.name}: sign-in did not complete — {(snap.error or '')[:90]}", file=sys.stderr)
            continue
        # The row is replaced by a REAL measurement of the now-authenticated server, built through
        # the same label path as the original pass — so the refreshed row cannot disagree with the
        # one it replaces, and a server that turns out to be risky says so immediately.
        entry = entries.get(row.name) or {}
        label = _label_for(snap, measure(snap), entry, args)
        state, detail = fleet.state_of(label)
        refreshed[row.name] = FleetRow(name=row.name, state=state, detail=detail, url=row.url,
                                       clients=row.clients)
        print(f"  {row.name}: signed in — {detail}", file=sys.stderr)
    return refreshed


if __name__ == "__main__":
    sys.exit(main())
