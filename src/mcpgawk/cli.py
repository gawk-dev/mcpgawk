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
import os
import shlex
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from . import drift, fleet, history, runlog
from .fleet import FleetRow
from .consent import gate_stdio_consent
from .discover import detect_unscannable, discover_report
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


def _consent_agents(entries: dict | None) -> list[str]:
    """The client names behind the discovered fleet, for the consent question. Reads `_clients`
    (plural, a list) — the key discovery actually emits. This read `_client` for weeks: the
    consent prompt's "which of your tools" detail rendered empty on every machine while every
    test stayed green, because the tests supplied the inputs production never did."""
    return sorted({str(c).strip()
                   for e in (entries or {}).values() if isinstance(e, dict)
                   for c in (e.get("_clients") or [])} - {""})


def _discovery_problems(sources: list[dict]) -> list[str]:
    """Delegates to discover.problem_lines — one renderer for the CLI and the panel, so the two
    surfaces cannot drift apart on what counts as a reportable shortfall."""
    from .discover import problem_lines
    return problem_lines(sources)


def _headers(pairs: list[str] | None) -> dict[str, str]:
    out = {}
    for p in pairs or []:
        k, _, v = p.partition(":")
        out[k.strip()] = v.strip()
    return out


class _NoMatchingServers(Exception):
    """`--only` named nothing that exists. Carries no message: `_run` has already told the user
    what it looked for and what was there. Exists so that outcome can leave `_run` without
    violating its 3-tuple return contract."""


async def _run(args) -> tuple[list[ServerSnapshot], dict[str, dict], list[tuple[str, dict]]]:
    """Returns snapshots, the raw entry (command/args/headers) each came from, and the targets we
    deliberately did NOT scan (consent withheld). The entries feed the opt-in supply-chain/
    oauth-scopes checks and the fleet view's auth step; the skipped list keeps unscanned servers
    VISIBLE, so the summary can never imply coverage it doesn't have."""
    if args.stdio:
        parts = shlex.split(args.stdio)
        # An mcp.json entry is heterogeneous by definition — a command string beside an args list,
        # or a url beside a headers mapping. Declared once here so the http branch below is the same
        # variable and the same shape, rather than mypy inferring `Sequence[str]` from whichever
        # branch it saw first and then rejecting the other one's headers dict.
        entry: dict[str, Any] = {"command": parts[0], "args": parts[1:]}
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
            from .oauth_login import build_login_provider, store_preregistered_client
            if getattr(args, "oauth_client_id", None):
                _secret = (os.environ.get(args.oauth_client_secret_env)
                           if getattr(args, "oauth_client_secret_env", None) else None)
                if getattr(args, "oauth_client_secret_env", None) and not _secret:
                    print(f"mcpgawk scan: --oauth-client-secret-env "
                          f"{args.oauth_client_secret_env} is not set in the environment",
                          file=sys.stderr)
                    return 2
                _ruri = store_preregistered_client(
                    url, args.oauth_client_id, _secret,
                    getattr(args, "oauth_redirect_uri", None))
                print(f"  Using your pre-registered OAuth client. The provider must have "
                      f"this EXACT redirect URI registered: {_ruri}", file=sys.stderr)
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
    sources: list[dict] = []
    if args.config:
        cfg = _load_config(args.config)
    else:
        # Module-level name on purpose: tests stub `cli.discover_report` to inject a fleet, the
        # same seam they used on discover_servers before the report existed.
        cfg, sources = discover_report()
    def _selected(name: str, entry: dict) -> bool:
        # Match the display name OR any name a client actually uses for this server. After dedup the
        # display name is one client's; asking for the name YOUR client shows you matched nothing at
        # all — not even an "unknown server" — so the server was unreachable by the only name you had.
        if not only:
            return True
        return bool(only & ({name} | set((entry.get("_names") or {}).values())
                            | set(entry.get("_aliases") or ())))

    targets = [(n, e) for n, e in cfg.items() if _selected(n, e)]
    if only and not targets:
        # "Nothing matched what you asked for" and "you have nothing" are different answers, and
        # printing the empty-fleet copy for the first one told a user with 30 servers that they had
        # none. Name what was actually there so a typo is obvious.
        print(f"mcpgawk: no server matches --only {','.join(sorted(only))}.", file=sys.stderr)
        if cfg:
            print(f"  configured here: {', '.join(sorted(cfg))}", file=sys.stderr)
        # RAISE, never `return 2`: this function's contract is a 3-tuple and its caller unpacks it
        # unconditionally, so returning an int crashed the CLI on any --only typo. The caller turns
        # this into exit 2, which also keeps it out of main()'s catch-all — a typo is a normal
        # outcome, not a tool ERROR to be recorded in the run log as one.
        raise _NoMatchingServers
    if is_discovery and not targets:
        # "Nothing was found" and "nothing was looked at" must never render alike: say what WAS
        # examined, and name every source that existed but yielded nothing readable — an empty
        # fleet asserted over a config we failed to parse is the false all-clear this product
        # exists to prevent.
        print(f"mcpgawk: no scannable MCP servers found — looked in {len(sources)} config "
              f"location(s) across {len({s['client'] for s in sources})} client(s).",
              file=sys.stderr)
        for line in _discovery_problems(sources):
            print(f"  ⚠ {line}", file=sys.stderr)
        print("  Point it at a config:  mcpgawk scan path/to/mcp.json\n"
              "  Or scan one server:    mcpgawk scan --stdio \"npx -y <server>\"  |  --http <url>",
              file=sys.stderr)
        return [], {}, []
    if is_discovery:
        for line in _discovery_problems(sources):
            print(f"mcpgawk: ⚠ {line}", file=sys.stderr)
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
    p = argparse.ArgumentParser(
        prog="mcpgawk",
        description="gawk at an MCP server before you trust it",
        epilog=(
            "Free, and included here:\n"
            "  verify    run a server in a sandbox and watch what it actually does\n"
            "  decide    review and approve servers that changed since you trusted them\n\n"
            "mcpgawk Platform — continuous protection (£29/month — https://mcp.gawk.dev/pricing.html):\n"
            + "".join(f"  {c:<9} {d}\n" for c, d in PLATFORM_CAPABILITIES.items())
            + "Run `mcpgawk <capability>` once subscribed. Scanning, behavioural verification\n"
            + "and the runtime guard stay free and open-source.\n\n"
            + "Your subscription:\n"
            + "".join(f"  {c:<9} {d}\n" for c, d in ACCOUNT_COMMANDS.items())
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # `--version` is the first thing anyone types when something is wrong, and its ABSENCE is not
    # cosmetic: this CLI shipped without it, so a seven-release-stale install stayed invisible for
    # six days while every "verified live" claim was checked against the repo instead of the
    # binary. A tool that cannot state its own version cannot be supported.
    # ...and it must answer the question a person is ACTUALLY asking. A tester ran this, read
    # `mcpgawk 0.1.29`, and reported it as a problem — because the number alone cannot tell you
    # whether it is the current build. Settling that took eight checks across three registries
    # (2026-08-19). The staleness check already fetches PyPI on ordinary runs; --version now says
    # what it found. Line one is unchanged, byte for byte, because install.sh and every human habit
    # depend on it.
    #
    # A CUSTOM ACTION, not `action="version"`: the latter needs its string at parser-BUILD time,
    # which would put a network call in front of `--help` and every subcommand.
    class _Version(argparse.Action):
        def __init__(self, option_strings, dest, **kw):
            super().__init__(option_strings, dest, nargs=0, **kw)

        def __call__(self, parser_, namespace, values, option_string=None):
            print(f"mcpgawk {_installed_version()}")
            try:
                from .staleness import currency_line
                print(f"  {currency_line()}")
            except Exception:                      # noqa: BLE001 — never fail the one command
                pass                               # that people run when something is wrong
            parser_.exit()

    p.add_argument("--version", action=_Version)
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("install-node",
                       help="fetch the Node runtime `verify` needs (26 MB download, no admin rights)",
                       description="Download the Node runtime that `verify` uses to run a server "
                                   "in a sandbox. About 26 MB, into mcpgawk's own directory: no "
                                   "admin rights, and nothing on the system is changed.")
    n.add_argument("--yes", "-y", action="store_true",
                   help="skip the confirmation — required in a non-interactive session, because "
                        "this downloads and then RUNS third-party code")
    s = sub.add_parser("scan", help="measure MCP server(s) locally",
                       description="Measure MCP servers on this machine: every tool they expose, "
                                   "what each one costs your context window, and what it can "
                                   "reach. With no argument it reads every agent config it can "
                                   "find. Give it a config path to scan only that client. Local "
                                   "servers are launched only after you say yes, because scanning "
                                   "one means running its code.")
    s.add_argument("config", nargs="?", help="path to an mcp.json config")
    s.add_argument("--stdio", help='one stdio server, e.g. "npx -y @modelcontextprotocol/server-filesystem /tmp"')
    s.add_argument("--http", help="one streamable-HTTP server URL")
    s.add_argument("--sse", help="one SSE server URL")
    s.add_argument("--header", action="append", help='HTTP header, e.g. "Authorization: Bearer XYZ" (repeatable)')
    s.add_argument("--login", action="store_true",
                   help="for a remote --http/--sse server that needs OAuth: open the browser, sign "
                        "in once, and scan (token stored locally in ~/.gawk/oauth)")
    s.add_argument("--oauth-client-id",
                   help="with --login, for a server that REFUSES automatic client registration "
                        "(figma, Slack — enterprise posture): use this pre-registered OAuth "
                        "client id. Register the pinned redirect URI mcpgawk prints with the "
                        "provider first")
    s.add_argument("--oauth-client-secret-env", metavar="VAR",
                   help="environment variable holding the pre-registered client's secret "
                        "(never passed on the command line; omit for a public client + PKCE)")
    s.add_argument("--oauth-redirect-uri",
                   help="override the pinned redirect URI (must match the provider's "
                        "registration EXACTLY)")
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
    s.add_argument("--full", action="store_true",
                   help="print the full per-server surface even when a baseline makes "
                        "what-changed the default view")
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
    b = sub.add_parser(
        "baseline",
        help="print the approved baseline — what you have agreed to trust, per server",
        description=(
            "The shared baseline every pillar compares against. `verify` and `monitor` read this "
            "so that approving a server once is approving it everywhere, instead of each keeping "
            "its own memory and contradicting the others."
        ),
    )
    b.add_argument("--json", action="store_true", help="machine-readable (the cross-runtime shape)")
    b.add_argument("--server", metavar="NAME", help="one server (name or alias) instead of all")

    a = sub.add_parser("approve",
                       help="accept a server's current tools as the trusted baseline (clears DRIFT)",
                       description="Accept a server's current tools as the baseline you trust. "
                                   "Until you do, a tool that appeared after the last baseline is "
                                   "treated as drift and its calls are blocked. Run it with no "
                                   "server name to see what is waiting.")
    a.add_argument("server", nargs="?",
                   help="the server name as it appears in your config, or its asserted identity")
    a.add_argument("--all", action="store_true", help="approve every server with pending drift")
    a.add_argument("--list", action="store_true",
                   help="show which servers have changes you have not approved, and change nothing")

    w = sub.add_parser(
        "wrong",
        help="mark a finding as a false positive — it stays listed as 'muted by you', never hidden",
        description=(
            "The false-positive affordance. `mcpgawk wrong <server> <tool>/<kind>` records that "
            "YOU judged that finding wrong. It keeps appearing, labelled 'muted by you', because "
            "a mistake you silenced must stay reviewable — absence of a finding is never safety, "
            "including absence you asked for."))
    w.add_argument("server", help="the server name as it appears in your config")
    w.add_argument("finding_id", metavar="finding-id",
                   help="the finding as the report prints it: <tool>/<kind>, "
                        "e.g. read_note/injection:reader-directed")
    w.add_argument("--undo", action="store_true", help="withdraw the mute")

    g = sub.add_parser(
        "guard",
        help="install a Claude Code hook that checks MCP tool calls against your approved baseline",
        description=(
            "Puts the approved baseline in your agent's loop. A single PreToolUse hook, installed "
            "once, checks every MCP tool call — no per-server rewiring and no proxy. The decision "
            "is made locally in ~10ms; nothing is uploaded and there is nothing to sign in to."
        ),
    )
    g.add_argument("action", nargs="?", default="status",
                   choices=["status", "install", "uninstall"],
                   help="default: status")
    g.add_argument("--settings", metavar="PATH",
                   help="settings file to edit (default: ~/.claude/settings.json)")

    k = sub.add_parser(
        "skills",
        help="scan agent SKILLS (SKILL.md trees) for injection, hidden text and risky content",
        description=(
            "Discovers agent skills across every supported host (Claude Code, Codex, Cursor, "
            "Copilot, Windsurf, Antigravity, Kiro, Gemini, opencode, Amp) and scans their content "
            "locally — nothing is uploaded anywhere. Give paths to scan a specific skill dir, a "
            "skills root, or a project instead of the whole machine."
        ),
    )
    k.add_argument("paths", nargs="*",
                   help="skill dir / skills root / project root (default: discover all hosts)")
    k.add_argument("--json", action="store_true", help="machine-readable output")
    k.add_argument("--fail-on-findings", action="store_true",
                   help="exit 1 if any finding fires (CI gate) — default reports and exits 0, "
                        "because a signal is a signal, not a verdict")

    pn = sub.add_parser(
        "panel",
        help="the control panel — every agent, server, call and decision on this machine",
        description="One window over the whole machine: which agents are covered, every MCP "
                    "server and its state, what the runtime guard has actually seen, and anything "
                    "waiting on you. A control surface, not a viewer: re-scan, verify, sign-in, "
                    "approve and protect all live here — but only on the tokened URL this command "
                    "prints. A bare 127.0.0.1:7718 (bookmark, restored tab) renders read-only "
                    "with no buttons, by design. Drift decisions also live in `mcpgawk decide`.")
    pn.add_argument("--port", type=int, default=7718, help="local port (default: 7718)")
    pn.add_argument("--no-open", action="store_true", help="print the URL, do not open a browser")

    d = sub.add_parser(
        "decide",
        help="review and decide on servers that changed after you approved them (opens locally)",
        description="The one screen a human is required for. Opens a LOCAL page showing each "
                    "server that changed since you trusted it, what changed, and lets you approve "
                    "or keep blocking. Read-only over your state until you click; approval needs "
                    "the token printed here, so an agent cannot drive it.")
    d.add_argument("--port", type=int, default=7717, help="local port (default: 7717)")
    d.add_argument("--no-open", action="store_true", help="print the URL, do not open a browser")

    sub.add_parser(
        "status",
        help="is anything watching, against what, and when did it last see something",
        description="One answer to 'am I protected'. Read-only — opens nothing, starts nothing. "
                    "Coverage is reported PER AGENT, never in aggregate: the hook installs into "
                    "Claude Code only, so a single cheerful tick would tell a Cursor user they "
                    "are covered when they are not.")
    rp = sub.add_parser(
        "report",
        help="write ONE file we can diagnose from — send it when something goes wrong",
        description=(
            "Collects everything about this machine into a single redacted zip: version and "
            "how mcpgawk was installed, per-agent hook state, the entire run history, the "
            "entire call log, every verify run, open drift alerts, and an inventory of both "
            "state directories. Nothing is uploaded — the command prints a path and stops. "
            "Server responses are removed by field name, home directories become ~, and every "
            "URL keeps its parameter names and loses their values. A store that could not be "
            "read is listed as 'unavailable', which means nobody looked — never 'nothing there'."
        ),
    )
    rp.add_argument("--output", metavar="PATH",
                    help="write here instead of ./mcpgawk-report-<timestamp>.zip")
    rp.add_argument("--note", metavar="TEXT",
                    help="what you were doing when it went wrong — travels in the bundle")

    r = sub.add_parser(
        "runs",
        help="what has run on this machine, and how it went",
        description=(
            "Your local run history — scans, and (with mcpgawk Platform) verify, enforce and monitor "
            "runs, newest first. Read from ~/.mcpgawk/runs.db; nothing is uploaded anywhere. "
            "A run that never closed shows as RUNNING, and as INCOMPLETE once its process is gone "
            "— it is never reported as success."
        ),
    )
    r.add_argument("--kind", choices=runlog.KINDS, help="only this kind of run")
    r.add_argument("--limit", type=int, default=20, help="how many to show (default 20)")
    r.add_argument("--json", action="store_true", help="machine-readable output")
    r.add_argument("--prune", action="store_true",
                   help="drop finished runs older than 90 days, then report what is left")

    d = sub.add_parser(
        "demo",
        help="watch the whole story in a throwaway sandbox — scan, approve, a rug-pull, a block",
        description="A self-contained walkthrough: mcpgawk plants a deliberately-bad MCP server "
                    "in a temporary sandbox, measures it, you approve it, the server turns "
                    "hostile, and the guard blocks the tool that appeared afterwards. Nothing "
                    "touches your real fleet, agents, or state. Offline; a few seconds.")
    d.add_argument("--sandbox", metavar="DIR",
                   help="use this directory for the sandbox instead of a fresh temp one")
    d.add_argument("--clean", action="store_true",
                   help="delete the sandbox on exit (default: keep it so you can inspect it)")

    # DISCOVERY ONLY — these never reach argparse at runtime. `_dispatch` intercepts `verify` and
    # the account commands before the parser is built, because each owns its own flags and the free
    # parser must not try to validate them. That interception also made them INVISIBLE: they were
    # absent from the `{scan,baseline,...}` list `--help` prints, so the beta guide ended up telling
    # testers "`verify` isn't in this build" about a working, free, flagship capability.
    # `add_argument` is deliberately absent: these parsers exist to be LISTED, and a flag written
    # here would be a second, silently-wrong copy of a contract the engine already owns.
    sub.add_parser(
        "verify",
        help="run a server in a sandbox and watch what it actually does",
        description="Run the server and observe it — the behavioural check. FREE. Its flags belong "
                    "to the verify engine, so run `mcpgawk verify` with no arguments to see them.")
    for _name, _help in ACCOUNT_COMMANDS.items():
        sub.add_parser(_name, help=_help)
    for _name, _help in PLATFORM_COMMANDS.items():
        sub.add_parser(_name, help=_help)
    return p


_SKILLS_NOT_CHECKED = (
    "not checked (needs semantic analysis, not attempted): intent vs stated purpose, "
    "financial-capability, third-party-content-exposure, system-service classification"
)


#: How each status reads in the terminal. RUNNING/INCOMPLETE deliberately do NOT look like success:
#: the whole point of the run log is that an unfinished run is visibly unfinished.
_RUN_MARK = {
    runlog.OK: "ok      ",
    runlog.FINDINGS: "findings",
    runlog.ERROR: "ERROR   ",
    runlog.RUNNING: "running…",
    runlog.INCOMPLETE: "INCOMPL.",
}


def _runs(args) -> int:
    """Local run history. Reconciles first, so a crashed run is shown as incomplete rather than
    eternally in progress."""
    runlog.reconcile_stale()
    if args.prune:
        dropped = runlog.prune()
        print(f"pruned {dropped} finished run(s) older than 90 days")

    runs = runlog.list_runs(kind=args.kind, limit=args.limit)

    if args.json:
        print(json.dumps([{
            "run_id": r.run_id, "kind": r.kind, "target": r.target,
            "started_at": r.started_at, "ended_at": r.ended_at,
            "status": r.status, "summary": r.summary,
        } for r in runs], indent=2))
        return 0

    if not runs:
        print("No runs recorded yet. Run `mcpgawk scan` and it will appear here.")
        return 0

    for r in runs:
        when = r.started_at[:19].replace("T", " ")
        target = r.target or "(fleet)"
        print(f"{when}  {_RUN_MARK.get(r.status, r.status):8}  {r.kind:8}  {target}")

    unfinished = [r for r in runs if not r.finished]
    if unfinished:
        print(f"\n{len(unfinished)} run(s) still open. They are not results — a run only counts "
              f"once it closes.")
    return 0


def _skills(args) -> int:
    """Scan agent skills. Local-only by construction: skills.py has no network imports at all —
    the differentiator against agent-scan, whose client uploads raw skill content for analysis."""
    from pathlib import Path

    from .signals import as_dicts
    from .skills import discover_skills

    snaps = discover_skills(explicit_paths=[Path(p) for p in args.paths] or None)
    total_findings = sum(len(s.findings) for s in snaps)

    if args.json:
        print(json.dumps({
            "skills": [{
                "name": s.name, "root": s.root, "hosts": s.hosts,
                "description": s.description,
                "files_scanned": len(s.files), "files_seen": s.files_seen, "capped": s.capped,
                "findings": as_dicts(s.findings),
            } for s in snaps],
            "not_checked": _SKILLS_NOT_CHECKED,
        }, indent=2))
    else:
        if not snaps:
            where = "the given path(s)" if args.paths else "any supported host on this machine"
            print(f"mcpgawk skills: no skills found under {where}.")
        for s in snaps:
            hosts = ", ".join(s.hosts)
            print(f"\n  {s.name}  ({s.root}; loaded by: {hosts})")
            # "scanned" meant "recorded", and a binary file is recorded with a hash and never
            # content-scanned — so a skill shipping a .bin/.pdf payload reported "12 file(s)
            # scanned … clean". Say how many were actually READ.
            read_n = sum(1 for f in s.files if getattr(f, "kind", "") not in ("binary", "oversize"))
            scope = f"    {read_n} file(s) content-scanned of {len(s.files)} recorded"
            if s.capped:
                scope += f" ({s.files_seen} seen — CAPPED, the remainder was not examined)"
            print(scope)
            if s.skipped:
                # The file cap already announced itself and these did not. A payload at depth 11,
                # behind a symlink, or in an unreadable directory left no trace at all.
                print(f"    {len(s.skipped)} path(s) NOT examined — absence of a finding does not "
                      f"cover them:")
                for rel, why in s.skipped[:8]:
                    print(f"      {rel} — {why}")
                if len(s.skipped) > 8:
                    print(f"      …and {len(s.skipped) - 8} more")
            if not s.findings:
                unread = (len(s.files) - read_n) + len(s.skipped)
                print("    clean under the local detectors" if not unread else
                      f"    no findings in what was read — {unread} file(s)/path(s) were not "
                      f"content-scanned, so this is not a clean bill")
            for f in s.findings:
                print(f"    ⚠ [{f.kind}] {f.tool}: {f.evidence}")
        if snaps:
            print(f"\n  {len(snaps)} skill(s), {total_findings} finding(s). "
                  f"All analysis LOCAL — no skill content left this machine.")
            print(f"  {_SKILLS_NOT_CHECKED}.")

    return 1 if (args.fail_on_findings and total_findings) else 0


def _baseline(args) -> int:
    """Print what the operator has agreed to trust — the spine other pillars read.

    Only approved state is exported. A sighting is not a baseline: printing the last thing seen
    would hand verify and monitor the poisoned surface as though it were trusted, which is the
    exact failure ADR-0012 exists to prevent.
    """
    from . import baseline as _baseline_mod

    # Third surface of the same defect: `baseline.export` reads through history.load, so an
    # unreadable store exported as "Nothing approved yet" — indistinguishable from a fresh machine
    # on the command whose entire job is showing what you agreed to trust.
    _, _store_err = _store_or_say_why(getattr(args, "history", None))
    _warn_if_store_unreadable(_store_err)
    data = _baseline_mod.export(getattr(args, "history", None))
    servers = data["servers"]

    if args.server:
        key = _baseline_mod.resolve(args.server, getattr(args, "history", None))
        if key is None or key not in servers:
            print(f"mcpgawk: nothing approved for '{args.server}'. "
                  f"Run `mcpgawk scan`, then `mcpgawk approve {args.server}`.", file=sys.stderr)
            return 2
        servers = {key: servers[key]}
        data = {**data, "servers": servers}

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    if not servers:
        if _store_err:
            print("Nothing can be shown — the approval store is unreadable, so what you approved "
                  "is UNKNOWN. See the warning above.")
            return 1
        print("Nothing approved yet. Run `mcpgawk scan`, then `mcpgawk approve <server>` to set "
              "the baseline that verify and monitor will compare against.")
        return 0

    print(f"Approved baseline — {len(servers)} server(s). "
          f"verify and monitor compare against exactly this.\n")
    for key in sorted(servers):
        rec = servers[key]
        alias = f" ({', '.join(rec['aliases'])})" if rec.get("aliases") else ""
        print(f"  {key}{alias}")
        print(f"    pin        {rec.get('pin') or '—'}")
        print(f"    tools      {len(rec.get('tools') or {})}")
        print(f"    approved   {rec.get('approved_at') or '—'}")
    return 0


def _store_or_say_why(path: str | None = None) -> "tuple[dict, str | None]":
    """Read the trust store, and hand back WHY it came back empty.

    `history.load()` throws away the reason `load_checked()` was built to return, and every CLI
    surface used it. Proven 2026-08-18 with a truncated history.json — the file holding every
    approval — where `mcpgawk approve --list` answered "Nothing to approve — every tracked server
    matches its approved baseline." An unreadable store rendered as a clean bill of health on the
    command a user runs to ask exactly that question.

    panel.py and status.py were fixed for this; the CLI was not. Degrading rather than raising is
    still right — a security tool that refuses to start because its own store is damaged does more
    harm than the drift it was watching — but the reason has to travel with the result.
    """
    store, err = history.load_checked(path or history.default_path())
    return store, err


def _warn_if_store_unreadable(err: "str | None") -> None:
    if err:
        print(f"mcpgawk: WARNING — the approval store could not be read ({err}).\n"
              f"         What follows is NOT a clean result; it is no result. Nothing below can "
              f"be trusted as 'unchanged' until this file is readable again:\n"
              f"         {history.default_path()}", file=sys.stderr)


def _approve(args) -> int:
    """`mcpgawk approve` — move the trusted baseline forward, deliberately."""
    # THE HUMAN GATE. Approval is the moment trust moves, and a blocked call is precisely when an
    # agent would be asked to approve its way past one. See baseline.approval_blocked_reason.
    from .baseline import approval_blocked_reason
    blocked = approval_blocked_reason()
    if blocked and not (args.list or (not args.server and not args.all)):
        print(f"mcpgawk approve: refusing — {blocked}", file=sys.stderr)
        return 4
    path = history.default_path()
    store, _store_err = _store_or_say_why(path)
    _warn_if_store_unreadable(_store_err)
    waiting = history.pending(store)

    if args.list or (not args.server and not args.all):
        if not waiting:
            if _store_err:
                print("Nothing to compare — the approval store is unreadable, so whether anything "
                      "changed is UNKNOWN. See the warning above.")
                return 1
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
        # Ambiguity gets its own message. "No tracked server matches" would be a lie when the
        # problem is that SEVERAL do, and approving the wrong one moves a baseline the operator
        # never looked at.
        candidates = history.resolve_all(store, args.server)
        if len(candidates) > 1:
            print(f"{args.server!r} matches {len(candidates)} tracked servers — refusing to guess "
                  f"which baseline to move. Approve one by its own key:", file=sys.stderr)
            for key in candidates:
                print(f"    mcpgawk approve {key}", file=sys.stderr)
            return 2
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


def _wrong(args) -> int:
    """`mcpgawk wrong` — design-contract item 4, the false-positive affordance.

    Same human gate as `approve`: silencing a security finding is a trust decision, and a blocked
    or flagged call is exactly when an agent would be asked to mute its way past one."""
    from .baseline import approval_blocked_reason

    blocked = approval_blocked_reason()
    if blocked:
        print(f"mcpgawk wrong: refusing — {blocked}", file=sys.stderr)
        return 4
    key = history.mute_finding(args.server, args.finding_id, undo=args.undo)
    if key is None:
        print(f"No tracked server matches {args.server!r}. Scan it first: mcpgawk scan",
              file=sys.stderr)
        return 2
    if args.undo:
        print(f"✓ unmuted {args.finding_id} on {args.server} — it reports normally again.")
    else:
        print(f"✓ muted {args.finding_id} on {args.server} as a false positive, on your judgement.")
        print("  It stays LISTED as 'muted by you' — never hidden — so a wrong mute stays "
              "reviewable. Undo: mcpgawk wrong "
              f"{args.server} {args.finding_id} --undo")
    return 0


# The paid capabilities, reachable as `mcpgawk <capability>` when mcpgawk Platform is installed.
#
# ONE BINARY, on purpose (2026-07-26). Two reasons, both load-bearing:
#   1. `gawk` cannot be an executable name. It is GNU AWK — it owns /usr/bin/gawk across the
#      Debian family and supplies /usr/bin/awk there through the alternatives system, so our own
#      `gawk` on PATH risks breaking a machine's `awk`. Debian Policy §10.1 requires one of two
#      colliding programs to be renamed; Homebrew's `gawk` formula is GNU awk, so the name is
#      simply unavailable. Everyone who tried this retreated: ast-grep deprecated `sg`, fd ships
#      as `fdfind`, bat as `batcat`.
#   2. A second binary for the paid tier is against convention anyway. Semgrep, Snyk, GitLab and
#      Terraform all keep ONE command and unlock with a licence/login. A separate binary is only
#      conventional when the paid thing is a different artefact (Docker Desktop). Ours isn't — it
#      is more analysis on the same inputs.
#
# They are listed in `--help` even when unavailable: a free user should be able to SEE what the
# subscription adds without installing anything, and get one honest line if they try it.
def _installed_version() -> str:
    """The version of the DISTRIBUTION actually installed — read from package metadata, never a
    hand-maintained constant. A literal here drifted from pyproject before and reported 0.1.0 on a
    0.1.3 install; metadata cannot disagree with what pip resolved."""
    try:
        from importlib.metadata import version
        return version("mcpgawk")
    except Exception:                              # noqa: BLE001 - a source checkout, not an error
        return "0+unknown (not installed as a distribution)"


#: ACCOUNT commands — about the subscription, not about a server. Separate from the capabilities
#: because they are never licence-gated: `login` is how a customer obtains a working licence, so
#: gating it behind one would be a locked door with the key inside.
#:
#: These shipped BROKEN. When `gawk` was retired (GNU-awk collision) and the paid capabilities
#: became subcommands of `mcpgawk`, the pillars were carried over and these were not — while
#: activate.html, the page every paying customer is sent to, instructed them to run
#: `mcpgawk login <key>`. It exited 2 with `invalid choice` on every install. Nobody could activate.
ACCOUNT_COMMANDS = {
    "login": "save your licence key so the paid capabilities unlock",
    "logout": "remove the saved licence key from this machine",
}

#: What a FREE install says for an account command. Deliberately not the capability message: the
#: user has (probably) just paid and is following instructions from their purchase email, so the
#: reply must confirm they are in the right place and name the ONE missing step — never read as
#: "you typed something wrong".
_ACCOUNT_NEEDS_PLATFORM = (
    "mcpgawk {cmd}: the mcpgawk Platform isn't installed in this environment yet.\n"
    "Your licence unlocks it, and your purchase email has the one-line install command.\n"
    "Lost it? https://mcp.gawk.dev/activate.html — or reply to the receipt and we'll resend.\n"
    "The free scanner (`mcpgawk scan`) keeps working either way."
)


def _run_account_command(command: str, rest: list[str]) -> int:
    """Delegate an account command to mcpgawk Platform, or explain honestly that it isn't here.

    Same optional-local-import shape as the capabilities: the free scanner is published to PyPI on
    its own and must never depend on, or ship, the paid engine.
    """
    try:
        from gawk_platform.cli import run_account
    except ImportError:
        print(_ACCOUNT_NEEDS_PLATFORM.format(cmd=command), file=sys.stderr)
        return 3
    return run_account(command, rest)


#: Platform commands that are neither pillars nor account commands. `push` was STRANDED when the
#: paid `gawk` binary was retired (GNU-awk collision): the pillars and the account commands were
#: carried into this dispatch and `push` was not — so the dashboard referenced a command that no
#: install, free or paid, could actually run. Same optional-import delegation as everything paid.
PLATFORM_COMMANDS = {
    "push": "send a scan receipt to your hosted fleet view (mcpgawk Platform)",
}

_PLATFORM_COMMAND_UNAVAILABLE = (
    "mcpgawk {cmd}: {desc}.\n"
    "This is a mcpgawk Platform command and the Platform isn't installed in this environment.\n"
    "  £29/month, 7-day free trial — https://mcp.gawk.dev/pricing.html\n"
    "The free scanner (`mcpgawk scan`) stays free and open-source either way."
)


def _run_platform_command(command: str, rest: list[str]) -> int:
    """Delegate a non-pillar Platform command, or explain honestly that it isn't here.

    Delegation goes through gawk_platform's own `main` so `push` keeps its deliberate routing
    there: top-level, NOT licence-pre-checked — the ingest endpoint is the authority on whether
    a receipt is accepted, and a Lemon Squeezy pre-check would block the request before it left.
    """
    try:
        from gawk_platform.cli import main as platform_main
    except ImportError:
        print(_PLATFORM_COMMAND_UNAVAILABLE.format(cmd=command, desc=PLATFORM_COMMANDS[command]),
              file=sys.stderr)
        return 3
    return platform_main([command, *rest])


#: `verify` is NOT here any more. Task 0 (2026-07-28) made behavioural verification free, and
#: leaving it on this list meant the engine shipped in the wheel behind a paywall the copy still
#: advertised — the code moved and the gate did not.
PLATFORM_CAPABILITIES = {
    "enforce": "guard a live server, call by call",
    "monitor": "watch a server for drift after you approved it",
    "build": "generate a server from an OpenAPI spec (in development)",
}

_PLATFORM_UNAVAILABLE = (
    "mcpgawk {cap}: {desc}.\n"
    "This is a mcpgawk Platform capability and it isn't installed in this environment.\n"
    "  £29/month, 7-day free trial — https://mcp.gawk.dev/pricing.html\n"
    "  Already subscribed? Your purchase email has the install instructions.\n"
    "The free scanner (`mcpgawk scan`) stays free and open-source either way."
)


def _run_platform_capability(capability: str, rest: list[str]) -> int:
    """Delegate to mcpgawk Platform if it is installed, else say so honestly and exit 3.

    The import is deliberately OPTIONAL and local: the free scanner is published to PyPI on its
    own and must never depend on, or ship, the paid engine. A paid install supersedes the free
    distribution in place (same distribution name), which is the GitLab CE→EE shape.
    """
    try:
        from gawk_platform.cli import run_pillar
    except ImportError:
        print(
            _PLATFORM_UNAVAILABLE.format(capability=capability, cap=capability,
                                         desc=PLATFORM_CAPABILITIES[capability]),
            file=sys.stderr,
        )
        return 3  # the same "not licensed / not available" code every paid entry point returns
    return run_pillar(capability, rest)


def _protect() -> int:
    """Bare `mcpgawk` — find the fleet, ask once, scan, turn runtime checking on, report.

    Deliberately an ORCHESTRATOR, not a second scanner: it drives the existing scan path (so there
    is exactly one scan implementation) and reads its result out of the history store, which is
    already the shared expectation store every other consumer reads. Adding a parallel scan here is
    how this codebase has previously grown two of something that later disagreed.
    """
    from . import history, protect

    #: Local stdio servers found on this machine. Bound HERE, before any branch, so the coverage
    #: report at the end cannot silently read an unbound name and fall back to "nothing skipped".
    local_servers: list[str] = []

    print("mcpgawk — checking what your agents can call, and turning protection on.\n")

    choice = protect.load_consent()

    # A SAVED consent is not a human. `launch` means "start every local stdio server", which puts
    # that server's live credentials on the process table of whatever machine this runs on. The
    # non-interactive fallback below was written to degrade to remote-only in exactly that case —
    # and a saved `launch` skipped straight past it, because the whole block is guarded on
    # `choice is None`. So CI, a piped run and an agent session all launched the fleet with real
    # keys, which is the one thing that branch exists to prevent (found 2026-08-02).
    #
    # Deliberately the SAME human-presence test the trust-store writes use: one definition of "is
    # a person here", not a second one that can disagree with the first.
    if choice == protect.LAUNCH_ALL and history.approval_blocked_reason() is not None:
        print("  A saved 'launch' consent does not carry to a non-interactive run — checking "
              "remote servers only.\n  Run this in your own terminal to include local servers.\n",
              file=sys.stderr)
        choice = protect.REMOTE_ONLY

    scan_args = ["scan", "--track"]
    if choice is None:
        # Count local servers first so the question can be specific about what it is asking for.
        try:
            from .discover import discover_servers
            found = discover_servers()
            entries = found[0] if isinstance(found, tuple) else found
            local_servers = [n for n, e in (entries or {}).items()
                             if isinstance(e, dict) and e.get("command")]
            local = len(local_servers)
            agents = _consent_agents(entries)
        except Exception:                          # noqa: BLE001 - discovery is best-effort here
            local, agents, local_servers = 0, [], []
        if local:
            choice = protect.ask_consent(local, agents)
            if choice is None:
                print("  Not asking in a non-interactive run — checking remote servers only.\n"
                      "  Run this in a terminal to include local servers.\n", file=sys.stderr)
                choice = protect.REMOTE_ONLY
            else:
                protect.save_consent(choice)
        else:
            # No local servers, so there is nothing to ask about — but the answer must still be
            # SAID. Leaving it None let a "no consent recorded" value flow into code that only ever
            # compares against LAUNCH_ALL: it happens to behave like remote-only today, and would
            # diverge silently the moment anything compared against REMOTE_ONLY instead.
            choice = protect.REMOTE_ONLY
    if choice == protect.LAUNCH_ALL:
        scan_args.append("--yes")
        # We just asked, with more detail than the scan's own gate gives. Tell it not to ask again.
        from .consent import CONSENT_GIVEN_ENV
        os.environ[CONSENT_GIVEN_ENV] = "1"

    rc = _dispatch(scan_args)

    # Runtime checking on. `guard.install` is idempotent and preserves foreign hooks, so re-running
    # `mcpgawk` is safe — which is the point of a front door you are meant to type again.
    # Every agent on this machine that HAS an interception point, not just Claude Code. status
    # reported six agents uncovered; five of them were only uncovered by our implementation.
    lines: list[str] = []
    try:
        from . import agents as agent_mod
        from .guard import install_for
        for adapter in agent_mod.ADAPTERS.values():
            if not adapter.config.parent.is_dir():
                continue                            # that agent is not on this machine
            try:
                lines.append(install_for(adapter))
            except Exception as exc:                # noqa: BLE001 - one agent must not stop the rest
                lines.append(f"  {adapter.label}: NOT enabled ({type(exc).__name__}: {exc})")
    except Exception as exc:                        # noqa: BLE001 - never lose the scan result
        lines.append(f"  Runtime checking NOT enabled ({type(exc).__name__}: {exc})")
    guard_line = "\n".join(lines) if lines else "  No agent with a hook point found."

    # ONLY where someone can watch it and stop it. This is a multi-minute fleet verify — every
    # discovered server launched in a fresh container doing a cold `npx …@latest` — and it ran
    # unconditionally on a bare `mcpgawk`. Off a TTY that means: no visible progress (stdout is
    # block-buffered, so the scan table that DID complete sits unflushed), no Ctrl-C, and a
    # process that looks hung for ten minutes and then dies with zero output. Which is exactly
    # what `test_bare_invocation_does_something_useful` was reporting, and could never pass:
    # its 300s harness budget is half the code's own 600s.
    #
    # The scan result above is already printed and is the useful answer. Behavioural verification
    # is the expensive, deliberate step, so off a TTY it is NAMED and skipped, never silently
    # dropped — an absent verify must not read as a clean one.
    if sys.stdout.isatty():
        _front_door_verify(choice)
    else:
        print("  Behavioural verification SKIPPED — it launches every server and takes minutes, "
              "so it needs a terminal you can watch and interrupt.\n"
              "  Run `mcpgawk verify` to do it deliberately. This is not a clean result; it is "
              "no result.\n", file=sys.stderr)

    store, _store_err = _store_or_say_why()
    _warn_if_store_unreadable(_store_err)
    # `unchecked=[]` was hardcoded here — the ONLY production caller — while
    # protection_report's docstring promises "The 'not checked' block is never omitted and never
    # summarised into a number". It was omitted on every real run, because nothing ever passed a
    # value; only tests did. On a REMOTE_ONLY pass every local stdio server is skipped by design
    # (we refuse to launch their code without consent) and "Protected: N server(s)" printed with
    # no mention of the ones nobody looked at.
    _unchecked = ([(n, "not launched — this run checked remote servers only")
                   for n in sorted(local_servers)]
                  if choice == protect.REMOTE_ONLY else [])
    print(protect.protection_report(store, guard_line, unchecked=_unchecked))
    # ONBOARDING STAGE 5 ([FOUNDER] 2026-08-15: onboarding ends at protect + PANEL, and the
    # first run offers the bridge): until now the flow finished and the control surface was
    # never mentioned — a user completed the scan and had no idea a panel existed. TTY only,
    # a real question (the answer IS the consent), default yes; off a TTY, one honest hint
    # line and no prompt — a pipe must never hang on input().
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            ans = input("\n  See all of this live — servers, decisions, evidence — in the "
                        "control panel? [Y/n] ")
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans.strip().lower() in ("", "y", "yes"):
            from .panel import serve as panel_serve
            panel_serve(port=7718, open_browser=True)
    else:
        print("\n  The control panel shows all of this live: mcpgawk panel")
    return rc


def _behaviour_tool_count() -> int:
    """Tools with observed behaviour in the profile, 0 on any failure — never raises."""
    try:
        from .guard_hook import behaviour_path
        raw = json.loads(behaviour_path().read_text(encoding="utf-8"))
        servers = raw.get("servers") if isinstance(raw, dict) else None
        if not isinstance(servers, dict):
            return 0
        return sum(len(v) for v in servers.values() if isinstance(v, dict))
    except Exception:  # noqa: BLE001 — a count, not a verdict
        return 0


def _front_door_verify(choice: str) -> None:
    """Behavioural verification as part of the default flow — the free tier's promise is what
    servers DO, and that must not require a second command (the product sentence says "on by
    default"). Never blocks protection: every failure here degrades to the name-only posture
    that `status` already reports honestly, and an incomplete run is recorded as INCOMPLETE,
    never as clean.

    Consent is the front door's own answer: local (stdio) servers are launched in the sandbox
    only under LAUNCH_ALL — the same yes that let the scan launch them. REMOTE_ONLY verifies
    remote servers only, which runs no code on this machine.
    """
    if os.environ.get("MCPGAWK_NO_VERIFY") == "1":
        return
    from . import verify as verify_mod
    reason = verify_mod.unavailable_reason()
    if reason is not None:
        print(f"\n  Behavioural verification skipped: {reason}")
        return
    try:
        import json as _json
        import tempfile

        from . import discover, protect, runlog
        entries = discover.discover_servers()
        allowed: dict[str, dict[str, Any]] = {}
        for name, e in (entries or {}).items():
            if not isinstance(e, dict):
                continue
            if e.get("command"):
                if choice == protect.LAUNCH_ALL:
                    allowed[name] = {k: e[k] for k in ("command", "args", "env") if k in e}
            elif e.get("url"):
                allowed[name] = {k: e[k] for k in ("url", "headers") if k in e}
        if not allowed:
            print("\n  Behavioural verification: nothing verifiable under the current consent —"
                  "\n  local servers are only launched after your yes. Re-run `mcpgawk` in a"
                  "\n  terminal to include them.")
            return
        # "in the sandbox" was printed here for weeks while nothing requested one (HANDOFF 38c).
        # --isolate is passed below; the engine itself announces, per server, when it has to
        # degrade (no Docker / uncontainerizable command) — so this line can promise the REQUEST
        # and let the engine report what actually ran.
        print(f"\n  Verifying what {len(allowed)} server(s) actually DO — container isolation is"
              f"\n  requested, and the engine reports per server if it must run without it"
              f"\n  (observed behaviour, not declared — a few minutes; Ctrl-C skips)…")
        run_id = runlog.start_run("verify", target="fleet")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         prefix="mcpgawk-frontdoor-") as fh:
            _json.dump({"mcpServers": allowed}, fh)
            cfg = fh.name
        try:
            # 60s, not 600. This is the FRONT DOOR: a budget it cannot honestly promise turns a
            # slow fleet into a ten-minute silence. Overrunning is already handled honestly —
            # verify_mod.run returns 4 and the run is recorded INCOMPLETE below — so a short
            # budget costs a truthful "did not finish", while a long one costs the user ten
            # minutes and still tells them nothing. `mcpgawk verify` is where you ask for the
            # long run; MCPGAWK_VERIFY_TIMEOUT still overrides for anyone who wants it here.
            timeout = float(os.environ.get("MCPGAWK_VERIFY_TIMEOUT", "60"))
            # Same evidence contract as the panel (see run_verify_fleet): every run archives the
            # engine's per-attempt audit stream in its own directory, never overwritten.
            from time import gmtime, strftime

            from .panel import behaviour_profile_path
            audit_args: list[str] = []
            try:
                run_dir = (behaviour_profile_path().parent / "verify-runs"
                           / strftime("%Y-%m-%dT%H-%M-%SZ", gmtime()))
                # secure_dir, not mkdir: this directory holds every reproduction attempt's audit
                # log. Plain mkdir left it 0755 (28 of them on the founder's machine, measured
                # 2026-08-13) while `~/.mcpgawk` and `~/.gawk` are both 0700.
                from .state import secure_dir
                secure_dir(run_dir.parent)   # mkdir(parents=True) leaves PARENTS at the default mode
                secure_dir(run_dir)
                audit_args = ["--audit-log", str(run_dir / "audit.jsonl")]
            except OSError:
                audit_args = []  # read-only HOME: run without the archive rather than not at all
            rc = verify_mod.run([cfg, "--isolate", *audit_args], timeout=timeout)
        finally:
            try:
                os.unlink(cfg)
            except OSError:
                pass
        if rc in (0, 1, 2):
            # Report what the profile actually CONTAINS, not that the run finished: a run that
            # completed against auth walls records nothing, and "recorded" with an empty profile
            # is exactly the swallowed-ambiguity this codebase forbids everywhere else.
            # rc 2 is the engine's completed-but-partial code (its exitCode contract: a server
            # error, a check that never finished, or an unenumerated dynamic-dispatch catalog),
            # not a crash — the engine has already named each unverified server just above.
            # Branding the whole run "did NOT complete" discarded behaviour that WAS recorded,
            # and one dead endpoint in any agent's config made every scan on that machine
            # read as an error forever.
            observed_tools = _behaviour_tool_count()
            runlog.finish_run(run_id,
                              runlog.INCOMPLETE if rc == 2
                              else runlog.FINDINGS if rc == 1 else runlog.OK,
                              {"servers": len(allowed), "observed_tools": observed_tools,
                               "front_door": True})
            partial = ("\n  PARTIAL — some server(s)/check(s) could not be verified (named"
                       "\n  above); their checks stay name-only." if rc == 2 else "")
            if observed_tools:
                print(f"  Observed behaviour recorded for {observed_tools} tool(s) — decisions"
                      f"\n  now rest on what servers DO. See `mcpgawk status`.{partial}")
            else:
                print("  The run completed but OBSERVED NOTHING (commonly auth walls or servers"
                      "\n  that would not exercise). Checks stay name-only, and `mcpgawk status`"
                      f"\n  says so honestly.{partial}")
        elif rc in (4, 130):
            runlog.finish_run(run_id, runlog.INCOMPLETE, {"rc": rc, "front_door": True})
            why = "skipped by you" if rc == 130 else "timed out"
            print(f"  Behavioural verification {why} — INCOMPLETE, so checks stay name-only"
                  "\n  until `mcpgawk verify` finishes a run. `mcpgawk status` says so honestly.")
        else:
            runlog.finish_run(run_id, runlog.ERROR, {"rc": rc, "front_door": True})
            print("  Behavioural verification did NOT complete — checks stay name-only."
                  "\n  That posture is reported honestly in `mcpgawk status`.")
    except Exception as exc:  # noqa: BLE001 — verification must never break protection
        print(f"\n  Behavioural verification errored ({type(exc).__name__}) — checks stay"
              "\n  name-only; protection is unaffected.")


def _scan_target(raw: list[str]) -> str | None:
    """What this scan was pointed at, for the run log's `target` column. A fleet scan (no explicit
    transport flag) legitimately has no single target and records None rather than inventing one."""
    for flag in ("--stdio", "--http", "--sse"):
        if flag in raw:
            i = raw.index(flag)
            if i + 1 < len(raw):
                return f"{flag.lstrip('-')}:{raw[i + 1]}"
    return None


def main(argv: list[str] | None = None) -> int:
    """Entry point. Wraps the real dispatch in a run-log record so `mcpgawk runs` can answer "what
    did I scan, when, and how did it go" — see runlog.py for why that record has to exist here in
    the free layer rather than in the paid pillars.

    Wrapping at the boundary rather than at each `return` is deliberate: the scan path has four
    exit points plus exceptions, and threading a close call through all of them is exactly how a
    history ends up with runs that silently never closed.
    """
    # Line-buffer stdout even when it is a pipe. Python block-buffers off a TTY, so a run that is
    # killed — by a timeout, by Ctrl-C, by CI — discards everything it had already produced. That
    # is how a bare `mcpgawk` came to look like it hung in total silence while it had in fact
    # printed the banner and the entire scan table: 3376 bytes, sitting in an 8 KiB buffer that
    # was never flushed. Work done but not shown is indistinguishable from work not done.
    # `reconfigure` is TextIOWrapper-only: a replaced or detached stdout (tests, embedding) may not
    # have it at all. Asked for by name rather than caught after the fact, so the absence is a
    # branch the reader and the type checker can both see.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        try:
            reconfigure(line_buffering=True)
        except ValueError:                # a detached buffer — nothing to line-buffer
            pass

    # The MCP SDK logs child-cleanup warnings WITH exc_info (terminate_posix_process_tree's
    # killpg can hit EPERM on macOS process groups), and this CLI configures no handlers, so
    # Python's last-resort handler printed the full traceback into the founder's first-run
    # banner — twice, 2026-08-15. The one-line fact stays ("No permission to signal …; waiting
    # for it to exit anyway" is honest and complete); the stack frames are for us, not the
    # operator's terminal. Filter on the handler, not the logger: the record is emitted by a
    # CHILD logger and propagated records skip ancestor loggers' filters.
    import logging as _logging
    if _logging.lastResort is not None and not any(
            type(f).__name__ == "_SdkCleanupNoise" for f in _logging.lastResort.filters):
        class _SdkCleanupNoise(_logging.Filter):
            def filter(self, record: _logging.LogRecord) -> bool:
                if record.name.startswith("mcp"):
                    record.exc_info = None
                    record.exc_text = None
                return True
        _logging.lastResort.addFilter(_SdkCleanupNoise())

    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw or raw[0] != "scan":
        code = _dispatch(argv)
        _staleness_advisory()
        return code

    # Cheap, and it keeps the timeline honest: a scan killed by Ctrl-C last week should not still
    # read as "in progress" today.
    runlog.reconcile_stale()
    run_id = runlog.start_run("scan", _scan_target(raw))
    try:
        code = _dispatch(argv)
    except BaseException as exc:                       # noqa: BLE001 - recorded, then re-raised
        runlog.finish_run(run_id, runlog.ERROR, {"error": f"{type(exc).__name__}: {exc}"})
        raise
    # Non-zero here means the scan RAN and something wants attention (findings, a caveat, drift) —
    # a crash would have raised. Calling that `error` would make every drift detection look like a
    # tool failure in the timeline.
    runlog.finish_run(run_id, runlog.FINDINGS if code else runlog.OK, {"exit_code": code})
    _staleness_advisory()
    return code


def _staleness_advisory() -> None:
    """One stderr line when this install is stale (journey plan: every run, cached, never
    load-bearing). Belt and braces around a module that already swallows everything: the hint
    must never cost the run it rides on."""
    try:
        from . import staleness

        line = staleness.advisory()
        if line:
            print(line, file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass


def _dispatch(argv: list[str] | None = None) -> int:
    # Intercept the paid capabilities BEFORE argparse: their arguments are the pillar's own, and
    # the free parser must not try to validate them.
    raw = list(sys.argv[1:] if argv is None else argv)
    # FREE, and dispatched before argparse for the same reason the paid capabilities are: the
    # engine owns its own flags and the free parser must not try to validate them.
    if raw and raw[0] == "verify":
        from .verify import run as run_verify
        return run_verify(raw[1:])
    if raw and raw[0] in PLATFORM_CAPABILITIES:
        return _run_platform_capability(raw[0], raw[1:])
    if raw and raw[0] in ACCOUNT_COMMANDS:
        return _run_account_command(raw[0], raw[1:])
    if raw and raw[0] in PLATFORM_COMMANDS:
        return _run_platform_command(raw[0], raw[1:])
    # THE FRONT DOOR. Typing the tool's own name used to print a usage block and exit 2 — an error
    # message as the first thing a new user sees. A usage block is what you print when you cannot
    # tell what someone wants; here we can: they want to be protected. See protect.py.
    if not raw:
        return _protect()

    p = build_parser()
    args = p.parse_args(argv)

    if args.cmd == "baseline":
        return _baseline(args)

    if args.cmd == "approve":
        return _approve(args)

    if args.cmd == "wrong":
        return _wrong(args)

    if args.cmd == "skills":
        return _skills(args)

    if args.cmd == "demo":
        from .demo import run_demo
        return run_demo(sandbox=args.sandbox, clean=args.clean)

    if args.cmd == "panel":
        from .panel import serve as panel_serve
        return panel_serve(port=args.port, open_browser=not args.no_open)

    if args.cmd == "decide":
        from .decide import serve
        return serve(port=args.port, open_browser=not args.no_open)

    if args.cmd == "status":
        from .status import collect_and_render
        print(collect_and_render())
        return 0

    if args.cmd == "report":
        from .report import run as _report
        return _report(output=args.output, note=args.note)

    if args.cmd == "runs":
        return _runs(args)

    if args.cmd == "install-node":
        from .node_runtime import install_node

        path, message = install_node(assume_yes=args.yes)
        print(("✓ " if path else "mcpgawk install-node: ") + message,
              file=sys.stdout if path else sys.stderr)
        # 3, not 1: "could not install" must never share an exit code with "installed, and
        # something about it was wrong". Same vocabulary as verify's could-not-run.
        return 0 if path else 3

    if args.cmd == "guard":
        from .guard import main as guard_main

        rest = [args.action]
        if args.settings:
            rest += ["--settings", args.settings]
        return guard_main(rest)

    # No args at all is VALID: it means "discover and scan everything on this machine". _run handles
    # the nothing-found message and default-deny consent before launching any discovered stdio server.
    try:
        snaps, entries, skipped = asyncio.run(_run(args))
    except _NoMatchingServers:
        return 2        # a typo at --only, already explained on stderr; not a tool failure
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

    # WHICH SERVERS ARE REFUSING US FOR CREDENTIALS. A failed probe never reaches history
    # (should_record drops it), so without this the one fact a UI needs to offer a sign-in —
    # the server answered 401/403 — dies with the scan. Rewritten wholesale so an offer never
    # outlives the problem it was made about.
    try:
        from . import remote_login as _rl
        _needs = {}
        for _sn, _lab in zip(snaps, labels):
            if (_lab.get("x-mcpgawk") or {}).get("error_kind") == "auth-required":
                _url = str((entries.get(_sn.name) or {}).get("url") or "")
                if _url:
                    _needs[_sn.name] = _url
        _rl.record_auth_needed(_needs)
    except Exception:                               # noqa: BLE001 — bookkeeping never costs a scan
        pass

    # Findings the human marked wrong (`mcpgawk wrong`): mark them muted — NEVER remove them —
    # so every renderer, JSON included, shows them as 'muted by you' rather than absent.
    try:
        _mark_muted_findings(labels)
    except Exception:                               # noqa: BLE001 — display state, never costs a scan
        pass

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
            # `migrate_from` carries every key this server could already be recorded under — the
            # legacy `transport:name` variants (B3) and, once the login is part of the identity, the
            # un-discriminated `mcp:<asserted>` — so switching to the server-asserted identity,
            # switching transport on a nameless server, and gaining a credential discriminator all
            # adopt an existing baseline instead of orphaning it. The fix for silent baseline resets
            # must not itself cause one, in any direction.
            current = drift.build_record(sn, m, measured_at=now)
            migrate_keys = history.legacy_identity_keys(sn)
            asserted = history.key_for(sn)
            key = history.legacy_key_for(sn) if asserted in collided else asserted
            # C2 — a server that changes the name it ASSERTS gets a new key, and a new key is a
            # first sighting, which is silence. Check before recording, or the entry we would be
            # comparing against is the one we just created.
            was = history.identity_change(history.load(), key, sn.name)
            if was in migrate_keys:
                # OUR key scheme changed, the server did not. `record` adopts that exact record
                # below, so the baseline DOES carry over — announcing "identifies itself as a
                # DIFFERENT server … its baseline does not carry over" would be a false alarm that
                # fires once for every credentialled server on upgrade, and it would be untrue.
                was = None
            if was:
                reidentified[sn.name] = was
            previous = history.record(key, current,
                                      migrate_from=migrate_keys,
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
            # A refused baseline has EMPTY diff lists, so `rug_pull`/`hostile` both read false —
            # calm, for a server nothing was compared against. A CI gate keying on those fields
            # would pass while the exit code says otherwise. Say plainly that no comparison
            # happened, so a consumer can distinguish "checked, clean" from "not checked".
            d["compared"] = rep.unreadable is None
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
    # LIVE FINDINGS COUNT. This was `caveats or drift or reidentified` — probe failures and
    # movement — so `mcpgawk scan --json` exited 0 on a fleet carrying injection findings, and any
    # CI gate built on that exit code passed. That it is a gap rather than a policy is settled by
    # the post-auth redraw below, which DOES count REVIEW towards its own exit. A finding the user
    # has explicitly muted is excluded: muting is a decision they made, not one we made for them.
    def _live_findings(lab: dict) -> bool:
        return any(not s.get("muted")
                   for s in (lab["x-mcpgawk"].get("bounded_signals") or []))

    failed = (any(lab["x-mcpgawk"].get("caveats") for lab in labels)
              or any(_live_findings(lab) for lab in labels)
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
            any_error = any_error or any(r.state in ("REVIEW", "INCOMPLETE", "UNREACHABLE",
                                                     "FAILED", "TIMED-OUT")
                                         for r in refreshed.values())
        _behavioural_capability_note()
        return 1 if (any_error or failed) else 0

    any_error = False
    # DRIFT LEADS — design-contract item 2 (drift over inventory: the noise control). Once a
    # baseline exists, the FIRST content of a tracked report is what changed since it — or one
    # line saying nothing did — and the full surface sits behind --full. Errors, first sightings
    # and re-identifications always render in full: "not shown" must never read as "checked clean".
    lead_view = args.track and not (args.full or args.verbose or args.detail)
    for lab in labels:
        name = lab["name"]
        caveats = bool(lab["x-mcpgawk"].get("caveats"))
        any_error = any_error or caveats
        rep = drift_reports.get(name)
        if not lead_view:
            print("\n" + render_cli(lab, verbose=args.verbose))
            if rep:
                print(drift.render(name, rep))
            continue
        if name in reidentified:
            print(f"\n  ⛔ {name} now identifies itself as a DIFFERENT server "
                  f"(was {reidentified[name]}). Its baseline does not carry over — treat it "
                  f"as unreviewed.")
            print("\n" + render_cli(lab, verbose=False))
        elif rep:
            # The change IS the report. What it gained/lost is quoted in the drift block; the
            # rest of the surface — unchanged since approval — stays behind --full.
            print("\n" + drift.render(name, rep))
        elif name in new_baselines:
            print(f"\n  ✓ {name}: baseline recorded — first sighting, nothing to diff yet. "
                  f"What you are trusting:")
            print("\n" + render_cli(lab, verbose=False))
        elif caveats:
            print("\n" + render_cli(lab, verbose=False))   # a failure is never summarised away
        else:
            n = lab["x-mcpgawk"]["tool_count"]
            signals = lab["x-mcpgawk"].get("bounded_signals") or []
            live = [s for s in signals if not s.get("muted")]
            muted_n = sum(1 for s in signals if s.get("muted"))
            if live:
                # UNCHANGED IS NOT CLEAN. This branch printed a lone green tick for any tracked
                # server with no drift and no probe error — and `caveats` covers probe/scan
                # failures only, never findings. So a server whose description was ALREADY
                # poisoned when you approved it, and has sat unchanged since, rendered as
                # "✓ no change since your baseline" with the findings printed nowhere: render_cli
                # is skipped on this path and render_summary is skipped too (it is gated on
                # any_error). The old line even named findings you had MUTED while omitting the
                # live ones, which is the asymmetry that gives the game away.
                any_error = True
                print(f"\n  ⚠ {name}: no change since your baseline, but it was never clean — "
                      f"{len(live)} live finding{'s' if len(live) != 1 else ''} still stand:")
                print("\n" + render_cli(lab, verbose=False))
            else:
                muted_note = f", {muted_n} finding{'s' if muted_n != 1 else ''} muted by you" \
                    if muted_n else ""
                print(f"\n  ✓ {name}: no change since your baseline "
                      f"({n} tool{'s' if n != 1 else ''}{muted_note} — full surface: --full).")
    # Local (stdio) servers — launched this run or merely configured. Both inherit the same
    # ambient credentials the moment anything starts them, so both count towards that warning.
    local_servers = (sum(1 for e in entries.values() if e.get("command"))
                     + sum(1 for _, e in skipped if e.get("command")))
    if not lead_view or any(drift_reports) or any_error:
        print("\n" + render_summary(labels, local_servers=local_servers) + "\n")
    else:
        print()
    # Scanning is not protection. A report with no next step is how the author finished a scan on
    # his own machine and stayed unprotected — the hook existed, worked, and was never installed
    # because nothing ever mentioned it. Only shown when it is actually actionable.
    _installed = _guard_is_installed()
    if _installed is None:
        print("  Whether your agents are checking these servers could not be determined — the "
              "guard probe failed. Run `mcpgawk guard status`.\n")
    elif not _installed:
        print("  Your agents are not checking these servers yet. `mcpgawk` turns that on.\n")
    _behavioural_capability_note()
    return 1 if (any_error or failed) else 0


def _behavioural_capability_note() -> None:
    """B5 — never a silent fallback: a scan on a machine that cannot run behavioural checking
    says so, in the same words `status` uses. Advisory only; it never fails the scan."""
    try:
        from .capability import unavailable_line

        line = unavailable_line()
        if line:
            print(f"  ⚠ {line}\n")
    except Exception:  # noqa: BLE001
        pass


def _mark_muted_findings(labels: list[dict]) -> None:
    """Stamp `muted: True` onto every bounded signal the human has recorded as wrong for that
    server (matched by `<tool>/<kind>`, resolved through the server's aliases)."""
    store = history.load()
    for lab in labels:
        muted_ids = history.muted(store, history.resolve(store, lab["name"]))
        if not muted_ids:
            continue
        for s in (lab["x-mcpgawk"].get("bounded_signals") or []):
            if f"{s.get('tool')}/{s.get('kind')}" in muted_ids:
                s["muted"] = True


def _guard_is_installed() -> "bool | None":
    """Is the runtime guard installed? True / False / None when the probe itself failed.

    Was `return True` on exception, "to stay quiet rather than nag wrongly" — which meant a broken
    probe silenced "Your agents are not checking these servers yet." on exactly the machines most
    likely to need it. Silence there is indistinguishable from coverage, and this is the last line
    of a scan: the one a user reads to decide whether they are done.

    Still never raises — an advisory probe must not fail a completed scan — but "I could not tell"
    is now its own answer, and the caller says so instead of picking the reassuring one.
    """
    try:
        from .guard import status
        return "NOT installed" not in status()
    except Exception:                              # noqa: BLE001 - advisory only
        return None


def _signin_failure_line(name: str, snap_error: str, flow_error: str | None) -> str:
    """One honest line for a sign-in that died — never a traceback, never circular advice.

    Both failures shipped to the founder's terminal on figma (2026-08-14): the SDK's raw
    'OAuth flow error' traceback, then our own scan-path message telling them to "retry with
    `--login`" — from INSIDE the login flow that had just failed. A server that refuses Dynamic
    Client Registration (403 on the registration endpoint) is a dead end for this flow, and the
    honest answer names that instead of sending the user in a circle."""
    err = " ".join((flow_error or snap_error or "no detail").split())
    if "Registration failed" in err:
        # This class is no longer a dead end: BYO-client shipped 2026-08-15 — but the founder's
        # very next scan still read "check figma's documentation", because this message predated
        # the feature and nothing tied the two together. The refusal now names our own way
        # through it.
        return (f"  {name}: this server refuses automatic client registration ({err[:120]}) — "
                f"it only accepts OAuth clients it already knows about. The way through: create "
                f"an OAuth app in {name}'s developer console, register the redirect URI mcpgawk "
                f"prints, then run once:  mcpgawk scan --login <url> --oauth-client-id <id> "
                f"[--oauth-client-secret-env VAR]")
    # Scan-path advice is circular inside the login flow itself: we ARE `--login`.
    err = err.split("; retry with")[0]
    return f"  {name}: sign-in did not complete — {err[:160]}"


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
            from .oauth_login import last_flow_error
            print(_signin_failure_line(row.name, snap.error or "", last_flow_error()),
                  file=sys.stderr)
            continue
        # The row is replaced by a REAL measurement of the now-authenticated server, built through
        # the same label path as the original pass — so the refreshed row cannot disagree with the
        # one it replaces, and a server that turns out to be risky says so immediately.
        entry = entries.get(row.name) or {}
        label = _label_for(snap, measure(snap), entry, args)
        state, detail = fleet.state_of(label)
        refreshed[row.name] = FleetRow(name=row.name, state=state, detail=detail, url=row.url,
                                       clients=row.clients, names=row.names)
        print(f"  {row.name}: signed in — {detail}", file=sys.stderr)
    return refreshed


if __name__ == "__main__":
    sys.exit(main())
