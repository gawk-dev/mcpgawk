"""`mcpgawk panel` — the local control panel.

WHAT THIS IS. One window over everything the tool knows about this machine: which agents are
covered and which are not, every MCP server and its state, what the runtime guard has actually
seen, what verify observed, and anything waiting on a decision. Tabs, tiles, live parameters —
read from the real stores, never from a fixture.

WHY IT EXISTS SEPARATELY FROM `decide`. `decide` answers one question at one moment ("this server
changed — yes or no"). The panel answers "what is the state of my machine", which is a different
job and a different frequency. Keeping them apart means the blocking question never has to compete
for attention with a dashboard.

THREE RULES IT KEEPS, all learned the hard way in this codebase:

1. **It computes nothing.** Every number comes from the module that owns it — `history.pending`,
   `spool.summarise`, `guard.is_installed_for`, `runlog.list_runs`. A panel that derives its own
   figures is a second opinion, and this repo has paid for several.
2. **Absence is never coverage.** An agent with no interception point says so; a store that cannot
   be read says so. A tile must never show a confident zero for something it failed to look at.
3. **No script, no network.** CSP is `default-src 'none'` and the tabs are pure CSS, because this
   page renders prose written by potentially hostile servers.

Read-only. Every mutating action lives in `decide`, behind its token.
"""
from __future__ import annotations

import html
import json
import time
import re
import os
import pathlib
from pathlib import Path
from typing import Any

from . import dxt

TABS = ("fleet", "runtime", "evidence", "decisions")


def _esc(v: object) -> str:
    return html.escape(str(v), quote=True)


def _config_finding_rows(entries: dict[str, Any]) -> list[dict[str, Any]]:
    """Config-only findings shaped as panel finding rows. A pure function of the entries dict so
    it is testable without discovery; guarded by the caller like every other collect() probe.
    Severity: RISKY_KINDS carry "medium" (they flip a fleet row to REVIEW on their own); the
    rest "low" — informational, sorted after every verify conviction, never above one."""
    from .configcheck import RISKY_KINDS, check

    rows: list[dict[str, Any]] = []
    for name, entry in entries.items():
        try:
            found = check(name, entry)
        except Exception:                          # noqa: BLE001 — one bad entry must not blank the rest
            continue
        for f in found:
            rows.append({
                "server": name,
                "verified_at": "",                 # nothing ran — that is the point of this class
                "tool": "—",
                "code": f.kind,
                "class": "config",
                "severity": "medium" if f.kind in RISKY_KINDS else "low",
                "repro": "—",
                "suppressed": False,
                "evidence": _clip(f.evidence),
                "first_party": False,
            })
    return rows


def collect() -> dict[str, Any]:
    """Everything the panel shows, gathered from the owning modules.

    Each probe is independently guarded and records its own failure: one unreadable store must
    degrade ITS tile, never blank the page and never render as a confident zero."""
    from . import agents as agent_mod
    from . import guard, history, runlog, spool

    data: dict[str, Any] = {"errors": {}}

    try:
        from .discover import discover_report, problem_lines
        found, sources = discover_report()
        data["entries"] = found or {}
        # The sweep's own shortfalls (unparsable config, unreadable file, unrecognised entry
        # shapes, disabled servers) — rendered on the Servers tab so a partial fleet can never
        # present as a complete one. Same lines the CLI prints.
        data["discovery_problems"] = problem_lines(sources)
    except Exception as exc:                       # noqa: BLE001
        data["entries"], data["discovery_problems"] = {}, []
        data["errors"]["fleet"] = f"{type(exc).__name__}: {exc}"

    try:
        # Capabilities that exist for this user but that NO local scan can reach — account-hosted
        # connectors and browser native-messaging hosts. The CLI has always listed these; the
        # panel did not, so on the screen the operator actually uses they were simply absent,
        # which is the one rendering a discovery tool must never produce.
        from .discover import detect_unscannable
        from .cli import _known_names
        # A server configured on this machine is never "beyond this machine" — robinhood-trading
        # was listed once as a Claude Code server needing sign-in and once as an account-hosted
        # connector that cannot be scanned, on the same page (2026-09-03).
        data["unscannable"] = detect_unscannable(exclude=_known_names(data.get("entries") or {},
                                                                     []))
    except Exception as exc:                       # noqa: BLE001
        data["unscannable"] = []
        data["errors"]["unscannable"] = f"{type(exc).__name__}: {exc}"

    try:
        # load_checked, not load: `load` degrades an unreadable store to an empty one, and an
        # empty store renders as a calm, confident "nothing approved, nothing wrong" panel that is
        # byte-identical to a fresh machine. The corruption never raised, so this except never
        # fired and the error tile never appeared. The reason has to travel WITH the result.
        store, load_error = history.load_checked(history.default_path())
        data["store"] = store
        data["pending"] = history.pending(store)
        if load_error:
            data["errors"]["baseline"] = load_error
    except Exception as exc:                       # noqa: BLE001
        data["store"], data["pending"] = {"servers": {}}, []
        data["errors"]["baseline"] = f"{type(exc).__name__}: {exc}"

    try:
        data["activity"] = spool.summarise()
        data["recent_calls"] = spool.read(limit=40)
        # How many of the DECLINED calls went to a capability no scan can baseline (a browser
        # host)? "Run a scan" is the wrong advice for those, and on this machine they were
        # 1,323 of 1,933 (2026-09-03). Same window as `summarise`.
        _unsc = {str(u.get("name")) for u in (data.get("unscannable") or [])
                 if isinstance(u, dict)}
        if _unsc and isinstance(data["activity"], dict):
            data["activity"]["deferred_unscannable"] = sum(
                1 for r in spool.read(limit=5000)
                if r.get("decision") == "defer" and str(r.get("server")) in _unsc)
        # DENIALS ARE NOT A RECENT-EVENTS QUESTION. `recent_calls` is a 40-row display window, and
        # classification used it — so a server the guard blocked 100 calls ago silently lost its
        # "Blocked" tier while the banner (which reads full state) still said a server was blocked
        # right now. Reproduced on the founder's fleet 2026-08-14: the Blocked filter returned
        # "0 of 17" beside 10 rendered `deny` chips. The tier now asks the whole session window.
        # ONE wide read, shared by everything that needs more than the display tile. It used to be
        # two separate scans of the same file; `read` returns most-recent-first, so the narrower
        # windows are slices of the wide one and stay exactly what they were.
        _wide = spool.read(limit=5000)
        data["denied_servers"] = {r.get("server") for r in _wide
                                  if r.get("decision") == "deny" and r.get("server")}
        # A wider window than the recent-calls tile: sessions are the unit an operator reviews
        # ("what did my agent do in that run"), and a 40-row window would show fragments of one.
        data["session_calls"] = _wide[:1000]
        # The agent x server tree counts against the widest window the panel holds: a pair that
        # went quiet last week is still a pair the operator governs, and a narrow window would
        # drop it from the fleet entirely rather than show it as idle.
        data["fleet_calls"] = _wide
    except Exception as exc:                       # noqa: BLE001
        data["activity"], data["recent_calls"] = None, []
        data["denied_servers"] = set()
        data["session_calls"] = []
        data["fleet_calls"] = []
        data["errors"]["runtime"] = f"{type(exc).__name__}: {exc}"

    try:
        # `is_installed_for` answers "is our marker in this config?" — true for a hook whose
        # interpreter or script has since gone, which checks nothing. The panel's rule is that
        # unenforceable is never rendered as checked, so it asks whether the hook can actually RUN.
        _health = {a.key: guard.hook_health_for(a)
                   for a in agent_mod.ADAPTERS.values() if a.config.is_file()}
        data["hooks"] = {k: v == "ok" for k, v in _health.items()}
        data["hook_health"] = _health
        data["adapters"] = agent_mod.ADAPTERS
        data["no_hook"] = agent_mod.NO_HOOK_POINT
    except Exception as exc:                       # noqa: BLE001
        data["hooks"], data["adapters"], data["no_hook"] = {}, {}, {}
        data["errors"]["hooks"] = f"{type(exc).__name__}: {exc}"

    try:
        data["runs"] = runlog.list_runs(limit=12)
    except Exception as exc:                       # noqa: BLE001
        data["runs"] = []
        data["errors"]["runs"] = f"{type(exc).__name__}: {exc}"

    data["observed"] = {}
    #: Which servers were actually LOOKED AT, whatever the verdict. `observed` (the profile's
    #: `servers`) only ever contains CONVICTIONS, so using it to answer "was this verified?" reads
    #: a clean server as one that was never run — the cleaner the fleet, the emptier the evidence.
    #: Measured 2026-07-30: engine verified five servers, `servers` held two, tiles said
    #: "Unverified 9" straight after a successful run. `verified` is the observation record.
    data["verified_runs"] = {}
    try:
        prof = behaviour_profile_path()
        if prof.is_file():
            _doc = json.loads(prof.read_text(encoding="utf-8"))
            data["observed"] = _doc.get("servers") or {}
            data["verified_runs"] = _doc.get("verified") or {}
    except Exception as exc:                       # noqa: BLE001
        data["errors"]["observed"] = f"{type(exc).__name__}: {exc}"

    #: The last verify's FULL report — the findings themselves, not a count of them. Kept so the
    #: rest of the panel can respond to a verify at all; before this the convictions lived only in
    #: the subprocess's stdout and vanished on restart.
    data["findings"] = []
    data["verify_at"] = ""
    # EVERY verified server, not only those with findings (slice 3, 2026-09-05): a clean server's
    # `verifiedAt` and sandbox backend never left the report file, so the API could not say
    # "verified in a sandbox on <date>" for exactly the servers that earned it.
    data["verified"] = {}
    try:
        rep = behaviour_profile_path().parent / "last-verify.json"
        if rep.is_file():
            _r = json.loads(rep.read_text(encoding="utf-8"))
            data["verify_at"] = _r.get("generatedAt") or _r.get("at") or ""
            for s in (_r.get("servers") or []):
                if isinstance(s, dict) and s.get("server"):
                    data["verified"][str(s["server"])] = {
                        "at": s.get("verifiedAt") or data["verify_at"] or None,
                        "backend": s.get("sandboxBackend"),
                        "degraded": s.get("sandboxDegradedReason"),
                        "status": s.get("status"),
                        "transport": s.get("transport"),
                        "tools_checked": s.get("toolsChecked"),
                        "checks_planned": s.get("checksPlanned"),
                        "checks_completed": s.get("checksCompleted"),
                        "complete": s.get("complete"),
                        "incomplete_reasons": [str(x) for x in (s.get("incompleteReasons") or [])][:4],
                    }
                for f in (s.get("findings") or []):
                    # The written report is FLAT (code/class/severity/tool at top level). The first
                    # version of this read f["candidate"]["toolName"] — the shape of the in-memory
                    # candidate, which is what the TS test double used — and would have rendered 21
                    # rows of "?" against the founder's real file. `candidate` is kept only as a
                    # fallback so an older report still parses.
                    cand = f.get("candidate") or {}
                    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
                    where = [str(x) for x in (ev.get("egress") or ev.get("hosts") or [])][:4]
                    _hosts = [str(x) for x in ((f.get("evidence") or {}).get("egress")
                                               or (f.get("evidence") or {}).get("hosts") or [])]
                    data["findings"].append({
                        "server": s.get("server"),
                        # When this server was last actually verified. The report can now carry
                        # servers from EARLIER runs (a single-server verify no longer deletes the
                        # rest), so a finding must be able to say how old it is instead of
                        # inheriting the run timestamp of a run that never touched it.
                        "verified_at": s.get("verifiedAt") or data["verify_at"],
                        "tool": f.get("tool") or cand.get("toolName"),
                        "code": f.get("code") or cand.get("code"),
                        "class": f.get("class") or cand.get("findingClass"),
                        "severity": f.get("severity") or cand.get("severity"),
                        "repro": f"{f.get('reproOk', '?')}/{f.get('reproTotal', '?')}",
                        "suppressed": bool(f.get("suppressed")),
                        # WHAT IT ACTUALLY DID. A class name is a label; the hosts it contacted are
                        # the evidence, and the whole product rests on showing evidence not labels.
                        "evidence": _clip(", ".join(where) or str(ev.get("note") or "")),
                        # Every host it reached is this machine's own loopback: it never left.
                        "loopback": bool(_hosts) and all(_is_loopback_host(h) for h in _hosts),
                        # Classified, never dropped: a first-party finding stays listed and says why.
                        "first_party": first_party(str(s.get("server") or ""), _hosts,
                                                   (data.get("entries") or {}).get(s.get("server"))),
                    })
    except Exception as exc:                       # noqa: BLE001
        # Named separately from `observed`: "we could not read the findings" and "we could not read
        # the behaviour profile" send the user to different files.
        data["errors"]["findings"] = f"{type(exc).__name__}: {exc}"

    # Config-only findings (configcheck.py), recomputed from the entries just discovered — never
    # persisted, so they can't go stale and they exist on the machine that has never run a verify.
    # This is the beta-tester-1 fix reaching the panel: her Findings tab said 0 because verify had
    # never run, while her config alone carried four findings. Merged into the same list so the
    # count and table treat them as first-class; class "config" says where they came from.
    try:
        data["findings"].extend(_config_finding_rows(data.get("entries") or {}))
    except Exception as exc:                       # noqa: BLE001
        data["errors"]["configcheck"] = f"{type(exc).__name__}: {exc}"

    try:
        from .verify import unavailable_reason
        data["verify_blocked"] = unavailable_reason()
    except Exception:                              # noqa: BLE001
        data["verify_blocked"] = "verification engine not available in this install"

    try:
        data["monitor"] = monitor_status()
    except Exception as exc:                       # noqa: BLE001 — degrade the tile, not the page
        data["monitor"] = {"installed": False, "db_present": False, "error": str(exc)}

    try:
        data["gateway"] = gateway_status()
    except Exception as exc:                       # noqa: BLE001 — degrade the tile, not the page
        data["gateway"] = {"installed": False, "audit_present": False, "error": str(exc)}

    return data


def _agent_rows(d: dict[str, Any]) -> list[tuple[str, str, str, int, str]]:
    """(client_key, label, state, server_count, detail) per agent found on this machine.
    The client key is what a Protect action must carry — labels are display-only."""
    from .status import CLIENT_LABELS

    counts: dict[str, int] = {}
    for entry in (d.get("entries") or {}).values():
        if isinstance(entry, dict):
            for c in entry.get("_clients") or []:
                counts[str(c)] = counts.get(str(c), 0) + 1

    rows = []
    for client, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        label = CLIENT_LABELS.get(client, client)
        if client in (d.get("adapters") or {}):
            on = (d.get("hooks") or {}).get(client)
            if on:
                # "every MCP call checked against your baseline" was rendered from `on` alone —
                # which only says the hook RUNS. On the founder's machine (2026-08-18) that line
                # sat beside a green chip while `mcpgawk status`, from the same spool, reported
                # 1513 calls seen, 57 checked and 1456 NOT checked: the guard declined for want of
                # a baseline projection and let them through. A 26x overstatement of protection, on
                # the screen a beta tester screenshots. `_activity_headline` had already been fixed
                # for exactly this and its docstring says so; the Agents tab kept the old claim.
                #
                # The counts are MACHINE-WIDE — the spool records no per-client breakdown — so the
                # wording says "on this machine" rather than implying it measured this agent.
                act = d.get("activity") if isinstance(d.get("activity"), dict) else {}
                seen = act.get("calls") or 0
                checked, deferred = act.get("checked"), act.get("deferred") or 0
                if checked is None:
                    det = "hook installed — this log does not record how many calls were checked"
                elif not seen:
                    det = "hook installed — no MCP calls seen yet, so nothing has been checked"
                elif deferred:
                    det = (f"hook installed — on this machine {checked} of {seen} call(s) were "
                           f"checked; {deferred} were NOT — no or stale baseline, or a capability "
                           f"no scan can reach (a browser host). Run a scan for the servers.")
                else:
                    det = (f"every MCP call checked against your baseline "
                           f"({checked} on this machine)")
                rows.append((client, label, "on", n, det))
            else:
                rows.append((client, label, "off", n,
                             "hook point exists but is not installed"))
        else:
            why = (d.get("no_hook") or {}).get(client, "no pre-execution hook point")
            rows.append((client, label, "none", n, why))
    return rows


#: The severity vocabulary — FOUR tiers, fixed, used everywhere including the sort order and the
#: coverage bar. Snyk uses critical/high/medium/low, Stainless fatal/error/warning/note; the point
#: is not which words but that there is exactly one set. Ours is stated in terms of what is true of
#: a server rather than borrowed from vulnerability scanning, because "medium severity MCP server"
#: means nothing.
#:
#: UNVERIFIED is the important one and the reason this list is not three long: a server nothing has
#: ever watched is not clean, and every other surface in this product already refuses to let absence
#: read as safety. It is the "Not Scanned" segment Snyk puts in its coverage bar.
#: FINDINGS exists because "At baseline" was counting servers we had CONVICTED. On 2026-07-30 the
#: result banner read "21 tool(s) with findings on 2 server(s): browserstack, vault-rag" while the
#: coverage bar two inches below counted both of them, in green, as At baseline. `_classify` asked
#: only "was it observed?" — so watching a server and catching it misbehaving moved it into the
#: SAFE segment. A server we convicted is not at its baseline; it is the most important thing on
#: the page.
TIERS = (
    ("blocked", "Blocked", "a call was denied — the guard stopped something"),
    ("changed", "Changed", "moved since you approved it; your agents cannot call it"),
    # "With findings", not "Findings": every tier counts SERVERS, and the Findings tab's badge
    # counts FINDINGS. One page read "5 Findings" in the radar and "6" on the Findings tab —
    # the same word, two units (live 2026-09-03). The label now carries its unit.
    ("findings", "With findings", "verification caught it doing something — exfiltration, SSRF "
                                  "or injected output"),
    ("unverified", "Unverified", "never watched — absence of a finding, not safety"),
    ("baseline", "At baseline", "matches what you approved, and behaviour was observed"),
)


def _classify(name: str, key: str | None, d: dict) -> str:
    """One server's tier. Ordered worst-first: the first thing that is true wins."""
    # BOTH universes. `denied_servers` is the full session history (added 2026-08-14 because the
    # 40-row display window silently dropped the tier); `recent_calls` is that window, and callers
    # that build `d` themselves may supply only it. Asking either keeps both correct — a deny is a
    # deny whenever it happened.
    if name in (d.get("denied_servers") or set()) or any(
            c.get("decision") == "deny" for c in (d.get("recent_calls") or [])
            if c.get("server") == name):
        return "blocked"
    # Convictions outrank "changed" and "unverified": a server verification CAUGHT doing something
    # is a stronger statement than one whose declared surface moved, and it must never fall through
    # to "baseline" just because it was observed.
    # CHANGED OUTRANKS FINDINGS. The briefing's own rule: "a server waiting on a decision is
    # BLOCKED right now; findings are evidence already in hand". Ordering findings first put
    # browserstack, gitnexus and resend — all changed, all blocked — under the Findings chip, so
    # one page said "1 Changed" in the radar, "4 servers changed" in the ask card and "4
    # approval(s) waiting" in the strip (2026-09-03). Three numbers for one fact.
    if key and key in (d.get("pending") or []):
        return "changed"
    real = [f for f in (d.get("findings") or [])
            if f.get("server") == name and not f.get("first_party") and not f.get("suppressed")]
    if real:
        return "findings"
    # OBSERVED means "a run exercised it", not "a run convicted it". Testing membership of the
    # convictions map made every clean server permanently "unverified", so the coverage bar could
    # only ever improve by finding something WRONG. A run that exercised nothing (toolsChecked 0 —
    # e.g. an OAuth server that never listed its tools) is correctly still unverified.
    ran = (d.get("verified_runs") or {}).get(name)
    exercised = isinstance(ran, dict) and (ran.get("toolsChecked") or 0) > 0
    if not exercised and name not in (d.get("observed") or {}):
        return "unverified"
    return "baseline"




def policy_rows(d: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """(policy, enforced by, state on this machine now, chip class) — five statements an
    enterprise reviewer maps to controls (founder, 2026-09-03: "Server approval required · Least
    privilege · Continuously verify integrity · Detect & respond to change · Audit everything").
    mcpgawk enforced most of these and stated none as policy. The state column is READ, never
    asserted: a control that is off says off, and no row is ever a percentage.
    """
    from . import history as _h
    store = d.get("store") if isinstance(d.get("store"), dict) else {"servers": {}}
    agents = _agent_rows(d)
    covered = sum(1 for _k, _l, st, _n, _det in agents if st == "on")
    pending = len(d.get("pending") or [])
    approved_n = sum(1 for e in (store.get("servers") or {}).values()
                     if isinstance(e, dict) and isinstance(e.get("approved"), dict))
    rows: list[tuple[str, str, str, str]] = []
    # 1
    st = (f"guard in {covered} of {len(agents)} agent(s) · {pending} changed server(s) blocked now"
          if agents else "no agents found on this machine")
    rows.append(("Server approval required",
                 "a baseline is trusted only after `mcpgawk approve`; the guard hook refuses a "
                 "server whose surface moved off it",
                 st, "ok" if covered and covered == len(agents) else "warn"))
    # 2
    gw = d.get("gateway") or {}
    gw_live = bool((gw.get("live") or {}).get("listen"))
    rows.append(("Least privilege",
                 "per-principal tool allowlists at the gateway; the scan names every tool that "
                 "can write or send data and says when a read-only token would do",
                 "gateway running — allowlists enforced" if gw_live
                 else "gateway not running — nothing narrows what an agent may call",
                 "ok" if gw_live else "warn"))
    # 3
    mon = d.get("monitor") or {}
    mon_live = bool(mon.get("running"))
    watched = len(mon.get("servers") or {}) if isinstance(mon.get("servers"), dict) else 0
    rows.append(("Continuously verify integrity",
                 "every scan compares the exact surface pin against the approved one; the "
                 "monitor re-checks on a schedule",
                 (f"monitor running · {watched} server(s) re-checked on a schedule" if mon_live
                  else f"monitor NOT running — {approved_n} baseline(s) re-checked only when "
                       f"someone scans"),
                 "ok" if mon_live else "warn"))
    # 4
    moved = _h.changed_within(store, days=7)
    rows.append(("Detect and respond to change",
                 "drift is itemised per tool and blocks the server until a person decides; "
                 "verify reproduces behaviour in a sandbox",
                 f"{len(moved)} server(s) first seen changed in the last 7 days · {pending} awaiting a "
                 f"decision · last verify {str(d.get('verify_at') or 'never')[:19]}",
                 "warn" if pending else "ok"))
    # 5
    act = d.get("activity") if isinstance(d.get("activity"), dict) else {}
    calls = act.get("calls") or 0
    audit = bool(gw.get("audit_present"))
    rows.append(("Audit everything",
                 "every hooked call lands in the spool (arguments never recorded); every gateway "
                 "decision in a hash-chained trail; every run in the run registry",
                 f"{calls} call(s) recorded · gateway trail {'present' if audit else 'absent'} · "
                 f"{len(d.get('runs') or [])} recent run(s)",
                 "ok" if calls else "warn"))
    return rows


def _servers_of_this_run(rep_doc: dict, targets: dict) -> list[dict]:
    """The report entries THIS run produced — never the ones `_merge_verify_report` carried
    forward from earlier runs. The banner for a one-server verify of resend read "20 first-party
    finding(s) folded" (2026-09-03): browserstack's, from the fleet run four minutes earlier,
    counted off the merged file. A banner describes its own run, or it is the stale-verify
    banner in a new coat."""
    out = []
    for s in (rep_doc.get("servers") or []):
        if not isinstance(s, dict):
            continue
        sname = str(s.get("server") or "")
        if not sname or (targets and sname not in targets):
            continue
        out.append(s)
    return out


def _merge_verify_report(report_path: Path | str, prev_report: dict) -> None:
    """Preserve servers the latest run did not cover, instead of deleting their results.

    `gawk-verify --out` writes the report for the run it just did. The panel verifies ONE server
    at a time by design (a fleet run costs minutes), so every row-level verify replaced the file
    with a single-server report and silently erased every other server's reproduced findings: the
    pill flipped red -> green "At baseline" and the Findings tab claimed "No verify has run yet"
    seconds after one had.

    What is deliberately NOT done here: recomputing the top-level `summary`. That value is derived
    by the engine's status algebra over the servers IT verified, and synthesising a merged one in
    Python would be a fourth implementation of the algebra we just finished consolidating. The
    summary therefore keeps describing THIS run, `merged` says the server list is wider than it,
    and every server entry carries `verifiedAt` so a preserved result can be shown with its age
    rather than passed off as current.
    """
    try:
        fresh = json.loads(Path(report_path).read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return                       # nothing written (engine failed) — leave the previous file be

    now = fresh.get("generatedAt") or ""
    fresh_servers = [s for s in (fresh.get("servers") or []) if isinstance(s, dict)]
    covered = {s.get("server") for s in fresh_servers}
    for s in fresh_servers:
        s.setdefault("verifiedAt", now)

    kept = []
    for s in (prev_report.get("servers") or []):
        if not isinstance(s, dict) or s.get("server") in covered:
            continue                 # this run has a newer answer for it
        s.setdefault("verifiedAt", prev_report.get("generatedAt") or "")
        kept.append(s)

    if not kept:
        return                       # the run covered everything we had — the file is already right

    fresh["servers"] = fresh_servers + kept
    fresh["merged"] = True
    # Same treatment for run-level errors, so a server that failed to start does not vanish either.
    fresh_errors = [e for e in (fresh.get("errors") or []) if isinstance(e, dict)]
    fresh["errors"] = fresh_errors + [
        e for e in (prev_report.get("errors") or [])
        if isinstance(e, dict) and e.get("server") not in covered
    ]
    try:
        tmp = f"{report_path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(fresh, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, report_path)
    except OSError:
        pass                         # a read-only HOME must not fail an otherwise-good run


def verify_verdict(*, checked: int, skipped: list, errors: int, hits: int,
                   folded: int = 0, backend: str | None = None,
                   degraded: str | None = None,
                   label_noise: str | None = None) -> tuple[str, str, str]:
    """(outcome, level, detail) for one server a verify run touched.

    "observed" is NOT a verdict — it says we managed to run, which is a fact about US. The founder
    watched this page award `browserstack` a green `observed` chip while the grey text beside it
    read "20 with findings": the chip said good news, the sentence said his most-used server was
    convicted on every tool checked.

    Order matters and is deliberate — the first thing that is true wins:
      convictions > checks that never completed > checks never attempted > NOTHING CHECKED > clean.
    """
    bits = [f"{checked or hits} tool(s) watched"]
    if skipped:            # never let an untested tool read as a clean one
        bits.append(f"{len(skipped)} not invoked — absence there proves nothing")
    if errors:
        bits.append(f"{errors} check(s) never completed")
    if backend:            # the truth about isolation, per server, instead of a claim
        bits.append(f"isolation: {backend}")
    if degraded:           # container isolation was requested and did NOT run — say why
        bits.append(f"ran WITHOUT container isolation — {degraded.split('—')[0].strip()}")
    if folded:             # classified, never dropped — the list is on the Findings screen
        bits.append(f"{folded} first-party finding(s) folded (the vendor's own traffic)")
    if label_noise:        # the server's own labels were noise and were ignored — SAY so here,
        # not only in the JSON. Kite sat "verified-looking" for two weeks behind blanket labels
        # because no human surface ever printed the reason ([FOUNDER] 2026-08-14). The note's
        # first clause already reads as a sentence; prefixing "ignored as uninformative" again
        # printed the phrase twice on the founder's row.
        bits.append(f"its own {label_noise.split('—')[0].strip()}")
    detail = " · ".join(bits)

    if hits:               # convictions outrank everything: this is the headline, not an aside
        return (f"{hits} tool(s) with findings", "bad", detail)
    if errors:             # nothing proven wrong AND some checks never ran => not clean
        return ("incomplete — not clean", "warn", detail)
    if skipped:
        return (f"partial — {checked} of {checked + len(skipped)} checked", "warn", detail)
    if not checked:
        # ZERO checked is not a clean pass, it is the absence of one. This used to fall through to
        # the green badge, so a server with 85 declared tools and a 0/85 coverage bar on the same
        # page was awarded "clean - 0 tool(s)" AND counted into the headline "1 clean".
        return ("not verified — 0 tool(s) checked", "warn", detail)
    return (f"clean — {checked} tool(s)", "ok", detail)


def classified_servers(d: dict[str, Any]) -> list[tuple[str, dict, str | None, str]]:
    """(name, entry, store_key, tier) for every discovered server, sorted worst-first.
    One classification, shared by the page and the CSV export — two copies would be two answers."""
    entries = d.get("entries") or {}
    servers = (d.get("store") or {}).get("servers") or {}
    out: list[tuple[str, dict, str | None, str]] = []
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        key = next((k for k, v in servers.items()
                    if name in ((v or {}).get("aliases") or [])), None)
        out.append((name, entry, key, _classify(name, key, d)))

    # FALL BACK TO THE APPROVED BASELINE. This list used to be purely discovery-driven, so when
    # discovery came back short the panel reported "0 of 0 server(s)" while the CLI, at the same
    # instant on the same HOME, listed 15. Worse than a wrong number: a server you approved and
    # which then vanished from every config is exactly the one worth seeing, and it was the one
    # guaranteed to be missing. Anything in the trust store that discovery did not account for is
    # added here and marked, so the row can say it is not currently configured.
    seen_names = {n for n, _, _, _ in out}
    seen_keys = {k for _, _, k, _ in out if k}
    for key, rec in servers.items():
        aliases = [a for a in ((rec or {}).get("aliases") or []) if a]
        label = aliases[0] if aliases else key
        already = key in seen_keys or label in seen_names or any(a in seen_names for a in aliases)
        if already:
            continue
        out.append((label, {"_baseline_only": True}, key, _classify(label, key, d)))

    order = {t: i for i, (t, _, _) in enumerate(TIERS)}
    out.sort(key=lambda r: (order.get(r[3], 9), r[0]))
    return out


def _esc_attr(v: object) -> str:
    return html.escape(str(v), quote=True)


def _spark(series: list[int], w: int = 120, h: int = 26) -> str:
    """A sparkline as inline SVG. No script, no library — the CSP here is `default-src 'none'`,
    and a chart that needs a CDN is a chart that does not render offline."""
    if not series or max(series) == 0:
        return f'<svg class="spark" viewBox="0 0 {w} {h}" preserveAspectRatio="none"></svg>'
    top = max(series)
    step = w / max(len(series) - 1, 1)
    pts = " ".join(f"{i * step:.1f},{h - (v / top) * (h - 3) - 1.5:.1f}"
                   for i, v in enumerate(series))
    return (f'<svg class="spark" viewBox="0 0 {w} {h}" preserveAspectRatio="none">'
            f'<polyline points="{pts}"/></svg>')


def activity_rows(limit: int = 2000) -> list[dict]:
    """Every logged event, newest first, with the five questions answered on each row:
    WHEN (ts), WHERE (server), WHAT (tool), the decision and WHY (basis; full reason for a deny),
    HOW/WHO (agent adapter + session). Reads the spool — the one record every path writes to.

    The deny REASON is reconstructed from the shared decision core rather than stored, because the
    free spool records metadata not prose (its own rule) — but the reason a declared-tier deny
    fires is a pure function of (server, tool), so it can be shown without having been logged.
    """
    from . import spool
    try:
        rows = spool.read(limit=limit)
    except Exception:                              # noqa: BLE001 — a view must not crash on its data
        return []
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        decision = r.get("decision")
        why = r.get("reason")
        if not why and decision == "deny":
            try:
                from . import decision as _dec
                why = _dec.deny_reason(str(r.get("server")), str(r.get("tool")))
            except Exception:                      # noqa: BLE001
                why = None
        out.append({
            "when": r.get("ts"), "server": r.get("server"), "tool": r.get("tool"),
            "decision": decision, "basis": r.get("basis"),
            "agent": r.get("adapter"), "session": r.get("session"), "why": why,
        })
    return out


def export_log_jsonl(path: str | None = None) -> bytes:
    """The raw append-only log, verbatim — the same bytes `cat ~/.mcpgawk/calls.jsonl` shows."""
    from . import spool
    target = path or spool.spool_path()
    try:
        with open(target, "rb") as fh:
            return fh.read()
    except OSError:
        return b""


def export_log_csv(limit: int = 100000) -> bytes:
    """The log as CSV — every row, every field, for a spreadsheet or an auditor."""
    import csv
    import io
    rows = activity_rows(limit=limit)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["when", "server", "tool", "decision", "basis", "agent", "session", "why"])
    for r in rows:
        w.writerow([r.get(k) or "" for k in
                    ("when", "server", "tool", "decision", "basis", "agent", "session", "why")])
    return buf.getvalue().encode("utf-8")


def export_findings_csv() -> bytes:
    """Every finding, spreadsheet-shaped — the same rows the Findings screen shows, including
    folded and muted ones with their status stated, never silently dropped."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["server", "tool", "finding", "severity", "contacted", "reproduced",
                "first_party", "muted"])
    for f in collect().get("findings") or []:
        w.writerow([f.get("server") or "", f.get("tool") or "",
                    f.get("class") or f.get("code") or "", f.get("severity") or "",
                    f.get("evidence") or "", f.get("repro") or "",
                    bool(f.get("first_party")), bool(f.get("suppressed"))])
    return buf.getvalue().encode("utf-8")


def export_servers_csv() -> bytes:
    """The fleet, one row per server, with the SAME tier the page shows — the export must never
    disagree with the screen it exports."""
    import csv
    import io
    d = collect()
    store = d.get("store") or {}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["server", "key", "tier", "transport", "agents", "tools", "calls_seen"])
    for name, entry, key, tier in classified_servers(d):
        detail = server_detail(store, key, d.get("recent_calls") or []) if key else None
        w.writerow([name, key or "", tier,
                    "local" if entry.get("command") else "remote",
                    ", ".join(entry.get("_clients") or []),
                    len(detail["current_tools"]) if detail else "",
                    detail["calls_seen"] if detail else 0])
    return buf.getvalue().encode("utf-8")


def declared_vs_observed(detail: dict, observed: dict | None) -> list[dict]:
    """Per-tool join of what a server DECLARES against what verify OBSERVED — task 4's view.

    Honesty rules: a tool with no observation says "not observed", never "clean" (the profile is
    positive-only — absence is not evidence); a recorded observation for a tool the server no
    longer exposes is still shown, because evidence about a disappeared tool is a finding, not
    noise; and the baseline column distinguishes approved from added-since-approval.
    """
    obs = observed if isinstance(observed, dict) else {}
    current = detail.get("current_tools") or []
    approved = set(detail.get("approved_tools") or [])
    raw_ann = detail.get("annotations")
    annotations = raw_ann if isinstance(raw_ann, dict) else {}

    def bare(key: str) -> str:
        # The measured store namespaces item keys by kind ("tool.vault_search"); the behaviour
        # profile records the wire name ("vault_search"). Join on the wire name — without this,
        # one real tool rendered as two rows: an approved-but-unobserved ghost and a
        # gone-but-convicted twin. Found the first time real evidence flowed through this view.
        return key[5:] if key.startswith("tool.") else key

    rows = []
    joined: set[str] = set()
    for tool in current:
        name = bare(tool)
        joined.add(name)
        _ann = annotations.get(tool)
        ann: dict[str, Any] = _ann if isinstance(_ann, dict) else {}
        ro = ann.get("readOnlyHint")
        # Report the STRONGEST thing the server said, not a flattened version of it. kite declares
        # all 22 of its tools `readOnlyHint: false` AND `destructiveHint: true` — including
        # get_quotes and get_profile — and this column rendered every one of them as the milder
        # "writes". Showing less than the server admitted is the same failure as showing more:
        # `destructiveHint` is also exactly what drift watches for a rug-pull, so it must be visible.
        if ro is True:
            declared = "read-only"
        elif ro is False:
            declared = "destructive" if ann.get("destructiveHint") is True else "writes"
        else:
            declared = "undeclared"
        _sig = obs.get(name)
        sig: dict[str, Any] = _sig if isinstance(_sig, dict) else {}
        seen = [k for k in ("source", "sink") if sig.get(k) is True]
        rows.append({
            "tool": name,
            "baseline": "approved" if tool in approved else "added",
            "declared": declared,
            "observed": "+".join(seen) if seen else None,
        })
    for tool, sig in obs.items():
        if bare(tool) in joined or not isinstance(sig, dict):
            continue
        seen = [k for k in ("source", "sink") if sig.get(k) is True]
        rows.append({"tool": bare(tool), "baseline": "gone", "declared": "no longer exposed",
                     "observed": "+".join(seen) if seen else None})
    return rows


#: Adapters that are recorded but are NOT an agent identity, and why. Rendering these as if they
#: were agents would invent attribution the data does not hold — the same overclaim as reporting a
#: clean bill for a check that could not run.
_NOT_AN_AGENT = {
    "obot-filter": ("through the gateway",
                    "a gateway filter is given no agent identity, so these calls are known to "
                    "have happened and not known to belong to any one agent"),
    "?": ("(unrecorded)", "these rows carry no adapter — they predate agent attribution"),
}

#: Written by the hook before 0.1.14, when the adapter was hardcoded. It is claude-code's traffic,
#: but the rows do not SAY so, so it keeps its own node with the reason on it rather than being
#: quietly merged into claude-code and inflating that agent's numbers.
_LEGACY_ADAPTERS = {"claude-code-hook": "claude-code"}


def agent_server_tree(d: dict[str, Any], rows: list[dict] | None = None) -> list[dict]:
    """The fleet as agent → servers, which is the relationship an operator actually governs.

    The flat server list answers "what is installed". It cannot answer "who can reach this", and
    that is the question behind every approval: a server is not risky in itself, it is risky
    because some agent can call it. So the root is the AGENT and the branch is the servers that
    agent can reach — the pair, not the server, is the addressable thing.

    A pair gets here two ways and the difference is the point:
      DECLARED  the agent's own config lists the server (discover's `_clients`) — reachable.
      OBSERVED  a call was actually recorded for that pair (the spool) — used.
    Declared-and-never-used is unproven surface; observed-but-undeclared is a server reaching an
    agent by some route its config does not explain, which is worth seeing on its own.

    The counts are only ever as wide as the window handed in, and the caller states that window
    on the page. `recent_calls` is a 40-row DISPLAY tile — building pair counts on it would put a
    number on screen that reads as the pair's activity and is really "of the last 40 calls
    anywhere". That exact confusion already cost this panel a wrong Blocked tier (see collect()),
    so the default is the wider session window and the basis is never left implicit.

    Pure data, no HTML, so the numbers can be tested without a renderer.
    """
    if rows is None:
        rows = d.get("fleet_calls") or d.get("session_calls") or d.get("recent_calls") or []
    pairs: dict[tuple[str, str], dict] = {}

    # THE THIRD STATE, AND ACROSS THE WIDER MCP WORLD THE COMMON ONE. A server behind a login has
    # no calls for a reason that is the opposite of "nobody wants it": nobody can use it yet. Left
    # undistinguished it renders exactly like a server that is configured and ignored, so the one
    # server asking for a human action looks like the one that needs none.
    entries = d.get("entries") or {}
    signin: set[str] = set()
    for _n, _e in entries.items():
        if not isinstance(_e, dict):
            continue
        try:
            if _login_button_applicable(_e, _n):
                signin.add(str(_n))
        except Exception:                          # noqa: BLE001 - a fleet view must still render
            pass

    def _pair(agent: str, server: str) -> dict:
        return pairs.setdefault((agent, server), {
            "agent": agent, "server": server, "calls": 0, "denied": 0,
            "last": None, "declared": False, "observed": False,
            "needs_signin": server in signin})

    for name, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        for client in entry.get("_clients") or []:
            _pair(str(client), str(name))["declared"] = True

    for r in rows:
        if not isinstance(r, dict) or not r.get("server"):
            continue
        agent = r.get("adapter") or "?"
        p = _pair(str(agent), str(r["server"]))
        p["observed"] = True
        p["calls"] += 1
        if r.get("decision") == "deny":
            p["denied"] += 1
        ts = r.get("ts")
        if isinstance(ts, str):
            p["last"] = max(p["last"], ts) if p["last"] else ts

    by_agent: dict[str, dict] = {}
    for (agent, _server), p in pairs.items():
        node = by_agent.setdefault(agent, {
            "agent": agent, "label": agent, "servers": [], "calls": 0, "denied": 0,
            "awaiting_signin": 0, "last": None, "attributed": True, "note": None,
            "legacy_of": None})
        node["servers"].append(p)
        node["calls"] += p["calls"]
        node["denied"] += p["denied"]
        node["awaiting_signin"] += 1 if p["needs_signin"] else 0
        if p["last"]:
            node["last"] = max(node["last"], p["last"]) if node["last"] else p["last"]

    for agent, node in by_agent.items():
        if agent in _NOT_AN_AGENT:
            node["label"], node["note"] = _NOT_AN_AGENT[agent]
            node["attributed"] = False
        elif agent in _LEGACY_ADAPTERS:
            node["legacy_of"] = _LEGACY_ADAPTERS[agent]
            node["note"] = (f"recorded under a legacy adapter name; this is {node['legacy_of']} "
                            f"traffic from before 0.1.14, kept separate because the rows do not "
                            f"say so themselves")
        # Worst first inside an agent: denials, then busiest, then alphabetical for a stable page.
        node["servers"].sort(key=lambda p: (-p["denied"], not p["needs_signin"],
                                            -p["calls"], p["server"]))

    out = list(by_agent.values())
    # Agents that blocked something lead; then the ones doing the most; unattributed last, because
    # it is a bucket rather than an actor.
    out.sort(key=lambda n: (not n["attributed"], -n["denied"], -n["calls"], n["agent"]))
    return out


#: Tree geometry. Fixed columns and a fixed row pitch: the layout is computed on the server, so
#: every value here is a real coordinate rather than something a browser resolves later.
_TW = {"agent_w": 272, "srv_w": 300, "tool_w": 260, "call_w": 320, "h": 46,
       "pitch": 54, "gap": 44, "pad": 10}


def _clip(text: str, n: int) -> str:
    """SVG text does not wrap. A label that overruns its box would draw straight across the
    connectors, so it is cut here rather than left to overlap the drawing."""
    text = str(text)
    return text if len(text) <= n else text[: n - 1] + "\u2026"


def _wrap(text: str, width: int, lines: int) -> list[str]:
    """Break on spaces into at most `lines` of `width`, the last one clipped.

    SVG text does not wrap, and the deny reason is the whole point of the deepest node — a single
    clipped line turned "explains why" back into "shows that it happened".
    """
    words, out, cur = str(text).split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            out.append(cur)
            cur = w
            if len(out) == lines:
                break
        else:
            cur = f"{cur} {w}" if cur else w
    if len(out) < lines and cur:
        out.append(cur)
    if len(out) == lines and (len(words) > sum(len(o.split()) for o in out)):
        out[-1] = _clip(out[-1] + " …", width)
    return out


def _tnode(x: int, y: int, w: int, title: str, meta: list[str], href: str, *,
           accent: bool = False, alarm: bool = False, aria: str = "") -> str:
    """One box. A link, so the whole node is the target — the drill-down is a GET and a
    re-render, which is what keeps this drawing script-free under the panel's CSP.

    TWO meta lines, not one. The first drawing packed four facts onto a single line and clipped
    it, so the numbers this view exists to show ended in an ellipsis. Clipping is sized from the
    box and the font (monospace advance ~0.6em) rather than a constant guessed before any real
    label was seen — but the fix for a long line is a second line, not a smaller cap.
    """
    cls = "tn" + (" tnsel" if accent else "") + (" tnbad" if alarm else "")
    label = f'<title>{_esc(aria or title)}</title>'
    lines = [m for m in meta if m][:2]
    tt = (f'<text class="tnt" x="{x + 12}" y="{y + (17 if lines else 27)}">'
          f'{_esc(_clip(title, int((w - 24) / 7.5)))}</text>')
    cap = int((w - 24) / 6.6)
    mt = "".join(f'<text class="tnm" x="{x + 12}" y="{y + 30 + i * 12}">{_esc(_clip(m, cap))}</text>'
                 for i, m in enumerate(lines))
    return (f'<a href="{_esc_attr(href)}" class="{cls}">{label}'
            f'<rect x="{x}" y="{y}" width="{w}" height="{_TW["h"]}" rx="9"/>{tt}{mt}</a>')


def _elbow(x1: int, y1: int, x2: int, y2: int) -> str:
    """The branch itself: out, across, in. Orthogonal because a tree read at a glance needs the
    parent-child line to be traceable, not a curve crossing three siblings."""
    mid = x1 + 22
    return (f'<path class="tbr" d="M{x1} {y1} H{mid} V{y2} H{x2}"/>')


def pair_tools(rows: list[dict], agent: str, server: str, limit: int = 10) -> tuple[list[dict], int]:
    """What this AGENT actually called on this SERVER, by tool. Returns (shown, hidden).

    Computed only for the branch the operator opened — the fleet window is thousands of rows and
    every pair would be a scan nobody asked for. Per-pair, not per-server: `server_detail` has a
    tools breakdown already and it is the WHOLE server's, which under an agent node would read as
    that agent's traffic and would not be.

    The hidden count is returned rather than swallowed: a list silently cut at ten reads as the
    complete set, and this view's whole claim is that it shows what an agent can reach.
    """
    by: dict[str, dict] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        if (r.get("adapter") or "?") != agent or r.get("server") != server:
            continue
        tool = r.get("tool") or "(unnamed)"
        t = by.setdefault(tool, {"tool": tool, "calls": 0, "denied": 0, "last": None})
        t["calls"] += 1
        if r.get("decision") == "deny":
            t["denied"] += 1
        ts = r.get("ts")
        if isinstance(ts, str):
            t["last"] = max(t["last"], ts) if t["last"] else ts
    out = sorted(by.values(), key=lambda t: (-t["denied"], -t["calls"], t["tool"]))
    return out[:limit], max(0, len(out) - limit)


def pair_calls(rows: list[dict], agent: str, server: str, tool: str,
               limit: int = 8) -> tuple[list[dict], int]:
    """The individual rulings for one agent+server+tool, newest first. Returns (shown, hidden).

    This is where the tree stops counting and starts explaining: each row is a decision with the
    basis it rested on and, for a refusal, the reason the engine gave. A count of "2 blocked" is
    the claim; these are what backs it.
    """
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        if (r.get("adapter") or "?") != agent or r.get("server") != server:
            continue
        if (r.get("tool") or "(unnamed)") != tool:
            continue
        decision = r.get("decision") or "?"
        why = r.get("reason")
        if not why and decision == "deny":
            # The spool does not always carry the text — the same reconstruction `activity_rows`
            # uses. A refusal drawn without its reason is the bare counter this panel's own
            # interaction contract forbids.
            try:
                from . import decision as _dec
                why = _dec.deny_reason(str(server), str(tool))
            except Exception:                          # noqa: BLE001 - a drawing must still draw
                why = None
        out.append({"ts": r.get("ts"), "decision": decision,
                    "basis": r.get("basis") or "", "reason": why or "",
                    "adapter": r.get("adapter") or ""})
    # `read` already hands rows newest-first; sorting on the stamp keeps that true if it stops.
    out.sort(key=lambda r: r["ts"] or "", reverse=True)
    return out[:limit], max(0, len(out) - limit)


def _surface_nodes(server: str, surfaces: dict | None, surfurl, x: int, y: int, w: int,
                   sx: int, sw: int, sy: int, pitch: int) -> tuple[list[str], int]:
    """THE SIBLING BRANCH. Findings, decisions and evidence hang off the SERVER, not off a tool,
    so they are drawn beside the tool list rather than as a fifth column (founder's tree,
    27 Aug; re-verified open 3 Sep). One node per surface that has something, each a link into
    the drill-through that already exists — nothing new is computed here, and a server with
    nothing on any surface draws nothing, so absence stays absence."""
    surf = (surfaces or {}).get(server) or {}
    out: list[str] = []
    cy = y
    items: list[tuple[str, list[str], str, bool]] = []
    if surf.get("findings"):
        n = surf["findings"]
        items.append((f'{n} finding{"" if n == 1 else "s"}',
                      ["verification caught it", "open the Findings tab"],
                      surfurl("findings"), True))
    if surf.get("decisions"):
        n = surf["decisions"]
        items.append((f'{n} decision{"" if n == 1 else "s"} waiting',
                      ["changed since you approved it", "open the Decisions tab"],
                      surfurl("decisions"), False))
    if surf.get("evidence"):
        items.append(("evidence", ["the verify run behind these numbers", "open the Evidence tab"],
                      surfurl("evidence"), False))
    for title, meta, href, alarm in items:
        out.append(_elbow(sx + sw, sy + _TW["h"] // 2, x, cy + _TW["h"] // 2))
        out.append(_tnode(x, cy, w, title, meta, href, alarm=alarm,
                          aria=f'{server}: {title} — {meta[1]}'))
        cy += pitch
    return out, cy


def render_fleet_tree(tree: list[dict], rowurl, window: int, expanded: str | None = None,
                      agurl=None, open_server: str | None = None, srvurl=None,
                      rows: list[dict] | None = None, open_tool: str | None = None,
                      toolurl=None, surfaces: dict | None = None, surfurl=None) -> str:
    """The fleet drawn as a tree: agents, the servers each can reach, and that pair's tools.

    [FOUNDER 2026-08-26] "when i say it to be a branch in a tree i meant like this" — a drawn
    node-link diagram, not a nested list. Two levels open at once now: agent -> server -> tool,
    each opening to the RIGHT of its parent.

    Server-rendered inline SVG, and that is a constraint doing real work rather than a preference.
    The panel serves under a CSP that forbids inline script, so there is no client-side layout
    step: every coordinate is computed here, each node is an `<a>`, and opening a branch is a GET
    that re-renders the drawing. Colour comes from the panel's own tokens through `var(--…)`, so
    the tree restyles with everything else and introduces no palette of its own.
    """
    if not tree:
        return ('<p class="ddh">No agent has an MCP server configured, and no call has been '
                'recorded yet. This fills in as soon as one does.</p>')

    agurl = agurl or (lambda a: "/")
    srvurl = srvurl or (lambda a, sv: "/")
    toolurl = toolurl or (lambda a, sv, tl: "/")
    surfurl = surfurl or (lambda kind: "/")
    rows = rows or []
    names = [n["agent"] for n in tree]
    open_agent = expanded if expanded in names else names[0]

    pad, pitch, gap = _TW["pad"], _TW["pitch"], _TW["gap"]
    ax, aw = pad, _TW["agent_w"]
    sx, sw = pad + aw + gap, _TW["srv_w"]
    tx, tw = sx + sw + gap, _TW["tool_w"]
    cx, cw = tx + tw + gap, _TW["call_w"]
    parts, notes, y = [], [], pad
    widest = sx + sw

    for node in tree:
        is_open = node["agent"] == open_agent
        ay = y
        # Line one is the shape of the fleet, line two is what asks for a decision.
        reach = [f'{len(node["servers"])} server{"" if len(node["servers"]) == 1 else "s"}']
        if node["calls"]:
            reach.append(f'{node["calls"]} calls')
        asks = []
        if node.get("awaiting_signin"):
            asks.append(f'{node["awaiting_signin"]} awaiting sign-in')
        if node["denied"]:
            asks.append(f'{node["denied"]} blocked')
        bits = reach + asks
        # Closing is as reachable as opening: the link toggles rather than only ever descending.
        parts.append(_tnode(ax, ay, aw, node["label"], [" · ".join(reach), " · ".join(asks)],
                            agurl("" if is_open else node["agent"]),
                            accent=is_open, alarm=bool(node["denied"]),
                            aria=(f'{node["label"]}, {" · ".join(bits)}'
                                  + (f' — {node["note"]}' if node.get("note") else "")
                                  + f' — {"close" if is_open else "open"} this agent')))
        if node.get("note"):
            notes.append((node["label"], node["note"]))
        if not is_open:
            y = ay + pitch
            continue

        cursor = ay
        for pair in node["servers"]:
            sy = cursor
            if pair["needs_signin"]:
                state = "needs sign-in"
            elif pair["declared"] and pair["observed"]:
                state = ""
            elif pair["declared"]:
                state = "configured, never used"
            else:
                state = "used, not in this config"
            nums = []
            if pair["calls"]:
                nums.append(f'{pair["calls"]} calls')
            if pair["denied"]:
                nums.append(f'{pair["denied"]} blocked')
            if pair["last"]:
                nums.append(_ago(pair["last"]))
            meta = [state, " · ".join(nums) or ("" if state else "no calls recorded")]
            srv_open = pair["server"] == open_server
            parts.append(_elbow(ax + aw, ay + _TW["h"] // 2, sx, sy + _TW["h"] // 2))
            parts.append(_tnode(
                sx, sy, sw, pair["server"], meta,
                srvurl(node["agent"], "" if srv_open else pair["server"]),
                accent=srv_open, alarm=bool(pair["denied"]),
                aria=(f'{pair["server"]}, {" · ".join(m for m in meta if m)} — '
                      f'{"close" if srv_open else "open"} the tools this agent called')))
            # TWO TARGETS ON ONE ROW, because they are two different questions. The box opens the
            # branch; this opens the server's own detail drawer. Making the box do both would have
            # cost the drawer its only route in from the fleet.
            parts.append(
                f'<a href="{_esc_attr(rowurl(pair["server"]))}" class="tdet">'
                f'<title>{_esc(pair["server"])} — open the server detail</title>'
                f'<text x="{sx + sw - 12}" y="{sy + 30}" text-anchor="end">detail ›</text></a>')

            if not srv_open:
                cursor = sy + pitch
                continue

            shown, hidden = pair_tools(rows, node["agent"], pair["server"])
            if not shown:
                parts.append(_elbow(sx + sw, sy + _TW["h"] // 2, tx, sy + _TW["h"] // 2))
                parts.append(_tnode(tx, sy, tw, "no calls recorded",
                                    ["this pair has made none in the window", ""],
                                    srvurl(node["agent"], ""),
                                    aria="no calls recorded for this pair in this window"))
                widest = max(widest, tx + tw)
                # The server's own surfaces are drawn even when this pair made no calls: a
                # finding is a fact about the server, not about this agent's traffic.
                snodes, send = _surface_nodes(pair["server"], surfaces, surfurl,
                                              tx, sy + pitch, tw, sx, sw, sy, pitch)
                parts.extend(snodes)
                cursor = max(sy + pitch, send)
                continue

            tcursor = sy
            for tool in shown:
                ty = tcursor
                tnums = [f'{tool["calls"]} calls']
                if tool["denied"]:
                    tnums.append(f'{tool["denied"]} blocked')
                tool_open = tool["tool"] == open_tool
                parts.append(_elbow(sx + sw, sy + _TW["h"] // 2, tx, ty + _TW["h"] // 2))
                parts.append(_tnode(
                    tx, ty, tw, tool["tool"],
                    [" · ".join(tnums), _ago(tool["last"]) if tool["last"] else ""],
                    toolurl(node["agent"], pair["server"], "" if tool_open else tool["tool"]),
                    accent=tool_open, alarm=bool(tool["denied"]),
                    aria=(f'{tool["tool"]}, {" · ".join(tnums)} — '
                          f'{"close" if tool_open else "open"} the individual rulings')))
                if not tool_open:
                    tcursor = ty + pitch
                    continue

                # LEVEL FOUR: where the tree stops counting and explains. "2 blocked" is the
                # claim; these rulings, each with the basis it rested on and the reason the engine
                # gave, are what backs it.
                calls, chid = pair_calls(rows, node["agent"], pair["server"], tool["tool"])
                for k, c in enumerate(calls):
                    cy = ty + k * pitch
                    # Basis joins the heading so BOTH meta lines belong to the reason — the
                    # reason is what this node exists to say, and it needs the room.
                    head = " · ".join(x for x in (c["decision"], _ago(c["ts"]), c["basis"]) if x)
                    why = c["reason"] or ("no reason recorded" if c["decision"] == "deny" else "")
                    parts.append(_elbow(tx + tw, ty + _TW["h"] // 2, cx, cy + _TW["h"] // 2))
                    parts.append(_tnode(cx, cy, cw, head,
                                        _wrap(why, int((cw - 24) / 6.6), 2) if why else ["", ""],
                                        rowurl(pair["server"]),
                                        alarm=c["decision"] == "deny",
                                        aria=(f'{c["decision"]} at {c["ts"]}, basis {c["basis"]}'
                                              + (f' — {why}' if why else ""))))
                widest = max(widest, cx + cw)
                if chid:
                    parts.append(_tnode(cx, ty + len(calls) * pitch, cw,
                                        f'+{chid} more ruling{"" if chid == 1 else "s"}',
                                        ["older than the eight shown", ""], rowurl(pair["server"]),
                                        aria=f'{chid} further rulings, not drawn'))
                tcursor = ty + max(1, len(calls) + (1 if chid else 0)) * pitch
            widest = max(widest, tx + tw)
            if hidden:
                # NO SILENT CAP. A list cut at ten reads as the complete set, and this view's
                # whole claim is that it shows what an agent can reach.
                parts.append(_tnode(tx, tcursor, tw, f'+{hidden} more tool{"" if hidden == 1 else "s"}',
                                    ["quieter than the ten shown", ""], rowurl(pair["server"]),
                                    aria=f'{hidden} further tools, not drawn — open the server'))
                tcursor += pitch
            snodes, tcursor = _surface_nodes(pair["server"], surfaces, surfurl,
                                             tx, tcursor, tw, sx, sw, sy, pitch)
            parts.extend(snodes)
            cursor = max(sy + pitch, tcursor)
        y = max(ay + pitch, cursor)

    height = y + pad
    width = widest + pad
    svg = (f'<svg class="ftree" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
           f'role="group" aria-label="agents, the MCP servers each can reach, and the tools called" '
           f'xmlns="http://www.w3.org/2000/svg">{"".join(parts)}</svg>')
    # THE NOTES MUST REACH THE SCREEN, not just the data. Moving from a list to a drawing dropped
    # them silently — the legacy node stopped saying why it is separate and the gateway bucket
    # stopped saying it carries no agent identity — because the tests asserted the note on the
    # node dict and nothing asserted it was rendered. A node that is set apart without its reason
    # is exactly the unexplained number this view exists to avoid.
    foot = ("".join(f'<p class="tfoot"><b>{_esc(label)}</b> — {_esc(text)}</p>'
                    for label, text in notes))
    basis = (f'<p class="ddh tbasis">Calls and blocks counted over the last {window} recorded '
             f'call(s). "Configured" is read from each agent\'s own config; "used" means a call '
             f'was actually recorded for that pair. Select an agent, then a server, to open its '
             f'branch; "detail ›" opens the server itself.</p>')
    return f'<div class="ftwrap">{svg}</div>{foot}{basis}'


def sessions_summary(rows: list[dict]) -> list[dict]:
    """One row per agent session, newest first — the session record an operator reviews.

    Calls with no session identity are grouped under a visible "(no identity)" row rather than
    dropped: those are exactly the calls the sequence check cannot protect, and hiding them
    would render the gap invisible.
    """
    by: dict[str, dict] = {}
    for r in rows:
        if not isinstance(r, dict) or not r.get("server"):
            continue
        _sid = r.get("session")
        sid: str = _sid if isinstance(_sid, str) else "(no identity)"
        s = by.setdefault(sid, {"session": sid, "calls": 0, "denied": 0,
                                "servers": set(), "agents": {}, "first": None, "last": None})
        s["calls"] += 1
        if r.get("decision") == "deny":
            s["denied"] += 1
        s["servers"].add(r.get("server"))
        adapter = r.get("adapter") or "?"
        s["agents"][adapter] = s["agents"].get(adapter, 0) + 1
        ts = r.get("ts")
        if isinstance(ts, str):
            s["first"] = min(s["first"], ts) if s["first"] else ts
            s["last"] = max(s["last"], ts) if s["last"] else ts
    out = []
    for s in by.values():
        out.append({
            "session": s["session"],
            "agent": max(s["agents"], key=s["agents"].get) if s["agents"] else "?",
            "calls": s["calls"], "denied": s["denied"], "servers": len(s["servers"]),
            "first": s["first"], "last": s["last"],
        })
    out.sort(key=lambda s: s["last"] or "", reverse=True)
    return out


#: Hosts a launcher must reach to INSTALL the server. Contacting these is the package manager
#: doing its job, not the tool exfiltrating.
_LAUNCHER_HOSTS = ("registry.npmjs.org", "npmjs.org", "pypi.org", "files.pythonhosted.org",
                   "objects.githubusercontent.com")


def _identity_tokens(server: str, entry: dict | None) -> set[str]:
    """What this server is called, in every form we can derive WITHOUT the network.

    From the name (`Kite MCP Server` -> `kite`), and from the launch command/args, where a package
    name carries the vendor (`@circleci/mcp-server-circleci` -> `circleci`). Deliberately offline:
    a verifier that phones a registry to decide what is suspicious has its own egress problem.
    """
    noise = {"mcp", "server", "servers", "npx", "uvx", "-y", "run", "cli", "com", "www", "api",
             "app", "io", "dev", "ai", "get", "the"}
    words: set[str] = set()
    blob = server + " " + " ".join(str(x) for x in ([(entry or {}).get("command")]
                                                    + list((entry or {}).get("args") or [])))
    for w in re.split(r"[^A-Za-z0-9]+", blob.lower()):
        if len(w) >= 4 and w not in noise:
            words.add(w)
    return words


def _registrable(host: str) -> str:
    """`api-accessibility.browserstack.com` -> `browserstack`. Crude on purpose: no PSL, no network,
    and a wrong answer only ever costs us a finding shown that could have been folded away."""
    parts = [p for p in str(host).lower().split(".") if p]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def verify_runs_dir() -> Path:
    """Where each verify run archives its evidence (one directory per run)."""
    return behaviour_profile_path().parent / "verify-runs"


def observed_hosts_index(max_runs: int = 20) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """`{server: {tool: [{"host", "allowed"}]}}` from the verify evidence archive — every host each
    tool was OBSERVED contacting, including on attempts that found nothing (slice 7, 2026-09-05).
    Per server the NEWEST run that contains that server wins, not `dirs[-1]`: a single-server
    verify no longer speaks for the rest of the fleet. Bounded to the newest `max_runs` runs.
    Empty on any failure: absent evidence is stated by the caller, never invented here."""
    index: dict[str, dict[str, dict[str, bool]]] = {}
    runs = verify_runs_dir()
    try:
        dirs = sorted((p for p in runs.iterdir() if p.is_dir()), key=lambda p: p.name,
                      reverse=True)[:max_runs]
    except OSError:
        return {}
    for run in dirs:
        seen_here: dict[str, dict[str, dict[str, bool]]] = {}
        try:
            with (run / "audit.jsonl").open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    if ev.get("type") != "raw-observation":
                        continue
                    server, tool = str(ev.get("server")), str(ev.get("tool"))
                    hosts = seen_here.setdefault(server, {}).setdefault(tool, {})
                    for item in (ev.get("egress") or []):
                        if isinstance(item, dict):
                            host = item.get("hostname") or item.get("host")
                            allowed = bool(item.get("allowed"))
                        else:
                            host, allowed = str(item), False
                        if host:
                            hosts[str(host)] = hosts.get(str(host), False) or allowed
        except OSError:
            continue
        for server, tools in seen_here.items():
            if server not in index:            # newest run containing THIS server wins
                index[server] = tools
    return {s: {t: [{"host": h, "allowed": a} for h, a in sorted(hs.items())]
                for t, hs in sorted(tools.items())}
            for s, tools in index.items()}


def finding_timeline(server: str, tool: str, code: str = "") -> dict[str, Any]:
    """Every reproduction ATTEMPT behind one finding, newest run, in order.

    The engine emits one `raw-observation` per attempt — including the attempts that found
    nothing — precisely so a human can audit the verdict instead of trusting it. Until this view
    existed that stream was archived and never read: the page showed one summary line
    ("localhost · 3/3") and the reasoning behind it was invisible.

    Returns `{"found": bool, "why": str, "run": str, "attempts": [...]}`. `found=False` always
    carries a WHY — "no archive yet" and "this finding has no attempts" are different facts and a
    blank timeline must never be shown as if nothing happened.
    """
    out: dict[str, Any] = {"found": False, "why": "", "run": "", "attempts": []}
    runs = verify_runs_dir()
    try:
        dirs = sorted((p for p in runs.iterdir() if p.is_dir()), key=lambda p: p.name)
    except OSError:
        out["why"] = (f"no evidence archive yet ({runs}). Runs from before this version did not "
                      f"keep one — verify again and the full attempt trail will be here.")
        return out
    if not dirs:
        out["why"] = (f"no evidence archive yet ({runs}). Verify again and every attempt behind "
                      f"this finding will be recorded here.")
        return out
    newest = dirs[-1]
    out["run"] = newest.name
    audit = newest / "audit.jsonl"
    attempts: list[dict[str, Any]] = []
    try:
        with audit.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue        # one corrupt line must not blank the whole trail
                if ev.get("type") != "raw-observation":
                    continue
                if str(ev.get("server")) != server or str(ev.get("tool")) != tool:
                    continue
                if code and str(ev.get("code")) != code:
                    continue
                attempts.append(ev)
    except OSError as exc:
        out["why"] = f"the evidence archive for run {newest.name} could not be read: {exc}"
        return out
    if not attempts:
        out["why"] = (f"the newest run ({newest.name}) recorded no attempts for this tool — the "
                      f"finding is from an EARLIER run, so its own trail is not this one. "
                      f"Verify this server again to record a current trail.")
        return out
    out["found"] = True
    out["attempts"] = attempts
    return out


def _clip(text: str, limit: int = 160) -> str:
    """Cut long evidence at a WORD boundary with an ellipsis — never mid-word. The Findings table
    showed "then v1.0" and "then v1.0.16 exfiltrated —" as two different endings of one sentence
    (2026-09-03), which reads as two different facts."""
    text = str(text or "")
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:—-(")
    return cut + "…"


def _is_loopback_host(host: str) -> bool:
    """localhost, 127.0.0.0/8, ::1 — traffic that never left this machine."""
    import ipaddress
    h = str(host or "").strip().lower().split(":")[0] if not str(host).startswith("[") \
        else str(host)[1:].split("]")[0]
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def first_party(server: str, hosts: list[str], entry: dict | None) -> bool:
    """Is every host this tool contacted the server's OWN documented back end?

    THE REASON THIS EXISTS. On the founder's fleet, 42 of 42 findings were `undeclared-egress`:
    browserstack's 20 tools reaching `api.browserstack.com`, resend's 21 reaching `api.resend.com`.
    That is each server doing the one thing it exists to do. The engine's check is not broken — it
    convicts on any host outside `allowedHosts`, and `allowedHosts` is an mcpgawk config extension
    that no real MCP config carries, so in practice it degrades to "contacted anything at all".
    A detector that fires on 100% of normal traffic trains the user to ignore red.

    Conservative by construction: ANY host we cannot tie to the server's identity or to a package
    registry makes the whole finding NOT first-party. Exfiltration hides in the one unfamiliar host,
    not in the twenty familiar ones.
    """
    if not hosts:
        return False
    ident = _identity_tokens(server, entry)
    for h in hosts:
        if h in _LAUNCHER_HOSTS:
            continue
        reg = _registrable(h)
        if reg and any(reg in tok or tok in reg for tok in ident):
            continue
        return False
    return True


def journey_steps(d: dict[str, Any]) -> list[dict[str, Any]]:
    """The six stages of getting this machine under the gateway, each with its REAL state.

    Design decision (2026-08-01): the tabs stay grouped by function — the LiteLLM pattern, where
    the nav is objects you operate and the journey lives in a guided first run. This is that
    guided run, as data: one row per stage, `state` in done/now/todo, a fact line drawn from the
    machine (never a promise), and `where` naming the tab that carries the control.

    Rule 2 of the journey mockup: a stage you haven't reached is a STEP, not an empty room — so
    every stage is listed always, and an unreached one says what would make it real rather than
    rendering as a blank. The strip disappears only when every stage is done.
    """
    from . import history as _h

    entries = d.get("entries") or {}
    store = (d.get("store") or {}).get("servers") or {}
    ran = d.get("verified_runs") or {}
    calls = d.get("recent_calls") or []
    gw = d.get("gateway") or {}
    live = gw.get("live") or {}
    rows = _agent_rows(d)
    protected = sum(1 for _, _, st, _, _ in rows if st == "on")
    approved = sum(1 for k in store if _h.approved({"servers": store}, k))
    clients = sorted({c for e in entries.values() if isinstance(e, dict)
                      for c in (e.get("_clients") or [])})
    signins = signin_asks(entries)      # ONE source — the briefing strip reads the same list
    # An audit row whose principal is not the process-wide declared name is a call the gateway
    # attributed to a KEY — the end state this whole journey exists to reach.
    attributed = [p for p in (gw.get("by_principal") or [])
                  if p.get("principal") and p["principal"] != "(no identity asserted)"]

    steps: list[dict[str, Any]] = []
    steps.append({
        "key": "see", "title": "See the fleet",
        "state": "done" if entries else "now",
        "fact": (f"{len(entries)} server(s) found across {len(clients)} client(s)"
                 if entries else "no servers discovered yet"),
        "where": "Servers",
        "problems": d.get("discovery_problems") or []})
    cannot_n = len(d.get("unscannable") or [])
    # A capability that CANNOT be signed into is not a pending sign-in. Counting them together
    # would either overstate the work left or, worse, imply they are one click from covered.
    cannot_note = (f" · {cannot_n} capability(ies) cannot be signed into from here"
                   if cannot_n else "")
    steps.append({
        "key": "connect", "title": "Connect what needs signing in",
        "state": "now" if signins else "done",
        "fact": ((f"{len(signins)} server(s) need your browser sign-in before they will speak"
                  if signins else "nothing is waiting on a sign-in") + cannot_note),
        "where": "Servers"})
    steps.append({
        "key": "verify", "title": "Verify what they do",
        "state": "done" if ran else "now",
        # SAME UNIVERSE ON BOTH SIDES. `ran` is keyed by every name a verify run has ever
        # recorded — aliases, baseline-only entries, servers since removed — while `entries` is
        # what discovery sees NOW. Dividing one by the other rendered "25 of 11 server(s) watched
        # running" on the founder's machine (reproduced live 2026-08-14): a numerator larger than
        # its own denominator, on the step that represents the product's differentiator. Count
        # only servers that are BOTH currently present and have been watched.
        "fact": (f"{len([n for n in entries if n in ran])} of {len(entries)} server(s) "
                 f"watched running"
                 if entries else "verify runs a server and records what it actually does"),
        "where": "Evidence"})
    steps.append({
        "key": "protect", "title": "Protect the agents",
        "state": "done" if rows and protected == len(rows) else "now" if rows else "todo",
        "fact": (f"{protected} of {len(rows)} agent(s) have the pre-execution hook"
                 if rows else "no agent with a hook point found on this machine"),
        "where": "Agents"})
    steps.append({
        "key": "gateway", "title": "Put the gateway in the path",
        "state": "done" if live else "now",
        "fact": (f"running at {live.get('listen') or 'stdio'}" if live else
                 "no gateway running — one endpoint in front of the fleet is the point"),
        "where": "Gateway"})
    steps.append({
        "key": "keys", "title": "Give each agent its own key",
        "state": "done" if attributed else "todo" if not live else "now",
        "fact": (f"{len(attributed)} principal(s) have calls attributed to them"
                 if attributed else
                 "no call has been attributed to an agent key yet" if live else
                 "needs a running gateway with --principals"),
        "where": "Gateway"})
    # Approvals are the free-tier spine and belong in the fact line of 'see', not a stage of
    # their own — the founder's flow is fleet → trust → gateway, not a checklist of features.
    if approved:
        steps[0]["fact"] += f" · {approved} at an approved baseline"
    if calls:
        # SEEN, not "checked" — same defect as the Activity headline, second surface. `calls` here
        # is the raw recent-call list; whether the guard actually checked any of them is a
        # different question this line cannot answer, so it must not imply the answer.
        steps[3]["fact"] += f" · {len(calls)} recent call(s) seen"
    return steps


def next_best_action(d: dict[str, Any]) -> tuple[str, str]:
    """The ONE thing to do now, in priority order — and where it is.

    Every screen in this panel was a report: it stated facts and left the user to work out what they
    implied. The founder's recurring question all through 2026-07-30 was some form of "so what do I
    do with this?" A control surface answers that without being asked.

    Priority is by cost of being wrong: a server waiting on a decision is BLOCKED right now; findings
    are evidence already in hand; an unprotected agent is a gap; an unverified server is an unknown.
    Returns (text, tier) — tier drives the colour, so "nothing needs you" cannot look like an alarm.
    """
    pending = len(d.get("pending") or [])
    if pending:
        # NAME THE FILTER. "blocked right now" is true (the guard refuses a changed server), but
        # a user reading it reaches for the Blocked filter and finds nothing — those servers carry
        # the "Changed" tier. Saying both words is what closes the gap between the alarm and the
        # place the alarm's subject can be found.
        return (f"{pending} server(s) changed since you approved them — your agents cannot call "
                f"them right now. Open Decisions, or filter Servers by Changed.", "bad")
    findings = [f for f in (d.get("findings") or [])
                if not f.get("suppressed") and not f.get("first_party")]
    # Low-severity config findings (unpinned versions, install scripts) must not hijack the next
    # best action: unpinned is the ecosystem's README default, so on a fresh install this branch
    # would outrank real onboarding steps with an alarm about normality — the same tone rule the
    # fleet rows and the scan exit code already follow (configcheck.RISKY_KINDS, founder call
    # 2026-08-23). They stay in the count and the table; they just don't get to be "Next:".
    # Alarm unless EXPLICITLY low: a finding with no severity field (older verify reports) must
    # not be silently demoted — ambiguity never reads as safe (availability yes, ambiguity no).
    alarming = [f for f in findings if str(f.get("severity")).lower() != "low"]
    if alarming:
        servers = len({f.get("server") for f in alarming})
        return (f"{len(alarming)} finding(s) across {servers} server(s) — open Findings and decide "
                f"which are real.", "bad")
    # PRESENT on this machine, not the size of the constant. `no_hook` is a static table of agents
    # that HAVE no interception point (VS Code, Claude Desktop) — so `len()` of it is 2 on every
    # machine in the world, and the panel printed "2 agent(s) have no pre-execution hook" as its
    # next best action on a machine whose Agents tab said "No agents found". A number presented as
    # machine state has to come from the machine; this intersects the table with the clients
    # discovery actually saw. Eval Tier 4.
    seen_clients = {c for e in (d.get("entries") or {}).values() if isinstance(e, dict)
                    for c in (e.get("_clients") or [])}
    unprot = sorted(set(d.get("no_hook") or {}) & seen_clients)
    if unprot:
        return (f"{len(unprot)} agent(s) here have no pre-execution hook ({', '.join(unprot)}), so "
                f"their calls are not checked — open Agents.", "warn")
    entries = d.get("entries") or {}
    ran = d.get("verified_runs") or {}
    never = [n for n in entries if not (isinstance(ran.get(n), dict)
                                        and (ran[n].get("toolsChecked") or 0) > 0)]
    if never:
        return (f"{len(never)} server(s) have never been watched running. Absence of a finding is "
                f"not safety — verify one from its row.", "warn")
    return ("Nothing needs you right now.", "ok")


#: A result older than this is history, not news. The banner is the panel's only feedback channel,
#: so a stale one is actively misleading: the founder's real `last-action.json` held a "login ·
#: kite" result from three days earlier, still rendered as the current state of the machine.
_BANNER_MAX_AGE_S = 15 * 60


def _local_stamp(stamp: object) -> str:
    """An ISO timestamp as this machine's local `YYYY-MM-DD HH:MM:SS`; unreadable stamps come
    back trimmed as written. The Evidence page listed runs at `05:05:46` under a header that
    said the panel started at `10:37` (2026-09-03) — UTC and local, neither labelled."""
    from datetime import datetime, timezone
    s_ = str(stamp or "")
    try:
        dt = datetime.fromisoformat(s_.replace("Z", "+00:00"))
    except ValueError:
        return s_[:19]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _local_hms(stamp: object) -> str:
    """A spool timestamp (UTC, `Z`) as this machine's wall-clock HH:MM:SS. The call table showed
    05:07:57 under a header saying 10:37 (2026-09-03): UTC in one column, local in the other,
    neither labelled. Unreadable stamps come back as written."""
    from datetime import datetime, timezone
    s_ = str(stamp or "")
    try:
        dt = datetime.strptime(s_[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return s_[11:19]
    return dt.astimezone().strftime("%H:%M:%S")


def _ago(stamp: object) -> str:
    """"2m ago" for an ISO-8601 Z timestamp; "just now" under a minute; the raw value if unparseable
    (never an empty string — a result with no time is exactly what this is fixing)."""
    from datetime import datetime, timezone
    if not isinstance(stamp, str) or not stamp:
        return "at an unrecorded time"
    try:
        when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        # Gateway and session stamps carry offsets or no Z — same fact, other spellings.
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
        except ValueError:
            return stamp
    secs = max(0, int((datetime.now(timezone.utc) - when).total_seconds()))
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def _banner_is_stale(action: dict | None, max_age_s: int = _BANNER_MAX_AGE_S) -> bool:
    """True when a COMPLETED action is old enough that showing it would misrepresent now.

    Running actions are never stale — a long verify legitimately shows for minutes.
    """
    if not isinstance(action, dict) or action.get("running"):
        return False
    if action.get("signin_pending") and _signin_child_alive():
        return False                   # a person is mid sign-in; the link and the button must stay
    from datetime import datetime, timezone
    stamp = action.get("at")
    if not isinstance(stamp, str) or not stamp:
        # NOT stale: undated, which is a different thing. Suppressing it would DESTROY a result —
        # and losing a verdict is worse than showing an ambiguous one. `_ago` labels it "at an
        # unrecorded time" so the operator knows exactly what they are and are not being told.
        # (Caught by an existing test when the first version hid a real "rescanned" outcome.)
        return False
    try:
        when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - when).total_seconds() > max_age_s


def _activity_headline(summary: object) -> str:
    """seen / checked / DECLINED — never a single number labelled "checked".

    The panel rendered `summary["calls"]` (every call RECORDED) under the label "calls checked".
    On the founder's machine that read "860 calls checked" while the CLI, from the same spool,
    reported 41 checked and 832 declined — the guard had no baseline projection and let them
    through. A ~20x overstatement of protection, on the screen a beta tester screenshots.

    The honest numbers were already computed and sitting in the same dict (`checked`, `deferred` —
    spool.summarise), and `spool.py` even documents this exact defect in a comment. The panel
    simply read the wrong key. So this is not new measurement: it is the panel finally saying what
    the engine already knew.

    A declined call is styled as a WARNING and carries its remedy, because "we did not check this"
    must never be able to read as "this was fine" — the product's oldest rule.
    """
    if not isinstance(summary, dict):
        return "<b>—</b> calls seen"
    seen = summary.get("calls") or 0
    checked = summary.get("checked")
    deferred = summary.get("deferred") or 0
    if checked is None:
        # Written before the distinction existed: say so rather than infer a number.
        return (f"<b>{seen}</b> calls seen · <span class=\"warn\">how many were CHECKED is not "
                f"recorded in this log</span>")
    out = f"<b>{seen}</b> seen · <b>{checked}</b> checked against an approved baseline"
    if deferred:
        unsc = summary.get("deferred_unscannable") or 0
        scannable = max(deferred - unsc, 0)
        out += (f" · <span class=\"warn\"><b>{deferred}</b> NOT checked — the guard declined "
                f"(no or stale baseline) and let them through")
        if unsc:
            out += (f"; {unsc} of those went to a browser host no scan can baseline"
                    + (f", run a scan for the other {scannable}" if scannable else ""))
        else:
            out += "; run a scan"
        out += "</span>"
    return out


def _setup_flow_html(setup_text: str) -> str:
    """The guided sign-in, rendered for a HUMAN.

    The server's text is a prompt aimed at an AI client — "Display the public key below…",
    "present ALL of these steps…", "Once the user provides the API key, run 'configure_api_key'".
    Printing that at a person reads as noise ([FOUNDER] 2026-08-14: "there should be a simple and
    better way"). So: the key gets its own block with a Copy button, the machine-directed lines
    are dropped, the user-directed numbered steps survive verbatim, and the paste-form is the
    last step. If nothing parseable is found the raw text still renders — losing information is
    worse than losing polish.
    """
    import re as _re
    pem = _re.search(r"-----BEGIN [A-Z ]*KEY-----[\s\S]*?-----END [A-Z ]*KEY-----", setup_text)
    steps = []
    for line in setup_text.splitlines():
        line = line.strip()
        if not _re.match(r"^\d+\.", line):
            continue
        # machine-directed or replaced-by-UI steps are dropped, not rephrased
        lowered = line.lower()
        if any(m in lowered for m in ("copy the public key", "paste it back here",
                                      "run 'configure_api_key'", "run 'check_auth_status'",
                                      "paste the resulting", "copy the resulting api key")):
            continue
        steps.append(_re.sub(r"^\d+\.\s*", "", line, count=1).strip())
    if not pem:
        return (f'<div style="margin-top:8px;font-family:ui-monospace,monospace;'
                f'font-size:12px;word-break:break-all">'
                f'{_esc(setup_text).replace(chr(10), "<br>")}</div>')
    key_text = pem.group(0)
    steps_html = "".join(f"<li>{_esc(st)}</li>" for st in steps)
    return (
        f'<ol style="margin:10px 0 0 18px;padding:0">'
        f'<li>Copy your public key:'
        f'<div style="margin:6px 0;padding:8px;border:1px solid rgba(0,0,0,.12);'
        f'border-radius:6px;font-family:ui-monospace,monospace;font-size:11.5px;'
        f'word-break:break-all;background:rgba(255,255,255,.5)">{_esc(key_text).replace(chr(10), "<br>")}</div>'
        f'<button type="button" class="gbtn" data-copy="{_esc(key_text)}">Copy key</button></li>'
        f'{steps_html}'
        f'<li>Paste the API key you created:</li></ol>')


def _action_banner(action: dict | None, token: str = "", fresh: bool = False) -> str:
    """The last action's state, full-width under the card header. Shown to EVERYONE — status is
    not an action, and gating it behind the token hid "Running verify…" from the founder's own
    read-only view (2026-07-30)."""
    action = action or {}
    running = action.get("running")
    banner = ""
    if _banner_is_stale(action):
        return ""                      # old news is not feedback; the row pills carry the state
    if running:
        note = action.get("notice") or ""
        note_html = f'<br><b>{_esc(note)}</b>' if note else ""
        # THE LINK, IF THERE IS ONE. An OAuth sign-in cannot finish without a human opening a URL;
        # printing it into a pipe nobody reads is the same as not having the feature.
        link = action.get("login_url") or ""
        link_html = (f'<br><a class="gbtn" href="{_esc(link)}" target="_blank" '
                     f'rel="noopener noreferrer">Open the sign-in page</a>'
                     f'<div class="dim" style="margin-top:6px;word-break:break-all">{_esc(link)}</div>'
                     if link else "")
        # LIVE ELAPSED TIME is the tracer bullet for the progress work (2026-08-24): the first
        # thing a "is it hung?" reader needs is proof the clock is moving. It rides the existing
        # self-refresh, and later slices (per-server tick, cancel) extend this same banner.
        elapsed = _elapsed(action.get("at"))
        banner = (f'<div class="abanner run">Running {_esc(action.get("label"))}… '
                  f'<b>{_esc(elapsed)}</b> so far. A fleet verify runs each server in a sandbox, '
                  f'so this can take several minutes. This page updates itself.'
                  f'{note_html}{link_html}</div>')
    elif action.get("message"):
        # The RESULT, per server, on the page. A one-line "done" that points at a terminal is the
        # CLI-only habit this surface replaces: the user must be able to see WHICH server produced
        # nothing and what the engine said about it, here.
        rows = action.get("rows") or []
        detail = ""
        if rows:
            detail = ('<table class="arows"><tbody>' + "".join(
                f'<tr><td class="nm">{_esc(r.get("server"))}</td>'
                f'<td><span class="chip {_esc(r.get("level") or "bad")}">'
                f'{_esc(r.get("outcome"))}</span></td>'
                f'<td class="dim">{_esc(r.get("detail")).replace(chr(10), "<br>").replace(" ⏎ ", "<br>")}'
                f'{_fixblock(r)}</td></tr>'
                for r in rows) + "</tbody></table>")
        # THE BANNER TAKES THE WORST ROW'S COLOUR. It used to be green whenever the action
        # COMPLETED — so a run reporting 5 unverified servers and 21 convictions was styled as
        # success, and read as the opposite of what it found. Completing is not a good outcome;
        # finding nothing wrong is.
        worst = ("bad" if any(r.get("level") == "bad" for r in rows)
                 else "warn" if any(r.get("level") == "warn" for r in rows)
                 else (action.get("level") or "ok"))
        # SUBJECT and TIME, always. The banner used to render the bare message — a naked "done"
        # with no answer to "done WHAT, and WHEN", which then survived a panel restart and sat
        # there for days claiming an outcome. Both fields were already stored on the action; they
        # were simply never printed.
        subject = _esc(action.get("label") or "action")
        when = _esc(_ago(action.get("at")))
        setup_text = action.get("setup_text") or ""
        setup_key = action.get("setup_key") or ""
        setup_html = ""
        if setup_text:
            # Deliberately not scrubbed (a PUBLIC key is public by construction; the prose
            # redactor cannot tell it from a secret) but always HTML-escaped, and rendered for a
            # HUMAN — see _setup_flow_html.
            body_html = _setup_flow_html(setup_text)
            form_html = (f'<form method="POST" action="/" style="margin-top:8px">'
                         f'<input type="hidden" name="token" value="{_esc(token)}">'
                         f'<input type="hidden" name="act" value="login-configure"><input type="hidden" name="tab" value="n0">'
                         f'<input type="hidden" name="key" value="{_esc(setup_key)}">'
                         f'<input type="password" name="value" placeholder="paste the API key" '
                         f'style="min-width:280px" autocomplete="off" required> '
                         f'<button class="gbtn" type="submit">Configure &amp; verify</button>'
                         f'</form>' if token else
                         '<div class="dim">open the tokened URL from your terminal to finish</div>')
            setup_html = (f'<div style="margin-top:8px;font-family:ui-monospace,monospace;'
                          f'font-size:12px;word-break:break-all">{body_html}</div>{form_html}')
        done_link = action.get("login_url") or ""
        done_link_html = (f'<br><a class="gbtn" href="{_esc(done_link)}" target="_blank" '
                          f'rel="noopener noreferrer">Open the sign-in page</a>'
                          f'<div class="dim" style="margin-top:6px;word-break:break-all">'
                          f'{_esc(done_link)}</div>' if done_link else "")
        # An in-band sign-in (kite) is measured through the session the link belongs to, and
        # only a person knows when the browser said yes: this button is that "yes". Re-asking
        # the server's login tool would mint a NEW link each time (measured on kite, 2026-09-04),
        # so the panel never polls — it waits for the click, exactly as the CLI waits for Enter.
        _pending = action.get("signin_pending") or ""
        if _pending and token:
            done_link_html += (
                f'<form method="POST" action="/" style="margin-top:8px">'
                f'<input type="hidden" name="token" value="{_esc(token)}">'
                f'<input type="hidden" name="key" value="{_esc(_pending)}">'
                f'<input type="hidden" name="tab" value="n0">'
                f'<button class="act-btn" name="act" value="login-done">I have signed in — '
                f'measure {_esc(_pending)} now</button></form>')
        # ROUND 2 (founder-approved 24 Aug), FIXED 24 Aug evening: the popup opens ONCE — on the
        # load that immediately follows completion (`fresh`, from the POST redirect's done=1 or
        # the live-update fragment at the completion moment) — and NEVER re-opens on later loads,
        # where it renders as the slim collapsed record. The first version rendered `open` on
        # every load while the result was recent, and its full-viewport scrim sat over the page
        # swallowing every click — "none of the buttons are working" (founder). The popup also
        # carries NO scrim now: a result should be visible, not block the page.
        # A pending in-band sign-in keeps the record OPEN on every load: the person leaves for the
        # browser and comes back to a self-refreshed page, and the "I have signed in" button must
        # not be folded away behind the summary (advisor, 2026-09-04, before the founder's walk).
        _open = " open" if (fresh or action.get("signin_pending")) else ""
        banner = (f'<details{_open} class="amodal"><summary><b>{subject}</b> — finished {when}'
                  f'<span class="aclose"></span></summary>'
                  f'<div class="abanner done {_esc(worst)}" role="dialog">'
                  f'<b>{subject}</b> — finished {when}<br>'
                  f'{_esc(action.get("message"))}{setup_html}{done_link_html}{detail}</div></details>')
    return banner


def _action_buttons(token: str, action: dict | None, tab: str = "n0") -> str:
    """The buttons that make this a control surface, not a report: run a scan, verify the fleet.
    Pure POST forms (no script — the CSP forbids it), each carrying the session token so an agent
    that opens this page cannot press them. STATUS IS NOT AN ACTION: the token buys these buttons,
    never the banner — a viewer without it sees all state and zero controls."""
    if not token:
        return ""                                # read-only: the state, none of the controls
    dis = " disabled" if (action or {}).get("running") else ""
    tok = _esc(token)
    return f"""<form method="POST" action="/" style="display:inline">
  <input type="hidden" name="token" value="{tok}">
  <input type="hidden" name="tab" value="{tab}">
  <button class="act-btn" name="act" value="verify"{dis}>Verify fleet (run &amp; watch)</button>
</form>
<form method="POST" action="/" style="display:inline">
  <input type="hidden" name="token" value="{tok}">
  <input type="hidden" name="tab" value="{tab}">
  <button class="act-btn" name="act" value="scan"{dis}>Re-scan</button>
</form>"""


def _connect_card() -> str:
    """The one-paste enrolment moment (founder, 2026-08-07 — Natoma's Get Config, applied
    local-first): hand any MCP client mcpgawk's OWN read-only server as one copied block, so the
    agent can ask this machine's scanner before it trusts a server.

    HONESTY, per the design-integrity rule: this connects the agent to the scanner's ANSWERS.
    It enforces nothing — call-time blocking is the pre-execution hook (Protect) — and the card
    says so in its first breath. Static HTML, no token, no state: `mcpgawk-mcp` is a console
    script in every install, stdio, keyless, read-only by construction (mcp_server.py)."""
    return """
<div class="card"><div class="chead"><h1>Connect your agent</h1></div>
  <div class="note">One paste, like adding any MCP server: your agent gets two read-only tools
  (<code>scan_mcp_fleet</code>, <code>scan_mcp_server</code>) and can ask this machine's scanner
  before trusting a server. This does <b>not</b> block anything by itself — call-time blocking is
  the pre-execution hook (the Protect action above).</div>
  <div class="gwrap">
    <input type="radio" name="cfg" id="c0" checked aria-label="Claude Code config"><label class="gl" for="c0">Claude Code</label>
    <input type="radio" name="cfg" id="c1" aria-label="Claude Desktop config"><label class="gl" for="c1">Claude Desktop</label>
    <input type="radio" name="cfg" id="c2" aria-label="Cursor config"><label class="gl" for="c2">Cursor</label>
    <input type="radio" name="cfg" id="c3" aria-label="VS Code config"><label class="gl" for="c3">VS Code</label>
    <div class="cs" id="cs0"><div class="snip">claude mcp add mcpgawk -- mcpgawk-mcp</div>
      <div class="note">Run in any terminal. Remove later with <code>claude mcp remove mcpgawk</code>.</div></div>
    <div class="cs" id="cs1"><div class="snip">{ "mcpServers": { "mcpgawk": { "command": "mcpgawk-mcp" } } }</div>
      <div class="note">Merge into <code>~/Library/Application Support/Claude/claude_desktop_config.json</code>, then restart Claude Desktop.</div></div>
    <div class="cs" id="cs2"><div class="snip">{ "mcpServers": { "mcpgawk": { "command": "mcpgawk-mcp" } } }</div>
      <div class="note">Merge into <code>~/.cursor/mcp.json</code>.</div></div>
    <div class="cs" id="cs3"><div class="snip">{ "servers": { "mcpgawk": { "command": "mcpgawk-mcp" } } }</div>
      <div class="note">Merge into VS Code's <code>mcp.json</code> (Command Palette → "MCP: Open User Configuration").</div></div>
    <div class="note">Any other MCP client: the command is <code>mcpgawk-mcp</code> — stdio, no arguments, no key. It refuses to launch stdio servers unless the caller asks; scanning stays consent-gated.</div>
    <div class="ddh">Or let your agent set itself up — paste this prompt into it</div>
    <div class="snip">Add an MCP server named "mcpgawk" to your own configuration: command "mcpgawk-mcp", stdio transport, no arguments, no environment variables. Then call its scan_mcp_fleet tool and summarise which of my MCP servers are unverified or changed since approval.</div>
  </div>
</div>"""




_TAB_LABELS = (("n9", "Today"), ("n0", "Servers"), ("n1", "Agents"), ("n2", "Evidence"),
               ("n3", "Decisions"), ("n4", "Activity"), ("n5", "Trust"), ("n6", "Findings"),
               ("n7", "Gateway"), ("n8", "Monitor"))

#: One written line per module, rendered under its name in the rail. The nav used to offer ten
#: bare nouns with counts and no story (founder, 24 Aug); these lines make the rail read as
#: what exists → what needs you → what runs → the receipts. Keep each under ~9 words.
_TAB_BLURBS = {
    "n0": "every server your agents can reach, and its state",
    "n6": "what verification caught a server doing",
    "n4": "every call an agent made, and the guard’s decision",
    "n3": "servers that changed after you approved them",
    "n1": "which agents carry the pre‑execution hook",
    "n7": "one endpoint in front of the fleet, a key per agent",
    "n8": "watches running servers for drift between scans",
    "n2": "every artefact recorded, and where it lives on disk",
    "n5": "what this build is and what actually ran",
}


def _radio_tabs(tab: str) -> str:
    """The nav radios, with `checked` following the REQUESTED tab. The radio state is
    client-side only, so every full page load snapped back to Servers — a founder mid-review
    on Findings clicked "see every attempt" and landed on the first tab (2026-08-15). Links
    and forms carry `tab=`; unknown values fall back to Servers."""
    # Today (n9) is the landing view — the reimagined shell (founder-approved 25 Aug): the glance
    # first; the full instrument stays one click away under Detail.
    current = tab if tab in {t for t, _ in _TAB_LABELS} else "n9"
    return "\n".join(
        f'<input type="radio" name="nav" id="{t}"{" checked" if t == current else ""} '
        f'aria-label="{label} tab">' for t, label in _TAB_LABELS)

def monitor_gap_note(d: dict[str, Any]) -> str:
    """What the DRIFT surfaces cannot speak for, as one sentence, or "" when there is nothing.

    The Decisions queue and the blocked-calls table are both built from what THIS machine's scan
    history and guard log contain. Neither reads the monitor. On 2026-08-18 both rendered an
    all-clear while the monitor held SEVEN unaccepted alerts across four servers — one of which
    (`kite`) had stopped answering entirely, three of which the scanner has never even seen.

    The two stores cannot be joined: scan history keys look like `mcp:Kite MCP Server`, the
    monitor's like `kite`, and the overlap on this machine is EXACTLY ZERO. So this does not try to
    merge them — it names the gap and points at the surface that owns it. A count that cannot be
    reconciled is still worth more than a silent zero.

    Returns "" when the monitor was never installed or its DB is absent: "no monitor" is not
    "no alerts", and inventing a reassuring zero here is the bug this function exists to prevent.
    """
    # DEFENSIVE BY DESIGN. This function exists to stop a surface overstating safety; if it can
    # itself raise, it takes the page down and the user sees LESS than before. `d["monitor"]` is
    # whatever collect() managed to produce, including an error shape, so nothing here may assume
    # a type. Caught by test_panel_e2e when the first version assumed a dict (2026-08-18).
    mon = d.get("monitor") if isinstance(d, dict) else None
    if not isinstance(mon, dict) or not mon.get("db_present"):
        return ""
    rows = [r for r in (mon.get("servers") or []) if isinstance(r, dict)]
    hot = [r for r in rows if (r.get("open_alerts") or 0) > 0]
    if not hot:
        return ""
    total = sum(r.get("open_alerts") or 0 for r in hot)
    who = ", ".join(_esc(str(r.get("server_id"))) for r in hot[:6])
    return (f' Monitoring is separately holding <b>{total} unaccepted alert(s)</b> on {who} — '
            f'not covered here. See <b>Monitor</b>.')


#: The JSON face of `collect()` (ledger 108, step 1). AN ALLOW-LIST, NEVER A DUMP: `entries`
#: carry `headers` and `env` — credentials — and a `json.dumps(..., default=str)` over the raw
#: dict is exactly how a secret leaks through a repr. Every top-level key of `collect()` must be
#: named here or in `API_WITHHELD`; `tests/test_panel_api_state.py` fails the moment a new key is
#: added to `collect()` without a decision. Reading is open (the page and the exports are too);
#: the session token buys the buttons, not the state — do not "fix" that in the route.
API_SCHEMA = 1
API_ALLOWED = ("errors", "discovery_problems", "unscannable", "pending", "activity",
               "denied_servers", "hooks", "hook_health", "adapters", "no_hook", "runs",
               "observed", "verified_runs", "findings", "verify_at", "verify_blocked",
               "monitor", "gateway", "recent_calls", "verified")
#: Present in `collect()`, deliberately NOT in the API as-is: the two wide call windows are
#: thousands of rows (a consumer wants the agent→server tree, served as `tree` instead); `entries`
#: and `store` are PROJECTED below rather than copied.
API_WITHHELD = ("session_calls", "fleet_calls", "entries", "store")
#: Entry fields a consumer may see. `headers`/`env` become NAME lists; `_meta` (a plugin's icon
#: paths and tool titles) is dropped.
_API_ENTRY_FIELDS = ("url", "command", "args", "type", "_clients", "_names", "_aliases")


def _api_entry(entry: dict) -> dict:
    out = {k: entry.get(k) for k in _API_ENTRY_FIELDS if entry.get(k) is not None}
    headers = entry.get("headers")
    env = entry.get("env")
    out["header_names"] = sorted(str(k) for k in headers) if isinstance(headers, dict) else []
    out["env_names"] = sorted(str(k) for k in env) if isinstance(env, dict) else []
    return out


def _api_store(store: dict, d: dict | None = None) -> dict:
    """The approved surface per server: names, pin, when, tool NAMES. Never the raw record.

    With `d` (the whole `collect()` dict) each server also carries what a machine consumer needs to
    compose a confidence line without a second request: WHO approved and WHEN (absent is `null`,
    never the measurement time), the last sighting, the tier, whether a decision is pending, the
    calls seen, and the verify facts joined from the report by config name. `sandbox` says in
    words what the sandbox could and could not do — "not exercised (remote)" is a statement, not a
    gap to paper over."""
    from . import history as _history
    servers = {}
    entries = (d or {}).get("entries") or {}
    verified_by_name = (d or {}).get("verified") or {}
    hosts_index: dict = {}
    if d is not None:
        try:
            hosts_index = observed_hosts_index()
        except Exception:                          # noqa: BLE001 — evidence absent, not invented
            hosts_index = {}
    pending = set((d or {}).get("pending") or [])
    calls = (d or {}).get("fleet_calls") or (d or {}).get("recent_calls") or []
    for key, se in ((store or {}).get("servers") or {}).items():
        if not isinstance(se, dict):
            continue
        approved = se.get("approved") if isinstance(se.get("approved"), dict) else None
        hist = se.get("history") if isinstance(se.get("history"), list) else []
        last = hist[-1] if hist and isinstance(hist[-1], dict) else None
        def _surface(rec):
            if not rec:
                return None
            tools = rec.get("tools")
            names = sorted(tools) if isinstance(tools, dict) else \
                sorted(str(t.get("name")) for t in tools if isinstance(t, dict)) if isinstance(tools, list) else []
            return {"pin": rec.get("pin"), "measured_at": rec.get("measured_at"),
                    "login_id": rec.get("login_id"), "tools": names}
        row = {"aliases": list(se.get("aliases") or []),
               "approved": _surface(approved), "last": _surface(last),
               "history_len": len(hist), "retired": se.get("retired")}
        at, by = _history.approval_provenance(store or {}, str(key))
        if row["approved"] is not None:
            row["approved"]["at"] = at            # null for a baseline approved before the field
            row["approved"]["by"] = by
        row["seen_at"] = last.get("measured_at") if last else None
        row["seen_pin"] = last.get("pin") if last else None
        if d is not None:
            aliases = [str(a) for a in (se.get("aliases") or [])]
            # The hook records the name the agent CALLED: the config name for a configured server,
            # the bare identity (`fixture` for `mcp:fixture`) for one scanned from the CLI.
            bare = str(key).split(":", 1)[-1]
            names = [n for n in entries if n in aliases] or [bare]
            row["tier"] = _classify(names[0], str(key), d)
            row["pending"] = str(key) in pending
            seen_by = set(names) | set(aliases) | {str(key), bare}
            row["calls_seen"] = sum(1 for c in calls if isinstance(c, dict)
                                    and str(c.get("server")) in seen_by)
            ver = next((verified_by_name[n] for n in names if n in verified_by_name), None)
            row["verified"] = ver
            # What each tool was OBSERVED contacting, from the evidence archive; None when this
            # server was never in a run (a remote server: "not exercised" lives in `sandbox`).
            row["hosts_seen"] = next((hosts_index[n] for n in names if n in hosts_index), None)
            transport = ((approved or last or {}).get("transport")) or (ver or {}).get("transport")
            if ver and ver.get("backend"):
                row["sandbox"] = str(ver["backend"])
            elif transport in ("http", "sse"):
                row["sandbox"] = "not exercised (remote)"
            else:
                row["sandbox"] = "not verified"
        servers[str(key)] = row
    return {"servers": servers}


def _api_jsonable(v):
    if isinstance(v, dict):
        return {str(k): _api_jsonable(x) for k, x in v.items()}
    if isinstance(v, (set, frozenset)):
        return sorted(_api_jsonable(x) for x in v)
    if isinstance(v, (list, tuple)):
        return [_api_jsonable(x) for x in v]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(type(v).__name__)                   # never repr(): a repr is where secrets hide


def api_state(d: dict[str, Any]) -> dict[str, Any]:
    """`collect()` projected for a machine consumer. COST: `collect()` reads sqlite, a 5000-row
    spool and the verify runs — a consumer polls this on the daemon's cadence (minutes), never
    per second."""
    from datetime import datetime, timezone
    try:
        from . import __version__ as _ver
    except Exception:                              # noqa: BLE001
        _ver = "0+unknown"
    out: dict[str, Any] = {"schema": API_SCHEMA, "mcpgawk": _ver,
                           "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    for k in API_ALLOWED:
        if k in d:
            out[k] = _api_jsonable(d[k])
    out["entries"] = {str(n): _api_entry(e) for n, e in (d.get("entries") or {}).items()
                      if isinstance(e, dict)}
    out["store"] = _api_jsonable(_api_store(d.get("store") or {}, d))
    try:
        out["tree"] = _api_jsonable(agent_server_tree(d))
    except Exception as exc:                       # noqa: BLE001 — the rest of the state still ships
        out["tree"] = None
        out.setdefault("errors", {})["tree"] = f"{type(exc).__name__}: {exc}"
    return out


def render(d: dict[str, Any], token: str = "", action: dict | None = None,
           q: str = "", tier_filter: str = "", sel: str = "", tl: str = "", tab: str = "",
           ag: str = "", br: str = "", tc: str = "", stale_token: bool = False,
           fresh_action: bool = False) -> str:
    """The panel.

    Built against how LiteLLM, OpenRouter, Snyk and Stainless actually present this, not invented:
    a left sidebar of flat nouns; landing on the primary object (servers) rather than a vanity
    overview; metric cards that ARE the drill-down affordance; one `Group by` instead of many chart
    types; a fixed four-tier vocabulary used as the sort key; row detail inline rather than a new
    page; and a coverage bar with an explicit unverified segment.

    Deliberately absent, because they need scale or a second user to mean anything: tenant/org
    scope switchers, teams and seats, spend and budgets, MTTR and period-over-period deltas. A "+12%
    since last week" badge on three findings is not information.
    """
    from . import history as _h

    # NB there is deliberately no `entries` local any more. The row counter was its last consumer,
    # and it was the wrong source for it (see the note at the counter): discovery-only, while the
    # rows come from `classified`. Anything here that needs discovery should say `d["entries"]` at
    # the point of use, so it cannot quietly become the default answer to "how many servers".
    store = d.get("store") or {}
    servers = store.get("servers") or {}
    # The gateway pane reads this machine unless collect() already did — render(d) with a
    # synthetic d in tests must not require the key.
    global _D_FOR_ROLES
    _D_FOR_ROLES = {**d, "_token": token}
    # The silent read-only fallback for a WRONG key bit the founder four times in one night —
    # a present-but-stale key now announces itself as loudly as the dead-panel banner does.
    # Identical for every wrong key: it must teach nothing about the right one.
    stale_banner = ""
    if stale_token:
        stale_banner = ('<div class="stalekey">This link&#39;s session key is STALE — the '
                        'panel restarted after it was printed, so every button is hidden. '
                        'Use the fresh link from the terminal running '
                        '<code>mcpgawk panel</code>.</div>')
    # A walk of an outdated install must announce itself — same class of confusion as the
    # stale key, so it renders in the same place with the same weight.
    stale_banner += _staleness_note()
    gwpane = _gateway_pane(d.get("gateway") or gateway_status(), token, action)
    monpane = _monitor_pane(d.get("monitor") or {"installed": False, "db_present": False})
    # Seeded server-side so the log is never empty while it waits for its first live event —
    # a sweep is on a 300s cycle, and five minutes of blank "live" pane reads as broken.
    slog = _session_log_html(session_log_lines())
    pending = d.get("pending") or []
    act = d.get("activity") or {}
    calls = d.get("recent_calls") or []
    rows = _agent_rows(d)
    covered = sum(n for _, _, s, n, _ in rows if s == "on")
    uncovered = sum(n for _, _, s, n, _ in rows if s != "on")

    # --- the session record: one row per agent run, newest first -------------------------------
    # ONE folding rule, shared by sessions / activity / evidence / Trust: rows about servers
    # not in the current fleet (removed servers, and pytest/demo residue that leaked into real
    # stores before the write guards) fold into a labelled count. Rendering them unlabelled is
    # what read as "cooked up values" ([FOUNDER] 2026-08-15); dropping them silently would be
    # worse. The stores keep everything; the exports show everything.
    _fleet_names = set((d.get("entries") or {}).keys())
    for _se in ((d.get("store") or {}).get("servers") or {}).values():
        _fleet_names.update((_se or {}).get("aliases") or [])
    # A capability no scan can reach is still part of THIS machine's fleet: claude-in-chrome's
    # 1,323 live calls were folded as "removed servers and old test fixtures" (2026-09-03).
    _fleet_names.update(str(u.get("name")) for u in (d.get("unscannable") or [])
                        if isinstance(u, dict) and u.get("name"))

    sess_parts: list[str] = []
    _sess_calls = d.get("session_calls") or calls
    _in_fleet = [r for r in _sess_calls if isinstance(r, dict)
                 and r.get("server") in _fleet_names]
    _foreign_sessions = {r.get("session") for r in _sess_calls if isinstance(r, dict)} \
        - {r.get("session") for r in _in_fleet}
    _sess_calls = _in_fleet
    all_sessions = sessions_summary(_sess_calls)
    for s in all_sessions[:10]:
        sid = s["session"]
        shown = _esc(sid[:12] + ("…" if len(sid) > 12 else ""))
        denied = (f'<span class="chip bad">{s["denied"]}</span>' if s["denied"] else "0")
        # The bare time-of-day slice interleaved sessions from different DAYS as apparently
        # unsorted times ([FOUNDER] 2026-08-15: "the session information is not correct" — it
        # was sorted correctly and DISPLAYED wrongly). Relative age, full stamp on hover.
        last = (f'<span title="{_esc(str(s["last"]))}">{_esc(_ago(s["last"]) or "—")}</span>'
                if s["last"] else "—")
        # DRILL-DOWN, not a dead row ([FOUNDER] 2026-08-15: "show in the form of a drilldown
        # way"): the session's own calls open in place. <details> — works with JS disabled,
        # nothing for the CSP to allow.
        own = [r for r in _sess_calls
               if isinstance(r, dict) and r.get("session") == sid][-12:]
        drill_rows = "".join(
            f'<tr><td class="dim"><span title="{_esc(str(r.get("ts") or ""))}">'
            f'{_esc(_ago(str(r.get("ts") or "")))}</span></td>'
            f'<td>{_esc(str(r.get("decision") or "—"))}</td>'
            f'<td class="nm">{_esc(str(r.get("tool") or "—"))}</td>'
            f'<td class="dim">{_esc(str(r.get("server") or "—"))}</td></tr>'
            for r in reversed(own)) or \
            '<tr><td colspan="4" class="dim">no calls recorded for this session</td></tr>'
        drill = (f'<details class="sessdrill"><summary class="whysum">'
                 f'{len(own)} recent call(s)</summary>'
                 f'<table class="mini"><thead><tr><th>when</th><th>verdict</th><th>tool</th>'
                 f'<th>server</th></tr></thead><tbody>{drill_rows}</tbody></table></details>')
        sess_parts.append(
            f'<tr><td class="nm" title="{_esc(sid)}">{shown}<br>{drill}</td>'
            f'<td>{_esc(s["agent"])}</td>'
            f'<td class="num">{s["calls"]}</td><td class="num">{denied}</td>'
            f'<td class="num">{s["servers"]}</td><td class="dim">{last}</td></tr>')
    if len(all_sessions) > 10:
        sess_parts.append(f'<tr><td colspan="6" class="dim">…and {len(all_sessions) - 10} more '
                          f'session(s) — the full record is in the exports above.</td></tr>')
    if _foreign_sessions:
        sess_parts.append(
            f'<tr><td colspan="6" class="dim">{len(_foreign_sessions)} session(s) touched only '
            f'servers not in your current fleet (removed servers and old test fixtures) — '
            f'folded, kept in the exports.</td></tr>')
    sess = "".join(sess_parts) or \
        '<tr><td colspan="6" class="dim">Nothing recorded yet — use your agent once.</td></tr>'

    # --- classify every server once; the tier drives sort, counts and the coverage bar ---------
    classified = classified_servers(d)
    counts = {t: sum(1 for r in classified if r[3] == t) for t, _, _ in TIERS}
    total = max(len(classified), 1)

    # Metric cards were removed with the 2026-07-31 redesign: the approved mockup carries these
    # numbers in the pill rail counts and the filter-row count instead of a card strip.

    # --- coverage bar. The unverified segment is the point --------------------------------------
    segs = "".join(
        f'<span class="seg {t}" style="width:{counts[t] / total * 100:.1f}%" '
        f'title="{_esc_attr(label)}: {counts[t]}"></span>'
        for t, label, _ in TIERS if counts[t])
    # The tier DESCRIPTIONS existed since the TIERS table was written and were discarded by every
    # renderer (24 Aug audit) — they surface here as tooltips, so the legend explains itself.
    legend = "".join(
        f'<span class="lg" title="{_esc_attr(why)}"><i class="sw {t}"></i>'
        f'{_esc(label)} <b>{counts[t]}</b></span>'
        for t, label, why in TIERS)
    coverage = f'<div class="bar">{segs}</div><div class="legend">{legend}</div>'

    # --- servers (the landing view) -------------------------------------------------------------
    # The row follows the approved mockup's table grammar (LiteLLM's, per DESIGN.md): icon square +
    # bold name over grey mono id, transport as an outline tag, right-aligned numerics, and the
    # tier as a fully-rounded tinted tag in the shape of their Healthy / Degraded column.
    _tag = {"blocked": "bad", "findings": "bad", "changed": "warn",
            "unverified": "unv", "baseline": "ok"}
    _tlabel = {t: lbl for t, lbl, _ in TIERS}
    #: name -> how many tools this server DECLARES destructive; feeds the first-run story with a
    #: real number instead of an invented one.
    _destr: dict[str, int] = {}
    #: name -> (tools watched, tools total) for every measured server — the Coverage bars.
    _cov: dict[str, tuple[int, int]] = {}

    # ROW DETAIL IS A DRAWER, NOT AN INLINE EXPANSION (plate 4). The old <details> expansion
    # pushed every row below it down the page; with no JavaScript the drawer is a GET link
    # (?sel=<name>) and a re-render: the table collapses to three columns beside a fixed-width
    # aside and never reflows. Clicking the selected row again closes it.
    from urllib.parse import quote as _urlq

    def _rowurl(target: str | None) -> str:
        parts = ([f"t={_urlq(token)}"] if token else []) \
            + ([f"q={_urlq(q)}"] if q else []) \
            + ([f"tier={_urlq(tier_filter)}"] if tier_filter else []) \
            + ([f"sel={_urlq(target)}"] if target else []) + ["tab=n0"]
        return "/?" + "&".join(parts) if parts else "/"

    # THE FLEET ROOT IS THE PAIR, NOT THE SERVER. A server is not risky in itself; it is risky
    # because some agent can reach it, so the agent owns the node and its servers are the branch.
    _fleet_rows = d.get("fleet_calls") or d.get("session_calls") or []

    def _agurl(target: str) -> str:
        """Opening a branch is a GET, like every other drill-down on this page. The other query
        state rides along so opening an agent never silently drops a filter or a selection."""
        parts = ([f"t={_urlq(token)}"] if token else []) \
            + ([f"q={_urlq(q)}"] if q else []) \
            + ([f"tier={_urlq(tier_filter)}"] if tier_filter else []) \
            + ([f"sel={_urlq(sel)}"] if sel else []) \
            + ([f"ag={_urlq(target)}"] if target else []) + ["tab=n0"]
        return "/?" + "&".join(parts)

    def _srvurl(agent: str, target: str) -> str:
        """Opening a server's tools keeps its agent open — a branch that closed its own parent
        would make the second level unreachable in one click."""
        parts = ([f"t={_urlq(token)}"] if token else []) \
            + ([f"q={_urlq(q)}"] if q else []) \
            + ([f"tier={_urlq(tier_filter)}"] if tier_filter else []) \
            + ([f"sel={_urlq(sel)}"] if sel else []) \
            + ([f"ag={_urlq(agent)}"] if agent else []) \
            + ([f"br={_urlq(target)}"] if target else []) + ["tab=n0"]
        return "/?" + "&".join(parts)

    def _toolurl(agent: str, server: str, target: str) -> str:
        """Opening a tool's rulings keeps its agent AND its server open — every ancestor stays
        open, or the branch closes under the thing you just clicked."""
        parts = ([f"t={_urlq(token)}"] if token else []) \
            + ([f"q={_urlq(q)}"] if q else []) \
            + ([f"tier={_urlq(tier_filter)}"] if tier_filter else []) \
            + ([f"sel={_urlq(sel)}"] if sel else []) \
            + ([f"ag={_urlq(agent)}"] if agent else []) \
            + ([f"br={_urlq(server)}"] if server else []) \
            + ([f"tc={_urlq(target)}"] if target else []) + ["tab=n0"]
        return "/?" + "&".join(parts)

    # The server-scoped surfaces for the tree's sibling branch: counts the tabs already hold,
    # keyed by the server's display name — no new truth, only a route to the existing ones.
    _surfaces: dict[str, dict[str, int | bool]] = {}
    _pending_keys = set(d.get("pending") or [])
    for _n, _e, _k, _t in classified:
        _fn = sum(1 for f in (d.get("findings") or [])
                  if isinstance(f, dict) and f.get("server") == _n
                  and not f.get("first_party") and not f.get("suppressed"))
        _dn = 1 if (_k and _k in _pending_keys) else 0
        if _fn or _dn:
            _surfaces[_n] = {"findings": _fn, "decisions": _dn, "evidence": bool(_fn)}
    _surf_tab = {"findings": "n6", "decisions": "n3", "evidence": "n2"}

    def _surfurl(kind: str) -> str:
        return "/?" + "&".join(([f"t={_urlq(token)}"] if token else [])
                               + [f"tab={_surf_tab.get(kind, 'n0')}"])

    fleet_tree = render_fleet_tree(agent_server_tree(d), _rowurl, len(_fleet_rows),
                                   expanded=ag, agurl=_agurl, open_server=br, srvurl=_srvurl,
                                   rows=_fleet_rows, open_tool=tc, toolurl=_toolurl,
                                   surfaces=_surfaces, surfurl=_surfurl)

    sel_active = bool(sel) and any(n == sel for n, _, _, _ in classified)
    drawer = ""
    srows = []
    #: Baseline-only servers render grouped under ONE band that states their shared fact once,
    #: instead of repeating it in every row's cells (panel UX pass, 24 Aug).
    bo_rows: list[str] = []
    #: Servers whose ONLY blocker is a browser sign-in — the one ask a machine cannot do for the
    #: operator, so the briefing strip names them (founder, 24 Aug: "the only time it should ask
    #: me is when a server needs authentication").
    #: ONE SOURCE OF TRUTH with the Getting-set-up stepper (`journey_steps`): both read
    #: `signin_asks`. The strip used to collect this inside the row loop, AFTER the search
    #: filter's `continue` — so a search narrowed the operator's to-do count, and the stepper
    #: (reading the full fleet) said "1 pending" while the strip said "nothing" (25 Aug, 09-03).
    _auth_asks: list[str] = signin_asks(d.get("entries") or {})
    #: name -> measured tool count, so the sign-in card can say whether the server has been
    #: measured at all (kite: 22 tools signed out) or genuinely stays unmeasured (notion: 401).
    _tools_by_name: dict[str, int] = {}
    _ghosts = 0                      # remembered in the trust store, configured nowhere now
    for name, entry, key, tier in classified:
        detail = server_detail(store, key, calls) if key else None
        local = "local" if entry.get("command") else "remote"
        # A server present in the trust store but in nobody's config right now. It is shown (its
        # absence from this page was the defect) but must not be presented as something an agent
        # can currently call. THE FACT IS STATED ONCE, by the group band these rows render under —
        # it used to be printed per row in TWO cells on top of the Blocked pill (founder, 24 Aug:
        # one screen carried the same sentence nine times), so the cells go back to being data.
        _baseline_only = bool(entry.get("_baseline_only"))
        if _baseline_only:
            local = "—"
        clients = ", ".join(entry.get("_clients") or []) or "—"
        # Agent names never break mid-word ("claude-\ndesktop" — founder's 24 Aug layout report):
        # each name is its own no-wrap span, so the cell wraps BETWEEN names only.
        _agents_cell = (", ".join(f'<i class="ag">{_esc(c)}</i>'
                                  for c in (entry.get("_clients") or [])) or "—")
        seen = detail["calls_seen"] if detail else 0
        tools = len(detail["current_tools"]) if detail else "—"
        _tools_by_name[name] = tools if isinstance(tools, int) else 0
        _ghosts += 1 if entry.get("_baseline_only") else 0
        # THREE DIFFERENT FACTS WERE BEING SHOWN AS ONE NUMBER. `current_tools` is the latest
        # sighting, `approved_tools` is what the operator agreed to, and the verify line counts
        # against whatever that run saw — so one screen could read "baseline 44", "45" and
        # "20 of 44" and look simply wrong. It was not wrong; it was unlabelled. And the gap
        # between approved and now is DRIFT, which is the single thing this product exists to
        # notice — hiding it inside a bare count is the worst place to lose it.
        tools_approved = len(detail["approved_tools"]) if detail else 0
        drift_note = ""
        if detail and isinstance(tools, int) and tools_approved and tools != tools_approved:
            more = tools - tools_approved
            # A NUMERIC COLUMN CARRIES NUMBERS; the annotation gets its own non-breaking line
            # under the number. The old inline parenthetical ("(92 approved, 3 added since)")
            # wrapped across four lines inside the narrow tools column (founder, 24 Aug); the
            # full sentence survives in the tooltip.
            drift_note = (f'<span class="dt" title="{tools_approved} approved, '
                          f'{abs(more)} {"added" if more > 0 else "removed"} since">'
                          f'{"+" if more > 0 else "−"}{abs(more)} since approval</span>')
        checked = min(((d.get("verified_runs") or {}).get(name) or {}).get("toolsChecked") or 0,
                      tools if isinstance(tools, int) else 0)
        # Two row actions. `approve` is offered only when this server is actually waiting on a
        # decision — a button that is always present teaches the user to press it without reading.
        _acts = ""
        if token and entry.get("command"):
            _acts += ('<button class="act-sm" name="act" value="verify" title="Run this server '
                      'and watch what it contacts">verify</button>')
        if token and key and key in (d.get("pending") or []):
            _acts += ('<button class="act-sm warn" name="act" value="approve" title="Accept this '
                      'server\'s current surface as the trusted baseline">approve</button>')
        # Sign-in posts in its OWN form carrying the fleet NAME — run_login addresses by name,
        # while verify/approve share the store-key form below. Sharing one hidden key gave
        # figma's button the literal string "None" (its store key), a dead button that failed
        # with "no server named 'None'" when clicked.
        _login_form = ""
        if token and _login_button_applicable(entry, name):
            _login_form = (f'<form method="POST" action="/" class="rowact">'
                           f'<input type="hidden" name="token" value="{_esc(token)}">'
                           f'<input type="hidden" name="key" value="{_esc(name)}">'
            f'<input type="hidden" name="tab" value="n0">'
                           f'<button class="act-sm" name="act" value="login" title="Complete '
                           f'this server\'s browser sign-in now — a browser window opens on '
                           f'this machine and the token stays local">sign in</button></form>')
        _forms = (f'<form method="POST" action="/" class="rowact">'
                  f'<input type="hidden" name="token" value="{_esc(token)}">'
                  f'<input type="hidden" name="key" value="{_esc(name if entry.get("command") else key)}">'
                  f'<input type="hidden" name="tab" value="n0">'
                  f'{_acts}</form>' if _acts else "") + _login_form
        # ONE grid item per cell, always. Two sibling <form>s here became two grid items, so the
        # row's 7-column grid pushed the sign-in button onto a phantom second line below the row
        # (kite, founder's 24 Aug layout report). The wrapper makes the cell a single flex item.
        act_cell = f'<span class="actwrap">{_forms}</span>' if _forms else ""
        if detail:
            # NB `tool_lines`, not `tl` — `tl` is render's finding-timeline parameter, and reusing
            # the name here silently clobbered it: the trail link rendered but never opened.
            tool_lines = "".join(
                f'<tr><td class="nm">{_esc(t)}</td><td class="dim">{n} call(s)</td></tr>'
                for t, n in detail["calls_by_tool"][:8]) or \
                '<tr><td colspan="2" class="dim">no calls recorded for this server</td></tr>'
            dvo_rows = declared_vs_observed(detail, (d.get("observed") or {}).get(name))
            _destr[name] = sum(1 for r in dvo_rows if r["declared"] == "destructive")
            if not entry.get("_baseline_only"):
                # A record for a server no longer configured anywhere is HISTORY: its tools are
                # not "currently exposed", and counting them (18 of "271", 2026-09-03) inflates
                # the fleet the coverage bar claims to describe.
                _cov[name] = (checked, len(detail["current_tools"]))
            # SAY A SERVER-LEVEL FACT ONCE, AT THE SERVER. When NOTHING on this server was
            # observed, every row used to repeat "not observed — absence is not a claim of safety".
            # On kite that is 22 identical sentences, which reads as filler and buries the fact
            # that actually matters: this server was never observed AT ALL, and (for a browser-auth
            # server) never can be here. The founder pointed at the wall of repeats twice.
            none_observed = bool(dvo_rows) and not any(r["observed"] for r in dvo_rows)
            unobservable = none_observed and _auth_shaped(entry)
            if unobservable:
                why = ("Nothing here was observed, and cannot be: this server signs in through a "
                       "browser (mcp-remote) before it lists tools, and a verify run has no browser. "
                       "Every row below is DECLARED only — the server's own word, unchecked.")
            elif none_observed:
                why = ("Nothing here was observed — no behaviour was recorded for this server, so "
                       "every row below is DECLARED only: the server's own word, unchecked. "
                       "Absence of observation is not a claim of safety.")
            else:
                why = ""
            dvo_parts = []
            for r in dvo_rows:
                base = {"approved": "ok", "added": "warn", "gone": "bad"}[r["baseline"]]
                if r["observed"]:
                    obs_cell = f'<span class="chip warn">{_esc(r["observed"])}</span>'
                elif r["baseline"] == "gone":
                    obs_cell = '<span class="dim">—</span>'
                elif none_observed:
                    obs_cell = '<span class="dim">—</span>'   # stated once above, not 22 times
                else:
                    # The absence-is-not-safety clause is stated ONCE per drawer (the `why` line
                    # and the table heading carry it) — not appended to every unobserved row.
                    obs_cell = '<span class="dim">not observed</span>'
                dvo_parts.append(
                    f'<tr><td class="nm">{_esc(r["tool"])}</td>'
                    f'<td><span class="chip {base}">{r["baseline"]}</span></td>'
                    f'<td class="dim">{_esc(r["declared"])}</td><td>{obs_cell}</td></tr>')
            dvo = "".join(dvo_parts) or \
                '<tr><td colspan="4" class="dim">no measured surface yet — run mcpgawk</td></tr>'
            if name == sel:
                backend = ((d.get("verified_runs") or {}).get(name) or {}).get("backend")
                never = len(detail["current_tools"]) - checked
                callout = (f'<div class="unobs">{never} tool(s) were never invoked — their rows '
                           'below are declared only.</div>'
                           if checked and never > 0 else '')
                _dw = [w for w in re.split(r"[^0-9A-Za-z]+", name) if w]
                _dmark = ((_dw[0][0] + (_dw[1][0] if len(_dw) > 1 else (_dw[0][1:2] or "")))
                          .upper() if _dw else "?")
                _cost = detail['cost_index']
                drawer = f"""<aside class="side">
  <header class="mhead">
    <span class="mmark {_tag[tier]}">{_esc(_dmark)}</span>
    <div class="mtitle"><h3>{_esc(name)}</h3>
      <span class="id">{_esc(key if key else "mcp:" + name)}</span></div>
    <span class="chip {_tag[tier]}"><i></i>{_esc(_tlabel[tier])}</span>
    <a class="mclose" href="{_rowurl(None)}" aria-label="Close" title="Close">&times;</a>
  </header>
  {f'<div class="mactions">{act_cell}</div>' if act_cell else ''}
  <div class="mbody">
  <div class="statgrid">
    <div class="stat"><span class="sl">Transport</span><span class="sv">{_esc(detail['transport'] or local)}</span></div>
    <div class="stat"><span class="sl">Protocol</span><span class="sv">{_esc(detail['protocol'] or '—')}</span></div>
    <div class="stat"><span class="sl">Tools now</span><span class="sv">{len(detail['current_tools'])}</span></div>
    <div class="stat"><span class="sl">Approved</span><span class="sv">{len(detail['approved_tools'])}</span></div>
    <div class="stat"><span class="sl">Watched</span><span class="sv">{checked}</span></div>
    <div class="stat"><span class="sl">Isolation</span><span class="sv">{_esc(backend or 'none')}</span></div>
    <div class="stat"><span class="sl">Context cost</span><span class="sv">{_cost:,} tok</span></div>
    <div class="stat"><span class="sl">Snapshots</span><span class="sv">{detail['snapshots']}</span></div>
    <div class="stat"><span class="sl">Measured</span><span class="sv">{_esc(detail['measured_at'][:10] or '—')}</span></div>
    <div class="stat"><span class="sl">Also known as</span><span class="sv">{_esc(', '.join(detail['aliases']) or '—')}</span></div>
  </div>
  {callout}
  <div class="ddh">what the guard has seen</div>
  <div class="tscroll"><table class="mini"><tbody>{tool_lines}</tbody></table></div>
  <div class="ddh">declared vs observed · verdicts rest on observation, not names</div>
  {f'<div class="unobs">{_esc(why)}</div>' if why else ''}
  <div class="tscroll"><table class="mini"><thead><tr><th>tool</th><th>baseline</th><th>declared</th>
  <th>observed</th></tr></thead><tbody>{dvo}</tbody></table></div>
  </div>
</aside>"""
        elif name == sel:
            # Selected but never measured: the drawer states that instead of pretending detail.
            _dw = [w for w in re.split(r"[^0-9A-Za-z]+", name) if w]
            _dmark = ((_dw[0][0] + (_dw[1][0] if len(_dw) > 1 else (_dw[0][1:2] or "")))
                      .upper() if _dw else "?")
            drawer = f"""<aside class="side">
  <header class="mhead">
    <span class="mmark {_tag[tier]}">{_esc(_dmark)}</span>
    <div class="mtitle"><h3>{_esc(name)}</h3><span class="id">mcp:{_esc(name)}</span></div>
    <span class="chip {_tag[tier]}"><i></i>{_esc(_tlabel[tier])}</span>
    <a class="mclose" href="{_rowurl(None)}" aria-label="Close" title="Close">&times;</a>
  </header>
  {f'<div class="mactions">{act_cell}</div>' if act_cell else ''}
  <div class="mbody">
  <div class="unobs">Never measured — nothing is recorded for this server yet. Re-scan records
    its declared surface; verify watches it run.</div>
  </div>
</aside>"""
        # SERVER-SIDE FILTERING. The CSP here is `default-src 'none'` — no script — so a filter is a
        # GET form and a re-render, not a client-side hide. Eleven rows fit on a screen; forty do
        # not, and "scroll and squint" is the friction this removes.
        # `signin` is not a tier — it cuts ACROSS them, which is the whole reason the ask was
        # wrong before: a server waiting on a person can sit in any tier. The briefing strip links
        # here, so the control lands on exactly the servers it just counted instead of on a tier
        # list that does not contain them.
        if tier_filter == "signin":
            if not _login_button_applicable(entry, name):
                continue
        elif tier_filter and tier != tier_filter:
            continue
        # Search the names each CLIENT uses too, not only the display name. One server can be
        # configured under a different name in every tool, so a reader typing the name their own
        # config shows them found NOTHING for a server sitting on the page under another name —
        # the same defect already fixed for `--only` and the terminal fleet view.
        aliases = " ".join((entry.get("_names") or {}).values()) + " " + \
                  " ".join(entry.get("_aliases") or [])
        if q and q.lower() not in f"{name} {key or ''} {clients} {aliases}".lower():
            continue
        words = [w for w in re.split(r"[^0-9A-Za-z]+", name) if w]
        mark = ((words[0][0] + (words[1][0] if len(words) > 1 else (words[0][1:2] or ""))).upper()
                if words else "?")
        _is_sel = sel_active and name == sel
        who = f"""<a class="who" href="{_rowurl(None if _is_sel else name)}">
    <span class="mark">{_esc(mark)}</span><span>
    <span class="nm">{_esc(name)}</span>
    <span class="id">{_esc(key if key else "mcp:" + name)}</span></span></a>"""
        # The state names the missing VERB where one is known: a server whose only blocker is
        # authentication says "Needs sign-in" instead of a generic "Unverified", so the row's
        # state and the row's action always agree (panel UX pass, founder-approved 24 Aug).
        _row_tag, _row_lbl = _tag[tier], _tlabel[tier]
        # THE ROW'S LABEL AND THE OPERATOR'S TO-DO LIST ARE TWO DIFFERENT QUESTIONS, and tying
        # them together is what made the headline lie. Relabelling only makes sense where the tier
        # would otherwise say "Unverified" — a server with findings must keep saying Findings. But
        # the ASK does not belong to a tier: a server waiting on a sign-in is waiting whatever
        # else is true of it. Gating the ask on `tier == "unverified"` meant kite (findings),
        # notion and Revolut X (baseline) all needed a person while the strip said "Needs you:
        # nothing" directly above the list that showed them. Measured on the founder's fleet
        # 2026-08-27. The ask is now collected for every server; only the label is conditional.
        if name in _auth_asks:
            if tier == "unverified":
                _row_tag, _row_lbl = "warn", "Needs sign-in"
        state_tag = (f'<span><span class="chip {_row_tag}"><i></i>'
                     f'{_esc(_row_lbl)}</span></span>')
        # ROWS KEEP ONE SHAPE. The old split view reshaped every row to three columns whenever a
        # server was selected — the whole table reflowed under the reader. Detail is a MODAL now
        # (round 2, founder-approved): the table never moves; the selected row just highlights.
        if True:
            # "45 / 20 watched" read as forty-five-of-twenty ([FOUNDER] 2026-08-15: "45 of 20
            # what is this ???"). The fraction goes smaller-first, labelled, in brackets.
            watched_s = (f'<span class="wt" title="{checked} of {tools} tools watched by a '
                         f'verify run">{checked}/{tools} watched</span>'
                         if checked and isinstance(tools, int) and checked < tools else '')
            (bo_rows if _baseline_only else srows).append(f"""<div class="row{' sel' if _is_sel else ''}">
  {who}
  <span><span class="chip mode">{local}</span></span>
  <span class="dim cl-agents">{_agents_cell}</span>
  <span class="n cl-num"><b>{tools}</b>{drift_note}{watched_s}</span>
  <span class="n cl-num"><b>{seen}</b></span>
  {state_tag}
  {act_cell or '<span></span>'}
</div>""")

    _shown = len(srows) + len(bo_rows)             # the filter count counts ROWS, never the band
    _band = (f'<div class="grpband">Approved but in no agent’s config ({len(bo_rows)}) '
             f'— nothing can call these right now</div>' if bo_rows else '')
    _rows_html = ("".join(srows) + _band + "".join(bo_rows)) or (
        '<div class="note" style="margin-top:13px">Nothing matches. '
        f'<a href="/?t={_esc(token)}">Clear the filter.</a></div>')
    servers_table = (
        '<div class="thead"><span>server</span><span>transport</span>'
        '<span class="cl-agents">agents</span><span class="n cl-num">tools</span>'
        '<span class="n cl-num">calls</span><span>state</span>'
        # The column head appears only when the controls do (token present): a header naming
        # actions over a tokenless read-only view would promise controls the page refuses.
        + ('<span>actions</span>' if token else '<span></span>') + '</div>'
        + _rows_html)
    if sel_active:
        # ROUND 2 (founder-approved 24 Aug): detail is a centred modal over the dimmed, unmoved
        # table — not a side drawer that reflowed everything. The scrim is a LINK (no script
        # needed to close); Esc closes via panel.js; small screens get a bottom sheet (CSS).
        servers_table += (
            f'<a class="scrim" href="{_rowurl(None)}" aria-label="Close server detail"></a>'
            f'<div class="modal" role="dialog" aria-modal="true">{drawer}</div>')

    # --- Coverage: the mockup's Spend-by-Team bars, measuring watched tools instead of money ----
    # One bar per MEASURED server; the number that matters is the gap. Servers never measured are
    # counted in words, not silently absent — absence from this list must not read as coverage.
    _watched_sum = sum(c for c, _ in _cov.values())
    _tools_sum = sum(t for _, t in _cov.values())
    _unmeasured = len(classified) - _ghosts - len(_cov)   # ghosts are not 'never measured'
    cov_bars = "".join(
        f'<div class="cbar"><span class="lb">{_esc(n)}</span>'
        f'<div class="track"><div class="fill" style="width:{(c / t * 100) if t else 0:.0f}%">'
        f'</div></div><span class="vl">{c} / {t}</span></div>'
        for n, (c, t) in sorted(_cov.items(), key=lambda kv: (kv[1][0] - kv[1][1], kv[0]))) or \
        ('<div class="unobs">No server has been measured yet — nothing to draw a bar from. '
         'An empty chart here is not coverage.</div>')
    cov_count = (f'<b>{_watched_sum}</b> of {_tools_sum} tools <i>currently exposed</i> watched'
                 + (f' · {_unmeasured} server(s) never measured' if _unmeasured else ''))

    # --- THE BRIEFING STRIP (founder, 24 Aug): the first line of the Servers card answers
    # "where does my fleet sit on the radar, and what actually needs ME" — and the only things
    # that ever need the operator are a browser sign-in and a trust decision. Verification is
    # the machine's job; the chips are the radar, worst tier first, each a filter link.
    def _tierurl(t: str) -> str:
        return ("/?" + "&".join(([f"t={_urlq(token)}"] if token else [])
                                + [f"tier={_urlq(t)}", "tab=n0"]))
    _radar = "".join(
        f'<a class="chip {_tag[t]} bchip" href="{_tierurl(t)}"><i></i>{counts[t]} {_esc(lbl)}</a>'
        for t, lbl, _why in TIERS if counts[t])
    # THE CHANGE WINDOW ("Changes (7d)"): how many servers first moved off their approved pin
    # this week — the fleet's change rate, from sightings already in the store. Distinct from
    # the Changed tier, which is what is STILL pending; a server changed and approved on
    # Tuesday counts here and not there.
    from .history import changed_within as _changed_within
    _moved_7d = _changed_within(store, days=7) if isinstance(store, dict) else []
    if _moved_7d:
        _radar += (f'<a class="chip warn bchip" href="{_tierurl("changed")}" title="'
                   f'{_esc(", ".join(_h.display_name(store, k) for k, _ in _moved_7d[:8]))}">'
                   f'<i></i>{len(_moved_7d)} first seen changed in 7d</a>')
    _asks = []
    if _auth_asks:
        _who = ", ".join(_esc(n) for n in _auth_asks[:2]) + \
               (f" +{len(_auth_asks) - 2} more" if len(_auth_asks) > 2 else "")
        _asks.append(f'<a class="bask" href="{_tierurl("signin")}">'
                     f'{len(_auth_asks)} sign-in(s) — {_who}</a>')
    if pending:
        _asks.append(f'<label class="bask" for="n3">{len(pending)} approval(s) waiting</label>')
    _needs = (' · '.join(_asks) if _asks
              else 'nothing — sign-ins and trust decisions are the only things that ever will')
    _ghost_note = (f' · {_ghosts} remembered, configured nowhere now' if _ghosts else '')
    brief = (f'<div class="brief"><span class="bcount"><b>{len(classified) - _ghosts}</b> servers'
             f'{_ghost_note} · '
             f'{_watched_sum} of {_tools_sum} exposed tools watched</span>'
             f'<span class="bradar">{_radar}</span>'
             f'<span class="bneeds"><b>Needs you:</b> {_needs}</span></div>')

    # ---- THE TODAY VIEW (slice 1 of the reimagined shell, founder-approved 25 Aug) -------------
    # One verdict sentence · the only asks a machine cannot do · the fleet worst-first with quiet
    # groups folded to one line. Depth lives one click away under Detail; nothing was deleted.
    _f_by_srv: dict[str, int] = {}
    for _f in (d.get("findings") or []):
        if not _f.get("first_party") and not _f.get("suppressed"):
            _s = str(_f.get("server") or "")
            _f_by_srv[_s] = _f_by_srv.get(_s, 0) + 1
    _asks_n = len(_auth_asks) + (1 if pending else 0)
    _t_head = (f"{_asks_n} thing{'s' if _asks_n != 1 else ''} need"
               f"{'' if _asks_n != 1 else 's'} you." if _asks_n else "All quiet.")
    _cards = []
    for _n in _auth_asks[:3]:
        _act = (f'<form method="POST" action="/" class="rowact">'
                f'<input type="hidden" name="token" value="{_esc(token)}">'
                f'<input type="hidden" name="key" value="{_esc(_n)}">'
                f'<input type="hidden" name="tab" value="n9">'
                f'<button class="act-btn" name="act" value="login">Sign in now</button></form>'
                if token else '<span class="dim">open the tokened URL from your terminal to act</span>')
        _nt = _tools_by_name.get(_n, 0)
        # "Its tools stay unmeasured" was printed for kite and Revolut X, both measured (22 and
        # 21 tools) minutes earlier by a scan. Say what is true for THIS server.
        _until = (f"Measured signed out: {_nt} tool{'s' if _nt != 1 else ''}. Sign in to "
                  f"measure what it shows a signed-in session." if _nt
                  else "Until then its tools stay unmeasured.")
        _cards.append(f'<div class="ask"><span class="ak">sign in — only you can</span>'
                      f'<h5>{_esc(_n)} is waiting on a browser sign-in</h5>'
                      f'<p>{_esc(_until)}</p>{_act}</div>')
    if len(_auth_asks) > 3:
        _cards.append(f'<div class="ask calm">+{len(_auth_asks) - 3} more sign-in(s) — see the '
                      f'fleet below.</div>')
    if pending:
        _cards.append(f'<div class="ask"><span class="ak">trust decision — only you should</span>'
                      f'<h5>{len(pending)} server{"s" if len(pending) != 1 else ""} changed after '
                      f'you approved {"them" if len(pending) != 1 else "it"}</h5>'
                      f'<p>Blocked meanwhile — the rug-pull shape is exactly this.</p>'
                      f'<label class="act-btn albl" for="n3">Review &amp; decide</label></div>')
    _asks_html = "".join(_cards) or ('<div class="ask calm">Nothing needs you — sign-ins and '
                                     'trust decisions are the only things that ever will.</div>')
    _PROBLEM = {"blocked", "findings", "changed"}
    _trows = []
    for _n2, _e2, _k2, _t2 in classified:
        _is_auth = _n2 in _auth_asks
        if _t2 not in _PROBLEM and not _is_auth:
            continue
        if _t2 == "blocked" and _e2.get("_baseline_only"):
            continue                                   # folded to one group line below
        # THE PROBLEM KEEPS ITS NAME. A sign-in is an ask, not a state: kite (findings) and
        # Revolut X (measured, at baseline) both rendered as "waiting on your browser sign-in"
        # here, hiding the finding and contradicting the Servers table one click away.
        if _t2 == "changed":
            _why2 = "changed since approval — blocked until you decide"
            # A changed server with findings says BOTH: the reorder that made the counts agree
            # must not hide the conviction ("a server we convicted is not at its baseline").
            _nf2 = _f_by_srv.get(_n2, 0)
            if _nf2:
                _why2 += f" · {_nf2} finding{'s' if _nf2 != 1 else ''} to review"
        elif _t2 == "findings":
            _nf = _f_by_srv.get(_n2, 0)
            _why2 = (f"{_nf} finding{'s' if _nf != 1 else ''} to review" if _nf
                     else "has findings on record")
        elif _t2 == "blocked":
            _why2 = "blocked"
        else:
            _why2 = "waiting on your browser sign-in"
        if _is_auth and _t2 in _PROBLEM:
            _why2 += " · also waiting on your sign-in"
        _w2 = [w for w in re.split(r"[^0-9A-Za-z]+", _n2) if w]
        _mk2 = ((_w2[0][0] + (_w2[1][0] if len(_w2) > 1 else (_w2[0][1:2] or ""))).upper()
                if _w2 else "?")
        _lbl2, _tg2 = ((_tlabel[_t2], _tag[_t2]) if _t2 in _PROBLEM else ("Needs sign-in", "warn"))
        _trows.append(
            f'<tr><td class="tmk"><span class="mmark {_tg2}" style="width:26px;height:26px;'
            f'font-size:11px;border-radius:7px">{_esc(_mk2)}</span></td>'
            f'<td><span class="nm">{_esc(_n2)}</span> '
            f'<span class="id">{_esc(_k2 if _k2 else "mcp:" + _n2)}</span></td>'
            f'<td class="dim">{_esc(_why2)}</td>'
            f'<td><span class="chip {_tg2}"><i></i>{_esc(_lbl2)}</span></td>'
            f'<td class="tact"><a href="{_rowurl(_n2).replace("tab=n0", "tab=n0")}">open</a></td></tr>')
    _bo_n = sum(1 for _n2, _e2, _k2, _t2 in classified
                if _t2 == "blocked" and _e2.get("_baseline_only"))
    _quiet_unv = counts.get("unverified", 0) - len(_auth_asks)
    _grp_lines = ""
    if _bo_n:
        _grp_lines += (f'<tr class="tgrp"><td colspan="5">approved but in no agent’s config '
                       f'({_bo_n}) — nothing can call these '
                       f'<a href="{_tierurl("blocked")}">show</a></td></tr>')
    if _quiet_unv > 0:
        _grp_lines += (f'<tr class="tgrp"><td colspan="5">unverified ({_quiet_unv}) '
                       f'<a href="{_tierurl("unverified")}">show</a></td></tr>')
    if counts.get("baseline"):
        _grp_lines += (f'<tr class="tgrp"><td colspan="5">at baseline, quiet '
                       f'({counts["baseline"]}) <a href="{_tierurl("baseline")}">show</a></td></tr>')
    _mon_live = bool((d.get("monitor") or {}).get("running") or (d.get("monitor") or {}).get("servers"))
    today_pane = f"""<section class="pane" id="p9">
    <div class="card">
      <div class="chead"><h1>Today</h1><div class="tools">
        {_action_buttons(token, action, tab="n9")}</div></div>
      <div class="mbody" style="padding:16px 18px 20px">
        <div class="tverdict"><span class="th1">{_esc(_t_head)}</span>
          <span class="tsub">{len(classified) - _ghosts} servers{_ghost_note} · {_watched_sum} of {_tools_sum} exposed
          tools exercised{' · monitor live' if _mon_live else ''}</span>
          <span class="bradar">{_radar}</span></div>
        <div class="asks">{_asks_html}</div>
        <div class="fhead2">Fleet · worst first</div>
        <table class="ttable">{"".join(_trows) or
          '<tr><td class="dim" style="padding:10px 4px">No server needs attention right now.</td></tr>'}
        {_grp_lines}</table>
      </div>
    </div>
  </section>"""

    # --- runtime: agents, then the call log with one Group by ----------------------------------
    _tiers = "".join(
        f'<option value="{k}"{" selected" if tier_filter == k else ""}>{_esc(lbl)}</option>'
        for k, lbl, _ in TIERS)
    filterbar = (
        '<form method="GET" action="/" class="filters">'
        + '<input type="hidden" name="tab" value="n0">'
        + (f'<input type="hidden" name="t" value="{_esc(token)}">' if token else "")
        + f'<input class="fq" type="search" name="q" aria-label="filter servers" value="{_esc(q)}" '
          'placeholder="search server, key or agent">'
        + f'<select name="tier"><option value="">every tier</option>{_tiers}</select>'
        + '<button class="filter-btn" type="submit">filter</button>'
        + (f'<a class="clearf" href="/?t={_esc(token)}">clear</a>' if (q or tier_filter) else "")
        # `len(classified)`, NOT `len(entries)`. `entries` is discovery only, while the rows now
        # fall back to the approved baseline (queue #12) — so a machine whose configs had gone
        # rendered "2 of 0 server(s)": a denominator smaller than its own numerator. The counter
        # has to describe the same universe the rows come from, or the fix for #12 just moves the
        # wrong number somewhere else.
        + f'<span class="count rowcount">{_shown} of {len(classified)} server(s)'
        + (' matching this filter' if (q or tier_filter) else "") + '</span>'
        + '</form>')

    def _timeline_row(f: dict) -> str:
        """The expanded evidence trail for ONE finding: every reproduction attempt the engine
        made, in order, with what came back and where it went.

        This is the answer to "the page shows a verdict, not the reasoning". The engine records
        an observation per attempt — including attempts that found nothing — and the summary line
        ("localhost · 3/3") is a compression of exactly this. An attempt that FAILED is shown as
        an infra failure, never folded into the successes: 2 of 3 attempts succeeding is a weaker
        claim than 3 of 3 and the page has to say so.
        """
        tlm = finding_timeline(str(f.get("server") or ""), str(f.get("tool") or ""),
                               str(f.get("code") or ""))
        if not tlm["found"]:
            return (f'<tr class="tlrow"><td colspan="6"><div class="tlbox dim">'
                    f'{_esc(tlm["why"])}</div></td></tr>')
        rows = []
        blocked_any = False
        for a in tlm["attempts"]:
            okflag = bool(a.get("ok"))
            for h in (a.get("egress") or []):
                if not h.get("allowed"):
                    blocked_any = True
            hosts = ", ".join(
                f'{h.get("method") or ""} {h.get("host") or h.get("hostname") or "?"}'.strip()
                # An undeclared host is not merely noted — the sandbox gateway REFUSES it (403
                # "blocked by sandbox no-egress"). Saying only "(not declared)" while the next
                # column shows the tool's 403 invites the reading that the DESTINATION refused
                # it. The founder read it exactly that way on the live page.
                + ("" if h.get("allowed") else " (not declared — blocked here)")
                for h in (a.get("egress") or [])) or "no network call observed"
            body = (a.get("resultTextExcerpt") or "").strip()
            # The engine truncates at 2000 chars ON PURPOSE (a spot-check trail, never a mirror of
            # the server's data). Say so where it happens rather than implying this is everything.
            trunc = " …(excerpt — the engine keeps the first 2000 chars only)" if len(body) >= 2000 else ""
            # The 403 in this cell is usually OURS — the tool relaying the sandbox's refusal.
            # The note below the table said so and the founder still read the rows as "all the
            # findings are 403 errors" (2026-08-15): the label has to sit ON the row.
            ours = ('<span class="chip warn">our sandbox\'s block</span> '
                    if "403" in body and "blocked by sandbox" in body else "")
            rows.append(
                f'<tr><td class="dim">#{_esc(a.get("attempt"))}</td>'
                f'<td><span class="chip {"ok" if okflag else "warn"}">'
                f'{"observed" if okflag else "could not run"}</span></td>'
                f'<td class="dim">{_esc(hosts)}</td>'
                f'<td class="dim mono">{ours}{_esc((body or a.get("infraDetail") or "—")[:400])}'
                f'{_esc(trunc)}</td></tr>')
        ran = sum(1 for a in tlm["attempts"] if a.get("ok"))
        head = (f'{len(tlm["attempts"])} attempt(s) recorded · {ran} produced an observation · '
                f'run {tlm["run"]}')
        # WHOSE ERROR IS IT. The sandbox refuses undeclared egress with a 403, and the tool
        # reports that refusal as its own failure — so the rightmost column can show an error
        # that came from US. Unlabelled, that reads as "the destination rejected it" or worse,
        # "the check is broken", which is the opposite of what happened: the call was attempted
        # and we stopped it. Stated whenever any host was blocked.
        blocked_note = (
            '<div class="tlnote">The undeclared call above was BLOCKED by mcpgawk\'s sandbox '
            '(HTTP 403 “blocked by sandbox no-egress”). An error in the last column is usually '
            'the tool reporting OUR block, not a reply from the destination — the finding is '
            'that the call was attempted at all.</div>') if blocked_any else ""
        return (f'<tr class="tlrow"><td colspan="6"><div class="tlbox">'
                f'<div class="tlhead">{_esc(head)}</div>'
                f'<table class="tlt"><thead><tr><th>attempt</th><th>outcome</th>'
                f'<th>where it went</th><th>what came back</th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table>'
                f'{blocked_note}'
                f'<div class="dim tlfoot">Raw record: '
                f'{_esc(str(verify_runs_dir() / tlm["run"] / "audit.jsonl"))}</div>'
                f'</div></td></tr>')

    _f_all = d.get("findings") or []
    _f_real = [f for f in _f_all if not f.get("first_party") and not f.get("suppressed")]
    fcount = (f"{len(_f_real)} needing a decision · {len(_f_all) - len(_f_real)} folded"
              if _f_all else "nothing recorded yet")
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _tl_key(f: dict) -> str:
        return f'{f.get("server") or ""}\x1f{f.get("tool") or ""}\x1f{f.get("code") or ""}'

    def _tl_link(f: dict) -> str:
        """A GET link and a re-render — the CSP forbids script, same as the server drawer."""
        key = _tl_key(f)
        parts = ([f"t={_urlq(token)}"] if token else []) \
            + ([f"q={_urlq(q)}"] if q else []) \
            + ([f"tier={_urlq(tier_filter)}"] if tier_filter else []) \
            + ([f"tl={_urlq(key)}"] if tl != key else []) \
            + ["tab=n6"]
        label = "hide trail" if tl == key else "see every attempt"
        return f'<a class="tll" href="/?{"&amp;".join(parts)}#p6">{label}</a>'

    _SEL_TR = '<tr class="selrow">'
    def _age_note(f: dict) -> str:
        """Say so when this row is OLDER than the run that produced the page.

        `collect()` has carried a per-finding `verified_at` since single-server verifies stopped
        deleting everyone else's results (queue #10) — precisely so a preserved finding could state
        its own age instead of inheriting the timestamp of a run that never touched it. Nothing
        rendered it, so on screen a week-old conviction and one from thirty seconds ago were
        indistinguishable, which is the half of #10 that survived the fix. Shown only when it
        DIFFERS from the run: on an ordinary full-fleet run every row carries the same date, and a
        note repeated on every row is read as furniture rather than as information.
        """
        own = str(f.get("verified_at") or "")[:10]
        run = str(d.get("verify_at") or "")[:10]
        if not own or own == run:
            return ""
        return f'<div class="dt">from an earlier run · {_esc(own)}</div>'

    frows = "".join(
        (_SEL_TR if tl == _tl_key(f) else "<tr>")
        + f'<td class="nm">{_esc(f.get("server"))}{_age_note(f)}</td>'
        f'<td class="nm">{_esc(f.get("tool") or "—")}</td>'
        f'<td>{_esc(f.get("class") or f.get("code") or "?")}{_foldnote(f)}</td>'
        f'<td><span class="chip {_fchip(f)}">{_esc(f.get("severity") or "?")}</span></td>'
        f'<td class="dim">{_esc(f.get("evidence") or "—")}</td>'
        f'<td class="dim">{_esc(f.get("repro"))} {_tl_link(f)}</td></tr>'
        + (_timeline_row(f) if tl == _tl_key(f) else "")
        for f in sorted(_f_all, key=lambda f: (bool(f.get("first_party")),
                                               _sev_rank.get(str(f.get("severity")).lower(), 9),
                                               str(f.get("server"))))) or \
        ('<tr><td colspan="6" class="dim">No verify has run yet. An empty table here is not a clean '
         'bill of health.</td></tr>')

    _nba_text, _nba_tier = next_best_action(d)
    nba = (f'<div class="nba {_nba_tier}"><b>Next:</b> {_esc(_nba_text)}</div>')

    # Discovery's own shortfalls, above the fleet list: a config that exists but could not be
    # used, an entry shape we skipped, a server the client disabled. Without this the list below
    # implies a completeness the sweep did not achieve ("nothing was found" ≠ "nothing was
    # looked at" — the same rule the CLI's empty state follows).
    # CANNOT BE SIGNED INTO — a first-class state, not a login that stays pending forever. An
    # account-hosted connector runs in the user's Anthropic account with no local endpoint: there
    # is nothing here to authenticate to, and offering a button would be a promise we cannot keep.
    cannot = ""
    if d.get("unscannable"):
        rows_ = "".join(
            f'<tr><td class="nm">{_esc(str(u.get("name") or ""))}</td>'
            f'<td><span class="chip unv">{_esc(str(u.get("kind") or ""))}</span></td>'
            f'<td class="dim">{_esc(str(u.get("why") or ""))}</td></tr>'
            for u in d["unscannable"])
        # ONE honesty sentence for this surface — the longer chorus (three claims in one note,
        # echoed again by the drawer and the coverage card) taught the reader to skip all of it.
        cannot = ('<div class="note">Reachable by your agents, not scannable from this machine — '
                  'each is named with why, and this list cannot prove it is complete.</div>'
                  '<table><thead><tr><th>capability</th><th>kind</th><th>why not</th></tr></thead>'
                  f'<tbody>{rows_}</tbody></table>')

    disc_problems = ""
    if d.get("discovery_problems"):
        items = "".join(f"<li>{_esc(ln)}</li>" for ln in d["discovery_problems"])
        disc_problems = (f'<div class="note warn">This fleet list is INCOMPLETE — discovery '
                         f'could not use everything it found:<ul style="margin:6px 0 0 18px">'
                         f'{items}</ul></div>')

    _ran = d.get("verified_runs") or {}
    # ONLY the current fleet renders as your fleet. The behaviour store keeps every server ever
    # verified — including pytest fixtures from before the real-home write guard (evil, mal,
    # dies…) — and rendering them unlabelled put fake servers in the founder's Trust table
    # (tab audit, 2026-08-15). Folded with names, never silently dropped.
    _ran_gone = sorted(n for n, o in _ran.items()
                       if isinstance(o, dict) and n not in _fleet_names)
    isorows = "".join(
        f'<tr><td class="nm">{_esc(n)}</td>'
        f'<td><span class="chip {"ok" if str(o.get("backend")) in ("proxied-container", "docker") else "warn"}">'
        f'{_esc(o.get("backend") or "?")}</span></td>'
        f'<td class="num dim">{o.get("toolsChecked", "?")}</td>'
        f'<td class="num dim">{len(o.get("skipped") or [])}</td></tr>'
        for n, o in sorted(_ran.items())
        if isinstance(o, dict) and n in _fleet_names) or \
        ('<tr><td colspan="4" class="dim">No verify has run yet. Nothing here means nothing was '
         'watched — not that nothing is wrong.</td></tr>')
    if _ran_gone:
        _gone_shown = ", ".join(_ran_gone[:12]) + (", …" if len(_ran_gone) > 12 else "")
        isorows += (f'<tr><td colspan="4" class="dim">{len(_ran_gone)} record(s) from servers '
                    f'not in your current fleet (removed servers and old test fixtures) — kept '
                    f'in the store, folded here: {_esc(_gone_shown)}</td></tr>')
    policyrows = "".join(
        f'<tr><td class="nm">{_esc(p_)}</td><td class="dim">{_esc(m_)}</td>'
        f'<td><span class="chip {c_}"><i></i>{_esc(s_)}</span></td></tr>'
        for p_, m_, s_, c_ in policy_rows(d))
    from .history import default_path as _history_path
    pathrows = "".join(
        f'<tr><td class="nm">{_esc(label)}</td><td class="dim">{_esc(str(pth))}</td></tr>'
        for label, pth in (
            ("approved baseline / history", _history_path()),
            ("last verify report", behaviour_profile_path().parent / "last-verify.json"),
            ("verify evidence archives (one dir per run: report + per-attempt audit.jsonl)",
             behaviour_profile_path().parent / "verify-runs"),
            ("last action result", _action_store()),
            ("observed behaviour", behaviour_profile_path())))

    def _protect_cell(ckey: str, st: str) -> str:
        # A Protect action ONLY where a hook point exists and is not installed. Where none exists
        # the gap is a stated fact with no button — an action that cannot work must not render.
        # Token-gated like every other mutation: an agent reading this page gets no control.
        if st != "off" or not token:
            return ""
        return (f'<form method="POST" action="/" class="rowact">'
                f'<input type="hidden" name="token" value="{_esc(token)}">'
                f'<input type="hidden" name="key" value="{_esc(ckey)}">'
            f'<input type="hidden" name="tab" value="n1">'
                f'<button class="act-sm warn" name="act" value="protect" title="Install the '
                f'pre-execution hook so every MCP call from this agent is checked against your '
                f'baseline">Protect</button></form>')

    arows = "".join(
        f'<tr><td class="nm">{_esc(label)}</td><td><span class="chip '
        f'{"ok" if st == "on" else ("warn" if st == "off" else "dim")}">'
        # "protected" claimed an outcome; "hook installed" states the fact this row actually
        # knows. Whether calls are being CHECKED is in the detail column, from the spool.
        f'{"hook installed" if st == "on" else ("not enabled" if st == "off" else "no hook point")}'
        f'</span></td><td>{n}</td><td class="dim">{_esc(det)}</td>'
        f'<td>{_protect_cell(ckey, st)}</td></tr>'
        for ckey, label, st, n, det in rows) or \
        '<tr><td colspan="5" class="dim">No agents found.</td></tr>'

    bd = call_breakdown(calls)
    groups = ""
    for gi, (gk, glabel) in enumerate((("server", "Server"), ("adapter", "Agent"),
                                       ("decision", "Decision"))):
        body = "".join(
            f'<tr><td class="nm">{_esc(k)}</td><td class="num">{v}</td>'
            f'<td class="barcell"><span style="width:{v / max(len(calls), 1) * 100:.0f}%"></span></td></tr>'
            for k, v in bd[gk][:10]) or '<tr><td colspan="3" class="dim">nothing recorded</td></tr>'
        groups += (f'<input type="radio" name="grp" id="g{gi}"{" checked" if gi == 0 else ""}>'
                   f'<label class="gl" for="g{gi}">{glabel}</label>'
                   f'<table class="gt" id="gt{gi}"><tbody>{body}</tbody></table>')

    log = "".join(
        f'<tr><td class="dim">{_esc(_local_hms(c.get("ts", "")))}</td>'
        f'<td><span class="chip {"bad" if c.get("decision") == "deny" else "dim"}">'
        f'{_esc(c.get("decision", ""))}</span></td>'
        f'<td class="nm">{_esc(c.get("server", ""))}.{_esc(c.get("tool", ""))}</td>'
        f'<td class="dim">{_esc(c.get("adapter", ""))}</td>'
        f'<td class="dim">{_esc(c.get("basis", ""))}</td></tr>'
        for c in calls[:30]) or \
        '<tr><td colspan="5" class="dim">No calls recorded yet — use your agent once.</td></tr>'

    # --- evidence -------------------------------------------------------------------------------
    # A "running" row whose recording process is GONE renders as interrupted, not running —
    # found live 2026-08-15: a panel restart killed an in-flight fleet verify and the row
    # would have said "running" forever. Same liveness test monitor_status already applies.
    def _run_status(r) -> tuple[str, str]:
        status = getattr(r, "status", "")
        if status == "running":
            import socket as _sock

            from . import runlog as _rl
            alive = (getattr(r, "host", "") == _sock.gethostname()
                     and _rl._pid_alive(getattr(r, "pid", None)))
            if not alive:
                return "interrupted — the process that ran it is gone", "warn"
            return status, "ok"
        return status, ("bad" if status == "error"
                else "warn" if status in ("findings", "incomplete") else "ok")

    runs = "".join(
        f'<tr><td class="dim">{_esc(_local_stamp(getattr(r, "started_at", "")))}</td>'
        f'<td class="nm">{_esc(getattr(r, "kind", ""))}</td>'
        f'<td><span class="chip {_run_status(r)[1]}">{_esc(_run_status(r)[0])}</span></td>'
        f'<td class="dim">{_esc(str(getattr(r, "target", "") or "fleet-wide")[:56])}</td></tr>'
        for r in (d.get("runs") or [])) or \
        '<tr><td colspan="4" class="dim">Nothing recorded yet.</td></tr>'

    # THE FINDINGS THEMSELVES. Until 2026-07-30 a verify's convictions lived only in a subprocess
    # buffer, so a run that convicted 21 tools left every view except the result banner untouched —
    # "apart from the verify the fleet output nothing changed in the panel". Severity-first: a
    # suppressed finding is still SHOWN, marked, never silently dropped.
    # (A second findings table used to be built here into `fnd` and then never rendered —
    # dead since the Findings screen moved to its own view. `frows` above is the one that
    # ships. Removed 2026-08-03; it was one of three long-standing ruff errors on this file.)

    vb = d.get("verify_blocked")
    vnote = (f'<div class="note warn">Behavioural verification unavailable — {_esc(vb)}</div>'
             if vb else
             '<div class="note ok"><b>Behavioural verification is available.</b> '
             # Verify runs from THIS panel request container isolation (--isolate) since HANDOFF
             # 38c's finding was closed; when Docker is unreachable or a command cannot be
             # containerized the engine falls back to the proxy-only sandbox and the per-server
             # rows say so. The isolation column shows what actually ran, never the request.
             '<code>mcpgawk verify &lt;config.json&gt;</code> runs each server and reports what it '
             'actually contacts. Free. Verify runs started here request container isolation '
             '(needs Docker) and report per server when they had to run without it.</div>')
    errs = "".join(f'<div class="note warn">Could not read {_esc(k)}: {_esc(v)} — this panel is '
                   f'showing less than the whole picture.</div>'
                   for k, v in (d.get("errors") or {}).items())

    # Activity, STRUCTURED — summary, then what needs your eyes, then the full record. A flat log
    # buries the one deny that matters under a thousand identical allows; a security view leads
    # with the exception.
    all_acts = activity_rows(limit=2000)
    _foreign_acts = [a for a in all_acts if a.get("server") not in _fleet_names]
    all_acts = [a for a in all_acts if a.get("server") in _fleet_names]
    # Identical denials collapse into one row with a count — the founder scrolled the same
    # verbatim reason five times ([FOUNDER] 2026-08-15); repetition hides the second problem.
    _seen_deny: dict[tuple, dict] = {}
    for a in all_acts:
        if a.get("decision") != "deny":
            continue
        k = (a.get("server"), a.get("tool"), a.get("why"))
        if k in _seen_deny:
            _seen_deny[k]["repeats"] += 1
        else:
            _seen_deny[k] = dict(a, repeats=1)
    notable = list(_seen_deny.values())

    def _act_row(a: dict, expand_why: bool = False) -> str:
        deny = a.get("decision") == "deny"
        why = a.get("why") or ""
        if deny and why:
            why_cell = (f'<div class="whyfull">{_esc(why)}</div>' if expand_why else
                        f'<details><summary class="whysum">show</summary>'
                        f'<div class="whyfull">{_esc(why)}</div></details>')
        else:
            why_cell = _esc(why or "—")
        reps = a.get("repeats") or 0
        rep_note = (f' <span class="dim">×{reps} identical</span>' if reps > 1 else "")
        return (f'<tr><td class="dim">{_esc(str(a.get("when") or "")[:19])}</td>'
                f'<td class="dim">{_esc(a.get("agent") or "—")}</td>'
                f'<td class="nm">{_esc(a.get("server") or "")}.{_esc(a.get("tool") or "")}</td>'
                f'<td><span class="chip {"bad" if deny else "dim"}">'
                f'{_esc(a.get("decision") or "")}</span>{rep_note}</td>'
                f'<td class="dim">{_esc(a.get("basis") or "")}</td><td>{why_cell}</td></tr>')

    act_summary = act if isinstance(act, dict) else {}
    span_first = all_acts[-1].get("when") if all_acts else None
    span_last = all_acts[0].get("when") if all_acts else None
    acts_notable = "".join(_act_row(a, expand_why=True) for a in notable) or \
        ('<tr><td colspan="6" class="dim">No call in this log was blocked, and nothing it '
         'covers overstepped its approved baseline.' + monitor_gap_note(d) + '</td></tr>')
    acts_full = "".join(_act_row(a) for a in all_acts[:500]) or \
        '<tr><td colspan="6" class="dim">Nothing recorded yet — use your agent once.</td></tr>'
    if _foreign_acts:
        # NAME THEM, with counts. "removed servers and old test fixtures" described 1,323 live
        # claude-in-chrome calls (a browser capability the spool names differently from the
        # native host discovery finds) as dead history (2026-09-03). Say what was folded.
        _fc: dict[str, int] = {}
        for _a in _foreign_acts:
            _fc[str(_a.get("server"))] = _fc.get(str(_a.get("server")), 0) + 1
        _top = ", ".join(f"{_esc(n)} ({c})" for n, c in
                         sorted(_fc.items(), key=lambda kv: -kv[1])[:4])
        _more = f", +{len(_fc) - 4} more" if len(_fc) > 4 else ""
        acts_full += (f'<tr><td colspan="6" class="dim">{len(_foreign_acts)} call(s) from '
                      f'{len(_fc)} server(s) not in your current fleet — {_top}{_more} — '
                      f'used but configured nowhere now, or old test fixtures. Folded here, '
                      f'kept in the exports.</td></tr>')

    def _dec_action(k: str) -> str:
        if not token:
            return '<span class="dim">approve in your terminal</span>'
        return (f'<form method="POST" action="/" class="rowact">'
                f'<input type="hidden" name="token" value="{_esc(token)}">'
                f'<input type="hidden" name="key" value="{_esc(k)}">'
                f'<input type="hidden" name="tab" value="n3">'
                f'<button class="act-sm" name="act" value="keep">Keep blocked</button>'
                f'<button class="act-sm warn" name="act" value="approve">Approve</button>'
                f'</form>')

    # WHAT CHANGED, on the row — the same drift report `mcpgawk decide` shows, because a person
    # cannot decide "trust this change" from the words "blocked · waiting on you" alone. Reuses
    # decide.pending_decisions (pure, owns this logic); servers pending without a comparable
    # record still get a row, stating only what is actually known.
    from . import decide as _dc
    _dec_items = {it["key"]: it for it in _dc.pending_decisions(store)}

    def _dec_what(k: str) -> str:
        it = _dec_items.get(k)
        if not it:
            return ('<span class="dim">Moved since you approved it; your agents cannot call it '
                    'until you look. Review it in Servers.</span>')
        rep = it["report"]
        plain_changed = [t for t in rep.changed if t not in rep.hostile]
        bits = []
        # Two hostile kinds, two sentences. "rewrote its own description" for a tool whose only
        # change was declaring itself destructive (browserstack, 2026-09-03) sends the reader to
        # compare text that did not change.
        _inj = getattr(rep, "injected", None)
        _esc_ = getattr(rep, "escalated", None)
        if _inj is None and _esc_ is None:
            _inj = list(rep.hostile)
        for t in (_inj or [])[:2]:
            bits.append(f'<span class="nm">{_esc(t)}</span> <span class="dim">rewrote its own '
                        'description after you approved it — the rug-pull signature.</span>')
        for t in [x for x in (_esc_ or []) if x not in (_inj or [])][:2]:
            bits.append(f'<span class="nm">{_esc(t)}</span> <span class="dim">now declares more '
                        'power than you approved — it marked itself destructive or open-world '
                        'after approval.</span>')
        for t in rep.added[:2]:
            bits.append(f'<span class="nm">{_esc(t)}</span> <span class="dim">appeared after you '
                        'approved this server. A tool that shows up later is how a malicious '
                        'update arrives.</span>')
        for t in rep.removed[:1]:
            bits.append(f'<span class="nm">{_esc(t)}</span> <span class="dim">was removed.</span>')
        for t in plain_changed[:1]:
            bits.append(f'<span class="nm">{_esc(t)}</span> <span class="dim">changed its '
                        'description.</span>')
        for t in rep.annotation_changed[:1]:
            bits.append(f'<span class="nm">{_esc(t)}</span> <span class="dim">changed its safety '
                        'annotations — a tool relabelled itself.</span>')
        total = (len(rep.hostile) + len(rep.added) + len(rep.removed) + len(plain_changed)
                 + len(rep.annotation_changed) + len(rep.schema_changed))
        if total > len(bits):
            bits.append(f'<span class="dim">…and {total - len(bits)} more change(s) — the full '
                        'diff is in <code>mcpgawk decide</code>.</span>')
        return "<br>".join(bits) or ('<span class="dim">The surface moved; the record predates '
                                     'detailed diffs.</span>')

    def _dec_chip(k: str) -> str:
        """What enforcement is ACTUALLY doing about this pending drift. The hook denies by
        tool-name projection, so a schema/annotation-only change (pending since 2026-08-15,
        the audit-B2 rug-pull class) leaves every call passing — a flat "Blocked" chip here
        claimed enforcement that was not happening, the worst lie a security product can
        render. [CLAUDE-PROPOSED, undecided]: whether schema drift should also deny."""
        base, latest = _h.approved(store, k), _h.last(store, k)
        if base and latest and base.get("items") != latest.get("items"):
            return '<span class="chip bad"><i></i>Blocked</span>'
        return ('<span class="chip warn"><i></i>NOT blocked — schema/annotations only, '
                'calls still pass</span>')

    def _dec_who(k: str) -> str:
        at, by = _h.approval_provenance(store, k)
        if not at and not by:
            base = _h.approved(store, k) or {}
            m = str(base.get("measured_at") or "")[:10]
            # The sighting's date is NOT the approval's date; say which one this is.
            return (f'<br><span class="dim">baseline measured {_esc(m)} · approval time and '
                    f'actor not recorded</span>') if m else ""
        return (f'<br><span class="dim">approved {_esc(str(at)[:10])}'
                f'{" · by " + _esc(by) if by else ""}</span>')

    dec = "".join(
        f'<tr><td class="nm">{_esc(_h.display_name(store, k))}{_dec_who(k)}</td>'
        f'<td>{_dec_what(k)}</td>'
        f'<td>{_dec_chip(k)}</td>'
        f'<td>{_dec_action(k)}</td></tr>'
        for k in pending) or \
        ('<tr><td colspan="4" class="dim">No server with an approved baseline has changed '
         'since you approved it.' + monitor_gap_note(d) + '</td></tr>')

    # While an action runs, the page REFRESHES ITSELF. Telling the user to reload is not a progress
    # indicator: 0.1.20 completed its scan in ~100s and went on showing "Running scan…" forever
    # because nobody reloaded, which is indistinguishable from a hang and was reported as one.
    # A meta refresh (not script — the CSP forbids script) is the only mechanism available here.
    # PROGRESSIVE ENHANCEMENT, decided 2026-08-14 [FOUNDER]: "design should come first and very
    # importantly the experience. i cannot accept your fact that js files not secure." Correctly
    # so — the threat on this page was never OUR script, it is INJECTED script riding
    # server-controlled text (tool descriptions), and CSP kills that by ALLOWLISTING
    # (`script-src 'self'` runs /panel.js and refuses every injected inline block), not by
    # banning JS wholesale. So: with JS, /events streams action state live and the page never
    # yanks; without JS, this refresh — now inside <noscript> — keeps the page honest exactly
    # as before. Same server-rendered truth on both paths.
    refresh = ('<noscript><meta http-equiv="refresh" content="5"></noscript>'
               if (action or {}).get("running") else "")
    agent_gaps = sum(1 for _, _, st, _, _ in rows if st != "on")

    # FIRST RUN — the screen that did not exist. Thirty seconds after install a user sees a scan
    # result and no story. Shown only while NOTHING is approved, nothing has been watched and no
    # call has been checked; the moment any of those is true the story is over and the card goes.
    # Every number is real; "no findings yet" is never allowed to read as safe.
    _nothing_yet = (not any(_h.approved(store, k) for k in servers)
                    and not calls and not (d.get("verified_runs") or {})
                    and not (d.get("findings") or []))
    firstrun = ""
    if _nothing_yet and classified:
        _destr_srvs = sorted(((n, c) for n, c in _destr.items() if c),
                             key=lambda kv: -kv[1])
        _watchable = [n for n, e, _, _ in classified if e.get("command")]
        if _destr_srvs and _destr_srvs[0][0] in _watchable:
            _suggest = (f'Start with <code>{_esc(_destr_srvs[0][0])}</code>: it declares '
                        f'{_destr_srvs[0][1]} destructive tool(s).')
        elif _watchable:
            _suggest = f'Start with <code>{_esc(_watchable[0])}</code>.'
        else:
            _suggest = ('No server here can be launched by verify (none has a local command) — '
                        'watching happens through the hook instead.')
        _destr_line = (f' {len(_destr_srvs)} of them declare tools that can write or delete.'
                       if _destr_srvs else '')
        _prot = sum(1 for _, _, st, _, _ in rows if st == "on")
        firstrun = f"""<div class="card"><div class="fr">
  <h2>{len(classified)} MCP server(s) are reachable by your agents.</h2>
  <p>None has been watched running, so nothing here is a verdict yet.{_destr_line}</p>
  <ol>
    <li><b>Approve what you already trust</b><span>Records today's tool surface as the baseline.
      After that, a server that changes is blocked until you look at it. Approval is human-only —
      it happens in Decisions or <code>mcpgawk decide</code>, never from an agent
      session.</span></li>
    <li><b>Watch one server run</b><span>Verify runs its tools and records every host it
      contacts. {_suggest}</span></li>
    <li><b>Protect the agents that can be protected</b><span>{_prot} of {len(rows)} agent(s) on
      this machine have the pre-execution hook installed. The gaps are on the Agents tab, stated
      rather than hidden.</span></li>
  </ol>
</div></div>"""
    # THE GUIDED FIRST RUN (function tabs stay; the journey is a strip over them). Every stage
    # carries its real state and names the tab holding its control. Gone entirely once every
    # stage is done — a checklist of ticks is noise on a machine already set up.
    # ONE LINE, NOT A CARD STACK. The six-item checklist card restated the nav and its counts
    # above the servers table — the founder's recording opened on three onboarding cards before
    # the product (24 Aug). Each step is now a chip: state dot + short verb, linking to the tab
    # that finishes it; the full fact rides in the tooltip. Gone entirely once every step is done.
    _steps = journey_steps(d)
    journey = ""
    if any(st.get("state") != "done" for st in _steps):
        _step_tab = {"see": "n0", "connect": "n0", "verify": "n2",
                     "protect": "n1", "gateway": "n7", "keys": "n7"}
        _step_word = {"see": "See", "connect": "Sign in", "verify": "Verify",
                      "protect": "Protect", "gateway": "Gateway", "keys": "Keys"}
        _chips = []
        for st in _steps:
            sid = str(st.get("key") or "")
            state = str(st.get("state") or "todo")
            tip = _esc_attr(f"{st.get('title') or ''} — {st.get('fact') or ''} · "
                            f"{st.get('where') or ''}")
            _chips.append(
                f'<label class="jchip {_esc(state)}" for="{_step_tab.get(sid, "n0")}" '
                f'title="{tip}"><i class="jdot"></i>'
                f'{_esc(_step_word.get(sid, str(st.get("title") or "")[:12]))}</label>')
        journey = ('<div class="jstrip"><span class="ngrp" style="margin:0">Getting set up</span>'
                   + "".join(_chips) + '</div>')

    _mon = d.get("monitor") or {}
    _mon_open = sum(int(r.get("open_alerts") or 0) for r in (_mon.get("servers") or []))
    _ct_mon = f'<span class="ct alert">{_mon_open}</span>' if _mon_open else ""

    # The badge alarms only for medium+ (verify convictions, TLS-off, plaintext credentials).
    # Low-severity config findings still show the count — visible, not shouting — or a fresh
    # install with ordinary unpinned `npx` servers boots to a red badge about the ecosystem's
    # default and teaches the reader to ignore red (founder call 2026-08-23).
    # "Not explicitly low" rather than "medium+": a missing severity (older verify reports) must
    # alarm, never be silently demoted — ambiguity never reads as safe.
    _f_alarm = any(str(f.get("severity")).lower() != "low" for f in _f_real)
    _ct_fnd = (f'<span class="ct{" alert" if _f_alarm else ""}">{len(_f_real)}</span>'
               if _f_real else "")
    _ct_dec = f'<span class="ct alert">{len(pending)}</span>' if pending else ""
    _ct_agt = f'<span class="ct">{agent_gaps} gap(s)</span>' if agent_gaps else ""
    _span = (f'{str(span_first or "")[:10]} → {str(span_last or "")[:10]}'
             if span_first else "nothing recorded yet")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">{refresh}<script src="/panel.js" defer></script>
<title>mcpgawk</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* LIKE FOR LIKE with LiteLLM's admin console — DESIGN.md; the approved target is
   docs/mockups/panel-redesign-2026-07-31.html. Their grammar, our objects: pill tab rail on a
   grey track, one white card per view, filter row with a right-aligned count, uppercase heads on
   a tinted row, two-line primary cell, fully-rounded tinted tags. Royal blue #2A33C2 stays ours.
   No script — the CSP is `default-src 'none'` and the tabs are pure CSS. */
/* Palette per the founder's reference (2026-08-15, chosen over Observatory dark): warm
   sage/cream field, white floating cards, ink-navy type, ONE hot orange accent used sparingly.
   Danger is deepened to crimson so an alarm never reads as the brand colour. */
:root{{--page:#ECEFEA;--card:#FFF;--rail:#E3E9E0;--line:#D8DFD3;--line-strong:#C2CCBB;
--ink:#1D2A30;--mut:#5C6B66;--fai:#626D66;--acc:#E8502B;--accent:#E8502B;--acc-ink:#C8401F;--acc-soft:#FCEAE3;
--ok:#157A40;--ok-bg:#E9F3EA;--warn:#96590A;--warn-bg:#FBF1E3;
--bad:#B3261E;--bad-bg:#F9E9E7;--unv:#707B74;--unv-bg:#EDF0EB;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace;
--sans:system-ui,-apple-system,"Segoe UI",sans-serif;
--ease:cubic-bezier(.23,1,.32,1);
--srow:minmax(190px,1.5fr) minmax(64px,.5fr) minmax(104px,.9fr) minmax(112px,.6fr)
 minmax(48px,.35fr) minmax(96px,.85fr) minmax(118px,auto)}}
/* LAYOUT CONTRACT (founder, 24 Aug): every column carries a PIXEL floor sized to its widest
   normal content, so nothing squeezes to a width its words cannot survive. One grid item per
   cell, always. Numeric columns carry numbers; their annotations (.dt/.wt) are their own
   non-breaking line beneath. Words never break mid-token: chips, pills, buttons, agent names
   and annotation lines are no-wrap; prose wraps at word boundaries only. */
*{{box-sizing:border-box}}
/* INSTRUMENT fusion ([FOUNDER] 2026-08-15): the two-voice rebrand's product voice FUSES
   with this shipped system rather than replacing it — same tokens, plus the paper dot-grid
   ground and floating-surface elevation from the approved direction sample. */
body{{margin:0;background:radial-gradient(rgba(29,42,48,.09) 1px, transparent 1.4px) 0 0/26px 26px,
var(--page);color:var(--ink);font-family:var(--sans);font-size:13.5px;
line-height:1.5}}
/* Natoma-grammar shell (founder, 2026-08-07): grouped left sidebar + one content column.
   Pure CSS grid — the radio-tab mechanics and the `~ .sheet` selectors are untouched. Direct
   children that are neither the sidebar nor a pane (header, banners, errors) span both columns. */
.sheet{{max-width:1280px;margin:0 auto;padding:22px 22px 90px;
display:grid;grid-template-columns:196px minmax(0,1fr);gap:0 26px;align-items:start}}
.sheet>:not(.rail):not(.pane){{grid-column:1/-1}}
.sheet>.abar.gtop{{grid-column:2;grid-row:2;align-self:start}}
.rail{{grid-row:2/span 2}}
.bhead{{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}}
.brandmark{{width:22px;height:22px;display:block}}
.ronote{{margin:0 0 14px;padding:10px 13px;border-radius:10px;font-size:12px;
border:1px solid var(--warn);background:var(--warn-bg);color:var(--warn)}}
.ngrp{{font-family:var(--mono);font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;
color:var(--fai);font-weight:500;margin:16px 10px 4px}}
.ngrp:first-child{{margin-top:2px}}
.brand{{font-weight:700;letter-spacing:-.02em;font-size:15px}}
.bsub{{font-family:var(--mono);font-size:11.5px;color:var(--fai)}}
input[type=radio]{{position:absolute;opacity:0;pointer-events:none}}#n0:focus-visible ~ .sheet label.pill[for=n0]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}#n1:focus-visible ~ .sheet label.pill[for=n1]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}#n2:focus-visible ~ .sheet label.pill[for=n2]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}#n3:focus-visible ~ .sheet label.pill[for=n3]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}#n4:focus-visible ~ .sheet label.pill[for=n4]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}#n5:focus-visible ~ .sheet label.pill[for=n5]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}#n6:focus-visible ~ .sheet label.pill[for=n6]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}#n7:focus-visible ~ .sheet label.pill[for=n7]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}#n8:focus-visible ~ .sheet label.pill[for=n8]{{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}}
.rail{{grid-column:1;display:flex;flex-direction:column;gap:2px;background:none;border:none;
padding:0;margin:0;position:sticky;top:18px}}
.pane{{grid-column:2}}
.pill{{display:flex;align-items:center;gap:8px;font-size:13.5px;color:var(--mut);
padding:7px 10px;border-radius:8px;border:1px solid transparent;cursor:pointer}}
.pill .ct{{margin-left:auto}}
.pill .dot{{width:6px;height:6px;border-radius:50%;background:var(--fai);flex:none;margin-top:6px}}
.pill .ct{{font-size:12px;color:var(--fai)}}
.pill{{align-items:flex-start}}
.pill .pw{{flex:1;min-width:0}}
.pill .prow{{display:flex;align-items:center;gap:8px}}
.pill .prow .ct{{margin-left:auto}}
.pill .pdesc{{display:block;font-size:11px;color:var(--fai);line-height:1.3;margin-top:1px}}
/* The group promise sits on its OWN line under the group label — deliberate structure instead
   of a mid-phrase wrap ("what runs in / the path", founder screenshot 24 Aug). The dot ties the
   promise to its label; the label itself never wraps. */
.ngrp{{white-space:nowrap}}
.ngrp i{{display:block;font-style:normal;text-transform:none;letter-spacing:0;font-weight:400;
font-size:11px;color:var(--mut);margin-top:1px;white-space:normal}}
.csub{{margin:1px 0 0;font-size:12.5px;color:var(--mut)}}
/* The briefing strip — radar first, and the ONLY asks a machine cannot do for the operator. */
.brief{{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:11px 16px;
border-bottom:1px solid var(--line);font-size:12.5px;color:var(--mut)}}
.brief .bcount b{{color:var(--ink);font-weight:650}}
.brief .bradar{{display:inline-flex;gap:6px;flex-wrap:wrap}}
.brief .bchip{{text-decoration:none;cursor:pointer}}
.brief .bneeds{{margin-left:auto}}
.brief .bneeds b{{color:var(--ink)}}
.brief .bask{{color:var(--acc-ink);font-weight:600;cursor:pointer;text-decoration:none}}
.brief .bask:hover{{text-decoration:underline}}
/* ---- TODAY (slice 1 of the reimagined shell) ---- */
.pill.pc{{align-items:center;padding:5px 10px;font-size:13px}}
.pill.pc .dot{{margin-top:0}}
.tverdict{{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;margin:2px 0 16px}}
.tverdict .th1{{font-size:22px;font-weight:650;letter-spacing:-.01em}}
.tverdict .tsub{{font-size:12.5px;color:var(--mut)}}
.tverdict .bradar{{margin-left:auto}}
.asks{{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:10px;margin:0 0 18px}}
.ask{{border:1px solid var(--line-strong);border-radius:12px;padding:12px 14px;background:var(--card)}}
.ask .ak{{font-family:var(--mono);font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--fai)}}
.ask h5{{margin:3px 0 2px;font-size:14px;font-weight:650}}
.ask p{{margin:0 0 10px;font-size:12px;color:var(--mut)}}
.ask.calm{{border-style:dashed;border-color:var(--line);color:var(--mut);display:flex;
align-items:center;font-size:13px}}
.albl{{display:inline-block;cursor:pointer}}
.fhead2{{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;
color:var(--fai);margin:0 0 6px}}
.ttable{{width:100%;border-collapse:collapse;font-size:13px}}
.ttable td{{padding:8px 10px 8px 0;border-top:1px solid var(--line);vertical-align:middle}}
.ttable .tmk{{width:34px}}
.ttable .id{{font-family:var(--mono);font-size:11px;color:var(--fai);display:block}}
.ttable .tact{{text-align:right}}
.ttable .tact a{{color:var(--acc-ink);font-weight:600;font-size:12.5px;text-decoration:none}}
.tgrp td{{background:var(--rail);font-family:var(--mono);font-size:11px;letter-spacing:.05em;
text-transform:uppercase;color:var(--mut);padding:6px 10px}}
.tgrp a{{color:var(--acc-ink);font-family:var(--sans);font-weight:600;text-transform:none;
letter-spacing:0;text-decoration:none;float:right}}
.grpband{{margin-top:10px;padding:5px 12px;border-radius:7px;background:var(--bad-bg);
color:var(--bad);font-family:var(--mono);font-size:11px;letter-spacing:.04em;
text-transform:uppercase;font-weight:600}}
.jstrip{{display:flex;align-items:center;gap:4px;flex-wrap:wrap;
margin:0 0 14px;padding:8px 12px;border:1px solid var(--line);border-radius:10px;
background:var(--card)}}
.jchip{{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--mut);
padding:3px 10px;border-radius:99px;cursor:pointer}}
.jchip:hover{{background:var(--srow)}}
.jchip .jdot{{width:7px;height:7px;border-radius:50%;background:var(--bad)}}
.jchip.done .jdot{{background:var(--ok)}}
.jchip.done{{color:var(--fai)}}
details.cwrap{{margin-top:14px}}
details.cwrap>summary{{cursor:pointer;font-size:13.5px;font-weight:600;color:var(--mut);
padding:10px 14px;border:1px solid var(--line);border-radius:10px;background:var(--card);
list-style-position:inside}}
details.cwrap[open]>summary{{margin-bottom:10px}}
/* ROUND 2 — popups. Server detail: a centred modal over the dimmed, unmoved table; the scrim is
   a link, so closing needs no script. Small screens get a bottom sheet. */
.scrim{{position:fixed;inset:0;background:rgba(23,23,15,.32);z-index:40;cursor:default}}
.modal{{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:41;
width:min(680px,94vw);max-height:86vh;overflow:hidden;background:var(--card);
border:1px solid var(--line-strong);border-radius:18px;
box-shadow:0 24px 70px rgba(23,23,15,.30),0 2px 8px rgba(23,23,15,.12);
display:flex;flex-direction:column;animation:modalin .16s cubic-bezier(.16,1,.3,1)}}
@keyframes modalin{{from{{opacity:0;transform:translate(-50%,-46%) scale(.98)}}
to{{opacity:1;transform:translate(-50%,-50%) scale(1)}}}}
@media (prefers-reduced-motion:reduce){{.modal{{animation:none}}}}
.modal .side{{border:none;padding:0;display:flex;flex-direction:column;min-height:0}}
/* MODAL HEADER — a tinted identity band: the same coloured mark as the row it came from, the
   name over its id, the state pill, and a round close. This is what makes it a dialog, not a
   rectangle of text (founder, 24 Aug). */
.mhead{{display:flex;align-items:center;gap:12px;padding:16px 18px;
background:var(--rail);border-bottom:1px solid var(--line-strong)}}
.mhead .mtitle{{flex:1;min-width:0}}
.mhead h3{{margin:0;font-size:17px;font-weight:640;letter-spacing:-.01em;line-height:1.2}}
.mhead .id{{font-family:var(--mono);font-size:11.5px;color:var(--fai);display:block;
margin-top:1px;overflow-wrap:anywhere}}
.mmark{{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;flex:none;
font-family:var(--mono);font-size:14px;font-weight:700;
background:var(--acc-soft);color:var(--acc-ink)}}
.mmark.ok{{background:var(--ok-bg);color:var(--ok)}}
.mmark.warn{{background:var(--warn-bg);color:var(--warn)}}
.mmark.bad{{background:var(--acc-soft);color:var(--acc-ink)}}
.mmark.unv{{background:var(--rail);color:var(--mut)}}
.mclose{{width:30px;height:30px;border-radius:50%;flex:none;display:grid;place-items:center;
font-size:20px;line-height:1;color:var(--mut);text-decoration:none;
border:1px solid var(--line-strong);background:var(--card);transition:all 140ms var(--ease)}}
.mclose:hover{{color:var(--ink);border-color:var(--mut)}}
/* Action bar under the header — the verbs sit on their own strip, not floating in the corner. */
.mactions{{display:flex;gap:8px;padding:12px 18px;border-bottom:1px solid var(--line);
background:var(--card)}}
.mactions .rowact,.mactions form{{display:inline-flex;gap:8px}}
.mbody{{padding:16px 18px 20px;overflow:auto;min-height:0}}
/* Stat grid — the metadata as a row of small tiles, not a bare two-column list. */
.statgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;
margin:0 0 14px}}
.stat{{border:1px solid var(--line);border-radius:9px;padding:8px 10px;background:var(--page)}}
.stat .sl{{display:block;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
color:var(--fai);margin-bottom:2px}}
.stat .sv{{display:block;font-size:13.5px;font-weight:600;font-variant-numeric:tabular-nums;
overflow-wrap:anywhere}}
@media (max-width:700px){{.modal{{left:0;right:0;bottom:0;top:auto;transform:none;width:auto;
max-height:90vh;border-radius:16px 16px 0 0;animation:none}}}}
/* Finished-action popup: a <details> that arrives OPEN only on the load right after completion
   (done=1); every later load renders it collapsed to the slim record. Dismissal is the native
   toggle; the once-only open is the one piece of state, carried by the URL, then scrubbed. */
details.amodal>summary{{list-style:none;cursor:pointer;font-size:12.5px;color:var(--mut);
padding:8px 12px;border:1px solid var(--line);border-radius:9px;background:var(--card);
display:flex;align-items:center;gap:8px}}
details.amodal>summary::-webkit-details-marker{{display:none}}
details.amodal>summary .aclose{{margin-left:auto;font-size:12px;color:var(--acc-ink)}}
details.amodal[open]>summary .aclose::after{{content:"Close"}}
details.amodal:not([open])>summary .aclose::after{{content:"View result"}}
/* NO SCRIM on a result popup — a full-viewport overlay here swallowed every click on the page
   ("none of the buttons are working", founder 24 Aug). The popup floats; the page stays live. */
details.amodal[open]>.abanner{{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);
z-index:41;width:min(560px,92vw);max-height:80vh;overflow:auto;margin:0;
border:1px solid var(--line-strong);border-radius:14px;
box-shadow:0 24px 70px rgba(23,23,15,.30),0 2px 8px rgba(23,23,15,.14)}}
@media (max-width:700px){{details.amodal[open]>.abanner{{left:0;right:0;bottom:0;top:auto;
transform:none;width:auto;border-radius:14px 14px 0 0}}}}
.ct.alert{{color:var(--bad);font-weight:600}}
#n0:checked~.sheet label[for=n0],#n1:checked~.sheet label[for=n1],
#n2:checked~.sheet label[for=n2],#n3:checked~.sheet label[for=n3],
#n4:checked~.sheet label[for=n4],#n5:checked~.sheet label[for=n5],
#n8:checked~.sheet label[for=n8],
#n6:checked~.sheet label[for=n6],#n7:checked~.sheet label[for=n7]{{background:var(--acc-soft);
color:var(--acc);font-weight:600;border-color:transparent}}
/* The active state highlights the NAME; the blurb stays quiet. Without this, the checked rule
   above bolds and tints the whole label, and the active blurb shouts (founder screenshot,
   24 Aug 14:39). Same id-level specificity so it wins over the rule above. */
#n0:checked~.sheet label[for=n0] .pdesc,#n1:checked~.sheet label[for=n1] .pdesc,
#n2:checked~.sheet label[for=n2] .pdesc,#n3:checked~.sheet label[for=n3] .pdesc,
#n4:checked~.sheet label[for=n4] .pdesc,#n5:checked~.sheet label[for=n5] .pdesc,
#n6:checked~.sheet label[for=n6] .pdesc,#n7:checked~.sheet label[for=n7] .pdesc,
#n8:checked~.sheet label[for=n8] .pdesc{{color:var(--fai);font-weight:400}}
#n0:checked~.sheet label[for=n0] .dot,#n1:checked~.sheet label[for=n1] .dot,
#n2:checked~.sheet label[for=n2] .dot,#n3:checked~.sheet label[for=n3] .dot,
#n4:checked~.sheet label[for=n4] .dot,#n5:checked~.sheet label[for=n5] .dot,
#n6:checked~.sheet label[for=n6] .dot,#n7:checked~.sheet label[for=n7] .dot,
#n8:checked~.sheet label[for=n8] .dot{{background:var(--acc)}}
.pane{{display:none}}
#n0:checked~.sheet #p0,#n1:checked~.sheet #p1,#n2:checked~.sheet #p2,
#n3:checked~.sheet #p3,#n4:checked~.sheet #p4,#n5:checked~.sheet #p5,
#n6:checked~.sheet #p6,#n7:checked~.sheet #p7,#n8:checked~.sheet #p8,
#n9:checked~.sheet #p9{{display:block}}
#n9:checked~.sheet label[for=n9]{{background:var(--acc-soft);color:var(--acc);font-weight:600;
border-color:transparent}}
/* BOUNDARIES (founder, 24 Aug): the card edge is drawn by its border, not implied by a blur —
   the old 40px shadow softened exactly the line it should have defined. Every card gets a
   HEADER BAND (tinted, hairline below) so where a panel starts is never ambiguous, and every
   in-card section (notes, filters, tables) sits between hairlines rather than floating. */
/* EACH PANE IS ITS OWN TILE (founder, 24 Aug): a firmer outline than the inner hairlines so the
   pane edge reads as a boundary at a glance, consistently across every tab. */
.card{{background:var(--card);border:1px solid var(--line-strong);border-radius:14px;
box-shadow:0 1px 2px rgba(35,42,38,.05),0 10px 26px rgba(35,42,38,.06);
overflow:hidden;margin-bottom:20px}}
.chead{{display:flex;align-items:center;gap:12px;padding:12px 16px;flex-wrap:wrap;
background:var(--rail);border-bottom:1px solid var(--line)}}
.chead h1{{margin:0;font-size:15px;font-weight:640;letter-spacing:-.01em}}
.tools{{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
.gbtn{{font:inherit;font-size:12px;padding:5px 11px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--mut);text-decoration:none;
display:inline-block;
transition:border-color 160ms var(--ease),color 160ms var(--ease),transform 160ms var(--ease)}}
.gbtn:active{{transform:scale(.97)}}
.act-btn{{font:inherit;font-size:12px;font-weight:600;padding:5px 12px;
border:1px solid var(--acc);border-radius:8px;background:var(--acc);color:#fff;cursor:pointer;
transition:background 160ms var(--ease),transform 160ms var(--ease)}}
.act-btn:active{{transform:scale(.97)}}
.act-btn[disabled]{{opacity:.5;cursor:default}}
.act-btn.sm{{background:var(--card);color:var(--acc)}}
a.act-btn{{text-decoration:none;display:inline-block}}
.abar{{display:flex;flex-wrap:wrap;gap:8px;padding:0 16px}}
.abar.gtop{{grid-column:2;padding:0;margin:0 0 12px}}
.abar:empty{{display:none}}
.abanner{{width:100%;padding:10px 13px;border-radius:10px;font-size:12px;margin:0 0 13px;
border:1px solid var(--warn);background:var(--warn-bg);color:var(--warn)}}
.abanner.done{{border-color:var(--ok);background:var(--ok-bg);color:var(--ok)}}
/* A result is coloured by WHAT IT FOUND, never by the fact that it finished — `.done.bad` and
   `.done.warn` come after `.done` so they win. */
.abanner.done.warn{{border-color:var(--warn);background:var(--warn-bg);color:var(--warn)}}
.abanner.done.bad{{border-color:var(--bad);background:var(--bad-bg);color:var(--bad)}}
.arows{{width:100%;border-collapse:collapse;margin-top:10px;font-size:12px}}
.arows td{{padding:5px 8px;border-top:1px solid var(--line);vertical-align:top;
overflow-wrap:anywhere}}
/* A verify row's detail carries paths and pins — one unbreakable 90-character token widened the
   table past the 560px popup and the detail column scrolled sideways (founder, 09-03; measured
   in Chrome: table 659px in a 558px box). `anywhere` lets the token break and the table fit. */
.arows .fixit{{overflow-wrap:anywhere}}
.arows td.nm{{font-family:var(--mono);white-space:nowrap;width:1%}}
.fixit{{margin-top:5px;padding:5px 8px;border-left:2px solid var(--acc);
background:var(--acc-soft);color:var(--ink);font-size:12px;line-height:1.5}}
.nba{{display:flex;gap:8px;align-items:baseline;margin:0 16px 13px;padding:11px 13px;
border-radius:10px;font-size:13.5px;border:1px solid var(--line);background:var(--card)}}
.nba.ok{{border-color:var(--ok);background:var(--ok-bg);color:var(--ok)}}
.nba.warn{{border-color:var(--warn);background:var(--warn-bg);color:var(--warn)}}
.nba.bad{{border-color:var(--bad);background:var(--bad-bg);color:var(--bad)}}
.filters{{display:flex;align-items:center;gap:9px;padding:0 16px 13px;flex-wrap:wrap;margin:0}}
.fq{{font:inherit;font-size:12px;padding:6px 11px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--ink);min-width:230px}}
.fq::placeholder{{color:var(--mut)}}
.filters select{{font:inherit;font-size:12px;padding:6px 11px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--ink)}}
.filter-btn{{font:inherit;font-size:12px;padding:6px 11px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--mut);cursor:pointer;
transition:border-color 160ms var(--ease),color 160ms var(--ease),transform 160ms var(--ease)}}
.filter-btn:active{{transform:scale(.97)}}
.clearf{{font-size:12px;color:var(--acc-ink)}}
.count{{margin-left:auto;font-size:12px;color:var(--mut)}}
.count b{{color:var(--ink);font-weight:600}}
.thead{{display:grid;grid-template-columns:var(--srow);gap:12px;align-items:center;
padding:9px 16px;background:var(--rail);border-top:1px solid var(--line);
border-bottom:1px solid var(--line);font-size:11.5px;letter-spacing:.09em;
text-transform:uppercase;color:var(--fai);font-weight:500}}
.row{{display:grid;grid-template-columns:var(--srow);gap:12px;align-items:center;
padding:11px 16px;border-bottom:1px solid var(--line)}}
.row:hover{{background:var(--srow)}}
.thead.s3,.row.s3{{grid-template-columns:minmax(180px,1.6fr) .9fr .5fr}}
.row.sel{{background:var(--acc-soft)}}
.who{{display:flex;align-items:center;gap:10px;min-width:0}}
a.who{{color:inherit;text-decoration:none}}
.split{{display:grid;grid-template-columns:minmax(0,1fr) 380px}}
.side{{border-left:1px solid var(--line);border-top:1px solid var(--line);padding:16px 16px 20px}}
.side h3{{margin:0;font-size:13.5px;font-weight:640}}
.shead{{display:flex;align-items:center;justify-content:space-between;gap:8px}}
.dacts{{margin-top:10px}}
.kv{{display:grid;grid-template-columns:auto 1fr;gap:7px 14px;margin:14px 0 0;font-size:12px}}
.kv dt{{color:var(--fai)}}
.kv dd{{margin:0;font-variant-numeric:tabular-nums}}
/* the drawer is 380px; a four-column tool table only fits with a fixed layout and wrapping
   names — without this, long tool names push the verdict columns past the card edge */
.side .mini{{table-layout:fixed}}
.side .mini th,.side .mini td{{font-size:11.5px;padding:5px 4px 5px 0}}
.side .mini th:first-child,.side .mini td:first-child{{overflow-wrap:anywhere}}
.side .mini .chip{{font-size:11.5px;padding:2px 7px}}
.side .mini .dim{{font-size:11.5px}}
.mark{{width:26px;height:26px;border-radius:7px;background:var(--acc-soft);color:var(--acc);
display:grid;place-items:center;font-size:11.5px;font-weight:700;flex:none}}
.who .nm{{font-family:var(--sans);font-weight:600;font-size:13.5px;display:block;
line-height:1.3}}
.who .id{{font-family:var(--mono);font-size:11.5px;color:var(--fai);display:block}}
.n{{text-align:right;font-variant-numeric:tabular-nums;font-size:13.5px}}
.n b{{font-weight:650}}
.n s{{text-decoration:none;color:var(--fai);font-size:12px}}
.chip{{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:550;
padding:3px 10px;border-radius:999px;white-space:nowrap;color:var(--mut);
background:var(--unv-bg)}}
.chip i{{width:5px;height:5px;border-radius:50%;background:currentColor;flex:none}}
.chip.mode{{background:transparent;border:1px solid var(--line)}}
/* Finding evidence trail: every reproduction attempt, opened by a GET link (no script). */
.tll{{margin-left:10px;font-size:12px;color:var(--acc-ink);text-decoration:none;white-space:nowrap}}
.tll:hover{{text-decoration:underline}}
.tlrow>td{{padding:0 0 14px 0;background:var(--acc-soft)}}
.tlbox{{margin:0 14px;padding:12px 14px;border:1px solid var(--line);border-radius:10px;
background:var(--card)}}
.tlhead{{font-size:12px;color:var(--mut);margin-bottom:8px}}
.tlt{{width:100%;table-layout:fixed}}
.tlt th{{font-size:11.5px}}
.tlt td{{vertical-align:top;padding:6px 8px;font-size:12px;overflow-wrap:anywhere}}
.tlfoot{{margin-top:8px;font-size:11.5px;overflow-wrap:anywhere}}
.tlnote{{margin-top:10px;padding:8px 10px;border-radius:8px;font-size:12px;
color:var(--warn);background:var(--warn-bg)}}
.mono{{font-family:var(--mono,ui-monospace,SFMono-Regular,Menlo,monospace)}}
.chip.ok{{color:var(--ok);background:var(--ok-bg)}}
.chip.warn{{color:var(--warn);background:var(--warn-bg)}}
.chip.bad{{color:var(--bad);background:var(--bad-bg)}}
.chip.unv{{color:var(--unv);background:var(--unv-bg)}}
.rowact{{display:inline-flex;gap:7px;justify-content:flex-end}}
.actwrap{{display:flex;gap:7px;justify-content:flex-end;flex-wrap:wrap;align-items:center}}
.actwrap .act-sm,.actwrap button{{white-space:nowrap}}
.dt,.wt{{display:block;font-size:11px;font-weight:400;color:var(--fai)}}
.row .dt,.row .wt{{white-space:nowrap}}
.cl-agents .ag{{font-style:normal;white-space:nowrap}}
/* .chip is the status pill — no-wrap. `.pill` is the NAV tab whose blurb MUST wrap; naming it
   here once painted every rail blurb as one endless line straight across the cards. */
.chip{{white-space:nowrap}}
.act-sm{{font:inherit;font-size:12px;padding:4px 11px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--mut);cursor:pointer;
transition:border-color 160ms var(--ease),color 160ms var(--ease),transform 160ms var(--ease)}}
.act-sm:active{{transform:scale(.97)}}
.act-sm.warn{{border-color:var(--acc);color:var(--acc);margin-left:6px}}
.bars{{padding:2px 16px 16px}}
.bar{{display:flex;height:9px;border-radius:999px;overflow:hidden;background:var(--rail);
margin:2px 0 10px}}
.seg.blocked,.seg.findings{{background:var(--bad)}}.seg.changed{{background:var(--warn)}}
.seg.unverified{{background:var(--unv)}}.seg.baseline{{background:var(--ok)}}
.legend{{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--mut)}}
.sw{{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}}
.sw.blocked,.sw.findings{{background:var(--bad)}}.sw.changed{{background:var(--warn)}}
.sw.unverified{{background:var(--unv)}}.sw.baseline{{background:var(--ok)}}
.legend b{{font-variant-numeric:tabular-nums}}
.cbar{{display:grid;grid-template-columns:150px minmax(0,1fr) auto;gap:12px;align-items:center;
margin:9px 0}}
.cbar .lb{{font-family:var(--mono);font-size:12px;color:var(--mut);overflow:hidden;
text-overflow:ellipsis;white-space:nowrap}}
.track{{height:9px;background:var(--rail);border-radius:999px;overflow:hidden}}
.fill{{height:100%;background:var(--acc);border-radius:999px}}
.cbar .vl{{font-size:12px;font-variant-numeric:tabular-nums;color:var(--ink)}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}
/* A wide table must scroll INSIDE the card, never be clipped by its overflow:hidden — the
   Findings table's last column was cut off with no way to reach it (founder's audit,
   2026-08-15). */
/* A wide table scrolls INSIDE its card — and the scroll must be VISIBLE and reachable.
   overflow:auto alone failed a real walk twice: macOS hides scrollbars until a horizontal
   gesture, a plain mouse wheel has no horizontal axis, so to a human the cut-off column
   simply did not exist ([FOUNDER] 2026-08-15: "it is not scrollable"). The scrollbar is
   therefore always painted when there is overflow, the region is keyboard-focusable
   (arrow keys scroll it), and a right-edge fade says "there is more" without words. */
/* Every table is a bounded TILE inset from the card edge — so a pane with two or three tables
   reads as two or three tiles, not one flat sheet (boundaries, 24 Aug). */
.tscroll{{overflow-x:auto;scrollbar-width:thin;scrollbar-color:var(--fai) var(--rail);
margin:0 16px 16px;border:1px solid var(--line);border-radius:10px}}
.tscroll table{{margin:0}}
.tscroll thead th{{background:var(--rail)}}
.tscroll::-webkit-scrollbar{{height:8px}}
.tscroll::-webkit-scrollbar-track{{background:var(--rail);border-radius:999px}}
.tscroll::-webkit-scrollbar-thumb{{background:var(--fai);border-radius:999px}}
.tscroll::-webkit-scrollbar-thumb:hover{{background:var(--mut)}}
.tscroll:focus-visible{{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}}
.tscroll.more{{-webkit-mask-image:linear-gradient(90deg,#000 calc(100% - 36px),transparent);
mask-image:linear-gradient(90deg,#000 calc(100% - 36px),transparent)}}
/* Session log — mono, dated, bounded; colours come from the same state tokens as everything
   else so a warn line here matches a warn pill everywhere. */
#slog{{max-height:340px;overflow-y:auto;font-family:var(--mono);font-size:11.5px}}
.slrow{{display:flex;gap:10px;padding:4px 2px;border-bottom:1px solid var(--line);color:var(--mut)}}
.slrow:last-child{{border-bottom:none}}
.slwhen{{color:var(--fai);white-space:nowrap}}
.slok{{color:var(--ok)}}.slwarn{{color:var(--warn)}}.slbad{{color:var(--bad)}}
th{{font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--fai);
text-align:left;font-weight:500;padding:9px 16px;background:var(--rail);
border-top:1px solid var(--line);border-bottom:1px solid var(--line)}}
td{{padding:10px 16px;border-bottom:1px solid var(--line);vertical-align:middle}}
td.num{{text-align:right;font-variant-numeric:tabular-nums;width:60px}}
td{{line-height:1.45}}
.nm{{font-family:var(--mono);font-size:12px}}
.dim{{color:var(--mut)}}
.dd{{border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:#FBFBFC;
padding:14px 16px}}
.ddgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px 20px;
font-size:12px;margin-bottom:12px}}
.ddgrid .k{{display:block;font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;
color:var(--fai)}}
.ddh{{font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--fai);
font-weight:500;margin:14px 0 8px}}
.mini{{font-size:12px}}
.mini th{{background:none;border-top:none;padding:5px 0}}
.mini td{{padding:5px 0;background:none}}
.unobs{{background:var(--rail);border-radius:10px;padding:10px 12px;margin:0 0 8px;
font-size:12px;color:var(--mut);line-height:1.5}}
.note{{margin:13px 16px;padding:10px 12px;border-radius:10px;background:var(--rail);
border:1px solid var(--line);font-size:12px;color:var(--mut);line-height:1.5}}
.note.ok{{background:var(--ok-bg);color:var(--ok)}}
.note.warn{{background:var(--warn-bg);color:var(--warn)}}
.whysum{{cursor:pointer;color:var(--acc-ink);font-size:12px}}
.stalekey{{grid-column:1/-1;background:var(--bad);color:#fff;border-radius:10px;
padding:11px 16px;font-size:13.5px;font-weight:550;margin-bottom:14px}}
.stalekey code{{color:#fff}}
/* Same confusion class as a stale key — a walked page whose code is behind its checkout —
   warn-toned because reading it is fine; believing it current is not. */
.stalecode{{grid-column:1/-1;background:var(--warn-bg);color:var(--warn);border:1px solid
var(--warn);border-radius:10px;padding:11px 16px;font-size:13.5px;margin-bottom:14px}}
.stalecode code{{color:var(--warn)}}
/* In-place drill-downs (sessions, gateway principals): a row must OPEN, not dead-end. */
/* Agent x server tree (fleet root), drawn server-side as inline SVG. Tokens only, no new
   colour: the accent marks the ONE open branch and nothing else competes with it. */
.ftwrap{{overflow-x:auto;margin-top:10px}}
svg.ftree{{display:block;max-width:100%;height:auto}}
svg.ftree .tn rect{{fill:var(--card);stroke:var(--line);stroke-width:1}}
svg.ftree .tn:hover rect{{stroke:var(--acc-ink)}}
svg.ftree .tnsel rect{{stroke:var(--acc);stroke-width:1.6;fill:var(--acc-soft)}}
svg.ftree .tnbad rect{{stroke:var(--bad)}}
svg.ftree .tnt{{font:550 12.5px var(--mono,ui-monospace,SFMono-Regular,Menlo,monospace);
fill:var(--ink)}}
svg.ftree .tnm{{font:11px var(--mono,ui-monospace,SFMono-Regular,Menlo,monospace);fill:var(--mut)}}
svg.ftree .tn:focus-visible rect{{outline:2px solid var(--accent);outline-offset:2px}}
/* The branch. Drawn under the boxes because a line that crosses a node reads as a connection. */
svg.ftree .tbr{{fill:none;stroke:var(--line);stroke-width:1.2}}
svg.ftree .tdet text{{font:11px var(--mono,ui-monospace,SFMono-Regular,Menlo,monospace);fill:var(--acc-ink)}}
svg.ftree .tdet:hover text{{text-decoration:underline}}
.tfoot{{margin-top:10px;font-size:12px;color:var(--mut);line-height:1.45}}
.tbasis{{margin-top:12px}}
.sessdrill{{margin-top:4px}}
.sessdrill .mini{{margin-top:6px;font-size:12px}}
.sessdrill .mini th,.sessdrill .mini td{{padding:4px 8px;font-size:11.5px}}
.whyfull{{white-space:pre-wrap;font-size:12px;color:var(--mut);margin-top:6px;max-width:60ch;
line-height:1.5}}
/* A sub-section heading is the LABEL of the tile beneath it — the tile's own border draws the
   boundary now (boundaries pass, 24 Aug), so the heading is clean text, not a divider. */
h2{{font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--fai);
font-weight:500;margin:0;padding:16px 16px 8px}}
.gwrap{{padding:0 16px 13px}}
.gl{{display:inline-block;font-size:12px;padding:4px 11px;border:1px solid var(--line);
border-radius:8px;margin:0 5px 10px 0;color:var(--mut);cursor:pointer}}
.gt{{display:none;margin-bottom:8px}}
.gt td{{padding:6px 10px}}
#g0:checked~#gt0,#g1:checked~#gt1,#g2:checked~#gt2{{display:table}}
#g0:checked~label[for=g0],#g1:checked~label[for=g1],#g2:checked~label[for=g2]
{{color:var(--ink);border-color:var(--acc)}}
.cs{{display:none}}
#c0:checked~#cs0,#c1:checked~#cs1,#c2:checked~#cs2,#c3:checked~#cs3{{display:block}}
#c0:checked~label[for=c0],#c1:checked~label[for=c1],#c2:checked~label[for=c2],
#c3:checked~label[for=c3]{{color:var(--ink);border-color:var(--acc)}}
.cs .note{{margin:8px 0 0;padding:8px 10px}}
.cs .snip{{margin:0}}
.barcell span{{display:block;height:6px;background:var(--acc);opacity:.45;border-radius:999px}}
.fr{{padding:20px 16px 24px;max-width:620px}}
.fr h2{{margin:0 0 7px;border-top:none;padding:0;font-size:19px;font-weight:640;letter-spacing:-.02em;text-transform:none;
color:var(--ink)}}
.fr>p{{color:var(--mut);margin:0 0 20px;font-size:13.5px;max-width:62ch}}
.fr ol{{list-style:none;margin:0;padding:0;counter-reset:s}}
.fr li{{counter-increment:s;display:grid;grid-template-columns:26px 1fr;gap:12px;padding:14px 0;
border-top:1px solid var(--line)}}
.fr li::before{{content:counter(s);width:22px;height:22px;border-radius:7px;
background:var(--acc-soft);color:var(--acc);font-size:11.5px;font-weight:700;display:grid;
place-items:center}}
.fr b{{display:block;font-size:13.5px}}
/* the numbered pseudo-element is grid item 1; the description must stay in column 2 or it
   wraps one word per line inside the 26px number column (latent in the mockup's own CSS) */
.fr li span{{grid-column:2;color:var(--mut);font-size:12px}}
.jrny{{list-style:none;margin:0;padding:0 16px 14px}}
.jstep{{display:grid;grid-template-columns:1fr;gap:2px;padding:8px 0;border-bottom:1px solid var(--line)}}
.jstep:last-child{{border-bottom:0}}
.jstep b{{font-size:13.5px}}
.jstep span{{color:var(--mut);font-size:12px}}
.jstep i{{font-style:normal;color:var(--acc)}}
.jstep.done b{{color:var(--ok)}}
.jstep.now b{{color:var(--acc)}}
.jstep.todo b{{color:var(--fai)}}
code{{font-family:var(--mono);font-size:12px;background:var(--rail);padding:2px 6px;
border-radius:6px}}
.snip{{font-family:var(--mono);font-size:12px;background:var(--rail);margin:0 16px 13px;
padding:10px 12px;border-radius:10px;overflow-x:auto;white-space:pre}}
@media (hover:hover) and (pointer:fine){{
  .gbtn:hover,.filter-btn:hover,.act-sm:hover{{border-color:var(--acc);color:var(--acc)}}
  .act-btn:hover{{background:#1f2799}}
  .act-btn.sm:hover{{background:var(--acc-soft)}}
  tbody tr:hover td{{background:#FAFAFB}}
  .row:not(.sel):hover{{background:#FAFAFB}}
  a.who:hover .nm{{color:var(--acc)}}
}}
@media (prefers-reduced-motion:reduce){{
  .gbtn,.act-btn,.act-sm,.filter-btn{{transition:color 160ms,border-color 160ms}}
  .gbtn:active,.act-btn:active,.act-sm:active,.filter-btn:active{{transform:none}}
}}
@media (max-width:840px){{
  .sheet{{display:block}}
  .rail{{flex-direction:row;flex-wrap:wrap;position:static;background:var(--rail);
  border:1px solid var(--line);border-radius:10px;padding:4px;margin-bottom:14px}}
  .ngrp{{display:none}}
  .pill{{display:inline-flex}}
  .pill .ct{{margin-left:0}}
  .thead,.row{{grid-template-columns:minmax(140px,1.5fr) .8fr 1fr auto}}
  .thead.s3,.row.s3{{grid-template-columns:minmax(140px,1.5fr) .9fr .5fr}}
  .cl-agents,.cl-num{{display:none}}
  .split{{grid-template-columns:1fr}}
  .side{{border-left:none}}
}}
</style></head><body>
{_radio_tabs(tab)}
<div class="sheet">
  {stale_banner}
  <div class="bhead"><img src="/brand.svg" alt="Nativerse" class="brandmark"><span class="brand">mcpgawk</span>
    <!-- WHICH BUILD AM I LOOKING AT. A running panel never reloads its code: on 2026-07-30 the
         founder read a 25-minute-old process three times and reported "nothing changed" —
         correctly, because that process predated the changes. -->
    <span class="bsub" title="when the code being served was last modified, and when this process started">
      local · this machine only · code {_esc(_CODE_AT)} · started {_esc(_STARTED)}</span></div>
  {'' if token else
   '<div class="ronote">Read-only view — this page holds the state but none of the controls. '
   'The action buttons live only on the tokened link (ending <code>?t=…</code>) that '
   '<code>mcpgawk panel</code> printed in your terminal. Reopen from there to act. '
   'That is deliberate: a bookmark or restored tab must not be able to drive this machine.</div>'}
  <div class="rail">
    <label class="pill" for="n9"><span class="dot"></span><span class="pw"><span class="prow">Today{f'<span class="ct alert">{_asks_n}</span>' if _asks_n else ''}</span><span class="pdesc">what needs you, and the fleet worst first</span></span></label>
    <label class="pill" for="n4"><span class="dot"></span><span class="pw"><span class="prow">History</span><span class="pdesc">every call, run and decision, newest first</span></span></label>
    <span class="ngrp">Detail <i>go deeper on demand</i></span>
    <label class="pill pc" for="n0"><span class="dot"></span>Servers <span class="ct">{len(classified) - sum(1 for _c in classified if (_c[1] or {}).get("_baseline_only"))}</span></label>
    <label class="pill pc" for="n6"><span class="dot"></span>Findings {_ct_fnd}</label>
    <label class="pill pc" for="n3"><span class="dot"></span>Decisions {_ct_dec}</label>
    <label class="pill pc" for="n1"><span class="dot"></span>Agents {_ct_agt}</label>
    <label class="pill pc" for="n7"><span class="dot"></span>Gateway</label>
    <label class="pill pc" for="n8"><span class="dot"></span>Monitor{_ct_mon}</label>
    <label class="pill pc" for="n2"><span class="dot"></span>Evidence</label>
    <label class="pill pc" for="n5"><span class="dot"></span>Trust</label>
  </div>
  <!-- ACTION FEEDBACK IS GLOBAL CHROME (25 Aug): a POST from ANY tab (keep/approve on
       Decisions, protect on Agents, the Gateway controls) reports HERE, visible wherever you
       are — the founder pressed Keep blocked and Approve on Decisions and saw nothing, because
       the banner used to live inside two specific panes only. -->
  <div class="abar gtop" id="action" data-live data-t="{token}">{_action_banner(action, token, fresh=fresh_action)}</div>
  {errs}
  {today_pane}
  <section class="pane" id="p0">
    {journey}
    {firstrun}
    <div class="card">
      <div class="chead"><h1>Servers</h1>
        <div class="tools">
        {_action_buttons(token, action)}
        <a class="gbtn" href="/export/servers.csv">Export .csv</a></div></div>
      {brief}
      {'' if token else
       '<div class="note">Read-only view — the state is open, the controls are not. The buttons '
       '(scan, verify, approve, protect) appear only through the link printed in the terminal '
       'that started the panel, which an agent that merely opens this page cannot supply. '
       'Lost the link? Restart <code>mcpgawk panel</code> and use the fresh one it prints.</div>'}
      {nba}
      {disc_problems}
      {cannot}
      {fleet_tree}
      <!-- Distinct class (cwrap ftable): a test pins the connect card below the fleet listing by
           searching for the first bare cwrap disclosure, so an identical wrapper here would
           satisfy that search while the card itself had moved. The rule still holds; this element
           is only made not to impersonate the one being checked. Note for whoever edits this
           comment: do not spell that element out literally here — a comment containing it is
           found by the same search, which is exactly how this went wrong once. -->
      <details class="cwrap ftable">
        <summary>Every server as one flat table</summary>
        {filterbar}
        {servers_table}
      </details>
    </div>
    <details class="cwrap">
      <summary>Connect your agent — one paste</summary>
      {_connect_card()}
    </details>
    <div class="card">
      <div class="chead"><h1>Coverage</h1></div>
      <div class="filters"><span class="count" style="margin-left:0">{cov_count}</span></div>
      <div class="bars">{coverage}
        <div class="ddh" style="margin-top:16px">watched per server · verify moves these bars</div>
        {cov_bars}</div>
      {vnote}
    </div>
  </section>

  <section class="pane" id="p6">
    <div class="card">
      <div class="chead"><h1>Findings</h1>
        <div class="tools"><a class="gbtn" href="/export/findings.csv">Export .csv</a></div></div>
      <div class="filters"><span class="count" style="margin-left:0">{fcount}</span></div>
      <div class="note">First-party egress — a server reaching its own vendor API — is listed and
        folded, not hidden. 42 of 42 findings on a real fleet were that; a detector that fires on
        normal traffic teaches you to ignore it.</div>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>server</th><th>tool</th><th>finding</th>
      <th>severity</th><th>what it contacted</th><th>reproduced</th></tr></thead>
      <tbody>{frows}</tbody></table></div>
    </div>
  </section>

  <section class="pane" id="p1">
    <div class="card">
      <div class="chead"><h1>Agents</h1>
        <div class="tools"><span class="count">{covered} covered · {uncovered} not</span></div></div>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>agent</th><th>coverage</th><th>servers</th><th>detail</th><th></th></tr>
      </thead><tbody>{arows}</tbody></table></div>
      <h2>sessions · one row per agent run</h2>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>session</th><th>agent</th><th class="num">calls</th>
      <th class="num">denied</th><th class="num">servers</th><th>last</th></tr></thead>
      <tbody>{sess}</tbody></table></div>
      <h2>group by</h2>
      <div class="gwrap">{groups}</div>
      <h2>recent calls · arguments are never recorded</h2>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>time</th><th>verdict</th><th>tool</th><th>agent</th><th>basis</th></tr>
      </thead><tbody>{log}</tbody></table></div>
    </div>
  </section>

  <section class="pane" id="p2">
    <div class="card">
      <div class="chead"><div><h1>Evidence</h1><p class="csub">The receipts of every run: what was
        scanned or verified, when, and how it went — this is provenance, not findings.</p></div>{f'<div class="tools"><span class="count">verified {_esc(d.get("verify_at") or "")[:19]}</span></div>' if d.get("verify_at") else ''}</div>
      <!-- Findings moved to their own screen (2026-07-31). Evidence keeps PROVENANCE — what ran,
           when, and how it went. Rendering the same findings in two places is two answers. -->
      <div class="note">Findings live on their own screen. This page is provenance: what ran, when,
        and how it went. <b>scan</b> = the surface was enumerated · <b>verify</b> = behaviour was
        exercised in the sandbox · <b>ok</b> = ran and found nothing · <b>findings</b> = something
        to review on Findings · <b>error</b> = the run itself failed · <b>fleet-wide</b> = every
        server, not one target.</div>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>started</th><th>what</th><th>result</th><th>target</th></tr></thead>
      <tbody>{runs}</tbody></table></div>
    </div>
  </section>

  <section class="pane" id="p3">
    <div class="card">
      <div class="chead"><h1>Decisions</h1>
        <div class="tools"><span class="count">mcpgawk decide</span></div></div>
      <div class="filters"><span class="count" style="margin-left:0"><b>{len(pending)}</b> waiting on you</span></div>
      <div class="note">Approving moves trust, so it is gated: the button below carries this
      session's token (in your terminal), which an agent that opened this page cannot supply. Review
      the change in Servers first — approval here is the same act as <code>mcpgawk decide</code>.</div>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th style="width:18%">server</th><th>what changed</th><th>severity</th>
      <th></th></tr></thead><tbody>{dec}</tbody></table></div>
    </div>
  </section>

  <!-- TRUST. A security product must be able to answer "where does this live and what actually
       ran" without the user reading our source. Every path is real and every backend is what the
       engine reported, not what a label claimed. -->
  <section class="pane" id="p5">
    <div class="card">
      <div class="chead"><div><h1>Trust</h1><p class="csub">Why you can believe this panel: which
        sandbox actually held each server, where every file lives on disk, and what this build
        is.</p></div>
        <div class="tools"><a class="gbtn" href="/export/calls.jsonl">Export .jsonl</a>
          <a class="gbtn" href="/export/calls.csv">Export .csv</a></div></div>
      <h2>what actually ran</h2>
      <div class="note">Per server, from the last behavioural run: which sandbox actually held it
        (<b>proxied-container</b> = full OS isolation · <b>proxy</b> = HTTP-only, weaker ·
        <b>none</b> = remote, cannot be sandboxed), how many tools were genuinely exercised, and
        how many were deliberately not invoked — an untested tool is never a clean one.</div>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>server</th><th>isolation used</th><th>tools checked</th>
      <th>not invoked</th></tr></thead><tbody>{isorows}</tbody></table></div>
      <h2>policy — what is enforced here, and its state on this machine now</h2>
      <div class="note">Five statements a security review maps to controls. Each names the
        mechanism that enforces it and what that mechanism is doing on THIS machine right now —
        never a percentage: a control that is off says off.</div>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>policy</th><th>enforced by</th><th>on this machine now</th></tr></thead><tbody>{policyrows}</tbody></table></div>
      <h2>where everything lives</h2>
      <div class="note">Every store this product writes, by full path — all local, nothing leaves
        this machine. Open them yourself; nothing here is asking to be trusted unread.</div>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>what</th><th>path</th></tr></thead><tbody>{pathrows}</tbody></table></div>
      <h2>this build</h2>
      <table><tbody>
        <tr><td class="nm">code last modified</td><td class="dim">{_esc(_CODE_AT)}</td></tr>
        <tr><td class="nm">panel started</td><td class="dim">{_esc(_STARTED)}</td></tr>
      </tbody></table>
      <div class="note" style="margin-top:13px">Every table on this page is downloadable:
        <a href="/export/calls.jsonl">calls.jsonl</a> · <a href="/export/calls.csv">calls.csv</a>.
        An empty table here is not a clean bill of health.</div>
    </div>
  </section>

  <section class="pane" id="p4">
    <div class="card">
      <div class="chead"><h1>Activity</h1>
        <div class="tools"><a class="gbtn" href="/export/calls.jsonl">Export .jsonl</a>
          <a class="gbtn" href="/export/calls.csv">Export .csv</a></div></div>
      <div class="filters"><span class="count" style="margin-left:0">{_activity_headline(act_summary)}
        · {len(notable)} denied · {_esc(_span)}</span></div>
      <h2>Needs your attention — blocked calls, with the full reason</h2>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>when</th><th>agent</th><th>server.tool</th><th>decision</th>
      <th>basis</th><th>why (verbatim)</th></tr></thead><tbody>{acts_notable}</tbody></table></div>
      <h2>The full record — every checked call, newest first</h2>
      <div class="note">Tool arguments are never recorded — the log is metadata, so it can never
      become the richest secret on your disk. <b>When</b> · <b>agent</b> (how &amp; who) ·
      <b>server.tool</b> (what &amp; where) · <b>decision</b> &amp; <b>basis</b> (why).</div>
      <div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>when</th><th>agent</th><th>server.tool</th><th>decision</th>
      <th>basis</th><th>why</th></tr></thead><tbody>{acts_full}</tbody></table></div>
    </div>
  </section>

  <section class="pane" id="p7">
    <div class="card">
      <div class="chead"><h1>Gateway</h1></div>
      {gwpane}
    </div>
  </section>

  <section class="pane" id="p8">
    <div class="card">
      <div class="chead"><h1>Monitor</h1></div>
      {monpane}
    </div>
    <div class="card">
      <div class="chead"><h1>Session log</h1>
        <div class="tools"><span class="count">live — updates as things happen</span></div></div>
      <div class="note">Runs, monitor sweeps, alerts and archived evidence, newest first — the
      same record <code>runs.db</code>, <code>monitor.db</code> and <code>verify-runs/</code>
      hold, streamed here while this page is open.</div>
      <div id="slog">{slog}</div>
    </div>
  </section>
</div>
</body></html>"""


# --------------------------------------------------------------------------------------------- #
# THE API. The panel is a frontend over this, not a report that happens to be HTML.
#
# Why this exists as a separate layer: the first cut rendered a string from `collect()` and served
# it. That is a report. It had a "re-scan" chip that looked like a button and did nothing — the
# exact "capability that looks present and does nothing" pattern this product exists to remove, and
# which I had criticised in an adapter an hour earlier. A frontend needs a CONTRACT: something it
# can poll, and something it can act against.
#
# Every value here is JSON-serialisable and comes from the module that owns it. This adds no
# derivation of its own; `state()` is `collect()` made transportable.
# --------------------------------------------------------------------------------------------- #

def state(d: dict[str, Any] | None = None) -> dict[str, Any]:
    """The whole panel payload, JSON-safe. One request, because the panel has one view of the
    machine and splitting it into six endpoints would let them disagree mid-refresh.
    `d` lets a caller that already ran `collect()` (status --json) reuse it."""
    d = d if d is not None else collect()
    store = d.get("store") or {}
    servers = store.get("servers") or {}
    entries = d.get("entries") or {}
    calls = d.get("recent_calls") or []

    items = []
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        key = next((k for k, v in servers.items()
                    if name in ((v or {}).get("aliases") or [])), None)
        det = server_detail(store, key, calls) if key else None
        items.append({
            "name": name, "key": key, "tier": _classify(name, key, d),
            "kind": "local" if entry.get("command") else "remote",
            "clients": list(entry.get("_clients") or []),
            "tools": len(det["current_tools"]) if det else None,
            "approved_tools": len(det["approved_tools"]) if det else None,
            "calls_seen": det["calls_seen"] if det else 0,
            "calls_by_tool": det["calls_by_tool"][:8] if det else [],
            "cost_index": det["cost_index"] if det else None,
            "transport": det["transport"] if det else None,
            "protocol": det["protocol"] if det else None,
            "snapshots": det["snapshots"] if det else 0,
            "measured_at": det["measured_at"] if det else None,
            "aliases": det["aliases"] if det else [],
            "observed": name in (d.get("observed") or {}),
        })
    order = {t: i for i, (t, _, _) in enumerate(TIERS)}
    items.sort(key=lambda r: (order.get(r["tier"], 9), r["name"]))

    by_hour: dict[str, int] = {}
    for c in calls:
        by_hour[str(c.get("ts", ""))[:13]] = by_hour.get(str(c.get("ts", ""))[:13], 0) + 1

    from . import baseline as _b
    return {
        "generated_at": _now(),
        "servers": items,
        "tiers": [{"id": t, "label": lbl, "why": why} for t, lbl, why in TIERS],
        "counts": {t: sum(1 for i in items if i["tier"] == t) for t, _, _ in TIERS},
        # FIVE values: `_agent_rows` yields (client_key, label, state, count, detail). Unpacking
        # four raised ValueError on any machine that has an agent at all — which is every machine
        # this payload is for. The client key is carried rather than dropped: it is what a Protect
        # action has to send back, and labels are display-only.
        "agents": [{"client": client, "label": lbl, "state": st, "servers": n, "detail": det}
                   for client, lbl, st, n, det in _agent_rows(d)],
        "activity": d.get("activity") or {},
        "series": [by_hour[k] for k in sorted(by_hour)][-24:],
        "calls": [{k: c.get(k) for k in ("ts", "decision", "server", "tool", "adapter", "basis")}
                  for c in calls[:50]],
        "breakdown": {k: v for k, v in call_breakdown(calls).items()},
        "runs": [{"started_at": str(getattr(r, "started_at", "")), "kind": getattr(r, "kind", ""),
                  "status": getattr(r, "status", ""), "target": getattr(r, "target", "") or "",
                  "run_id": getattr(r, "run_id", "")} for r in (d.get("runs") or [])],
        "pending": list(d.get("pending") or []),
        "verify_blocked": d.get("verify_blocked"),
        # The UI must know whether an action is POSSIBLE before it offers it. A button that is
        # rendered and then refuses is the thing this layer exists to stop.
        "can_act": _b.approval_blocked_reason() is None,
        "act_blocked_reason": _b.approval_blocked_reason(),
        "errors": d.get("errors") or {},
    }


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _elapsed(stamp: object) -> str:
    """"1m 12s" since an ISO-8601 Z stamp — a MOVING clock for a running action, distinct from
    _ago's past-tense phrasing. "0s" rather than a guess when unparseable."""
    from datetime import datetime, timezone
    if not isinstance(stamp, str) or not stamp:
        return "0s"
    try:
        when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return "0s"
    secs = max(0, int((datetime.now(timezone.utc) - when).total_seconds()))
    return f"{secs}s" if secs < 60 else f"{secs // 60}m {secs % 60:02d}s"


def run_scan() -> dict[str, Any]:
    """Trigger a real re-scan. Returns {ok, message}.

    Runs the SAME entry point the CLI does — `mcpgawk scan --track` in a subprocess — rather than
    reaching into the scan internals. A second scan path is a second answer, and this repo has paid
    for several of those. Subprocess rather than in-process because a scan can take a while; the
    panel must not block its own event loop on it.

    NO `--yes`. A GUI button must NEVER auto-launch every local server: some are OAuth proxies
    (mcp-remote) that block forever waiting for interactive browser auth, so `--yes` from a
    background thread hangs indefinitely (shipped in 0.1.20, hit immediately). Launching a local
    server runs its code and is a consent decision — that belongs to the front door `mcpgawk` in
    a terminal, never to a button. Without `--yes` the scan default-denies local launches and
    completes in seconds: it refreshes remote servers and re-reads what is already known.
    """

    import subprocess
    import sys as _sys
    try:
        # stdin=DEVNULL IS LOAD-BEARING, not tidiness. Without it the child inherits the terminal
        # the panel was launched from, so `consent.py` sees `sys.stdin.isatty()` is True, prints
        # "Launch these N local servers? [y/N]" to a stderr WE ARE CAPTURING, and blocks on a reply
        # nobody can type. The scan then sits there until the timeout below fires. That is the
        # founder's original "Running scan… gets stuck" report — and removing `--yes` in 0.1.20
        # created it, while that commit claimed the scan "completes in seconds". It was never run
        # through the button. With no stdin, consent takes its non-interactive default-deny path:
        # remote servers refresh, local ones are not launched, seconds not minutes.
        proc = subprocess.run([_sys.executable, "-m", "mcpgawk.cli", "scan", "--track"],
                              stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "scan timed out (120s) — a server may be unresponsive; "
                "run `mcpgawk` in a terminal to scan local servers with consent"}
    except OSError as exc:
        return {"ok": False, "message": f"could not start a scan: {exc}"}
    # A scan exits non-zero when it FOUND something. That is not a failure of the scan.
    ok = proc.returncode in (0, 1)
    return {"ok": ok,
            "message": ("rescanned — remote servers refreshed. Local servers are launched only "
                        "from `mcpgawk` in a terminal, with your consent." if ok
                        else (proc.stderr or "scan failed").strip().splitlines()[-1][:200])}


#: Shared state for a background action (scan/verify), so the page can show "running…" and then
#: the result without the request that started it blocking for the whole minute-plus it takes.
#: Identity of THIS running process, so the page can answer "am I looking at what I just built?".
#:
#: NOT the package version. `mcpgawk.__version__` resolves through importlib.metadata, which reads
#: the INSTALLED dist-info — and in a source checkout that is whatever was last `pip install`-ed.
#: On 2026-07-30 it reported v0.1.8 while pyproject said 0.1.20 and the code being served was newer
#: than both. A build indicator exists to be trusted; populating it from a number already known to
#: be wrong is worse than having none. (Same stale metadata makes the CLI's upgrade nag advise
#: users toward an OLDER build than the one they are running.)
#:
#: The truthful answer is the mtime of the code actually loaded: it is correct for a wheel install,
#: an editable install and a bare checkout alike, and it moves the moment the file does.
def _build_identity() -> tuple[str, str]:
    from datetime import datetime
    try:
        code_at = datetime.fromtimestamp(Path(__file__).stat().st_mtime).strftime("%d %b %H:%M")
    except OSError:                                 # noqa: BLE001 - identity must never break the page
        code_at = "?"
    return code_at, datetime.now().strftime("%H:%M:%S")


_CODE_AT, _STARTED = _build_identity()


def _staleness_note(module_file: Path | None = None) -> str:
    """A loud line when this INSTALL is older than the source checkout it was built from.

    [FOUNDER] 2026-08-15: a full release-gate walk drove an install 12 hours behind the
    checkout — palette, redirects and scroll fixes all existed and none were on the walked
    page, and nothing said so. Dev-machine only by construction: the uv tool receipt records
    the source directory it was built from; a customer install has no checkout on disk and a
    checkout run has no receipt above it, so both render nothing. Never breaks the page.
    """
    try:
        me = (module_file or Path(__file__)).resolve()
        receipt = next((p / "uv-receipt.toml" for p in me.parents
                        if (p / "uv-receipt.toml").is_file()), None)
        if receipt is None:
            return ""
        import re as _re
        m = _re.search(r'directory\s*=\s*"([^"]+)"', receipt.read_text(encoding="utf-8"))
        if not m:
            return ""
        src = Path(m.group(1)) / "src" / "mcpgawk"
        if not src.is_dir():
            return ""
        newest_src = max((f.stat().st_mtime for f in src.glob("*.py")), default=0.0)
        here = me.parent
        newest_installed = max((f.stat().st_mtime for f in here.glob("*.py")), default=0.0)
        behind = newest_src - newest_installed
        if behind < 60:
            return ""
        hours, mins = int(behind // 3600), int(behind % 3600 // 60)
        age = f"{hours}h {mins}m" if hours else f"{mins}m"
        return (f'<div class="stalecode">This install is <b>{age} behind its source '
                f'checkout</b> — the page you are walking predates the newest code in '
                f'{_esc(str(src.parent.parent))}. Reinstall to walk current code: '
                f'<code>uv tool install --force --reinstall --no-cache {_esc(m.group(1))}</code>'
                f'</div>')
    except Exception:  # noqa: BLE001 — a freshness hint must never break the page
        return ""


class _ActionState(dict):
    """The action banner's state, with URL credentials masked ON THE WAY IN.

    A configured server URL can carry its own key (`…/mcp?clientId=…&apiKey=…`, the shape a hosted
    MCP server actually uses and the shape one server on this machine has). Several action paths
    echo that URL into a message without meaning to: `subprocess.TimeoutExpired` stringifies to the
    WHOLE command line, and a sign-in timeout is the expected case, not an exotic one — the OAuth
    flow waits 330s for a human who may simply walk away. That message is rendered on the page AND
    persisted to disk by `_persist_action`, so it outlives the terminal.

    The gate is on the WRITE, not on the thirteen callers. A rule that lives in one caller is not a
    rule — this repo has paid for that shape repeatedly, most recently when the failure ladder
    printed a key that `redact_url` already knew how to mask. Every `update()` and every item
    assignment goes through the same scrub, including a state restored from disk, so a future
    action inherits the redaction without having to remember it.
    """

    #: Free-text fields a human reads. Masked with `redact_urls_in_text`, which keeps the host and
    #: the parameter names visible — an operator still has to be able to see WHICH server failed.
    #: `login_url` is deliberately NOT here. It is a one-time authorisation request the human must
    #: open verbatim; masking its query would hand over a broken link — and it carries a PKCE
    #: challenge and client id, which are public by construction, not secrets.
    _TEXT_FIELDS = ("message", "label", "notice")

    @staticmethod
    def _mask(text: str) -> str:
        """URL credentials first, then bare credential shapes.

        Until the 2026-08-13 sweep this masked URLs ONLY. The Playground takes ARGUMENTS typed by
        the user (`{"token": "sk-live-…"}`) and echoes a parse failure straight into this banner,
        and a pasted agent key is not a URL — so the one shape a human is most likely to hand the
        panel was the one shape the gate did not cover.

        Order is load-bearing and safe: `redact_url` leaves `apiKey=***`, which is too short for the
        prose redactor to re-match, so the readable masked URL survives the second pass.
        """
        from .redact import redact, redact_urls_in_text
        return redact(redact_urls_in_text(text) or "") or ""

    @staticmethod
    def _scrub(key: str, value: Any) -> Any:
        if key in _ActionState._TEXT_FIELDS and isinstance(value, str):
            return _ActionState._mask(value)
        if key == "rows" and isinstance(value, list):
            # Rows carry per-server `detail` and fix text down the same pipe to page and disk.
            return [{k: (_ActionState._mask(v) if isinstance(v, str) else v) for k, v in r.items()}
                    if isinstance(r, dict) else r for r in value]
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, self._scrub(key, value))

    def update(self, *args: Any, **kwargs: Any) -> None:       # type: ignore[override]
        for key, value in dict(*args, **kwargs).items():
            self[key] = value


_ACTION: dict[str, Any] = _ActionState(
    {"running": False, "label": "", "message": "", "rows": [], "at": ""})


def _begin_action(label: str) -> None:
    """Stamp a new action's label and CLEAR every field the previous action left behind.

    Driven live 2026-08-14: after a kite sign-in, every later banner still carried "Open the
    sign-in page" (the stale login_url), and the synchronous actions never set a label at all —
    "Start monitoring" reported its result under the headline "login-configure · __nosuch__".
    A banner that mixes two actions' state is wrong twice at once."""
    _ACTION.update(label=label, message="", rows=[], notice="", level="",
                   secret="", snippet="", login_url="", setup_text="", setup_key="",
                   signin_pending="", at=_now())


def _open_login_in_browser(url: str) -> None:
    """The panel runs on the operator's own machine, so a sign-in link OPENS THE BROWSER ITSELF —
    rendering only a link was a CLI habit ("it is just providing the link", founder 25 Aug). The
    banner keeps the link as the fallback for a blocked popup or an unusual default browser."""
    if not url or os.environ.get("MCPGAWK_NO_BROWSER"):
        return
    try:
        import threading
        import webbrowser
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    except Exception:                              # noqa: BLE001 — the link on the banner remains
        pass


#: The last completed action, kept ON DISK. `_ACTION` is in-memory, so restarting the panel erased
#: the result of a five-minute verify — the founder restarted three times and each time the page
#: went blank of everything he had just run. A result that vanishes when the process does is not a
#: record. Never stores `running`: a result is only ever persisted once it has finished.
def behaviour_profile_path() -> Path:
    """Where VERIFY writes what it observed, and everything else reads it.

    An env override exists for the same reason MCPGAWK_HISTORY and MCPGAWK_RUNS have one: without
    it the test suite writes to the developer's REAL profile. conftest's
    `_never_touch_real_home_state` was written on 2026-07-27 after exactly that happened to the
    enforce audit log, but this path was hardcoded and so slipped through the guard — every full
    suite run silently overwrote the founder's observed-behaviour data, twice diagnosed as a
    mystery writer before the cause was found on 2026-07-31.
    """
    override = os.environ.get("GAWK_BEHAVIOUR_PROFILE")
    return Path(override) if override else Path.home() / ".gawk" / "behaviour.json"


def _action_store() -> Path:
    return behaviour_profile_path().parent / "last-action.json"


def _persist_action() -> None:
    try:
        path = _action_store()
        path.parent.mkdir(parents=True, exist_ok=True)
        # `login_url` and `setup_text`/`setup_key` are intentionally absent: one-time sign-in
        # state has no business outliving the run in a file - a stale link or keypair block would
        # invite the human to act on a dead flow.
        keep = {k: _ACTION.get(k) for k in ("label", "message", "rows", "level", "at")}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(keep), encoding="utf-8")
        tmp.replace(path)                          # atomic: never leave a half-written result
    except (OSError, TypeError, ValueError):
        pass                                       # a read-only HOME must not break the action


def load_last_action() -> None:
    """Restore the last completed action into _ACTION, if nothing has run in this process yet."""
    if _ACTION.get("running") or _ACTION.get("message"):
        return
    try:
        path = _action_store()
        if not path.is_file():
            return
        saved = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(saved, dict):
            _ACTION.update({k: saved.get(k) for k in ("label", "message", "rows", "level", "at")
                            if saved.get(k) is not None})
    except (OSError, ValueError):
        pass
_ACTION_LOCK: Any = None


def _run_action_bg(kind: str, target: str | None = None,
                   value: str | None = None) -> None:
    """Run a long action (scan/verify) in the background, recording its state for the page.

    Never raises: a control panel whose own action button crashes the server is worse than one
    that reports the failure. The result lands in _ACTION for the next page render to show.
    """
    import threading
    global _ACTION_LOCK
    if _ACTION_LOCK is None:
        _ACTION_LOCK = threading.Lock()
    with _ACTION_LOCK:
        if _ACTION["running"]:
            # One at a time — but NEVER silently. This was a bare `return`, so during a two-minute
            # scan every other button did nothing with no feedback, which the founder experienced
            # as "it is running in the background throughout whenever we click on any button"
            # (2026-08-13). The dropped click is now SAID on the running banner.
            wanted = f"{kind} · {target}" if target else kind
            _ACTION.update(notice=f"‘{wanted}’ is queued — {_ACTION['label']} is still running "
                                  f"({_elapsed(_ACTION.get('at'))} so far). One action at a time; "
                                  f"start ‘{wanted}’ again once this finishes.")
            return
        _begin_action(f"{kind} · {target}" if target else kind)
        _ACTION.update(running=True)

    def work():
        # The panel's runs belong in the SAME provenance trail as the CLI's — Evidence listed
        # only CLI runs, so a verify clicked in the panel left no row at all (founder's tab
        # audit, 2026-08-15). Login stays un-logged deliberately: it is an auth act, not a
        # check run, and the closed KINDS set is closed for a reason.
        from . import runlog as _runlog
        run_id = _runlog.start_run(kind, target or "fleet") if kind in ("scan", "verify") else None
        status = _runlog.ERROR
        try:
            if kind == "login-configure":
                res = run_login_configure(target, value)
            elif kind == "scan":
                res = run_scan()
            elif kind == "verify":
                res = run_verify_fleet(target)
            elif kind == "login":
                res = run_login(target)
            elif kind == "login-done":
                res = run_login_done(target)
            else:
                res = {"ok": False, "message": f"unknown action {kind!r}"}
            msg = res.get("message") or ("done" if res.get("ok") else "failed")
            rows = res.get("rows") or []
            level = res.get("level") or ("ok" if res.get("ok") else "bad")
            status = (_runlog.FINDINGS if level == "bad"
                      else _runlog.OK if res.get("ok") else _runlog.INCOMPLETE)
        except Exception as exc:                  # noqa: BLE001 — an action must not kill the panel
            msg, rows, level = f"{type(exc).__name__}: {exc}", [], "bad"
        with _ACTION_LOCK:
            # `level` travels too. `_begin_action` clears it and this update never set it, so a
            # result with no rows — "verify timed out — INCOMPLETE, not clean", "did not complete
            # (exit 3)", an exception — rendered under the banner's fallback: GREEN. The headline
            # is the worst thing found; a failure with nothing to list is still a failure.
            _ACTION.update(running=False, message=msg, rows=rows, notice="", level=level,
                           at=_now())
        _persist_action()
        _runlog.finish_run(run_id, status, {"message": msg[:400]})

    threading.Thread(target=work, daemon=True).start()


def gateway_tools(live: dict[str, Any] | None, key: str = "") -> dict[str, Any]:
    """The tools THIS key can see through the running gateway, for the Playground picker.

    Uses the gateway's own REST skin (`GET /api/tools`), which invokes the same handlers as the
    MCP endpoint — so the list is per-caller filtered by the same rule that will decide the call.
    A failure is returned as a reason, never as an empty list: "this key sees no tools" and "we
    could not ask" are different facts.
    """
    listen = (live or {}).get("listen")
    if not listen:
        return {"ok": False, "tools": [], "error": "no gateway with an HTTP endpoint is running"}
    import urllib.error
    import urllib.request
    url = listen.rsplit("/mcp", 1)[0] + "/api/tools"
    req = urllib.request.Request(url)
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            doc = json.loads(r.read().decode("utf-8", "replace"))
        return {"ok": True, "tools": [t.get("name") for t in (doc.get("tools") or [])]}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "tools": [], "error": f"gateway answered {exc.code}"}
    except Exception as exc:                      # noqa: BLE001 — the reason goes on the page
        return {"ok": False, "tools": [], "error": f"{type(exc).__name__}: {exc}"}


def run_playground_call(tool: str | None, key: str | None,
                        arguments: str | None = None) -> dict[str, Any]:
    """Call ONE tool through the running gateway, as an agent would, and report the decision.

    The proof surface: the value of a gateway is the decision it makes, and until now the panel
    could only show decisions after some other process happened to make them. This makes one on
    demand — through the gateway's REST skin, which runs the SAME handlers, identity resolution
    and audit write as the MCP endpoint, so what you see here is what an agent would get.

    A BLOCK is a successful test of the gateway, not an error, and is reported that way.
    """
    tool = (tool or "").strip()
    if not tool:
        return {"ok": False, "message": "pick a tool to call"}
    live = (gateway_status().get("live") or {})
    listen = live.get("listen")
    if not listen:
        return {"ok": False, "message": "no gateway with an HTTP endpoint is running — start one "
                                        "with `--listen 127.0.0.1:8080`"}
    args: dict[str, Any] = {}
    if arguments and arguments.strip():
        try:
            parsed = json.loads(arguments)
            if not isinstance(parsed, dict):
                raise ValueError("arguments must be a JSON object")
            args = parsed
        except ValueError as exc:
            return {"ok": False, "message": f"arguments are not a JSON object: {exc}"}
    if live.get("keys") and not (key or "").strip():
        return {"ok": False, "message": "this gateway checks keys — paste an agent key to call "
                                        "as that agent (that is also what the audit will record)"}
    import urllib.error
    import urllib.request
    url = listen.rsplit("/mcp", 1)[0] + "/api/tools/call"
    body = json.dumps({"name": tool, "arguments": args}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key.strip()}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            doc = json.loads(r.read().decode("utf-8", "replace"))
        text = str(doc.get("content") or "")[:400]
        return {"ok": True, "level": "ok", "verdict": "ALLOWED",
                "message": f"{tool}: ALLOWED by the gateway — {text}"}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            doc = json.loads(exc.read().decode("utf-8", "replace"))
            detail = str(doc.get("error") or "")[:400]
        except Exception:                         # noqa: BLE001 — body may not be JSON
            detail = f"HTTP {exc.code}"
        # A block is the gateway WORKING. Levelled 'warn', never 'bad': styling a successful
        # refusal as a failure would teach the operator to read their own control as breakage.
        return {"ok": True, "level": "warn", "verdict": "BLOCKED",
                "message": f"{tool}: BLOCKED by the gateway — {detail}"}
    except Exception as exc:                      # noqa: BLE001
        return {"ok": False, "level": "bad",
                "message": f"could not reach the gateway: {type(exc).__name__}: {exc}"}


#: The role bundles the panel can build from what a scan already recorded. Deliberately three,
#: not a taxonomy: an operator picking from three understood options grants correctly, while a
#: long list gets skimmed and over-granted — and over-granting is the failure a gateway exists
#: to prevent.
ROLE_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("reader", "every tool the server declares read-only"),
    ("operator", "read-only tools plus the writes that are not destructive"),
    ("admin", "everything the fleet exposes, including destructive tools"),
)


def roles_from_baseline(d: dict[str, Any]) -> dict[str, list[str]]:
    """Grant bundles derived from the tools this machine has ALREADY seen, keyed by role name.

    Roles were hand-typed scope strings, which asks an operator to know both our scope vocabulary
    and every tool their servers expose. But an approved baseline already records each item's
    declared annotations as VALUES (drift._item_annotations), and the gateway derives its scopes
    from exactly those hints (enforce.derive_scopes.derive_policy: readOnlyHint -> `read`,
    destructiveHint -> `write:<tool>`, neither -> `unguarded`). So the bundles can be computed
    from what we know instead of typed from memory.

    Deliberately conservative where the server is vague: a tool with NO usable annotation lands in
    `unguarded`, and `unguarded` is granted only to admin — an unannotated tool is one the server
    author declined to describe, and reading that silence as "safe for everyone" is the mistake
    this whole product argues against.
    """
    from . import history as _h

    store = (d.get("store") or {}).get("servers") or {}
    read_tools: set[str] = set()
    write_tools: set[str] = set()
    destructive: set[str] = set()
    unannotated = False
    for key in store:
        rec = _h.approved({"servers": store}, key) or {}
        anns = rec.get("annotations")
        if not isinstance(anns, dict):
            continue
        for item, ann in anns.items():
            # Items are keyed `{kind}.{name}` (drift._iter_items) — tool./prompt./resource. Only
            # tools are callable, and the PREFIX MUST BE STRIPPED: the first cut of this produced
            # `write:tool.create_directory`, a scope no policy would ever match, which would have
            # granted nothing while looking exactly like a working role.
            if not item.startswith("tool."):
                continue
            name = item[len("tool."):]
            ann = ann if isinstance(ann, dict) else {}
            ro, de = ann.get("readOnlyHint"), ann.get("destructiveHint")
            if de is True:
                destructive.add(name)
            elif ro is True:
                read_tools.add(name)
            elif ro is False:
                write_tools.add(name)
            else:
                unannotated = True
    out = {
        "reader": ["read"] if read_tools else [],
        "operator": (["read"] if read_tools else []) + sorted(f"write:{t}" for t in write_tools),
        "admin": ((["read"] if read_tools else [])
                  + sorted(f"write:{t}" for t in (write_tools | destructive))
                  + (["unguarded"] if unannotated else [])),
    }
    return {k: v for k, v in out.items() if v}


def role_evidence(d: dict[str, Any]) -> str:
    """One line saying what the offered bundles are built FROM — a role proposed with no visible
    basis is a guess wearing a name."""
    roles = roles_from_baseline(d)
    if not roles:
        return ("No approved baseline yet, so there is nothing to build roles from. Scan and "
                "approve a server first — a role is a statement about tools we have seen.")
    reads = len([g for g in roles.get("admin", []) if g == "read"])
    writes = len([g for g in roles.get("admin", []) if g.startswith("write:")])
    return (f"Built from your approved baselines: "
            f"{'read-only tools' if reads else 'no read-only tools'}, {writes} write/destructive "
            f"tool(s)"
            + (" · tools your servers left unannotated are granted only to admin"
               if "unguarded" in roles.get("admin", []) else ""))


def _ensure_role(keys_file: str, role: str, grants: list[str]) -> None:
    """Write a role bundle into the principals registry if it is not already there.

    Never overwrites an existing bundle: an operator who tuned `reader` by hand must not have it
    silently replaced by our derivation the next time someone issues a key. Refuses to create an
    EMPTY bundle — a role granting nothing reads as protection while the key is useless, the same
    reason PrincipalRegistry refuses an unknown role at load.
    """
    if not grants:
        raise ValueError(f"{role} would grant nothing — approve a scanned server first, so the "
                         f"bundle can be built from tools we have actually seen")
    path = Path(keys_file)
    doc = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"principals": {}}
    roles = doc.setdefault("roles", {})
    if role in roles:
        return
    roles[role] = list(grants)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def principal_upstreams(keys_file: str | None) -> dict[str, list[str]]:
    """{principal: [backend, …]} it carries its OWN credential for. NAMES ONLY — never values.

    Two auth axes look identical in a UI and must not be confused. The operator's browser login
    (the sign-in button) is the OPERATOR's credential: right for scanning and verifying. A
    gateway that then used that one token for every agent behind it would make every agent act
    as the operator, and the audit could not tell them apart — which is why the engine refuses
    it (identity.upstream_for grants an upstream credential only to an AUTHENTICATED principal,
    never a declared name). So this surface answers the second question: which agents can reach a
    server as THEMSELVES.

    Deliberately read-only: adding a credential means putting a secret somewhere, and this panel
    does not collect secrets — it says who has one and points at where they are declared.
    """
    if not keys_file:
        return {}
    try:
        doc = json.loads(Path(keys_file).read_text(encoding="utf-8"))
        principals = doc.get("principals")
        if not isinstance(principals, dict):
            return {}
        out: dict[str, list[str]] = {}
        for name, spec in principals.items():
            up = (spec or {}).get("upstream") if isinstance(spec, dict) else None
            if isinstance(up, dict) and up:
                out[str(name)] = sorted(str(b) for b in up)
        return out
    except Exception:                             # noqa: BLE001 — unreadable means "unknown"
        return {}


def run_gateway_setup() -> dict[str, Any]:
    """Generate a loopback gateway config + principals template from the CURRENT fleet — files
    only, never a process. Starting a gateway is credential custody (it holds every backend
    secret), and custody is the human's act — the same invariant as the approve button
    ([FOUNDER] 2026-08-15: "provide the option to configure the gateway", answered with an
    affordance that does all the work and hands over ONE command). Never overwrites: a re-click
    reports the existing paths; delete the directory to regenerate.

    No secret is ever written: backend env vars become ${NAME} placeholders resolved from the
    operator's environment at start; the one generated operator key is written 0600 into the
    principals file the operator owns."""
    import secrets as _secrets
    import socket as _socket

    from . import discover
    gw_dir = behaviour_profile_path().parent / "gateway"
    cfg_p, pr_p = gw_dir / "gateway.yaml", gw_dir / "principals.json"
    start_cmd = f"mcpgawk enforce serve --gateway-config {cfg_p}"
    if cfg_p.exists() or pr_p.exists():
        return {"ok": True,
                "message": f"gateway config already generated — nothing overwritten. Start it "
                           f"in your terminal: {start_cmd}  (delete {gw_dir} to regenerate)"}
    try:
        servers = discover.discover_servers()
    except Exception as exc:                      # noqa: BLE001 — the reason goes ON the page
        return {"ok": False, "message": f"could not read the fleet to build backends: {exc}"}
    lines, folded = [], []
    for name, e in sorted(servers.items()):
        if not isinstance(e, dict):
            continue
        if e.get("command"):
            # Resolve Desktop-extension placeholders the way the scan path does — the raw entry
            # carries dxt-isms like ${__dirname}, which the gateway's loader reads as an unset
            # env var and (rightly) refuses to start on. Caught live on the founder's first
            # real start attempt, 2026-08-15.
            from . import dxt as _dxt
            launch = _dxt.resolve_for_launch(e) or e
            _blob = " ".join([str(launch.get("command") or "")]
                             + [str(a) for a in (launch.get("args") or [])])
            if "${" in _blob:
                folded.append(f"{name} (its launch command still carries unresolved "
                              f"placeholders — add this backend by hand)")
                continue
            from .redact import contains_secret as _cs
            if _cs(_blob):
                folded.append(f"{name} (its launch arguments embed a credential — add this "
                              f"backend by hand with the secret in env ${{VAR}})")
                continue
            e = launch
            lines.append(f"  {name}:")
            lines.append(f"    command: {e['command']}")
            if e.get("args"):
                lines.append(f"    args: {list(map(str, e['args']))!r}".replace("'", '"'))
            env = e.get("env") or {}
            if env:
                lines.append("    env:")
                from .decision import _CREDENTIAL_SHAPED as _cred
                from .redact import contains_secret as _secretish
                for k, v in env.items():
                    # A secret never reaches the file: credential-shaped names and
                    # secret-shaped values become ${VAR} for the operator's environment to
                    # supply. Everything else is written literally — REVOLUTX_CONFIG_DIR is a
                    # path, and demanding an export for a non-secret made the gateway refuse
                    # to start on values Desktop itself launches with (founder's second start
                    # attempt, 2026-08-15).
                    if _cred.search(k) or _secretish(str(v)):
                        lines.append(f'      {k}: "${{{k}}}"')
                    else:
                        lines.append(f'      {k}: {json.dumps(str(v))}')
        elif e.get("url"):
            # A URL can EMBED a credential in its query string (brandfetch does:
            # ?apiKey=…) — and this generator wrote it verbatim on its first live run
            # (caught 2026-08-15, the same credentials-in-URLs class as the monitor-alert
            # leak). The gateway only resolves ${VAR} in headers/env, not URLs, so a
            # placeholder would just break the URL: fold the server, with the reason.
            from urllib.parse import parse_qsl, urlparse
            _q = [k for k, _ in parse_qsl(urlparse(str(e["url"])).query)]
            from .decision import _CREDENTIAL_SHAPED
            if any(_CREDENTIAL_SHAPED.search(k) for k in _q):
                folded.append(f"{name} (its URL embeds a credential — add this backend by "
                              f"hand with the secret in a header ${{VAR}})")
            else:
                lines.append(f"  {name}:")
                lines.append(f"    url: {e['url']}")
        else:
            folded.append(name)
    if not lines:
        return {"ok": False, "message": "no launchable or URL server in the fleet — a gateway "
                                        "would have nothing to front"}
    folded_note = ""
    if folded:
        folded_note = ("# NOT included (nothing a gateway can launch or reach): "
                       + ", ".join(folded) + "\n")
    operator = f"operator@{_socket.gethostname().split('.')[0]}"
    key = _secrets.token_urlsafe(24)
    cfg = (
        "# Generated by the mcpgawk panel from the fleet it could see — no secrets inside.\n"
        "# ${VAR} values are read from the environment when the gateway starts and fail loudly\n"
        "# if unset. Grants are deny-by-default: add them per principal in principals.json.\n"
        "listen: 127.0.0.1:8080\n"
        f"principals: {pr_p}\n"
        f"audit_db: {gw_dir / 'audit.db'}\n"
        "call_timeout: 30\n"
        + folded_note +
        "backends:\n" + "\n".join(lines) + "\n")
    principals = json.dumps({"principals": {operator: {"key": key, "grants": []}}}, indent=2)
    try:
        gw_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        cfg_p.write_text(cfg, encoding="utf-8")
        cfg_p.chmod(0o600)
        pr_p.write_text(principals + "\n", encoding="utf-8")
        pr_p.chmod(0o600)
    except OSError as exc:
        return {"ok": False, "message": f"could not write {gw_dir}: {exc}"}
    return {"ok": True,
            "message": f"gateway config generated from your fleet ({sum(1 for ln in lines if not ln.startswith('    '))} backend(s)"
                       f"{', ' + str(len(folded)) + ' folded' if folded else ''}) — no secrets "
                       f"written, your key is in {pr_p} (0600). Start it in YOUR terminal (it "
                       f"will hold backend credentials; that belongs in your hands): {start_cmd}"}


def run_gateway_start() -> dict[str, Any]:
    """Generate (if needed) and START the gateway, detached, from the panel.

    The tokened click IS the consent — the same model as monitor-start, which already launches
    a credential-inheriting daemon from this page ([FOUNDER] 2026-08-15: expecting a manual
    command was "pathetic experience"; the earlier no-auto-start stance was inconsistent with
    the product's own consent model). Fail-closed is untouched: a missing ${VAR} or a bad
    config kills the child in its first second, and its OWN last words land on the banner —
    the same honest wait-and-report as monitoring."""
    import subprocess
    import sys as _sys
    import tempfile
    import time

    gw = gateway_status()
    live = gw.get("live") or {}
    if live.get("listen"):
        return {"ok": False, "message": f"a gateway is already running at {live['listen']}"}
    cfg = behaviour_profile_path().parent / "gateway" / "gateway.yaml"
    if not cfg.is_file():
        res = run_gateway_setup()
        if not res.get("ok"):
            return res
    cmd = [_sys.executable, "-m", "mcpgawk", "enforce", "serve", "--gateway-config", str(cfg)]
    log = tempfile.NamedTemporaryFile(prefix="mcpgawk-gateway-", suffix=".log", delete=False)
    try:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,  # noqa: S603
                                start_new_session=True)
    except Exception as exc:                      # noqa: BLE001 — the reason goes ON the page
        return {"ok": False, "message": f"could not start the gateway: {exc}"}
    # Config errors (an unset ${VAR}, a bad key) exit fast and MUST be reported as the child
    # said them; backends then connect serially, so a healthy child is simply still running.
    for _ in range(30):
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    if proc.poll() is not None:
        try:
            lines = [ln.strip() for ln in Path(log.name).read_text(errors="replace").splitlines()
                     if ln.strip()]
        except OSError:
            lines = []
        cause = next((ln for ln in lines
                      if any(w in ln.lower() for w in
                             ("licen", "error", "could not", "refus", "not set", "unknown",
                              "traceback", "failed", "crash"))), None)
        detail = f" — {cause or (lines[-1] if lines else f'exit {proc.returncode}')}"
        return {"ok": False, "message": f"the gateway did not stay up{detail}"}
    return {"ok": True,
            "message": f"gateway starting (pid {proc.pid}) — backends connect one by one and "
                       f"this tab flips to RUNNING when the endpoint is served. A server that "
                       f"cannot be reached stays honestly 'unavailable' without sinking the "
                       f"rest. Log: {log.name}"}


def run_monitor_start(include_local: bool = False) -> dict[str, Any]:
    """Start continuous monitoring from the panel, watching what this machine already has.

    THE GAP THIS CLOSES (audit 2026-08-02): monitoring was production-grade and NOTHING started
    it. `bootstrap_config_from_machine` existed with no caller, so a customer who never typed
    `mcpgawk monitor run` got zero monitoring while paying for it. LiteLLM's lesson applies —
    protective behaviour should not require an operator to discover a flag.

    Detached on purpose: the daemon outlives this panel process, and its heartbeat run row is what
    the Monitor tab reads to say RUNNING. Nothing is invented here — this is the same command the
    docs give, with the config the machine can already derive.
    """
    import subprocess
    import sys as _sys
    import tempfile
    import time
    try:
        import importlib.util
        if importlib.util.find_spec("gawk_platform") is None:
            return {"ok": False, "message": "continuous monitoring ships with mcpgawk Platform"}
    except Exception:                             # noqa: BLE001
        return {"ok": False, "message": "continuous monitoring ships with mcpgawk Platform"}
    if monitor_status().get("running") is True:
        return {"ok": False, "message": "monitoring is already running on this machine"}
    # NO --config: that is what makes the daemon monitor every server this machine already has
    # (bootstrap_config_from_machine). There is no --from-machine flag; passing one would abort
    # with "unrecognized arguments" while this page happily reported success.
    cmd = [_sys.executable, "-m", "mcpgawk", "monitor", "run"]
    if include_local:
        # The click on the labelled button IS the consent --include-local asks for.
        cmd.append("--include-local")
    log = tempfile.NamedTemporaryFile(prefix="mcpgawk-monitor-", suffix=".log", delete=False)
    try:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,  # noqa: S603
                                start_new_session=True)
    except Exception as exc:                      # noqa: BLE001 — the reason goes ON the page
        return {"ok": False, "message": f"could not start monitoring: {exc}"}
    # A DETACHED start that reports success the moment Popen returns is a lie waiting to happen:
    # a licence refusal, a missing store or a bad config exits in well under a second and the page
    # would still say "started". So wait, and if it is already gone, report ITS OWN last words.
    for _ in range(20):
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    if proc.poll() is not None:
        try:
            lines = [ln.strip() for ln in Path(log.name).read_text(errors="replace").splitlines()
                     if ln.strip()]
        except OSError:
            lines = []
        # The LAST line is often an unrelated upgrade notice; the CAUSE is usually earlier. Prefer
        # a line that names a failure, else fall back to the tail. Reporting the wrong line sends
        # the operator to debug something that is working.
        cause = next((ln for ln in lines
                      if any(w in ln.lower() for w in
                             ("licen", "error", "could not", "refus", "no mcp servers",
                              "not found", "traceback", "failed"))), None)
        detail = f" — {cause or (lines[-1] if lines else f'exit {proc.returncode}')}"
        return {"ok": False, "message": f"monitoring did not stay up{detail}"}
    return {"ok": True, "message": f"monitoring started (pid {proc.pid}) — it watches the servers "
                                   f"this machine already has and raises an alert when one moves. "
                                   f"This page shows it as RUNNING once it registers."}


def monitor_status(home: Path | str | None = None) -> dict[str, Any]:
    """What continuous monitoring is doing on this machine, read-only.

    The pillar was invisible here: `monitor.db` was read by `mcpgawk monitor status` and nothing
    else, so the surface the operator actually uses could not say whether the thing they pay for
    was running at all. Same honesty pattern as `gateway_status`: real rows when they exist, an
    explicit "not installed"/"never started" otherwise — and `running` comes from the run registry
    (a live heartbeat), never inferred from the database merely existing.
    """
    import importlib.util
    import socket

    from . import runlog

    db = ((Path(home) / ".gawk") if home else behaviour_profile_path().parent) / "monitor.db"
    out: dict[str, Any] = {
        "installed": importlib.util.find_spec("gawk_platform") is not None,
        "db_present": db.is_file(), "servers": [], "running": None, "since": None,
    }
    runs_db = str(Path(home) / ".mcpgawk" / "runs.db") if home else None
    try:
        out["running"] = False
        for r in runlog.list_runs(kind="monitor", limit=25, path=runs_db):
            if (r.status == runlog.RUNNING and r.host == socket.gethostname()
                    and runlog._pid_alive(r.pid)):
                out["running"], out["since"] = True, r.started_at
                break
    except Exception as exc:                      # noqa: BLE001 — recorded, never disguised
        out["running"] = None                     # None = "cannot tell", not "no"
        out["runs_error"] = str(exc)
    if not db.is_file():
        return out
    try:
        from gawk_platform.monitor.status import status_rows
        from gawk_platform.monitor.store import SqliteMonitorStore
        store = SqliteMonitorStore(str(db), read_only=True)
        try:
            out["servers"] = status_rows(store)
            # The tab said "7 unresolved alert(s)" and rendered none of them ([FOUNDER]
            # 2026-08-15: logs should be captured and made VISIBLE here). Newest first.
            out["alerts"] = [
                {"server": a.server_id, "kind": a.kind.value, "detail": a.detail,
                 "raised_at": a.raised_at, "state": a.state}
                for a in store.pending_alerts() + store.dead_lettered_alerts()][:20]
            if not out["alerts"]:
                try:
                    rows = store._conn.execute(
                        "select server_id, kind, detail, raised_at, state from alerts "
                        "order by id desc limit 20").fetchall()
                    out["alerts"] = [{"server": r[0], "kind": r[1], "detail": r[2],
                                      "raised_at": r[3], "state": r[4]} for r in rows]
                except Exception:                  # noqa: BLE001 — the count still renders
                    pass
        finally:
            store.close()
    except Exception as exc:                      # noqa: BLE001 — a broken db is a page note
        out["error"] = str(exc)
    return out


def session_log_lines(limit: int = 30) -> list[dict[str, str]]:
    """The machine's recent activity as ONE dated stream, newest first — runs starting and
    finishing, monitor sweeps, alerts raised, evidence archived.

    [FOUNDER] 2026-08-15: "where are the session logs getting updated and shown" — until now,
    nowhere. A monitor sweep or a verify archiving evidence happened in another process and an
    open panel page showed nothing until a manual reload; the record existed (runs.db,
    monitor.db, verify-runs/) and no surface streamed it. This derives from the SAME readers
    the CLI uses — `runlog.list_runs`, `monitor_status` — never a parallel parse.

    Timestamps are ABSOLUTE (as recorded), never "2m ago": the /events loop diffs the rendered
    fragment against the last one sent, and a relative time ticks every second, so the diff
    would never settle and the stream would rewrite the DOM once a second forever.
    """
    from . import runlog

    lines: list[dict[str, str]] = []
    try:
        # A machine that has never recorded a run has no db — that is a normal state, not a
        # broken one, and must not render as an error line.
        if Path(runlog.default_path()).is_file():
            import socket as _sock
            for r in runlog.list_runs(limit=15):
                what = " ".join(x for x in (getattr(r, "kind", ""), getattr(r, "target", ""))
                                if x)
                status = getattr(r, "status", "")
                # The same liveness rule as the Evidence table: dead recorder ≠ running.
                if status == "running" and not (getattr(r, "host", "") == _sock.gethostname()
                                                and runlog._pid_alive(getattr(r, "pid", None))):
                    status = "interrupted"
                _sm = getattr(r, "summary", "") or ""
                # `finish_run` writes a DICT ({"message": …} from the panel, {"exit_code": …}
                # from the CLI). `.strip()` on it raised AttributeError, the except below turned
                # the WHOLE runs section into "run log unreadable (AttributeError)", and no scan
                # or verify ever appeared in the Session log (2026-09-03).
                if isinstance(_sm, dict):
                    _sm = str(_sm.get("message") or _sm.get("error")
                              or (f"exit {_sm['exit_code']}" if "exit_code" in _sm else ""))
                summary = str(_sm).strip()
                text = f"{what} · {status}" + (f" — {summary[:90]}" if summary else "")
                lines.append({"when": getattr(r, "started_at", "") or "", "text": text,
                              "level": {"ok": "ok", "findings": "warn", "error": "bad",
                                        "incomplete": "warn",
                                        "interrupted": "warn"}.get(status, "")})
    except Exception as exc:  # noqa: BLE001 — one unreadable source must not blank the log,
        lines.append({"when": "",   # and must not vanish silently either
                      "text": f"run log unreadable ({exc.__class__.__name__})", "level": "bad"})
    try:
        mon = monitor_status()
        if mon.get("running") and mon.get("since"):
            lines.append({"when": str(mon["since"]),
                          "text": "monitor daemon running (300s cycle)", "level": "ok"})
        for a in (mon.get("alerts") or [])[:8]:
            state = a.get("state") or ""
            lines.append({"when": str(a.get("raised_at") or ""),
                          "text": f"alert · {a.get('server')} · {a.get('kind')}"
                                  + (f" · {state}" if state else ""),
                          "level": "warn" if state in ("", "pending") else ""})
        for s in (mon.get("servers") or []):
            if s.get("last_check"):
                ok = s.get("last_ok")
                lines.append({"when": str(s["last_check"]),
                              "text": f"monitor checked {s.get('server_id')} · "
                                      + ("clean" if ok else "not clean" if ok is False
                                         else "unknown"),
                              "level": "ok" if ok else "warn" if ok is False else ""})
    except Exception:  # noqa: BLE001
        pass
    try:
        rd = verify_runs_dir()
        if rd.is_dir():
            dirs = sorted((p for p in rd.iterdir() if p.is_dir()), reverse=True)[:5]
            for p in dirs:
                lines.append({"when": p.name,
                              "text": f"evidence archived · verify run {p.name}", "level": ""})
    except OSError:
        pass
    # One textual sort works because every writer records ISO-shaped timestamps; a source that
    # recorded none sorts last rather than being invented a time.
    lines.sort(key=lambda x: x["when"], reverse=True)
    return lines[:limit]


def _session_log_html(lines: list[dict[str, str]]) -> str:
    """The log as a token-free fragment — same rows for the seeded page and the /events stream,
    so what you see live is exactly what a reload would show."""
    if not lines:
        return ('<div class="note">Nothing recorded yet — runs, monitor sweeps, alerts and '
                'archived evidence will appear here as they happen.</div>')
    rows = []
    for ln in lines:
        when = _esc(str(ln.get("when") or "")[:19].replace("T", " "))
        cls = {"ok": "slok", "warn": "slwarn", "bad": "slbad"}.get(ln.get("level") or "", "")
        rows.append(f'<div class="slrow {cls}"><span class="slwhen">{when}</span>'
                    f'<span>{_esc(ln.get("text") or "")}</span></div>')
    return "".join(rows)


def _monitor_start_button(mon: dict[str, Any]) -> str:
    """Offered only where it can work: the pillar installed, and not already running. A button
    that cannot do its job is the pattern the sign-in button already avoids."""
    token = _D_FOR_ROLES.get("_token", "") if isinstance(_D_FOR_ROLES, dict) else ""
    if not token:
        return ('<div class="note">Starting monitoring is a control, not state — it appears only '
                'through the link printed in the terminal that started the panel. Or run: '
                '<code>mcpgawk monitor run</code></div>')
    if not mon.get("installed"):
        return ""
    return (f'<form method="POST" action="/" style="margin:0 16px 13px">'
            f'<input type="hidden" name="token" value="{_esc(token)}">'
            f'<input type="hidden" name="tab" value="n8">'
            f'<button class="act-btn" name="act" value="monitor-start">Start monitoring '
            f'(remote servers)</button> '
            f'<button class="act-btn" name="act" value="monitor-start-local" title="Polling a '
            f'local server SPAWNS it every interval, running its code with the credentials in '
            f'its config — this button is that consent">Start monitoring incl. local servers'
            f'</button></form>')


def _monitor_pane(mon: dict[str, Any]) -> str:
    """The Monitor tab. What is watched, when it was last checked, and what is unresolved."""
    frame = ('<div class="note">Monitoring re-checks each approved server on a schedule and '
             'raises an alert when its surface moves — the rug-pull case, where a server you '
             'already trusted changes after you approved it.</div>')
    if not mon.get("installed"):
        return frame + ('<div class="note">Continuous monitoring ships with mcpgawk Platform — not '
                        'installed in this environment.</div>')
    if mon.get("running") is True:
        state = (f'<div class="note ok">Monitoring RUNNING since '
                 f'{_esc(str(mon.get("since") or "")[:19])}.</div>')
    elif mon.get("running") is None:
        state = ('<div class="note warn">Cannot tell whether monitoring is running — the run '
                 f'registry is unreadable: {_esc(str(mon.get("runs_error") or ""))}</div>')
    else:
        state = ('<div class="note warn">Monitoring is NOT running. Nothing is re-checking these '
                 'servers, so a server that changes after you approved it will not raise an '
                 'alert.</div>' + _monitor_start_button(mon))
    if not mon.get("db_present"):
        return (frame + state
                + '<div class="note">No monitoring history on this machine yet — nothing has '
                  'been watched, which is not the same as nothing having changed.</div>')
    err = (f'<div class="note warn">monitoring history unreadable: {_esc(mon["error"])}</div>'
           if mon.get("error") else "")
    rows = mon.get("servers") or []
    if not rows:
        return frame + state + err + ('<div class="note">The monitoring store exists but holds no '
                                      'servers yet.</div>')
    # ONE staleness definition, shared with the CLI badge. The panel used its OWN 24h threshold
    # while the CLI (status.describe_state) uses STALE_AFTER_S = 1h, so a check 2h old read a green
    # "checked" here and "STALE 2h ago" in `mcpgawk monitor status` — the two surfaces disagreeing
    # by 24x about whether the fleet is being watched, on the surface the founder actually reviews.
    # And the panel swallowed an unparseable timestamp as fresh; `_age_seconds` returns None for
    # that (UNKNOWN), which must never render as a pass. Reached only when monitoring is installed,
    # so the monitor package is importable here (monitor_status already imported it above).
    from gawk_platform.monitor.status import STALE_AFTER_S, _age_seconds

    parts = []
    stale = 0
    retired_n = 0
    for r in rows:
        ok = r.get("last_ok")
        retired = r.get("retired") if isinstance(r.get("retired"), dict) else None
        if retired and retired.get("retired_at"):
            # The operator said this server has left. Not watched, not stale, not counted as
            # coverage — and its alerts were closed by that decision, on record (who, when).
            retired_n += 1
            parts.append(
                f'<tr><td class="nm">{_esc(str(r.get("server_id") or ""))}</td>'
                f'<td><span class="chip unv" title="{_esc(str(retired.get("reason") or ""))}">'
                f'retired {_esc(str(retired.get("retired_at") or "")[:10])} · by '
                f'{_esc(str(retired.get("retired_by") or "?"))}</span></td>'
                f'<td>{"yes" if r.get("has_baseline") else "<b>no</b>"}</td>'
                f'<td class="num">{r.get("open_alerts") or 0}</td>'
                f'<td class="dim">{_esc(str(r.get("last_check") or "never"))[:19]}</td></tr>')
            continue
        # A green "checked" with a 13-day-old timestamp read as coverage (founder's tab audit,
        # 2026-08-15: 8 local servers, last checked 1 Aug, under "11 watched" and RUNNING).
        # Local servers are excluded from polling BY DEFAULT — polling one spawns it with the
        # credentials in its config — and the tab must say which rows are history, not coverage.
        age = _age_seconds(r.get("last_check"))
        is_stale = age is None or age >= STALE_AFTER_S     # None = never-run OR unparseable: UNKNOWN
        # never checked != checked and failed. An unknown must never render as a pass.
        if is_stale and ok is not None:
            chip = '<span class="chip unv">stale — not being re-checked</span>'
            stale += 1
        else:
            chip = ('<span class="chip ok">checked</span>' if ok is True else
                    '<span class="chip bad">check failed</span>' if ok is False else
                    '<span class="chip unv">never checked</span>')
        alerts = (f'<span class="chip bad">{r["open_alerts"]}</span>' if r.get("open_alerts")
                  else "0")
        parts.append(
            f'<tr><td class="nm">{_esc(str(r.get("server_id") or ""))}</td>'
            f'<td>{chip}</td>'
            f'<td>{"yes" if r.get("has_baseline") else "<b>no</b>"}</td>'
            f'<td class="num">{alerts}</td>'
            f'<td class="dim">{_esc(str(r.get("last_check") or "never"))[:19]}</td></tr>')
    open_total = sum(int(r.get("open_alerts") or 0) for r in rows)
    live = len(rows) - stale - retired_n
    head = (f'<div class="filters"><span class="count" style="margin-left:0">{live} '
            f'server(s) watched live'
            + (f' · {stale} stale (in the store, NOT being re-checked)' if stale else '')
            + (f' · {retired_n} retired (left this machine — recorded, not erased)' if retired_n else '')
            + f' · {open_total} unresolved alert(s)</span></div>')
    stale_note = ""
    if stale:
        stale_note = ('<div class="note warn">Stale rows are HISTORY, not coverage. Local '
                      'servers are not polled by default — polling one spawns it every '
                      'interval, running its code with the credentials in its config. Start '
                      'monitoring with <code>--include-local</code> to poll them '
                      'deliberately.</div>')
    alert_rows = ""
    for a in (mon.get("alerts") or [])[:20]:
        detail = str(a.get("detail") or "")
        shown = _esc(detail[:140]) + ("…" if len(detail) > 140 else "")
        full = (f'<details class="sessdrill"><summary class="whysum">{shown}</summary>'
                f'<div class="whyfull">{_esc(detail)}</div></details>'
                if len(detail) > 140 else _esc(detail))
        alert_rows += (
            f'<tr><td class="dim"><span title="{_esc(str(a.get("raised_at") or ""))}">'
            f'{_esc(_ago(str(a.get("raised_at") or "")))}</span></td>'
            f'<td class="nm">{_esc(str(a.get("server") or ""))}</td>'
            f'<td><span class="chip warn">{_esc(str(a.get("kind") or ""))}</span></td>'
            f'<td>{full}</td>'
            f'<td class="dim">{_esc(str(a.get("state") or ""))}</td></tr>')
    alerts_tbl = ""
    if alert_rows:
        alerts_tbl = ('<h2>alerts · what monitoring raised, in its own words</h2>'
                      '<div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>when</th><th>server</th><th>kind</th>'
                      '<th>detail</th><th>delivery</th></tr></thead>'
                      f'<tbody>{alert_rows}</tbody></table></div>')
    return (frame + state + err + head + stale_note + alerts_tbl
            + '<h2>servers under watch</h2>'
              '<div class="tscroll" tabindex="0" role="region" aria-label="table, scrolls horizontally"><table><thead><tr><th>server</th><th>last check</th><th>baseline</th>'
              '<th>open alerts</th><th>when</th></tr></thead>'
              f'<tbody>{"".join(parts)}</tbody></table></div>')


def gateway_roles(keys_file: str | None) -> list[str]:
    """The role names defined in the running gateway's principal registry, for the issue-key
    form. Empty when there is no file, no roles block, or the file cannot be read — the form then
    offers no role and the issued key is deny-by-default, which is the honest state anyway."""
    if not keys_file:
        return []
    try:
        import json as _json
        doc = _json.loads(Path(keys_file).read_text(encoding="utf-8"))
        roles = doc.get("roles")
        return sorted(str(r) for r in roles) if isinstance(roles, dict) else []
    except Exception:                             # noqa: BLE001 — an unreadable file offers none
        return []


def run_issue_key(name: str | None, role: str | None = None) -> dict[str, Any]:
    """Issue ONE agent key against the running gateway's registry, and hand it back once.

    The LiteLLM virtual-key ceremony applied to agents: the operator names an agent, picks a role
    (a bundle the registry already defines), and gets a key + a paste-able config. The gateway
    hot-reloads its registry, so the key works on the next call without a restart — and the
    per-caller audit shipped this morning means every call it makes is attributable to THAT
    agent, which is the whole argument for routing agents through the gateway rather than the
    per-agent hooks (a hook only ever sees a self-asserted client name).
    """
    name = (name or "").strip()
    if not name:
        return {"ok": False, "message": "an agent key needs a name — it is what the audit trail "
                                        "will attribute every call to"}
    gw = gateway_status()
    live = gw.get("live") or {}
    keys_file = live.get("keys_file")
    if not live:
        return {"ok": False, "message": "no gateway is running on this machine — start one with "
                                        "`mcpgawk enforce serve --listen 127.0.0.1:8080 "
                                        "--principals <file>`, then issue keys against it"}
    if not keys_file:
        return {"ok": False,
                "message": "this gateway was started without --principals, so it has no key "
                           "registry to add to. Restart it with --principals <file> to give each "
                           "agent its own identity."}
    try:
        from gawk_platform.enforce.identity import issue_key
    except ImportError:
        return {"ok": False, "message": "agent keys ship with mcpgawk Platform (the gateway)"}
    # "+reader" means: this bundle does not exist in the registry yet — write it from the tools
    # we have actually seen, then issue against it. Without this the derived roles would be a
    # picker that produces nothing, which is worse than no picker.
    if role and role.startswith("+"):
        role = role[1:]
        try:
            _ensure_role(keys_file, role, roles_from_baseline(_D_FOR_ROLES or {}).get(role) or [])
        except Exception as exc:                  # noqa: BLE001 — the reason goes ON the page
            return {"ok": False, "message": f"could not define role {role}: {exc}"}
    try:
        key = issue_key(keys_file, name, role=role or None)
    except Exception as exc:                      # noqa: BLE001 — the reason goes ON the page
        return {"ok": False, "message": f"could not issue a key for {name}: {exc}"}
    listen = live.get("listen") or "http://127.0.0.1:8080/mcp"
    snippet = ('{\n  "mcpServers": {\n    "gawk": {\n'
               f'      "url": "{listen}",\n'
               f'      "headers": {{"Authorization": "Bearer {key}"}}\n'
               '    }\n  }\n}')
    role_note = f" with role {role}" if role else " with NO grants yet (deny-by-default)"
    return {"ok": True, "secret": key, "snippet": snippet,
            "message": f"issued a key for {name}{role_note}. Copy it now — it is shown once, "
                       f"and the gateway already accepts it (no restart needed)."}


def gateway_status(home: Path | str | None = None) -> dict[str, Any]:
    """What the gateway control plane looks like from this machine, read-only.

    Positioning is deliberate (founder, 2026-08-01): the gateway is the product's frame — ONE
    endpoint in front of the fleet, per-principal keys, policy, refusals, audit — and scan/verify
    is how it knows. So the panel shows this surface with or without mcpgawk Platform installed:
    real audit rows when they exist, an honest "ships with mcpgawk Platform" otherwise — the same
    pattern `status` uses for deep monitoring. `home` is injectable for tests, like discover's.

    `live` is the gateway running RIGHT NOW, read from the enforce run row (kind='enforce',
    status='running', pid still alive on this host) — the only place the listen endpoint exists;
    inbound.serve only ever prints it. A readable runs.db with no such row honestly means "not
    running"; an UNREADABLE one is recorded as `runs_error`, never passed off as "not running" —
    a swallowed error must not look like a real answer.
    """
    import importlib.util
    import socket
    import sqlite3

    from . import runlog

    # THROUGH behaviour_profile_path, never a hardcoded ~/.gawk: the hardcoded form is exactly
    # how the behaviour profile slipped past conftest's real-home guard (see that docstring).
    db = ((Path(home) / ".gawk") if home else behaviour_profile_path().parent) / "enforce-audit.db"
    out: dict[str, Any] = {
        "installed": importlib.util.find_spec("gawk_platform") is not None,
        "audit_present": db.is_file(),
        "events": [], "blocks": 0, "sessions": 0, "principals": [], "by_principal": [],
        "live": None, "unprotected": None,
    }
    # A lapsed trial: the gateway keeps running but no longer enforces. The Gateway pane must say so
    # in the state, not a footnote — silence reads as protection. Visibility only; never break the
    # page if the paid engine cannot be consulted.
    if out["installed"]:
        try:
            from gawk_platform.cli import ENDED, GRACE, license_state
            _lstate, _ = license_state()
            if _lstate in (GRACE, ENDED):
                out["unprotected"] = _lstate
        except Exception:                          # noqa: BLE001
            pass
    runs_db = str(Path(home) / ".mcpgawk" / "runs.db") if home else None
    try:
        for r in runlog.list_runs(kind="enforce", limit=25, path=runs_db):
            if (r.status == runlog.RUNNING and r.host == socket.gethostname()
                    and runlog._pid_alive(r.pid)):
                out["live"] = {"target": r.target, "since": r.started_at,
                               "listen": r.summary.get("listen"),
                               "keys": bool(r.summary.get("keys")),
                               "keys_file": r.summary.get("keys_file"),
                               "stdio": r.summary.get("transport") == "stdio"}
                break
    except Exception as exc:                      # noqa: BLE001 — recorded, never disguised
        out["runs_error"] = str(exc)
    if not db.is_file():
        return out
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            cols = ("at", "tool", "phase", "decision", "reason", "severity", "principal", "client")
            out["events"] = [dict(zip(cols, r)) for r in con.execute(
                "SELECT taken_at, tool_name, phase, decision, reason, severity, principal, client"
                " FROM events ORDER BY id DESC LIMIT 12")]
            # A BACKEND FAILURE IS NOT A POLICY BLOCK. `backend_error`/`timeout` rows carry
            # decision='block' so an allowed call always resolves to something (gateway.py's E4
            # rule), but counting them here told the operator the gateway had refused calls it had
            # actually ALLOWED and then watched die. The set is duplicated from
            # gawk_platform.enforce.gateway.FAILURE_PHASES because the panel ships in the FREE
            # package and cannot import the paid engine; `test_blocked_count_is_policy_only` pins
            # the two copies together so they cannot drift.
            out["blocks"] = con.execute(
                "SELECT COUNT(*) FROM events WHERE decision='block'"
                " AND phase NOT IN ('backend_error','timeout')").fetchone()[0]
            out["backend_failures"] = con.execute(
                "SELECT COUNT(*) FROM events WHERE decision='block'"
                " AND phase IN ('backend_error','timeout')").fetchone()[0]
            out["sessions"] = con.execute(
                "SELECT COUNT(DISTINCT session_id) FROM events").fetchone()[0]
            out["principals"] = [r[0] or "(no identity asserted)" for r in con.execute(
                "SELECT DISTINCT principal FROM events")]
            # Per-principal rollup, tool calls only: lifecycle rows (tool_name NULL) would count
            # every session per principal and say nothing about who DID what.
            out["by_principal"] = [
                {"principal": r[0] or "(no identity asserted)", "calls": r[1], "blocks": r[2] or 0,
                 "last": r[3]}
                for r in con.execute(
                    "SELECT principal, COUNT(*),"
                    " SUM(CASE WHEN decision='block'"
                    "          AND phase NOT IN ('backend_error','timeout')"
                    "     THEN 1 ELSE 0 END), MAX(taken_at)"
                    " FROM events WHERE tool_name IS NOT NULL"
                    " GROUP BY principal ORDER BY COUNT(*) DESC")]
        finally:
            con.close()
    except Exception as exc:                      # noqa: BLE001 — a broken db is a page note
        out["error"] = str(exc)
    return out


def _snippet_for(live: dict[str, Any]) -> str:
    """The "point your agent here" block for a RUNNING gateway — the exact config a customer
    pastes, not a description of one. HTTP shape from the live listen address; stdio has no
    address, so the honest offer there is `enforce install`, which wraps each configured server
    in place (the same wiring that gateway already has with the agent that launched it)."""
    if live.get("listen"):
        headers = (',\n      "headers": {"Authorization": "Bearer <your principal key>"}'
                   if live.get("keys") else "")
        cfg = ('{\n  "mcpServers": {\n    "gawk": {\n'
               f'      "url": "{live["listen"]}"{headers}\n'
               '    }\n  }\n}')
        return ('<div class="note">Point your agent here — one entry replaces every '
                'per-server block in its MCP config:</div>'
                f'<pre class="snip">{_esc(cfg)}</pre>')
    return ('<div class="note">This gateway speaks stdio to the agent that launched it — there '
            'is no address to share. To put every agent on this machine behind the gateway: '
            '<code>mcpgawk enforce install</code> (wraps each configured server in place, '
            'reversibly).</div>')


#: The collected page data, so the key form can build role bundles from the approved baseline
#: without threading `d` through three render helpers. Set once per render, read immediately.
_D_FOR_ROLES: dict[str, Any] | None = None


def _issue_key_form(live: dict[str, Any], token: str, action: dict[str, Any] | None) -> str:
    """The agent-invite ceremony: name an agent, pick a role, get ONE key + its config.

    LiteLLM's virtual-key flow, with agents as the invitees rather than people. Shown only with
    the panel token (issuing a credential is the most action-shaped thing this surface does, and
    an agent that merely opens the page must never be able to mint itself one) and only when a
    gateway with a key registry is actually running — an issue button pointing at nothing would
    be the "unblock that cannot work" pattern the sign-in button already avoids.
    """
    action = action or {}
    issued = ""
    if action.get("secret"):
        # Shown ONCE, and never persisted (see _persist_action's whitelist). No copy button:
        # the CSP forbids scripts, so the honest affordance is selectable text.
        issued = ('<div class="note ok">Copy this now — it is not stored and cannot be shown '
                  f'again:</div><pre class="snip">{_esc(action["secret"])}</pre>'
                  f'<pre class="snip">{_esc(action.get("snippet") or "")}</pre>')
    if not token:
        return issued + ('<div class="note">Issuing an agent key is a control, not state — it '
                         'appears only through the link printed in the terminal that started '
                         'the panel.</div>')
    if not live:
        return issued
    if not live.get("keys_file"):
        return issued + ('<div class="note warn">This gateway was started without '
                         '<code>--principals</code>, so it has no key registry: every caller is '
                         'the same principal and the audit cannot tell your agents apart. '
                         'Restart it with <code>--principals &lt;file&gt;</code> to give each '
                         'agent its own identity.</div>')
    roles = gateway_roles(live.get("keys_file"))
    derived = {} if roles else roles_from_baseline(_D_FOR_ROLES or {})
    if not roles and derived:
        opts = "".join(f'<option value="+{_esc(r)}">{_esc(r)} — {_esc(desc)}</option>'
                       for r, desc in ROLE_TEMPLATES if r in derived)
        return (issued
                + '<div class="ddh">Give an agent its own key</div>'
                + f'<div class="note">Name an agent, pick what it may touch, get a key — shown '
                  f'once. Paste that key into the agent\'s gateway config above; from then on '
                  f'its calls are attributed to it in the trail and limited to its grant. '
                  f'{_esc(role_evidence(_D_FOR_ROLES or {}))}</div>'
                + f'<form method="POST" action="/" class="filters">'
                  f'<input type="hidden" name="token" value="{_esc(token)}">'
                  f'<input type="hidden" name="tab" value="n7">'
                  f'<input name="name" aria-label="agent name" list="gw-principals" '
                  f'placeholder="pick a known agent or type a new name" '
                  f'title="Agents already seen by the gateway are in the list; a new name creates a new principal" '
                  f'maxlength="80" required>'
                  f'<select name="role"><option value="">no grants yet</option>{opts}</select>'
                  f'<button class="act-btn sm" name="act" value="issue-key">Issue agent key'
                  f'</button></form>')
    if roles:
        opts = "".join(f'<option value="{_esc(r)}">{_esc(r)}</option>' for r in roles)
        role_field = (f'<select name="role"><option value="">no grants yet</option>{opts}'
                      f'</select>')
        role_note = ""
    else:
        role_field = '<input type="hidden" name="role" value="">'
        role_note = ('<div class="note">No roles are defined in this registry yet. A key issued '
                     'now identifies its agent in the audit trail but can call nothing — add a '
                     '<code>"roles"</code> block (name → grant list) to grant in one step.</div>')
    return (issued + role_note
            + f'<form method="POST" action="/" class="filters">'
              f'<input type="hidden" name="token" value="{_esc(token)}">'
              f'<input type="hidden" name="tab" value="n7">'
              f'<input name="name" aria-label="agent name" list="gw-principals" '
              f'placeholder="pick a known agent or type a new name" '
              f'title="Agents already seen by the gateway are in the list; a new name creates a new principal" '
              f'maxlength="80" required>{role_field}'
              f'<button class="act-btn sm" name="act" value="issue-key">Issue agent key</button>'
              f'</form>')


def _playground_form(live: dict[str, Any], token: str) -> str:
    """Call a tool through the gateway, from here. The gateway's value is the DECISION it makes;
    until this, the panel could only show decisions some other process happened to trigger.

    Token-gated: this really calls a real tool on a real server. The tool list is fetched with no
    key (what an unauthenticated caller sees) purely to populate the picker — the CALL carries
    whatever key the operator pastes, which is what the audit will attribute it to.
    """
    if not token or not live.get("listen"):
        return ""
    probe = gateway_tools(live)
    if probe.get("tools"):
        opts = "".join(f'<option value="{_esc(t)}">{_esc(t)}</option>' for t in probe["tools"])
        picker = f'<select name="tool">{opts}</select>'
        note = ""
    else:
        picker = '<input name="tool" placeholder="tool name" maxlength="80" required>'
        note = (f'<div class="note">Could not list tools through the gateway'
                f'{" — " + _esc(probe.get("error") or "") if probe.get("error") else ""}. '
                f'Type a tool name to call it anyway.</div>'
                if not probe.get("ok") else
                '<div class="note">An unauthenticated caller sees no tools here — that is the '
                'gateway filtering by identity. Paste an agent key and name its tool.</div>')
    return (f'<div class="ddh">Try the gateway as an agent</div>'
            f'<div class="note">Prove a key works before wiring an agent: pick a tool, paste the '
            f'key, send it. The call takes the same '
            f'handlers, the same policy, and the decision lands in the trail below.</div>{note}'
            f'<form method="POST" action="/" class="filters">'
            f'<input type="hidden" name="token" value="{_esc(token)}">{picker}'
            f'<input type="hidden" name="tab" value="n7">'
            f'<input name="key" aria-label="agent key" placeholder="paste an agent key — issue one above if you have none" '
            f'title="The key is shown ONCE when you issue it (Issue agent key, above); it is never stored readable" '
            f'maxlength="200">'
            f'<input name="arguments" aria-label="tool arguments, JSON" placeholder=\'JSON arguments — {{}} for none\' '
            f'title=\'The tool&#39;s arguments as JSON, e.g. {{"query": "AAPL"}}; use {{}} to call with none\' maxlength="400">'
            f'<button class="act-btn sm" name="act" value="gw-call">Call through gateway</button>'
            f'</form>')


def _gateway_pane(gw: dict[str, Any], token: str = "",
                  action: dict[str, Any] | None = None) -> str:
    """The Gateway tab body. Frame first, then the LIVE gateway if one is running (endpoint +
    point-your-agent-here + the agent-key ceremony), then who did what per principal, then the
    raw trail."""
    frame = ('<div class="note">One endpoint in front of every server: agents call the gateway, '
             'the gateway enforces your approved baseline, observed behaviour and policy per '
             'principal — and every allow, block and refusal lands in a hash-chained audit '
             'trail. Scan and verify are how it knows.</div>')
    if gw.get("unprotected"):
        ended = gw["unprotected"] == "ended"
        frame = ('<div class="note bad"><b>UNPROTECTED</b> — your trial has '
                 + ("ended" if ended else "ended (the grant is still valid)")
                 + '. The gateway is passing every call through and enforcing NOTHING. Your agents '
                 'still work; they are not protected. '
                 '<a href="https://mcp.gawk.dev/pricing">Subscribe</a> to restore protection, or '
                 'run <code>mcpgawk enforce uninstall</code> to remove it.</div>') + frame
    live = gw.get("live")
    live_html = ""
    if live:
        what = _esc(str(live.get("target") or "your fleet"))
        since = _esc(str(live.get("since") or "")[:19])
        where = (f' · <code>{_esc(live["listen"])}</code>' if live.get("listen")
                 else " · stdio (no listener)")
        keys = " · per-principal keys in force" if live.get("keys") else ""
        live_html = (f'<div class="note ok">Gateway RUNNING since {since} — in front of '
                     f'{what}{where}{keys}</div>' + _snippet_for(live)
                     + _issue_key_form(live, token, action)
                     + _playground_form(live, token))
    elif gw.get("runs_error"):
        live_html = (f'<div class="note warn">Cannot tell whether a gateway is running — '
                     f'run registry unreadable: {_esc(gw["runs_error"])}</div>')
    if not live:
        live_html += _issue_key_form({}, token, action)
    if not gw.get("audit_present"):
        where = ("No gateway activity recorded on this machine yet. Start one: "
                 "<code>mcpgawk enforce serve --gateway-config deploy/gateway.example.yaml</code>"
                 if gw.get("installed") else
                 "The gateway ships with mcpgawk Platform — not installed in this environment.")
        return (frame + live_html
                + f'<div class="note">{where} Deployable from one YAML: see '
                  f'<code>deploy/gateway.example.yaml</code> and the Docker image.</div>')
    # Backend failures are shown ONLY when there are some, and never folded into block(s): a call
    # the gateway allowed and the backend then dropped is not protection, and the operator has to
    # be able to tell the two apart at a glance.
    _failed = gw.get("backend_failures", 0)
    head = (f'<div class="filters"><span class="count" style="margin-left:0">'
            f'Since it started, this gateway has refused {gw.get("blocks", 0)} call(s)'
            + (f', seen {_failed} backend failure(s)' if _failed else '')
            + f' across {gw.get("sessions", 0)} agent session(s) · agents seen: '
              f'{_esc(", ".join(gw.get("principals") or []) or "none yet")}</span></div>'
              + '<datalist id="gw-principals">'
              + "".join(f'<option value="{_esc(p)}"></option>'
                        for p in (gw.get("principals") or []) if p and "identity" not in p)
              + '</datalist>')
    if not live and not gw.get("runs_error"):
        _gtok = _D_FOR_ROLES.get("_token", "") if isinstance(_D_FOR_ROLES, dict) else ""
        _gw_dir = behaviour_profile_path().parent / "gateway"
        if (_gw_dir / "gateway.yaml").exists():
            live_html += (
                '<div class="note">Your generated config: <code>'
                f'{_esc(str(_gw_dir / "gateway.yaml"))}</code> — start it with the button '
                'below, or by hand: <code>mcpgawk enforce serve --gateway-config '
                f'{_esc(str(_gw_dir / "gateway.yaml"))}</code></div>')
        if _gtok:
            _glabel = ("Start gateway" if (_gw_dir / "gateway.yaml").exists()
                       else "Generate config from this fleet & start gateway")
            live_html += (
                f'<form method="POST" action="/" style="margin:0 16px 13px">'
                f'<input type="hidden" name="token" value="{_esc(_gtok)}">'
                f'<input type="hidden" name="tab" value="n7">'
                f'<button class="act-btn" name="act" value="gateway-start" title="Generates a '
                f'loopback config from your fleet if none exists (no secrets written), then '
                f'starts the gateway detached — your click is the consent">{_glabel}'
                f'</button></form>')
        # ONE command, and the real path. This note and the "Your generated config" note above it
        # gave two different start commands on one screen, this one pointing at a path that only
        # exists in the repo checkout (2026-09-03). When a generated config exists, name it.
        _cfg_path = (str(_gw_dir / "gateway.yaml") if (_gw_dir / "gateway.yaml").exists()
                     else "deploy/gateway.example.yaml")
        live_html += ('<div class="note">No gateway running right now — the trail below is '
                      'from earlier sessions. Start one: <code>mcpgawk enforce serve '
                      f'--gateway-config {_esc(_cfg_path)}</code></div>')
    per = ""
    if gw.get("by_principal"):
        ups = principal_upstreams((live or {}).get("keys_file"))
        parts = []
        _events = gw.get("events") or []
        for p in gw["by_principal"]:
            pname = str(p.get("principal") or "")
            blocked = (f'<span class="chip bad">{p["blocks"]}</span>' if p.get("blocks") else "0")
            own = ", ".join(ups.get(pname) or []) or "—"
            # The principal's own slice of the trail, in place — a flat total next to a name
            # answered nothing ([FOUNDER] 2026-08-15: drill-down, not static fields).
            mine = [e for e in _events
                    if str(e.get("principal") or "(no identity asserted)") == (pname or "(no identity asserted)")
                    ][:10]
            _prows = "".join(
                f'<tr><td class="dim"><span title="{_esc(str(e.get("at") or ""))}">'
                f'{_esc(_ago(str(e.get("at") or "")))}</span></td>'
                f'<td class="nm">{_esc(str(e.get("tool") or "—"))}</td>'
                f'<td>{_esc(str(e.get("decision") or ""))}</td>'
                f'<td class="dim">{_esc(str(e.get("reason") or ""))}</td></tr>'
                for e in mine) or \
                '<tr><td colspan="4" class="dim">no calls from this principal in the ' \
                'loaded trail</td></tr>'
            _pdrill = (f'<details class="sessdrill"><summary class="whysum">its own trail'
                       f'</summary><table class="mini"><thead><tr><th>when</th><th>tool</th>'
                       f'<th>decision</th><th>reason</th></tr></thead>'
                       f'<tbody>{_prows}</tbody></table></details>')
            parts.append(
                f'<tr><td class="nm">{_esc(pname)}<br>{_pdrill}</td>'
                f'<td class="num">{p.get("calls", 0)}</td>'
                f'<td class="num">{blocked}</td>'
                f'<td class="dim">{_esc(own)}</td>'
                f'<td class="dim"><span title="{_esc(str(p.get("last") or ""))}">'
                f'{_esc(_ago(str(p.get("last") or "")))}</span></td></tr>')
        note = ""
        if not ups:
            note = ('<div class="note">No agent carries its own credential for a backend yet, so '
                    'every call upstream is made as the gateway. Your browser sign-in is the '
                    '<b>operator\'s</b> credential — reusing it for every agent would make them '
                    'all act as you, and the trail could not tell them apart. Give an agent its '
                    'own access by adding an <code>upstream</code> block to its principal in the '
                    'registry (this panel never collects secrets).</div>')
        per = (note + '<table><thead><tr><th>principal</th><th>calls</th><th>blocked</th>'
               '<th>own credentials for</th><th>last seen</th></tr></thead>'
               f'<tbody>{"".join(parts)}</tbody></table>')
    rows = "".join(
        f'<tr><td class="dim"><span title="{_esc(str(e.get("at") or ""))}">'
        f'{_esc(_ago(str(e.get("at") or "")))}</span></td>'
        f'<td class="nm">{_esc(str(e.get("tool") or "—"))}</td>'
        f'<td>{_esc(str(e.get("decision") or ""))}</td>'
        f'<td class="dim">{_esc(str(e.get("reason") or ""))}</td>'
        f'<td>{_esc(str(e.get("principal") or "—"))}</td>'
        f'<td class="dim">{_esc(str(e.get("client") or "—"))}</td></tr>'
        for e in gw.get("events") or [])
    err = (f'<div class="note">audit trail unreadable: {_esc(gw["error"])}</div>'
           if gw.get("error") else "")
    return (frame + live_html + head + err + per
            + '<table><thead><tr><th>when</th><th>tool</th><th>decision</th><th>reason</th>'
              '<th>principal</th><th>client</th></tr></thead>'
              f'<tbody>{rows}</tbody></table>')


def _transport_flag(entry: dict | None, url: str) -> str:
    """`--sse` or `--http` — scan has to be TOLD which, because a URL is not a config path.

    SSE is chosen only on evidence (the entry declares it, or the URL ends in the conventional
    /sse), because guessing the transport wrong fails just as loudly as guessing the argument
    shape wrong did.
    """
    declared = ""
    if isinstance(entry, dict):
        for key in ("type", "transport"):
            value = entry.get(key)
            if isinstance(value, str):
                declared += value.lower()
    if "sse" in declared or url.rstrip("/").endswith("/sse"):
        return "--sse"
    return "--http"


def _run_login_cli(url: str, flag: str = "--http"):
    """The real `mcpgawk scan --http <url> --login` flow, in this same interpreter.

    Module-level so a test can stand in a fake without patching subprocess for everyone. 330s:
    the OAuth callback itself waits up to 5 minutes for the human to finish in the browser.

    `flag` is only nominally optional. This used to pass the URL as scan's POSITIONAL argument,
    which is a config FILE PATH (`cli.py:_load_config` opens it) — so every panel sign-in died
    with `FileNotFoundError: No such file or directory: 'https://…'` and reported it as
    "sign-in did not complete", blaming the sign-in for an argument bug. Found 2026-08-03 by the
    founder clicking the button on a real server, reproduced in one command afterwards.

    NOT `capture_output`. The flow PRINTS the authorisation URL (oauth_login._redirect, with
    flush) precisely so a human whose browser did not open can paste it — and capturing that into a
    pipe nobody reads until the child exits meant the panel showed "Running login…" for five and a
    half minutes and then "sign-in for kite did not complete". The sign-in never failed; it was
    never SHOWN to the human. Confirmed on the founder's own fleet 2026-08-14, and it is the second
    time this path has blamed the sign-in for a panel bug (see the argument bug above).

    So: the child writes to a real file, which the caller can read WHILE it runs.
    """
    import subprocess
    import sys as _sys
    import tempfile
    log = tempfile.NamedTemporaryFile("w+", prefix="mcpgawk-login-", suffix=".log", delete=False)
    proc = subprocess.Popen([_sys.executable, "-m", "mcpgawk", "scan", flag, url, "--login"],
                            stdout=log, stderr=subprocess.STDOUT, text=True)
    return proc, log.name


#: The ONE in-band sign-in the panel is holding for a click — name, child, log, url, started.
_SIGNIN_CHILD: dict[str, Any] = {}
_SIGNIN_LOCK = __import__("threading").Lock()


def _run_signin_cli(name: str):
    """The real `mcpgawk scan --only <name> --sign-in --yes` flow as a child, stdin piped.

    `MCPGAWK_SIGNIN_WAIT=stdin` tells the CLI a person is behind the pipe (the panel's button);
    the child prints the link, then blocks on one newline, then checks the server's OWN word on
    the session once and measures through it. One implementation, two front doors."""
    import subprocess
    import sys as _sys
    import tempfile
    log = tempfile.NamedTemporaryFile("w+", prefix="mcpgawk-signin-", suffix=".log", delete=False)
    env = {**os.environ, "MCPGAWK_SIGNIN_WAIT": "stdin"}
    proc = subprocess.Popen([_sys.executable, "-m", "mcpgawk", "scan", "--only", name,
                             "--sign-in", "--yes"],
                            stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
                            text=True, env=env)
    return proc, log.name


def _signin_child_alive() -> bool:
    with _SIGNIN_LOCK:
        proc = _SIGNIN_CHILD.get("proc")
    try:
        return proc is not None and proc.poll() is None
    except Exception:                              # noqa: BLE001 — a fake or a gone process
        return False


def _stop_signin_child(proc) -> None:
    """TERM first so the child's `held.close()` runs and its mcp-remote grandchild follows; KILL
    only if it lingers. An orphaned `mcp-remote https://mcp.kite.trade/mcp` is exactly what a
    careless cleanup mistook for its own on 2026-09-04."""
    try:
        if proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:                          # noqa: BLE001 — subprocess.TimeoutExpired
            proc.kill()
    except Exception:                              # noqa: BLE001 — already gone is fine
        pass


def _read_log(log_path: str) -> str:
    try:
        return pathlib.Path(log_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _await_child_link(proc, log_path: str, seconds: float) -> str:
    """Poll the child's log for the sign-in link (the OAuth flow's phrase, printed by --sign-in
    too) until it appears, the child exits, or `seconds` pass. "" when there is none."""
    import re as _re
    import time as _time
    deadline = _time.monotonic() + seconds
    while _time.monotonic() < deadline:
        hit = _re.search(r"paste this into a browser:\s*(https?://\S+)", _read_log(log_path))
        if hit:
            return hit.group(1).rstrip(".,)")
        if proc.poll() is not None:
            break
        _time.sleep(0.5)
    hit = _re.search(r"paste this into a browser:\s*(https?://\S+)", _read_log(log_path))
    return hit.group(1).rstrip(".,)") if hit else ""


def run_login_done(name: str | None) -> dict[str, Any]:
    """The human says the browser said yes: hand the held child its Enter, and report what the
    server said and what was measured — in the child's words, never a guess."""
    with _SIGNIN_LOCK:
        held = dict(_SIGNIN_CHILD)
    if not held or (name and held.get("name") != name):
        return {"ok": False,
                "message": (f"no sign-in is waiting for {name or 'this server'} — click "
                            f"‘sign in’ first, then ‘I have signed in’ once the browser says so")}
    proc, log_path, url = held["proc"], held["log_path"], held.get("url") or ""
    name = held["name"]
    try:
        if proc.poll() is None and proc.stdin is not None:
            try:
                proc.stdin.write("\n")
                proc.stdin.flush()
                proc.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass
        try:
            proc.wait(timeout=300)
        except Exception:                          # noqa: BLE001 — subprocess.TimeoutExpired
            proc.kill()
            return {"ok": False,
                    "message": f"{name}: the signed-in measurement did not finish within 5 minutes"}
    finally:
        with _SIGNIN_LOCK:
            if _SIGNIN_CHILD.get("proc") is proc:
                _SIGNIN_CHILD.clear()
    out = _read_log(log_path)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    measured = next((ln for ln in lines if ln.startswith("measured ") and "signed-in session" in ln), "")
    if measured:                                   # the child's own word is the evidence, not its exit code
        signed = next((ln for ln in lines if ln.startswith("signed in —")), "")
        return {"ok": True, "level": "ok",
                "message": f"{name}: {measured}" + (f" · {signed}" if signed else "")}
    refused = next((ln for ln in lines if "does not consider this session signed in" in ln), "")
    if refused:
        return {"ok": False, "message": f"{name}: {refused.split(': ', 1)[-1]}"}
    ended = next((ln for ln in lines if "held session" in ln and "scanning it the ordinary way" in ln), "")
    if ended:
        return {"ok": False, "message": f"{name}: {ended.split(': ', 1)[-1]}"}
    return {"ok": False,
            "message": f"sign-in for {name} did not complete — {_login_failure_detail(name, url, out)}"}


def _oauth_unsupported_reason(url: str) -> str:
    """"" if this endpoint plausibly speaks OAuth, else WHY it does not — in the operator's words.

    Two cheap, bounded questions, both answered in well under a second: does the endpoint challenge
    an unauthenticated request (401/403 + `WWW-Authenticate`), and does it publish either OAuth
    discovery document? A server that answers neither has no browser flow for us to start.

    Never raises and never blocks the button on a network hiccup: an unreachable check returns ""
    (proceed), because refusing a sign-in because our probe failed would be its own false negative.
    """
    import json as _json
    import urllib.error
    import urllib.parse
    import urllib.request
    try:
        parts = urllib.parse.urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        body = _json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                       "clientInfo": {"name": "mcpgawk", "version": "1"}}}).encode()
        # A real user-agent: kite answers curl with 200 and urllib with a Cloudflare 403, and a
        # bare 403 read as "it challenged us" is exactly the false positive that kept the dead
        # sign-in button on screen.
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "user-agent": "mcpgawk/panel (+https://mcp.gawk.dev)"})
        challenged = False
        try:
            with urllib.request.urlopen(req, timeout=6) as r:
                r.read(1)                      # answered WITHOUT auth: no challenge
        except urllib.error.HTTPError as exc:
            # WWW-Authenticate is THE signal (RFC 9728 / OAuth): a bare 401/403 can be a bot
            # block, a firewall, or a proxy, none of which have a browser flow for us to run.
            challenged = bool(exc.headers.get("WWW-Authenticate"))
        except Exception:                      # noqa: BLE001 — unreachable: do not block the button
            return ""
        if challenged:
            return ""
        for well_known in (".well-known/oauth-authorization-server",
                           ".well-known/oauth-protected-resource"):
            try:
                with urllib.request.urlopen(f"{origin}/{well_known}", timeout=6) as r:
                    if r.status == 200:
                        return ""
            except urllib.error.HTTPError:
                continue
            except Exception:                  # noqa: BLE001
                return ""
        return ("it answers without asking us to authenticate and publishes no OAuth metadata, so "
                "there is no browser flow to run. If it needs credentials, they are in-band — look "
                "at the server's own tools, or set a header on the entry")
    except Exception:                          # noqa: BLE001 — a check that fails must not block
        return ""


def run_login_configure(name: str | None, value: str | None) -> dict[str, Any]:
    """Finish a guided in-band setup: hand the user's API key to the server's own configure tool,
    then ask its status tool for the verdict. The key is passed through and never stored."""
    from . import discover, remote_login
    if not name or not value:
        return {"ok": False, "message": "configure needs the server name and the pasted key"}
    try:
        entry = discover.discover_servers().get(name)
    except Exception as exc:                      # noqa: BLE001
        return {"ok": False, "message": f"could not read the fleet: {exc}"}
    if not entry:
        return {"ok": False, "message": f"no server named {name!r} in the current fleet"}
    launchable = dxt.resolve_for_launch(entry) or {}
    if not launchable.get("command"):
        return {"ok": False, "message": f"{name} cannot be launched from here"}
    result = remote_login.inband_setup(
        launchable["command"], list(launchable.get("args") or []),
        dict(launchable.get("env") or {}), "configure", value)
    _ACTION.update(setup_text="", setup_key="")   # the flow is spent either way
    if not result:
        return {"ok": False, "message": f"{name} configure tool did not answer; run "
                                        f"mcpgawk verify to see the server error"}
    _, status_text = result
    bad = any(w in status_text.lower() for w in ("not configured", "error", "invalid", "failed"))
    return {"ok": not bad, "message": f"{name}, in its own words:",
            "rows": [{"server": name, "outcome": "sign-in status",
                      "level": "bad" if bad else "ok", "detail": status_text}]}


def run_login(name: str | None) -> dict[str, Any]:
    """Complete ONE server's interactive browser sign-in, from the panel.

    The "needs your sign-in" row used to end with "run `mcpgawk scan --login <url>` in your own
    terminal" — a dead end with a button-shaped hole. This runs the SAME flow: the browser opens
    on this machine, the token lands in ~/.gawk/oauth, and nothing new is invented — so the
    consent story is unchanged, only the typing is gone.
    """
    from . import discover, remote_login
    if not name:
        return {"ok": False, "message": "sign-in needs a server name"}
    try:
        servers = discover.discover_servers()
    except Exception as exc:                      # noqa: BLE001 — the failure goes ON the page
        return {"ok": False, "message": f"could not read the fleet: {exc}"}
    entry = servers.get(name)
    if entry is None:
        return {"ok": False,
                "message": f"no server named {name!r} in the current fleet — refresh and retry"}
    url = remote_login.login_url(entry, name)
    if not url:
        # A LOCAL server can still have an in-band sign-in surface (Revolut X: a Desktop
        # extension whose check_auth_status returns the numbered setup steps and instructs
        # clients to present them). The click is the consent to launch it — the same model as
        # the row's verify button. dxt resolves Desktop's own defaults for the launch env.
        if entry.get("command"):
            launchable = dxt.resolve_for_launch(entry) or {}
            if launchable.get("command"):
                # GUIDED first: if the server has a key-generation tool, RUN it — reciting "run
                # the generate_keypair tool" at a user who has no way to run it is a dead end
                # ([FOUNDER] 2026-08-14: "it is not working"). The result (a PUBLIC key) goes on
                # the banner to copy, next to a form that finishes the job with the API key they
                # bring back.
                setup = remote_login.inband_setup(
                    launchable["command"], list(launchable.get("args") or []),
                    dict(launchable.get("env") or {}), "start")
                if setup:
                    _, setup_text = setup
                    _ACTION.update(setup_text=setup_text, setup_key=name, login_url="")
                    return {"ok": True,
                            "message": f"{name}: keypair ready — finish the steps below and "
                                       f"you are signed in."}
                inband = remote_login.inband_login(
                    command=launchable["command"], args=list(launchable.get("args") or []),
                    env=dict(launchable.get("env") or {}))
                if inband:
                    auth_url, server_text = inband
                    _ACTION.update(login_url=auth_url or "", notice="")
                    _open_login_in_browser(auth_url or "")
                    return {"ok": True,
                            "message": f"{name}, in its own words:",
                            "rows": [{"server": name, "outcome": "sign-in steps",
                                      "level": "warn", "detail": server_text}]}
        return {"ok": False,
                "message": f"{name} has no browser sign-in we can run: it is not an mcp-remote "
                           f"launcher, and the last scan did not see it ask for credentials"}
    # DOES THIS SERVER ACTUALLY DO OAUTH? Measured on the founder's fleet 2026-08-14: `kite`
    # answers `initialize` with 200 and NO auth challenge, and both OAuth discovery endpoints 404 —
    # its sign-in is IN-BAND (one of its own tools returns a broker link). The panel offered a
    # browser OAuth flow anyway, which cannot succeed, and then sat on "Running login · kite…" for
    # 330 seconds before blaming the sign-in. Ask first; a server that never challenges us has no
    # OAuth flow to run, and saying so in two seconds beats hanging for five and a half minutes.
    unsupported = _oauth_unsupported_reason(url)
    if unsupported:
        # NOT the end of the story. kite and Revolut X sign in through their OWN login tool — the
        # tool returns the real authorisation URL bound to a session ([FOUNDER] 2026-08-14: "every
        # time kite connects me to the webpage and i need to provide access"). A genuine panel
        # does that call FOR the user and hands them the link, instead of telling them to go look
        # at the server's tools themselves.
        # HELD, not fire-and-forget: the link kite returns is bound to the session that asked,
        # and closing that session killed every link on arrival ("session error" the moment the
        # founder clicked, 2026-08-14). The session now stays alive ~5 minutes while the human
        # authorises.
        # kite and Revolut X sign in through their OWN login tool — the tool returns the real
        # authorisation URL bound to a session ([FOUNDER] 2026-08-14: "every time kite connects
        # me to the webpage and i need to provide access"). The button used to hand out that link
        # and let the held session close having measured nothing (`inband_login_held`) — the same
        # defect d011d04 fixed in the CLI (`scan --sign-in`) and left in place here, so the
        # founder's successful kite sign-in on 2026-09-04 changed nothing on the page. The panel
        # now drives THAT CLI path as a child, publishes its link, and keeps the child waiting for
        # the "I have signed in" click (login-done), which is the child's Enter.
        proc, log_path = _run_signin_cli(name)
        link = _await_child_link(proc, log_path, seconds=60.0)
        if link:
            with _SIGNIN_LOCK:
                previous = _SIGNIN_CHILD.get("proc")
                _SIGNIN_CHILD.clear()
                _SIGNIN_CHILD.update(name=name, proc=proc, log_path=log_path, url=url,
                                     started=_now())
            if previous is not None and previous is not proc:
                _stop_signin_child(previous)        # a second click must not orphan the first
            _ACTION.update(
                login_url=link, signin_pending=name,
                notice=(f"{name} signs in through its own login tool, and that login belongs to "
                        f"ONE MCP session. This link authorises the session mcpgawk is holding — "
                        f"it does NOT sign your agent in."))
            _open_login_in_browser(link)
            return {"ok": True,
                    "message": (f"{name} sign-in link is ready — open it, sign in, then click "
                                f"‘I have signed in’ within 5 minutes, while mcpgawk holds the "
                                f"session it is bound to. WHAT THIS DOES: measures {name} as a "
                                f"signed-in user and records which sign-in it was measured "
                                f"through. WHAT IT DOES NOT DO: sign your agent in — {name} binds "
                                f"a login to the one session that asked, so Claude Desktop (and "
                                f"every other client) must run {name}'s own login tool from "
                                f"inside that client.")}
        # No link: the child ended (or said why) before offering one — its reason, never a guess.
        _stop_signin_child(proc)
        out = _read_log(log_path)
        if "does not sign in through a login tool" in out:
            return {"ok": False, "message": f"{name} does not offer a browser sign-in: {unsupported}"}
        return {"ok": False,
                "message": f"sign-in for {name} did not complete — {_login_failure_detail(name, url, out)}"}
    try:
        proc, log_path = _run_login_cli(url, _transport_flag(entry, url))
    except Exception as exc:                      # noqa: BLE001
        return {"ok": False, "message": f"sign-in for {name} did not complete: {exc}"}

    # PUBLISH THE AUTHORISATION LINK — and ONLY that link. The first version published the first
    # http(s) URL in the child's log, which is the server's own MCP ENDPOINT from the header
    # lines; opening a JSON-RPC endpoint in a browser is a 404 page ({"status":404} — figma,
    # founder 25 Aug). The child prints the real authorize URL after a fixed marker and opens
    # the browser ITSELF (oauth_login), so the panel anchors on the marker, never re-opens
    # (double browser tabs), and never publishes the endpoint.
    import re as _re
    import time as _time
    deadline = _time.monotonic() + 330
    published = False
    _endpoint = (url or "").rstrip("/")
    while _time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if not published:
            try:
                text = pathlib.Path(log_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            hit = _re.search(r"paste this into a browser:\s*(https?://\S+)", text)
            if hit:
                link = hit.group(1).rstrip(".,)")
                if link.rstrip("/") != _endpoint:
                    _ACTION.update(login_url=link,
                                   notice=f"Your browser opened {name}'s sign-in page — the "
                                          f"link below is the fallback if it didn't.")
                    published = True
        _time.sleep(0.5)
    else:                                          # loop exhausted: the human never finished
        proc.kill()

    try:
        out = pathlib.Path(log_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        out = ""
    _ACTION.update(login_url="", notice="")        # the link is spent either way

    # The token ON DISK is the outcome that matters, not the subprocess's exit code — the flow
    # can exit non-zero after storing a perfectly good token (the follow-on probe may fail).
    if remote_login.stored_access_token(url):
        return {"ok": True, "message": f"signed in to {name} — the token is stored on this "
                                       f"machine; verify can use it now"}
    # The child's ACTUAL reason, never a bare "did not complete" — that phrasing blamed the
    # sign-in for an argument bug once already, and for this swallowing bug a second time. And
    # never the child's LAST line: that was the scan footer ("Scanned locally — your server
    # inventory never left this machine.") on the founder's figma click, 2026-09-03, with the
    # 403 registration refusal five lines above it.
    return {"ok": False,
            "message": f"sign-in for {name} did not complete — {_login_failure_detail(name, url, out)}"}


def _login_failure_detail(name: str, url: str, out: str) -> str:
    """The one line of a failed `scan --http <url> --login` that says WHY, from its merged output.

    Order: the line that already names the way through a registration refusal; else the
    refusal itself, rendered by the CLI's own `_signin_failure_line` (so the panel and the
    terminal say the same thing); else the probe's per-attempt error line; else the "✗" summary;
    else the last line. The circular "retry with `--login`" clause is cut wherever it survives."""
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not lines:
        return (f"the flow printed nothing at all; run `mcpgawk scan --http {url} --login` in "
                f"a terminal to see it")
    for ln in lines:
        if "refuses automatic client registration" in ln:
            return ln.split(": ", 1)[1] if ln.startswith(f"{name}: ") else ln
    refusal = next((ln for ln in lines if "Registration failed" in ln), None)
    if refusal:
        from .cli import _signin_failure_line
        return _signin_failure_line(name, refusal, None).strip().split(": ", 1)[1]
    reason = next((ln for ln in lines if ln.startswith("- ")), None) \
        or next((ln for ln in lines if ln.startswith("✗")), None) \
        or lines[-1]
    return reason.split("; retry with")[0].rstrip(":")


def signin_asks(entries: dict) -> list[str]:
    """The servers waiting on a browser sign-in — the operator's to-do list, in config order.

    THE ONE PLACE this question is answered. The Getting-set-up stepper and the briefing strip's
    "Needs you" each computed it before, and disagreed (a search filter narrowed one of them):
    two sources of truth for "what needs me" is the two-truths class this panel keeps hitting.
    """
    return [n for n, e in (entries or {}).items()
            if isinstance(e, dict) and _login_button_applicable(e, n)]


def _login_button_applicable(entry: dict, name: str = "") -> bool:
    """Offer sign-in wherever one can actually happen, and nowhere else.

    Two shapes qualify: an interactive-auth launcher (mcp-remote), and a plain REMOTE server that
    the last scan saw answer 401/403 — our engine has always been able to OAuth the second
    (`scan --http <url> --login`), and gating the button on the launcher's name alone meant those
    servers got no button at all while the capability sat unused. Evidence, never a guess: a
    remote server we have no auth-required record for is left alone rather than handed a button
    that may do nothing.

    A completed login still suppresses the offer — it would be a re-run trap.
    """
    from . import remote_login
    url = remote_login.login_url(entry, name)
    if not url:
        # LOCAL servers can still carry their own sign-in surface (Revolut X's check_auth_status
        # returns the setup steps). Offer the button when the BASELINE — no launch needed to
        # decide — records a login/status-shaped tool; the click is the consent to launch, same
        # as verify. A server with no baseline and no URL stays button-less: a button that may do
        # nothing is the old trap.
        if entry.get("command"):
            try:
                from . import history
                store = history.load()
                for key, se in (store.get("servers") or {}).items():
                    if name in (se.get("aliases") or []):
                        rec = se.get("approved") or (se.get("history") or [{}])[-1]
                        tools = [t.lower() for t in (rec.get("tools") or {})]
                        # AUTH-shaped evidence only — bare "setup"/"instructions" put a sign-in
                        # button on browserstack, whose auth is env keys it already carries, and
                        # the click called a test scaffolder (founder, live, 2026-08-14).
                        return any("login" in t or "check_auth_status" in t or "auth_status" in t
                                   or "keypair" in t for t in tools)
            except Exception:  # noqa: BLE001 - an unreadable store must not add buttons
                return False
        return False
    # A STORED TOKEN IS NOT PROOF OF ACCESS. `auth-needed.json` is rewritten wholesale by every
    # scan, so a name in it means THE LAST SCAN WAS REFUSED FOR CREDENTIALS — fresher and stronger
    # evidence than a token sitting in the store, which may be expired, revoked, or for a
    # different audience. Measured on the founder's fleet 2026-08-27: notion had a stored token,
    # the server refused a scan carrying that very token, and the panel called it "configured,
    # never used" — a server that needs a person shown as one that needs nothing, which is the
    # precise mislabel the sign-in state exists to prevent.
    if name and name in remote_login.auth_needed():
        stale = remote_login.refused_after_login(url)
        if stale:
            return True
        if stale is None and not remote_login.stored_access_token(url):
            return True
    # A completed sign-in suppresses the offer — a token for OAuth servers, the sign-in MARK for
    # in-band ones (kite: no token exists; `mark_inband_login` is the only evidence). Without the
    # second half the tile asked kite for a sign-in forever, including right after one succeeded
    # (founder, 2026-09-04).
    return not (remote_login.stored_access_token(url) or remote_login.stored_login_id(url))


#: Launchers that complete an INTERACTIVE browser sign-in before a server will speak MCP.
_INTERACTIVE_AUTH_MARKERS = ("mcp-remote", "mcp_remote")


def _auth_shaped(entry: dict) -> bool:
    """Does this server sign in interactively? Read from the launch command, not from a name."""
    blob = " ".join([str(entry.get("command") or "")] + [str(a) for a in (entry.get("args") or [])])
    return any(m in blob for m in _INTERACTIVE_AUTH_MARKERS)


def _fchip(f: dict) -> str:
    """Severity colour, unless the finding was folded as first-party — then it is not an alarm."""
    if f.get("suppressed") or f.get("first_party"):
        return ""
    if f.get("loopback"):
        return "warn"                     # a local call is a question, not an exfiltration alarm
    return "bad" if str(f.get("severity")).lower() in ("critical", "high") else "warn"


def _foldnote(f: dict) -> str:
    if f.get("suppressed"):
        return ' <span class="chip">muted by you</span>'
    if f.get("loopback") and not f.get("first_party"):
        # Deliberately NOT folded (test_local_surface_token pins that localhost is not the
        # vendor): a server reaching 127.0.0.1 may be probing a local service, which is SSRF's
        # home turf. But "undeclared-egress · high" reads as exfiltration, and vault-rag
        # reaching Ollama is not that. Name what it is so the reader checks the right thing.
        return (' <span class="chip">loopback · reached a service on THIS machine — not '
                'exfiltration; check what listens there</span>')
    if f.get("first_party"):
        return ' <span class="chip">first-party · matches this server\'s own identity</span>'
    return ""


def _fixblock(r: dict) -> str:
    return f'<div class="fixit">Fix: {_esc(r["fix"])}</div>' if r.get("fix") else ""


def _remedy(note: str, entry: dict) -> str:
    """The FIX for a failure we already recognise, in the user's terms.

    Naming a failure is not the same as making it actionable. The panel told the founder that
    `Revolut X` could not find a module, that `pencil` returned ENOENT and that `resend` referenced
    an unset variable — three real, specific, fixable faults — and then left him to work out what to
    do about each. A row that reports a problem whose remedy it knows, and withholds it, is a report
    rather than a control surface.

    Returns "" when we do not actually know the fix: an invented remedy is worse than none.
    """
    n = note or ""
    # A Claude Desktop EXTENSION first: its manifest legitimately contains ${__dirname} and
    # ${user_config.*}, which the HOST resolves at launch. Telling that operator to "replace it
    # with an absolute path" is advice to break a working config — the product blaming the user
    # for our own blind spot (38i-q). dxt.explain() states the limit as ours.
    from . import dxt
    if dxt.is_extension(entry):
        why = dxt.explain(entry)
        if why:
            return why
    if "${" in n and ("Cannot find module" in n or "No such file" in n):
        return ("this config contains a literal ${...} that nothing expanded — it was meant to be "
                "resolved by whatever wrote it. Replace it with an absolute path in the agent's MCP "
                "config.")
    if "ENOENT" in n or "no longer exists" in n:
        cmd = str(entry.get("command") or "")
        return ("the launch target does not exist on disk" + (f" ({cmd})" if cmd else "") +
                ". Reinstall the app, or remove the server from the agent's MCP config — a "
                "configured path that is empty today is a path something else could occupy tomorrow.")
    m = re.search(r"\$\{([A-Z0-9_]+)\}", n)
    if m and "not set" in n:
        var = m.group(1)
        return (var + " is not set. If it is in your Keychain, launch with "
                + var + "=$(security find-generic-password -s <service> -w) mcpgawk panel — the "
                "value never touches disk or a transcript.")
    return ""


def _nothing_recorded_outcome(note: str, entry: dict) -> tuple[str, str]:
    """Why a server recorded no behaviour, in the user's terms.

    A server behind interactive OAuth cannot be observed by a verify run: it wants a browser sign-in
    first, and a verify run has no browser and no user, so the server exposes zero
    tools. Reporting that as a bare "checked 0 tool(s)" made the founder reconnect the server and
    re-run, twice, chasing a fault that was not there. It is a LIMIT, and a limit has to be stated
    as one — while still never being dressed up as a pass. Absence of observation is not safety.
    """
    if "checked 0 tool(s)" in note and _auth_shaped(entry):
        # NOT "because the sandbox is isolated" — an earlier version of this string said that and it
        # was false: nothing in this codebase ever passes `--isolate`, so no container is involved.
        # The real reason is narrower and checkable: mcp-remote completes an interactive browser
        # sign-in before the server will list tools, and a verify run has no browser and no user.
        # A DEAD END ONLY WHILE IT IS ONE. If `mcpgawk scan --login` already completed this
        # server's browser flow, the token is on disk and the server can be verified as a remote
        # target with that bearer attached — no browser needed (see remote_login.py). Saying
        # "re-running will not change this" while a usable login sits in ~/.gawk/oauth is a
        # dead end we invented. The offer states its cost, because an authenticated verify makes
        # REAL calls as the user and archives response excerpts.
        from . import remote_login
        if remote_login.has_stored_login(entry):
            return ("needs your sign-in — but you have one",
                    remote_login.consent_text("this server", entry)
                    + " Nothing has been verified with it yet.")
        return ("needs your sign-in",
                "this server signs in through a browser (mcp-remote) before it will list tools, and "
                "a verify run has no browser and nobody to click. It exposed 0 tools. Still NOT "
                "verified — re-running will not change this without a stored login "
                "(`mcpgawk scan --login <url>` in your own terminal).")
    return ("no behaviour recorded", note)


def _engine_note(output: str, server: str) -> str:
    """The engine's own last word about ONE server, for the page.

    Best-effort by design: the engine returns no structured per-server result (see
    verify.run_captured), so this scrapes its lines. When nothing mentions the server it says so
    plainly rather than inventing a cause — an unexplained failure must not be dressed up as an
    explained one.
    """
    hits = [ln.strip() for ln in (output or "").splitlines()
            if server and server in ln and ln.strip()]
    if not hits:
        return "the engine said nothing about this server"
    return hits[-1][:300]


def run_verify_fleet(only: str | None = None) -> dict[str, Any]:
    """Verify every LOCAL server's behaviour in the sandbox — the same thing the front door does,
    triggered from the GUI. Remote servers are skipped here (they need per-server auth); local
    servers are launched, which is why this lives behind the panel's token like every other action
    that runs code."""
    import json as _json
    import tempfile

    from . import discover, verify as _verify
    reason = _verify.unavailable_reason()
    if reason is not None:
        return {"ok": False, "message": f"verify unavailable: {reason}"}
    entries = discover.discover_servers()
    entries = entries[0] if isinstance(entries, tuple) else (entries or {})
    # A Claude Desktop EXTENSION declares its command with host-resolved placeholders. Handing
    # them to the engine verbatim produced `Cannot find module '.../${__dirname}/dist/index.js'`
    # — an unverifiable server AND (before 38i-q) advice to "fix" a config that was never broken.
    # dxt.resolve_for_launch fills ${__dirname} from the manifest's own directory and returns None
    # when a ${user_config.*} value only Claude Desktop holds makes launching genuinely
    # impossible. Those servers stay in the fleet and are reported as unverified WITH the reason
    # (see _remedy) — never silently dropped, which would read as "nothing to check here".
    # THROUGH-GATEWAY ROUTING ([FOUNDER] 2026-08-15, generalised for every sign-in server): a
    # server whose sign-in is session-bound cannot be verified by a fresh spawn — kite's own
    # mcp-remote even collides with the gateway's on its fixed callback port. When a gateway is
    # LIVE and already fronts the server, verify talks to the gateway endpoint and addresses the
    # backend's namespaced tools; the in-band sign-in then authenticates the gateway's own
    # persistent session, which stays usable afterwards. Applies to ANY server needing sign-in.
    _gw = gateway_status()
    _gw_live = (_gw.get("live") or {}).get("listen")
    _gw_backends: set[str] = set()
    if _gw_live:
        try:
            import yaml as _yaml
            _cfgp = behaviour_profile_path().parent / "gateway" / "gateway.yaml"
            if _cfgp.is_file():
                _doc = _yaml.safe_load(_cfgp.read_text(encoding="utf-8")) or {}
                _gw_backends = set((_doc.get("backends") or {}).keys())
        except Exception:  # noqa: BLE001 — no readable config = no through-gateway routing
            _gw_backends = set()

    local = {}
    gatewayed = {}
    for n, e in entries.items():
        if not (isinstance(e, dict) and e.get("command")):
            continue
        # A session-bound sign-in server the live gateway fronts routes THROUGH the gateway.
        if (_gw_live and n in _gw_backends
                and _login_button_applicable(e, n)):
            _url = str(_gw_live)
            if not _url.startswith("http"):
                _url = f"http://{_url}"
            if not _url.rstrip("/").endswith("/mcp"):
                _url = _url.rstrip("/") + "/mcp"
            gatewayed[n] = {"url": _url, "transport": "http", "backendPrefix": n}
            continue
        launchable = dxt.resolve_for_launch(e) or e
        local[n] = {k: launchable[k] for k in ("command", "args", "env") if k in launchable}
    # ONE SERVER AT A TIME IS THE DEFAULT SHAPE, not a special case. The fleet button made every
    # answer cost five silent minutes, so the founder clicked it, waited, and left the page. A row
    # action returns in seconds and is the unit a user actually thinks in: "what about THIS server?"
    all_targets = {**local, **gatewayed}
    if only:
        if only not in all_targets:
            return {"ok": False, "message": f"{only} is not a local server on this machine"}
        local = {only: local[only]} if only in local else {}
        gatewayed = {only: gatewayed[only]} if only in gatewayed else {}
        all_targets = {**local, **gatewayed}
    if not all_targets:
        return {"ok": False, "message": "no local servers to verify"}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     prefix="mcpgawk-panel-verify-") as fh:
        _json.dump({"mcpServers": all_targets}, fh)
        cfg = fh.name
    try:
        # --out KEEPS THE FINDINGS. Without it the engine's 21 convictions existed only in this
        # subprocess's stdout: the banner showed a count until the panel restarted, and Evidence,
        # Decisions and every drill-down were untouched by a verify because nothing was persisted
        # for them to read. The founder: "apart from the verify the fleet output nothing changed in
        # the panel." The engine already writes the complete report atomically; we simply never
        # asked for it.
        report_path = behaviour_profile_path().parent / "last-verify.json"
        # KEEP THE PREVIOUS RESULTS. `--out` writes the report for THIS run, so verifying one
        # server rewrote the file with only that server in it and every other server's real,
        # reproduced findings were deleted — the row's pill flipped red to green "At baseline" and
        # the Findings tab said "No verify has run yet" seconds after one had. A per-server verify
        # is the DEFAULT shape here, so this path erased evidence on the common case.
        prev_report: dict[str, Any] = {}
        try:
            if report_path.is_file():
                prev_report = _json.loads(report_path.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            prev_report = {}                      # unreadable previous report: nothing to preserve
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass                                  # a read-only HOME must not fail the run
        # EVERY verify archives its FULL evidence. The engine emits a raw per-attempt
        # observation stream (--audit-log: one JSONL line per reproduction attempt, every
        # attempt, not just convictions) — and until 2026-07-31 nothing in the product ever
        # passed the flag, so the deepest record was discarded on every run while
        # last-verify.json was overwritten by the next one. Same gap-shape as --isolate: the
        # capability existed, no surface requested it. One directory per run, never rewritten;
        # the newest 30 are kept. Same-second runs share a directory (last writer wins on the
        # audit file) — acceptable for a human-driven surface, noted rather than hidden.
        import shutil as _shutil
        import time as _time
        runs_dir = behaviour_profile_path().parent / "verify-runs"
        run_dir = runs_dir / _time.strftime("%Y-%m-%dT%H-%M-%SZ", _time.gmtime())
        audit_args: list[str] = []
        try:
            # secure_dir, not mkdir: this directory holds every reproduction attempt's audit
            # log. Plain mkdir left it 0755 (28 of them on the founder's machine, measured
            # 2026-08-13) while `~/.mcpgawk` and `~/.gawk` are both 0700.
            from .state import secure_dir, secure_file
            secure_dir(run_dir.parent)   # mkdir(parents=True) leaves PARENTS at the default mode
            secure_dir(run_dir)
            audit_args = ["--audit-log", str(run_dir / "audit.jsonl")]
        except OSError:
            audit_args = []  # read-only HOME: run without the archive rather than not at all
        # A SILENT WRITE FAILURE IS A LIE. Both profile writers swallow OSError so a read-only
        # HOME cannot fail an otherwise-good run — reasonable, except the panel then reports
        # "behaviour recorded" when nothing was. Proven 2026-07-31: with ~/.gawk read-only the whole
        # suite ran green and the profile silently never updated. Compare the profile's mtime across
        # the run and say so when it did not move.
        prof_before = -1.0
        try:
            prof_before = behaviour_profile_path().stat().st_mtime
        except OSError:
            prof_before = -1.0
        # --isolate: the button says sandbox, so a sandbox must actually be requested (HANDOFF
        # 38c — the claim shipped for weeks with nothing ever passing this flag). The engine
        # degrades HONESTLY on its own: no Docker, or a command it cannot containerize, falls
        # back to the proxy-only sandbox and records sandboxDegradedReason per server, which is
        # surfaced in the rows below — never silently upgraded into a stronger claim.
        # IN-BAND SIGN-IN, SURFACED LIVE ([FOUNDER] 2026-08-15 "go ahead with kite"): the
        # engine now runs a session-bound server's own login tool and WAITS for the human.
        # The URL leaves the engine as an audit event; a tailer thread lifts it onto the
        # banner while the run is still going, so the human sees the link the moment it
        # exists instead of after the timeout.
        import threading
        _auth_stop = threading.Event()

        def _tail_auth_events() -> None:
            audit_p = run_dir / "audit.jsonl"
            pos = 0
            while not _auth_stop.wait(2.0):
                try:
                    with open(audit_p, encoding="utf-8", errors="replace") as fh:
                        fh.seek(pos)
                        for line in fh:
                            pos = fh.tell()
                            try:
                                ev = json.loads(line)
                            except ValueError:
                                continue
                            if ev.get("type") == "auth-needed" and ev.get("url"):
                                _open_login_in_browser(str(ev["url"]))
                                _ACTION.update(
                                    login_url=str(ev["url"]),
                                    notice=f"{ev.get('server')} signs in through its own "
                                           f"'{ev.get('tool')}' tool — open the link on this "
                                           f"banner to authorise THIS verify session. The run "
                                           f"waits up to 5 minutes.")
                            elif ev.get("type") == "auth-ok":
                                _ACTION.update(login_url="",
                                               notice=f"{ev.get('server')}: signed in — "
                                                      f"the checks are running.")
                            elif ev.get("type") == "auth-timeout":
                                _ACTION.update(login_url="",
                                               notice=f"{ev.get('server')}: sign-in was not "
                                                      f"completed in 5 minutes — auth-needing "
                                                      f"checks will fail honestly.")
                except OSError:
                    pass

        _tailer = threading.Thread(target=_tail_auth_events, daemon=True)
        if audit_args:
            _tailer.start()
        try:
            rc, engine_output = _verify.run_captured(
                [cfg, "--isolate", *audit_args, "--out", str(report_path)], timeout=1200)
        finally:
            _auth_stop.set()
        prof_after = -1.0
        try:
            prof_after = behaviour_profile_path().stat().st_mtime
        except OSError:
            prof_after = -1.0
        profile_unwritten = prof_after == prof_before
        # Merge THIS run's servers over the previous ones, rather than replacing the file.
        _merge_verify_report(report_path, prev_report)
        if audit_args:
            try:                                  # the report belongs with its audit stream
                archived = run_dir / "report.json"
                # copyfile does NOT carry the source's permissions (copy2 would), so this archive
                # was 0644 while the report it copies is 0600. Measured 2026-08-13.
                _shutil.copyfile(report_path, archived)
                secure_file(archived)
            except OSError:
                pass
            try:                                  # bounded retention: newest 30 run archives
                dirs = sorted((p for p in runs_dir.iterdir() if p.is_dir()),
                              key=lambda p: p.name)
                for old in dirs[:-30]:
                    _shutil.rmtree(old)
            except OSError:
                pass
    finally:
        try:
            os.unlink(cfg)
        except OSError:
            pass
    # Engine exit codes: 0 clean, 1 actionable findings, 2 COMPLETED-BUT-INCOMPLETE (check
    # errors / server errors / unenumerated dynamic dispatch — the report is fully written).
    # rc 2 used to return a bare "verify did not complete (exit 2)" with no rows, hiding the
    # per-server detail the report carries — seen live 2026-07-31 when every containerized probe
    # failed on colima (virtiofs mounts a fresh dir empty) and the page said one useless line
    # while the report named every tool and every infra failure. Incomplete is a RESULT.
    if rc in (0, 1, 2):
        # REPORT WHAT WAS RECORDED, NOT WHAT WAS ATTEMPTED. This said "verified {len(local)}
        # server(s)" — len(local) is the list handed to the engine, so a run where 5 of 8 produced
        # nothing still announced eight successes, while the tiles (which count a server as
        # verified only if it appears in behaviour.json) did not move at all. The founder read the
        # dashboard as fabricated, correctly. verify.run() returns ONE INT, so the engine's
        # per-server outcome cannot come back through it; the profile it writes is the only
        # ground truth available here, so the count is taken from there and the gap is NAMED.
        seen_map: dict[str, Any] = {}
        ran_map: dict[str, Any] = {}
        try:
            prof = behaviour_profile_path()
            if prof.is_file():
                _doc = json.loads(prof.read_text(encoding="utf-8"))
                seen_map = _doc.get("servers") or {}      # convictions
                ran_map = _doc.get("verified") or {}      # observation, clean or not
        except (OSError, ValueError):
            seen_map, ran_map = {}, {}            # unreadable profile => claim nothing observed
        # Per-server isolation degradation AND finding folding, from the report the engine just
        # wrote. --isolate is REQUESTED above; when what RAN was weaker (no Docker,
        # uncontainerizable command), the reason must reach the page — a degraded run silently
        # labelled "sandbox" is the exact overclaim this product exists to catch in others.
        # Folding: the SAME first-party classification the Findings screen applies (07293b2),
        # or the two surfaces contradict each other about one run. Seen live 2026-07-31 in the
        # founder's recording: this banner said "42 tool(s) with findings on 3 server(s)" in red
        # while Findings, one click away, said "1 needing a decision · 20 folded" and the table
        # showed those same servers green At-baseline. A first-party finding stays LISTED on the
        # Findings screen; here it is counted as folded, never as a conviction.
        degraded_map: dict[str, str] = {}
        noise_map: dict[str, str] = {}            # server -> its labels were ignored as noise
        real_map: dict[str, set] = {}             # server -> tools with non-first-party findings
        folded_map: dict[str, int] = {}           # server -> first-party findings folded
        report_readable = False
        try:
            _rep_doc = json.loads(report_path.read_text(encoding="utf-8"))
            report_readable = True
            for s in _servers_of_this_run(_rep_doc, all_targets):
                sname = str(s.get("server") or "")
                if s.get("sandboxDegradedReason"):
                    degraded_map[sname] = str(s["sandboxDegradedReason"])
                if s.get("labelNoiseNote"):
                    noise_map[sname] = str(s["labelNoiseNote"])
                for f in (s.get("findings") or []):
                    if f.get("suppressed"):
                        continue
                    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
                    hosts = [str(x) for x in (ev.get("egress") or ev.get("hosts") or [])]
                    tool = str(f.get("tool") or (f.get("candidate") or {}).get("toolName") or "?")
                    if first_party(sname, hosts, all_targets.get(sname)):
                        folded_map[sname] = folded_map.get(sname, 0) + 1
                    else:
                        real_map.setdefault(sname, set()).add(tool)
        except (OSError, ValueError):
            # Unreadable report: no degradation info, and fall back to RAW conviction counts from
            # the profile below — overcounting is the safe direction, silence is not.
            degraded_map, noise_map, real_map, folded_map, report_readable = {}, {}, {}, {}, False
        # A server counts as observed when a run EXERCISED it. Counting convictions instead meant a
        # clean fleet reported as an unverified one, and "observed 2 of 8" understated real work.
        seen = {n for n, o in ran_map.items()
                if isinstance(o, dict) and (o.get("toolsChecked") or 0) > 0} | set(seen_map)
        got = sorted(n for n in all_targets if n in seen)
        missing = sorted(n for n in all_targets if n not in seen)
        # Per-server rows for the PAGE. Sending the user to a terminal to find out which server
        # failed is the CLI-only habit this surface exists to replace.
        def _verdict(n: str) -> tuple[str, str, str]:
            """Thin adapter: pull this server's numbers out of the maps, then apply the rule.

            The rule itself lives at module level (`verify_verdict`) because it decides whether a
            server is presented as clean, and a safety verdict buried in a closure inside the
            function that runs a whole fleet verify is one that cannot be tested — which is how
            "clean - 0 tool(s)" shipped.
            """
            _o = ran_map.get(n)
            o: dict[str, Any] = _o if isinstance(_o, dict) else {}
            return verify_verdict(
                checked=o.get("toolsChecked") or 0,
                skipped=list(o.get("skipped") or []),
                errors=o.get("checkErrors") or 0,
                hits=len(real_map.get(n) or ()) if report_readable else len(seen_map.get(n) or {}),
                folded=folded_map.get(n, 0),
                backend=o.get("backend"),
                degraded=degraded_map.get(n),
                label_noise=noise_map.get(n),
            )

        rows = []
        for n in got:
            outcome, level, detail = _verdict(n)
            rows.append({"server": n, "outcome": outcome, "level": level, "detail": detail})
        needs_auth = 0
        for n in missing:
            note = _engine_note(engine_output, n)
            _spec = all_targets.get(n) or {}
            outcome, detail = _nothing_recorded_outcome(note, _spec)
            needs_auth += outcome == "needs your sign-in"
            rows.append({"server": n, "outcome": outcome, "level": "bad", "detail": detail,
                         "fix": _remedy(note, _spec)})

        # THE HEADLINE IS THE WORST THING FOUND, not "the action completed". This banner was green
        # while reporting 5 of 8 unverified and 21 convictions — success styling on a bad result,
        # which is how the founder read the page as saying the opposite of what it found.
        if report_readable:
            convicted = sorted(n for n in got if real_map.get(n))
            finding_tools = sum(len(real_map.get(n) or ()) for n in convicted)
        else:
            convicted = sorted(n for n in got if seen_map.get(n))
            finding_tools = sum(len(seen_map.get(n) or {}) for n in convicted)
        folded_total = sum(folded_map.values())
        parts = []
        if convicted:
            parts.append(f"{finding_tools} tool(s) with findings on "
                         f"{len(convicted)} server(s): {', '.join(convicted)}")
        if missing:
            parts.append(f"{len(missing)} of {len(local)} NOT verified"
                         + (f" ({needs_auth} need your sign-in)" if needs_auth else ""))
        if profile_unwritten:
            # Report it FIRST: every count below is read from a profile that did not update, so the
            # whole result may describe a previous run.
            parts.insert(0, f"observations were NOT saved — {behaviour_profile_path()} did not "
                            f"change. Everything below may be from an earlier run")
        clean = [r for r in rows if r["level"] == "ok"]
        # Folded findings are a FOOTNOTE, not an alarm: they must never turn a clean run red, and
        # never disappear either — the Findings screen lists every one with its reason.
        folded_note = (f"{folded_total} first-party finding(s) folded (vendors' own traffic — "
                       f"listed on Findings)") if folded_total else ""
        evidence_dir = str(run_dir) if audit_args else ""
        evidence_note = f"full evidence: {evidence_dir}" if evidence_dir else ""
        troubled = [r for r in rows if r["level"] != "ok"]
        if not parts and clean and not troubled:    # genuinely nothing wrong, nothing unchecked
            msg = f"clean — {len(clean)} local server(s) verified, no findings"
            tail = " · ".join(x for x in (folded_note, evidence_note) if x)
            return {"ok": True, "rows": rows, "level": "ok", "evidence_dir": evidence_dir,
                    "message": f"{msg} · {tail}" if tail else msg}
        if not parts:
            # ZERO verified must NEVER headline as clean. The founder read "clean — 0 local
            # server(s) verified" one line above a row saying "incomplete — not clean"
            # (2026-08-15, live) — a headline that contradicts its own rows is wrong twice.
            parts.append(f"incomplete — {len(troubled)} server(s) ran but proved nothing"
                         if troubled else "incomplete — nothing was verified")
        parts.append(f"{len(clean)} clean")
        if folded_note:
            parts.append(folded_note)
        if evidence_note:
            parts.append(evidence_note)
        return {"ok": False, "rows": rows, "level": "bad" if convicted else "warn",
                "evidence_dir": evidence_dir, "message": " · ".join(parts)}
    # The audit stream and report are written INCREMENTALLY by the engine, so even a timeout or
    # crash leaves partial evidence in the run archive — say where it is, not just that it failed.
    _ev = f" · partial evidence: {run_dir}" if audit_args else ""
    if rc == 4:
        return {"ok": False, "message": f"verify timed out — INCOMPLETE, not clean{_ev}"}
    return {"ok": False, "message": f"verify did not complete (exit {rc}){_ev}"}


#: The panel's ONE script. Served from our own origin so `script-src 'self'` allowlists it while
#: every injected inline block stays dead. It renders nothing itself: the server pre-renders the
#: banner fragment (`_action_banner`, the same function the full page uses — one rendering path,
#: one escaping path) and this only places it and settles the page ONCE when a run completes,
#: replacing the 5-second whole-page refresh whose yanking was the founder's "haywire".
_PANEL_JS = """\
(function () {
  "use strict";
  // Esc closes whatever popup is open (round 2): a finished-action popup collapses to its
  // summary line; the server-detail modal navigates to its scrim's close href. Enhancement
  // only — both popups close without script (summary click / scrim link).
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    var am = document.querySelector("details.amodal[open]");
    if (am) { am.removeAttribute("open"); return; }
    var scrim = document.querySelector("a.scrim");
    if (scrim && scrim.href) { window.location = scrim.href; }
  });
  document.addEventListener("click", function (ev) {
    var el = ev.target && ev.target.closest ? ev.target.closest("[data-copy]") : null;
    if (!el || !navigator.clipboard) return;
    navigator.clipboard.writeText(el.getAttribute("data-copy") || "").then(function () {
      var old = el.textContent;
      el.textContent = "Copied";
      setTimeout(function () { el.textContent = old; }, 1500);
    });
  });
  // A table that CAN scroll must LOOK like it: the right-edge fade appears only while there
  // is genuinely more to the right, and clears at the end of the scroll.
  var markScrollables = function () {
    var els = document.querySelectorAll(".tscroll");
    for (var i = 0; i < els.length; i++) (function (el) {
      var update = function () {
        el.classList.toggle("more", el.scrollWidth - el.clientWidth - el.scrollLeft > 4);
      };
      if (!el.getAttribute("data-sc")) {
        el.setAttribute("data-sc", "1");
        el.addEventListener("scroll", update, {passive: true});
        // Explicit, not left to the browser: a focused scroll region moves on arrow keys in
        // every engine, the same 40px step, and never steals keys typed into a child control.
        el.addEventListener("keydown", function (ev) {
          if (ev.target !== el) return;
          if (ev.key === "ArrowRight") { el.scrollLeft += 40; ev.preventDefault(); }
          if (ev.key === "ArrowLeft")  { el.scrollLeft -= 40; ev.preventDefault(); }
        });
      }
      update();
    })(els[i]);
  };
  markScrollables();
  window.addEventListener("resize", markScrollables);
  var bars = document.querySelectorAll(".abar[data-live]");
  var bar = bars.length ? bars[0] : null;
  if (!bar || !window.EventSource) return;   // no bar or ancient browser: noscript refresh rules
  // Result pop must survive the fast-action race: when the action finished BEFORE the stream
  // connected (wasRunning never true), the settle-reload never fires — so if THIS load followed
  // an action (done=1, noted before the URL is scrubbed), open the result popup on delivery.
  var justActed = location.search.indexOf("done=1") !== -1;
  var wasRunning = null;
  var t = bar.getAttribute("data-t") || "";
  var es = new EventSource(t ? "/events?t=" + encodeURIComponent(t) : "/events");
  var deadProbes = 0;
  es.onerror = function () {
    // The stream drops for two very different reasons: the 30-min stream deadline (the panel is
    // fine; EventSource reconnects on its own) and the panel PROCESS being gone — which twice
    // left the founder clicking silently dead buttons on a stale tab. Only a failed fetch of our
    // own script proves the second, so probe before declaring anything.
    setTimeout(function () {
      fetch("/panel.js", {cache: "no-store"}).then(function () { deadProbes = 0; })
        .catch(function () {
          deadProbes += 1;
          if (deadProbes < 2 || document.getElementById("gone-note")) return;
          es.close();
          var n = document.createElement("div");
          n.id = "gone-note";
          n.textContent = "This page's panel has stopped — it was closed or restarted. " +
            "The buttons here no longer reach anything. Reopen it from your terminal " +
            "(mcpgawk panel) and use the fresh link it prints.";
          n.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:9999;" +
            "padding:12px 16px;background:#7f1d1d;color:#fff;text-align:center;" +
            "font:600 13px/1.45 system-ui";
          document.body.prepend(n);
        });
    }, 1500);
  };
  es.onmessage = function (ev) {
    var d;
    try { d = JSON.parse(ev.data); } catch (e) { return; }
    if (typeof d.html === "string") {
      // PRESERVE the user's open/closed choice across swaps: the fragment re-delivers whenever
      // its text ages ("just now" -> "1m ago"), and a naive innerHTML replace slammed the record
      // shut the moment the user opened it (caught live, 25 Aug).
      var wasOpen = !!bar.querySelector("details.amodal[open]");
      bars.forEach(function (b) { b.innerHTML = d.html; });   // every live banner, every tab
      var det = bar.querySelector("details.amodal");
      if (det && (wasOpen || (justActed && d.running === false))) {
        det.setAttribute("open", "");
      }
      if (d.running === false) justActed = false;   // survive running frames; spend on the result
    }
    var slog = document.getElementById("slog");
    if (slog && typeof d.log === "string" && d.log) slog.innerHTML = d.log;
    if (wasRunning === true && d.running === false) {
      es.close();
      // One settle with fresh rows — routed through done=1 so the finished action pops exactly
      // once on that load (the URL is scrubbed below, so a later refresh shows the collapsed
      // record instead of re-opening the popup).
      var u = new URL(location.href);
      u.searchParams.set("done", "1");
      location.replace(u.toString());
      return;
    }
    wasRunning = d.running;
  };
  // A result popup DISMISSES ITSELF when you move on: switching tabs or clicking anywhere
  // outside it collapses the details (founder recording, 25 Aug: the gateway-call popup
  // followed them across four tabs until they found Close).
  document.addEventListener("change", function (ev) {
    if (ev.target && ev.target.name === "nav") {
      document.querySelectorAll("details.amodal[open]").forEach(function (d) {
        d.removeAttribute("open");
      });
    }
  });
  document.addEventListener("click", function (ev) {
    var open = document.querySelector("details.amodal[open]");
    if (open && !open.contains(ev.target)) open.removeAttribute("open");
  });
  // Scrub done=1 after it has done its one job, so refresh/bookmark never re-pops the result.
  if (location.search.indexOf("done=1") !== -1) {
    var clean = new URL(location.href);
    clean.searchParams.delete("done");
    history.replaceState(null, "", clean.toString());
  }
})();
"""


def serve(port: int = 7718, open_browser: bool = True, log=print) -> int:
    """Serve the panel as an authenticated LOCAL CONTROL SURFACE.

    Read views are open (there is nothing to authorise in looking). ACTIONS — re-scan, verify,
    approve — carry the same token model as `decide`, because those run code or move trust, and an
    agent can drive a browser: a page an agent stumbles onto must not be able to click them. The
    token is printed to this terminal and never written to any file the agent reads.
    """
    import secrets
    import threading
    import urllib.parse
    import webbrowser
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    token = secrets.token_urlsafe(24)
    load_last_action()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def _send_download(self, body: bytes, ctype: str, filename: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):                        # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/brand.svg":
                from ._brand import NATIVERSE_MARK_SVG
                body = NATIVERSE_MARK_SVG.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Cache-Control", "max-age=86400")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/panel.js":
                body = _PANEL_JS.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")   # ship with the page, never stale
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/events":
                # Live action state, as pre-rendered banner HTML — the exact same fragment and
                # escaping the full page uses. Streams only what the read-only page already shows,
                # so it grants nothing the bare URL does not. One thread per viewer
                # (ThreadingHTTPServer); localhost, single user, bounded below.
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                # The fragment is rendered WITH the token only for a caller that proved it
                # holds it — otherwise the stream would either wipe the tokened page's forms
                # (the first version did exactly that: the SSE update replaced the banner with a
                # tokenless fragment and the configure form vanished mid-flow) or leak the token
                # to any local reader. Same gate as the page itself.
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                stream_token = token if secrets.compare_digest(
                    (qs.get("t") or [""])[0], token) else ""
                last = None
                deadline = time.monotonic() + 30 * 60   # a tab left open re-connects on its own
                # The session log rides the same stream, recomputed every 5th tick — it reads
                # sqlite and a directory listing, and once a second per viewer would be churn
                # for a record whose fastest writer is a 300s sweep cycle. Token-free content
                # only: the same rows the read-only page already seeds.
                log_html = ""
                tick = 0
                try:
                    while time.monotonic() < deadline:
                        if tick % 5 == 0:
                            try:
                                log_html = _session_log_html(session_log_lines())
                            except Exception:  # noqa: BLE001 — the banner must keep streaming
                                pass
                        tick += 1
                        state = dict(_ACTION)
                        payload = json.dumps({"running": bool(state.get("running")),
                                              "html": _action_banner(state, stream_token),
                                              "log": log_html})
                        if payload != last:
                            self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                            self.wfile.flush()
                            last = payload
                        else:
                            self.wfile.write(b": hb\n\n")   # heartbeat keeps proxies honest
                            self.wfile.flush()
                        time.sleep(1.0)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass                                  # viewer left; the thread ends with them
                return
            # The record, downloadable. "Everything logged and available to download" — the raw
            # append-only log verbatim, or a spreadsheet-friendly CSV of the same rows. No token:
            # this is your own local record of your own machine, the same bytes `cat` would show.
            if path == "/api/state":
                # The JSON face (ledger 108). Token-free and read-only, like the exports and the
                # page: reading is open on this machine, the token buys the buttons. An
                # allow-list projection — see `api_state`.
                body = json.dumps(api_state(collect()), sort_keys=True).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/export/calls.jsonl":
                self._send_download(export_log_jsonl(), "application/x-ndjson", "mcpgawk-log.jsonl")
                return
            if path == "/export/calls.csv":
                self._send_download(export_log_csv(), "text/csv", "mcpgawk-log.csv")
                return
            if path == "/export/findings.csv":
                self._send_download(export_findings_csv(), "text/csv", "mcpgawk-findings.csv")
                return
            if path == "/export/servers.csv":
                self._send_download(export_servers_csv(), "text/csv", "mcpgawk-servers.csv")
                return
            if path != "/":
                # Any other path used to serve the full page with a 200 — a wrong URL looked
                # exactly like a right one. A panel answers for the routes it has.
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Not found. The panel lives at /")
                return
            # The action token is served ONLY to a request that already carries it. Before this,
            # do_GET embedded the full token in every response while read views were open, so any
            # local process — including an agent, with no credential at all — could GET the page,
            # scrape the hidden field and POST actions. Proven 2026-07-30: an agent-marked process
            # scraped the token and its `act=scan` POST returned HTTP 200. That defeated the whole
            # point of the gate, which exists because an agent asked to approve its own unblocking
            # will do it. Reading stays open; holding the token is what buys the buttons.
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            _traw = (q.get("t") or [""])[0]
            shown = token if secrets.compare_digest(_traw, token) else ""
            body = render(collect(), token=shown, action=dict(_ACTION),
                          stale_token=bool(_traw) and not shown,
                          fresh_action=bool((q.get("done") or [""])[0]),
                          q=(q.get("q") or [""])[0][:80],
                          tier_filter=(q.get("tier") or [""])[0][:20],
                          sel=(q.get("sel") or [""])[0][:120],
                          tl=(q.get("tl") or [""])[0][:200],
                          ag=(q.get("ag") or [""])[0][:80],
                          br=(q.get("br") or [""])[0][:120],
                          tc=(q.get("tc") or [""])[0][:120],
                          tab=(q.get("tab") or [""])[0][:3]).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            # NEVER CACHE THE PAGE. A live control surface must reflect the machine's state right
            # now — and, in dev, a rebuilt panel. Without this the browser served a stale copy and
            # a real change read as "nothing changed" (founder, 24 Aug). The page is state, not an
            # asset; only the versioned favicon/JS opt into caching above.
            self.send_header("Cache-Control", "no-store, must-revalidate")
            # Actions are same-origin POST forms; keep the strict CSP but allow the form submit.
            # `script-src 'self'` is the allowlist, not a relaxation: /panel.js (ours) runs,
            # and an inline <script> smuggled through a server-controlled description still
            # cannot — inline needs 'unsafe-inline', which stays absent.
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; "
                             "script-src 'self'; connect-src 'self'; img-src 'self'; "
                             "form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):                       # noqa: N802
            length = int(self.headers.get("Content-Length", 0) or 0)
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            got = (form.get("token") or [""])[0]
            if not secrets.compare_digest(got, token):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Refused: this action did not carry the panel's token, so it "
                                 b"did not come from you. The token is in your terminal.")
                return
            act = (form.get("act") or [""])[0]
            # The redirect must land the human back on the tab they acted from — radio-tab
            # state dies with the page load, and every action used to dump them on Servers.
            _rtab = (form.get("tab") or [""])[0]
            _rtab = _rtab if _rtab in {t for t, _ in _TAB_LABELS} else "n0"
            # done=1 marks the ONE load that follows the action, so its result pops exactly once
            # (see _action_banner) and a later refresh shows the collapsed record instead.
            _back = f"/?t={urllib.parse.quote(token)}&tab={_rtab}&done=1#action"
            if act in ("issue-key", "monitor-start", "monitor-start-local", "gw-call",
                       "gateway-setup", "gateway-start", "keep", "protect", "approve"):
                # The synchronous actions get the same two rules as the background ones:
                # never stomp a running action's banner (busy = SAID, not silent), and every
                # result renders under ITS OWN label — driven live 2026-08-14, "Start
                # monitoring" reported under the headline "login-configure · __nosuch__".
                if _ACTION.get("running"):
                    _ACTION.update(notice=f"‘{act}’ is queued — {_ACTION['label']} is still "
                                          f"running ({_elapsed(_ACTION.get('at'))} so far). One "
                                          f"action at a time; start ‘{act}’ again once it finishes.")
                    act = ""
                else:
                    _k = (form.get("key") or [""])[0]
                    _begin_action({"issue-key": f"issue-key · {(form.get('name') or [''])[0]}",
                                   "monitor-start": "monitor",
                                   "monitor-start-local": "monitor (incl. local)",
                                   "gateway-setup": "gateway setup",
                                   "gateway-start": "gateway start",
                                   # never the gw-call key: it is the agent's credential
                                   "gw-call": "gateway call",
                                   "keep": "keep blocked",
                                   "protect": f"protect · {_k}" if _k else "protect",
                                   "approve": f"approve · {_k}" if _k else "approve",
                                   }[act])
            if act in ("scan", "verify", "login", "login-done"):
                # `key` carries the server for a row action; absent = whole fleet.
                _run_action_bg(act, (form.get("key") or [""])[0] or None)
            elif act == "login-configure":
                # The pasted API key travels POST -> tool call and NOWHERE else: not into
                # _ACTION, not into any log - the scrubbers never even see it.
                _run_action_bg("login-configure", (form.get("key") or [""])[0] or None,
                               value=(form.get("value") or [""])[0] or None)
            elif act == "issue-key":
                # Issue ONE agent key against the RUNNING gateway's registry. Synchronous (a file
                # write, not a subprocess) and the secret is held in _ACTION for exactly one
                # render — see _persist_action, which never writes it to disk.
                res = run_issue_key((form.get("name") or [""])[0],
                                    (form.get("role") or [""])[0] or None)
                _ACTION.update(message=res.get("message") or "", rows=[],
                               level="ok" if res.get("ok") else "bad",
                               secret=res.get("secret") or "", snippet=res.get("snippet") or "",
                               at=_now())
            elif act in ("monitor-start", "monitor-start-local"):
                res = run_monitor_start(include_local=(act == "monitor-start-local"))
            elif act in ("gateway-setup", "gateway-start"):
                res = run_gateway_setup() if act == "gateway-setup" else run_gateway_start()
                _ACTION.update(message=res.get("message") or "", rows=[],
                               level="ok" if res.get("ok") else "bad",
                               secret="", snippet="", at=_now())
                _ACTION.update(message=res.get("message") or "", rows=[],
                               level="ok" if res.get("ok") else "bad",
                               secret="", snippet="", at=_now())
            elif act == "gw-call":
                # A real call through the running gateway. Synchronous: the REST skin answers in
                # one request and the whole point is to see the decision immediately.
                res = run_playground_call((form.get("tool") or [""])[0],
                                          (form.get("key") or [""])[0],
                                          (form.get("arguments") or [""])[0])
                _ACTION.update(message=res.get("message") or "", rows=[],
                               level=res.get("level") or ("ok" if res.get("ok") else "bad"),
                               secret="", snippet="", at=_now())
            elif act == "keep":
                # Leaving it blocked IS the decision — deliberately a no-op on state, exactly like
                # `decide`'s keep. The message confirms the consequence, not an action performed.
                _ACTION.update(message="Left blocked. Your agents still cannot call it.",
                               rows=[], level="ok", secret="", snippet="", at=_now())
            elif act == "protect":
                # Install the pre-execution hook for ONE agent — the same guard.install_for the
                # CLI uses (other vendors' hooks preserved, previous config backed up, atomic
                # write). Only rendered where a hook point exists; refused here for anything else
                # so a hand-rolled POST cannot invent one.
                key = (form.get("key") or [""])[0]
                from . import agents as _agents
                adapter = _agents.adapter_for(key)
                if adapter is None:
                    _ACTION.update(message=f"protect refused — no hook point exists for "
                                           f"{key or '(no agent named)'}",
                                   rows=[], level="warn", at=_now())
                else:
                    try:
                        from . import guard as _guard
                        note = " ".join(_guard.install_for(adapter).split())
                        _ACTION.update(message=f"protected — {note}",
                                       rows=[], level="ok", at=_now())
                    except Exception as exc:      # noqa: BLE001 — the failure goes ON the page
                        _ACTION.update(message=f"protect failed for {key}: {exc}",
                                       rows=[], level="bad", at=_now())
            elif act == "approve":
                key = (form.get("key") or [""])[0]
                # THE HUMAN GATE, ENFORCED — not merely rendered. `collect()` sets `can_act` from
                # approval_blocked_reason() to decide whether to DRAW this button, and that was the
                # only place it was consulted: a POST straight to this handler moved the trusted
                # baseline with no check at all. Hiding a button is not enforcement. This is the
                # same hole closed in the CLI on 2026-07-27, reopened by the GUI.
                from . import baseline as _bl
                blocked = _bl.approval_blocked_reason()
                if blocked and os.environ.get(_bl.APPROVE_OVERRIDE_ENV) != "1":
                    _ACTION.update(message=f"approve refused — {blocked}", at=_now())
                    self.send_response(303)
                    self.send_header("Location", _back)
                    self.end_headers()
                    return
                try:
                    from . import history
                    result = history.approve(key)
                    _ACTION.update(
                        message=(f"approved {key}" if result else f"nothing to approve for {key}"),
                        at=_now())
                except Exception as exc:          # noqa: BLE001
                    _ACTION.update(message=f"approve failed: {exc}", at=_now())
            # Carry the token back, or the redirect would land the human on a read-only page and
            # the buttons would vanish after the first click.
            self.send_response(303)
            self.send_header("Location", _back)
            self.end_headers()

    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as exc:
        # Port busy is the common case (a panel is already running), not a crash-worthy fault.
        # A raw traceback here is exactly the un-production roughness this tool is judged on.
        if exc.errno in (48, 98):                # EADDRINUSE on macOS / Linux
            log(f"\n  mcpgawk panel: port {port} is already in use — a panel is probably already"
                f"\n  open at http://127.0.0.1:{port}/ . To run a second one: mcpgawk panel"
                f" --port {port + 1}\n")
            return 1
        log(f"\n  mcpgawk panel: could not start on port {port} ({exc}).\n")
        return 1
    httpd.token = token                          # type: ignore[attr-defined]
    # The FULL token, not a 6-char prefix. The prefix was decorative: it authorised nothing, so the
    # real token had to be embedded in every page for the buttons to work — which is exactly how it
    # leaked. Carrying it in the URL keeps it where the docstring always said it was: this terminal
    # and the browser the human opens from it.
    url = f"http://127.0.0.1:{port}/?t={token}"
    log(f"\n  mcpgawk control panel — {url}\n  Ctrl-C to close.\n")
    if open_browser and not os.environ.get("MCPGAWK_NO_BROWSER"):
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("  closed.")
    finally:
        httpd.server_close()
    return 0


# --------------------------------------------------------------------------------------------- #
# DRILL-DOWN. A flat table is a summary; a control panel has to answer "and what about THAT one?".
# Every figure below is read from the store that owns it — this adds no derivation of its own.
# --------------------------------------------------------------------------------------------- #

def server_detail(store: dict[str, Any], key: str, calls: list[dict] | None = None) -> dict[str, Any]:
    """Everything known about ONE server: its approved surface, how it has moved over time, and
    what the runtime guard has actually seen it do.

    `history` is a real series — this store keeps up to 50 snapshots per server — so "when did this
    change" is answerable rather than just "it changed"."""
    from . import history as _h

    entry = (store.get("servers") or {}).get(key) or {}
    snaps = entry.get("history") or []
    approved = entry.get("approved") or {}
    latest = snaps[-1] if snaps else {}

    series = [{"at": s.get("measured_at") or "", "tools": len(s.get("items") or {}),
               "cost": s.get("cost_index") or 0} for s in snaps]

    aliases = list(entry.get("aliases") or [])
    mine = [c for c in (calls or [])
            if c.get("server") in aliases or c.get("server") == key]
    by_tool: dict[str, int] = {}
    for c in mine:
        by_tool[str(c.get("tool"))] = by_tool.get(str(c.get("tool")), 0) + 1

    return {
        "key": key,
        "name": _h.display_name(store, key),
        "aliases": aliases,
        "approved_tools": sorted((approved.get("items") or {}).keys()),
        "current_tools": sorted((latest.get("items") or {}).keys()),
        "texts": latest.get("texts") or {},
        "annotations": latest.get("annotations") or {},
        "transport": latest.get("transport") or "",
        "protocol": latest.get("protocol_version") or "",
        "cost_index": latest.get("cost_index") or 0,
        "measured_at": latest.get("measured_at") or "",
        "snapshots": len(snaps),
        "series": series[-30:],
        "calls_seen": len(mine),
        "calls_by_tool": sorted(by_tool.items(), key=lambda kv: -kv[1]),
        "pending": key in _h.pending(store),
    }


def call_breakdown(calls: list[dict]) -> dict[str, list[tuple[str, int]]]:
    """What the guard has seen, grouped the three ways a person asks about it: which server is
    busiest, which agent is generating traffic, and what was decided."""
    def tally(field: str) -> list[tuple[str, int]]:
        out: dict[str, int] = {}
        for c in calls:
            out[str(c.get(field) or "—")] = out.get(str(c.get(field) or "—"), 0) + 1
        return sorted(out.items(), key=lambda kv: -kv[1])

    return {"server": tally("server"), "adapter": tally("adapter"), "decision": tally("decision")}
