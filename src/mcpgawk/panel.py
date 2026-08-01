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
import re
import os
from pathlib import Path
from typing import Any

from . import dxt

TABS = ("fleet", "runtime", "evidence", "decisions")


def _esc(v: object) -> str:
    return html.escape(str(v), quote=True)


def collect() -> dict[str, Any]:
    """Everything the panel shows, gathered from the owning modules.

    Each probe is independently guarded and records its own failure: one unreadable store must
    degrade ITS tile, never blank the page and never render as a confident zero."""
    from . import agents as agent_mod
    from . import guard, history, runlog, spool

    data: dict[str, Any] = {"errors": {}}

    try:
        from .discover import discover_servers
        found = discover_servers()
        data["entries"] = found[0] if isinstance(found, tuple) else (found or {})
    except Exception as exc:                       # noqa: BLE001
        data["entries"] = {}
        data["errors"]["fleet"] = f"{type(exc).__name__}: {exc}"

    try:
        store = history.load(history.default_path())
        data["store"] = store
        data["pending"] = history.pending(store)
    except Exception as exc:                       # noqa: BLE001
        data["store"], data["pending"] = {"servers": {}}, []
        data["errors"]["baseline"] = f"{type(exc).__name__}: {exc}"

    try:
        data["activity"] = spool.summarise()
        data["recent_calls"] = spool.read(limit=40)
        # A wider window than the recent-calls tile: sessions are the unit an operator reviews
        # ("what did my agent do in that run"), and a 40-row window would show fragments of one.
        data["session_calls"] = spool.read(limit=1000)
    except Exception as exc:                       # noqa: BLE001
        data["activity"], data["recent_calls"] = None, []
        data["session_calls"] = []
        data["errors"]["runtime"] = f"{type(exc).__name__}: {exc}"

    try:
        data["hooks"] = {a.key: guard.is_installed_for(a)
                         for a in agent_mod.ADAPTERS.values() if a.config.is_file()}
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
    try:
        rep = behaviour_profile_path().parent / "last-verify.json"
        if rep.is_file():
            _r = json.loads(rep.read_text(encoding="utf-8"))
            data["verify_at"] = _r.get("generatedAt") or _r.get("at") or ""
            for s in (_r.get("servers") or []):
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
                        "tool": f.get("tool") or cand.get("toolName"),
                        "code": f.get("code") or cand.get("code"),
                        "class": f.get("class") or cand.get("findingClass"),
                        "severity": f.get("severity") or cand.get("severity"),
                        "repro": f"{f.get('reproOk', '?')}/{f.get('reproTotal', '?')}",
                        "suppressed": bool(f.get("suppressed")),
                        # WHAT IT ACTUALLY DID. A class name is a label; the hosts it contacted are
                        # the evidence, and the whole product rests on showing evidence not labels.
                        "evidence": (", ".join(where) or str(ev.get("note") or ""))[:160],
                        # Classified, never dropped: a first-party finding stays listed and says why.
                        "first_party": first_party(str(s.get("server") or ""), _hosts,
                                                   (data.get("entries") or {}).get(s.get("server"))),
                    })
    except Exception as exc:                       # noqa: BLE001
        # Named separately from `observed`: "we could not read the findings" and "we could not read
        # the behaviour profile" send the user to different files.
        data["errors"]["findings"] = f"{type(exc).__name__}: {exc}"

    try:
        from .verify import unavailable_reason
        data["verify_blocked"] = unavailable_reason()
    except Exception:                              # noqa: BLE001
        data["verify_blocked"] = "verification engine not available in this install"

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
                rows.append((client, label, "on", n,
                             "every MCP call checked against your baseline"))
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
    ("findings", "Findings", "verification caught it doing something — exfiltration, SSRF or "
                             "injected output"),
    ("changed", "Changed", "moved since you approved it; your agents cannot call it"),
    ("unverified", "Unverified", "never watched — absence of a finding, not safety"),
    ("baseline", "At baseline", "matches what you approved, and behaviour was observed"),
)


def _classify(name: str, key: str | None, d: dict) -> str:
    """One server's tier. Ordered worst-first: the first thing that is true wins."""
    calls = [c for c in (d.get("recent_calls") or []) if c.get("server") == name]
    if any(c.get("decision") == "deny" for c in calls):
        return "blocked"
    # Convictions outrank "changed" and "unverified": a server verification CAUGHT doing something
    # is a stronger statement than one whose declared surface moved, and it must never fall through
    # to "baseline" just because it was observed.
    real = [f for f in (d.get("findings") or [])
            if f.get("server") == name and not f.get("first_party") and not f.get("suppressed")]
    if real:
        return "findings"
    if key and key in (d.get("pending") or []):
        return "changed"
    # OBSERVED means "a run exercised it", not "a run convicted it". Testing membership of the
    # convictions map made every clean server permanently "unverified", so the coverage bar could
    # only ever improve by finding something WRONG. A run that exercised nothing (toolsChecked 0 —
    # e.g. an OAuth server that never listed its tools) is correctly still unverified.
    ran = (d.get("verified_runs") or {}).get(name)
    exercised = isinstance(ran, dict) and (ran.get("toolsChecked") or 0) > 0
    if not exercised and name not in (d.get("observed") or {}):
        return "unverified"
    return "baseline"


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
        ann = annotations.get(tool) if isinstance(annotations.get(tool), dict) else {}
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
        sig = obs.get(name) if isinstance(obs.get(name), dict) else {}
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
        sid = r.get("session") if isinstance(r.get("session"), str) else "(no identity)"
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
        return (f"{pending} server(s) changed since you approved them and are blocked right now — "
                f"open Decisions.", "bad")
    findings = [f for f in (d.get("findings") or [])
                if not f.get("suppressed") and not f.get("first_party")]
    if findings:
        servers = len({f.get("server") for f in findings})
        return (f"{len(findings)} finding(s) across {servers} server(s) — open Findings and decide "
                f"which are real.", "bad")
    unprot = len(d.get("no_hook") or {})
    if unprot:
        return (f"{unprot} agent(s) have no pre-execution hook, so their calls are not checked — "
                f"open Agents.", "warn")
    entries = d.get("entries") or {}
    ran = d.get("verified_runs") or {}
    never = [n for n in entries if not (isinstance(ran.get(n), dict)
                                        and (ran[n].get("toolsChecked") or 0) > 0)]
    if never:
        return (f"{len(never)} server(s) have never been watched running. Absence of a finding is "
                f"not safety — verify one from its row.", "warn")
    return ("Nothing needs you right now.", "ok")


def _action_banner(action: dict | None) -> str:
    """The last action's state, full-width under the card header. Shown to EVERYONE — status is
    not an action, and gating it behind the token hid "Running verify…" from the founder's own
    read-only view (2026-07-30)."""
    action = action or {}
    running = action.get("running")
    banner = ""
    if running:
        banner = (f'<div class="abanner run">Running {_esc(action.get("label"))}… '
                  'this can take a minute. This page updates itself.</div>')
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
                f'<td class="dim">{_esc(r.get("detail"))}{_fixblock(r)}</td></tr>'
                for r in rows) + "</tbody></table>")
        # THE BANNER TAKES THE WORST ROW'S COLOUR. It used to be green whenever the action
        # COMPLETED — so a run reporting 5 unverified servers and 21 convictions was styled as
        # success, and read as the opposite of what it found. Completing is not a good outcome;
        # finding nothing wrong is.
        worst = ("bad" if any(r.get("level") == "bad" for r in rows)
                 else "warn" if any(r.get("level") == "warn" for r in rows)
                 else (action.get("level") or "ok"))
        banner = (f'<div class="abanner done {_esc(worst)}">'
                  f'{_esc(action.get("message"))}{detail}</div>')
    return banner


def _action_buttons(token: str, action: dict | None) -> str:
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
  <button class="act-btn" name="act" value="scan"{dis}>Re-scan</button>
</form>
<form method="POST" action="/" style="display:inline">
  <input type="hidden" name="token" value="{tok}">
  <button class="act-btn" name="act" value="verify"{dis}>Verify fleet (run &amp; watch)</button>
</form>"""


def render(d: dict[str, Any], token: str = "", action: dict | None = None,
           q: str = "", tier_filter: str = "", sel: str = "", tl: str = "") -> str:
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

    entries = d.get("entries") or {}
    store = d.get("store") or {}
    servers = store.get("servers") or {}
    pending = d.get("pending") or []
    act = d.get("activity") or {}
    calls = d.get("recent_calls") or []
    rows = _agent_rows(d)
    covered = sum(n for _, _, s, n, _ in rows if s == "on")
    uncovered = sum(n for _, _, s, n, _ in rows if s != "on")

    # --- the session record: one row per agent run, newest first -------------------------------
    sess_parts: list[str] = []
    for s in sessions_summary(d.get("session_calls") or calls)[:10]:
        sid = s["session"]
        shown = _esc(sid[:12] + ("…" if len(sid) > 12 else ""))
        denied = (f'<span class="chip bad">{s["denied"]}</span>' if s["denied"] else "0")
        last = _esc(str(s["last"] or "")[11:19] or "—")
        sess_parts.append(
            f'<tr><td class="nm" title="{_esc(sid)}">{shown}</td><td>{_esc(s["agent"])}</td>'
            f'<td class="num">{s["calls"]}</td><td class="num">{denied}</td>'
            f'<td class="num">{s["servers"]}</td><td class="dim">{last}</td></tr>')
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
    legend = "".join(
        f'<span class="lg"><i class="sw {t}"></i>{_esc(label)} <b>{counts[t]}</b></span>'
        for t, label, _ in TIERS)
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
            + ([f"sel={_urlq(target)}"] if target else [])
        return "/?" + "&".join(parts) if parts else "/"

    sel_active = bool(sel) and any(n == sel for n, _, _, _ in classified)
    drawer = ""
    srows = []
    for name, entry, key, tier in classified:
        detail = server_detail(store, key, calls) if key else None
        local = "local" if entry.get("command") else "remote"
        clients = ", ".join(entry.get("_clients") or []) or "—"
        seen = detail["calls_seen"] if detail else 0
        tools = len(detail["current_tools"]) if detail else "—"
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
        act_cell = (f'<form method="POST" action="/" class="rowact">'
                    f'<input type="hidden" name="token" value="{_esc(token)}">'
                    f'<input type="hidden" name="key" value="{_esc(name if entry.get("command") else key)}">'
                    f'{_acts}</form>' if _acts else "")
        if detail:
            # NB `tool_lines`, not `tl` — `tl` is render's finding-timeline parameter, and reusing
            # the name here silently clobbered it: the trail link rendered but never opened.
            tool_lines = "".join(
                f'<tr><td class="nm">{_esc(t)}</td><td class="dim">{n} call(s)</td></tr>'
                for t, n in detail["calls_by_tool"][:8]) or \
                '<tr><td colspan="2" class="dim">no calls recorded for this server</td></tr>'
            dvo_rows = declared_vs_observed(detail, (d.get("observed") or {}).get(name))
            _destr[name] = sum(1 for r in dvo_rows if r["declared"] == "destructive")
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
                    obs_cell = ('<span class="dim">not observed — absence is not a claim of '
                                'safety</span>')
                dvo_parts.append(
                    f'<tr><td class="nm">{_esc(r["tool"])}</td>'
                    f'<td><span class="chip {base}">{r["baseline"]}</span></td>'
                    f'<td class="dim">{_esc(r["declared"])}</td><td>{obs_cell}</td></tr>')
            dvo = "".join(dvo_parts) or \
                '<tr><td colspan="4" class="dim">no measured surface yet — run mcpgawk</td></tr>'
            if name == sel:
                backend = ((d.get("verified_runs") or {}).get(name) or {}).get("backend")
                never = len(detail["current_tools"]) - checked
                callout = (f'<div class="unobs">{never} tool(s) were never invoked. Absence of a '
                           'finding for those is not a claim of safety.</div>'
                           if checked and never > 0 else '')
                drawer = f"""<aside class="side">
  <div class="shead"><h3>{_esc(name)}</h3><a class="gbtn" href="{_rowurl(None)}">Close</a></div>
  <span class="id">{_esc(key if key else "mcp:" + name)}</span>
  {f'<div class="dacts">{act_cell}</div>' if act_cell else ''}
  <dl class="kv">
    <dt>Transport</dt><dd>{_esc(detail['transport'] or local)}</dd>
    <dt>Protocol</dt><dd>{_esc(detail['protocol'] or '—')}</dd>
    <dt>Tools now</dt><dd>{len(detail['current_tools'])}</dd>
    <dt>Approved</dt><dd>{len(detail['approved_tools'])}</dd>
    <dt>Watched</dt><dd>{checked}</dd>
    <dt>Isolation</dt><dd>{_esc(backend or 'none recorded')}</dd>
    <dt>Context cost</dt><dd>{detail['cost_index']} tok</dd>
    <dt>Snapshots</dt><dd>{detail['snapshots']}</dd>
    <dt>Measured</dt><dd>{_esc(detail['measured_at'][:19] or '—')}</dd>
    <dt>Also known as</dt><dd>{_esc(', '.join(detail['aliases']) or '—')}</dd>
  </dl>
  {callout}
  <div class="ddh">what the guard has seen</div>
  <table class="mini"><tbody>{tool_lines}</tbody></table>
  <div class="ddh">declared vs observed · verdicts rest on observation, not names</div>
  {f'<div class="unobs">{_esc(why)}</div>' if why else ''}
  <table class="mini"><thead><tr><th>tool</th><th>baseline</th><th>declared</th>
  <th>observed</th></tr></thead><tbody>{dvo}</tbody></table>
</aside>"""
        elif name == sel:
            # Selected but never measured: the drawer states that instead of pretending detail.
            drawer = f"""<aside class="side">
  <div class="shead"><h3>{_esc(name)}</h3><a class="gbtn" href="{_rowurl(None)}">Close</a></div>
  <span class="id">mcp:{_esc(name)}</span>
  {f'<div class="dacts">{act_cell}</div>' if act_cell else ''}
  <div class="unobs">Never measured — nothing is recorded for this server yet. Re-scan records
    its declared surface; verify watches it run.</div>
</aside>"""
        # SERVER-SIDE FILTERING. The CSP here is `default-src 'none'` — no script — so a filter is a
        # GET form and a re-render, not a client-side hide. Eleven rows fit on a screen; forty do
        # not, and "scroll and squint" is the friction this removes.
        if tier_filter and tier != tier_filter:
            continue
        if q and q.lower() not in f"{name} {key or ''} {clients}".lower():
            continue
        words = [w for w in re.split(r"[^0-9A-Za-z]+", name) if w]
        mark = ((words[0][0] + (words[1][0] if len(words) > 1 else (words[0][1:2] or ""))).upper()
                if words else "?")
        _is_sel = sel_active and name == sel
        who = f"""<a class="who" href="{_rowurl(None if _is_sel else name)}">
    <span class="mark">{_esc(mark)}</span><span>
    <span class="nm">{_esc(name)}</span>
    <span class="id">{_esc(key if key else "mcp:" + name)}</span></span></a>"""
        state_tag = (f'<span><span class="chip {_tag[tier]}"><i></i>'
                     f'{_esc(_tlabel[tier])}</span></span>')
        if sel_active:
            srows.append(f"""<div class="row s3{' sel' if _is_sel else ''}">
  {who}
  {state_tag}
  <span class="n"><b>{tools}</b></span>
</div>""")
        else:
            watched_s = (f' <s>/ {checked} watched</s>'
                         if checked and isinstance(tools, int) and checked < tools else '')
            srows.append(f"""<div class="row">
  {who}
  <span><span class="chip mode">{local}</span></span>
  <span class="dim cl-agents">{_esc(clients)}</span>
  <span class="n cl-num"><b>{tools}</b>{watched_s}</span>
  <span class="n cl-num"><b>{seen}</b></span>
  {state_tag}
  {act_cell or '<span></span>'}
</div>""")

    _rows_html = "".join(srows) or (
        '<div class="note" style="margin-top:13px">Nothing matches. '
        f'<a href="/?t={_esc(token)}">Clear the filter.</a></div>')
    if sel_active:
        servers_table = (
            '<div class="split"><div>'
            '<div class="thead s3"><span>server</span><span>state</span>'
            '<span class="n">tools</span></div>'
            f'{_rows_html}</div>{drawer}</div>')
    else:
        servers_table = (
            '<div class="thead"><span>server</span><span>transport</span>'
            '<span class="cl-agents">agents</span><span class="n cl-num">tools</span>'
            '<span class="n cl-num">calls</span><span>state</span><span></span></div>'
            + _rows_html)

    # --- Coverage: the mockup's Spend-by-Team bars, measuring watched tools instead of money ----
    # One bar per MEASURED server; the number that matters is the gap. Servers never measured are
    # counted in words, not silently absent — absence from this list must not read as coverage.
    _watched_sum = sum(c for c, _ in _cov.values())
    _tools_sum = sum(t for _, t in _cov.values())
    _unmeasured = len(classified) - len(_cov)
    cov_bars = "".join(
        f'<div class="cbar"><span class="lb">{_esc(n)}</span>'
        f'<div class="track"><div class="fill" style="width:{(c / t * 100) if t else 0:.0f}%">'
        f'</div></div><span class="vl">{c} / {t}</span></div>'
        for n, (c, t) in sorted(_cov.items(), key=lambda kv: (kv[1][0] - kv[1][1], kv[0]))) or \
        ('<div class="unobs">No server has been measured yet — nothing to draw a bar from. '
         'An empty chart here is not coverage.</div>')
    cov_count = (f'<b>{_watched_sum}</b> of {_tools_sum} measured tools watched'
                 + (f' · {_unmeasured} server(s) never measured' if _unmeasured else ''))

    # --- runtime: agents, then the call log with one Group by ----------------------------------
    _tiers = "".join(
        f'<option value="{k}"{" selected" if tier_filter == k else ""}>{_esc(lbl)}</option>'
        for k, lbl, _ in TIERS)
    filterbar = (
        '<form method="GET" action="/" class="filters">'
        + (f'<input type="hidden" name="t" value="{_esc(token)}">' if token else "")
        + f'<input class="fq" type="search" name="q" value="{_esc(q)}" '
          'placeholder="search server, key or agent">'
        + f'<select name="tier"><option value="">every tier</option>{_tiers}</select>'
        + '<button class="filter-btn" type="submit">filter</button>'
        + (f'<a class="clearf" href="/?t={_esc(token)}">clear</a>' if (q or tier_filter) else "")
        + f'<span class="count rowcount">{len(srows)} of {len(entries)} server(s)'
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
            rows.append(
                f'<tr><td class="dim">#{_esc(a.get("attempt"))}</td>'
                f'<td><span class="chip {"ok" if okflag else "warn"}">'
                f'{"observed" if okflag else "could not run"}</span></td>'
                f'<td class="dim">{_esc(hosts)}</td>'
                f'<td class="dim mono">{_esc((body or a.get("infraDetail") or "—")[:400])}'
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
                f'<th>where it went</th><th>what the tool reported</th></tr></thead>'
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
            + ([f"tl={_urlq(key)}"] if tl != key else [])
        label = "hide trail" if tl == key else "see every attempt"
        return f'<a class="tll" href="/?{"&amp;".join(parts)}#p6">{label}</a>'

    _SEL_TR = '<tr class="selrow">'
    frows = "".join(
        (_SEL_TR if tl == _tl_key(f) else "<tr>")
        + f'<td class="nm">{_esc(f.get("server"))}</td>'
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

    _ran = d.get("verified_runs") or {}
    isorows = "".join(
        f'<tr><td class="nm">{_esc(n)}</td>'
        f'<td><span class="chip {"ok" if str(o.get("backend")) in ("proxied-container", "docker") else "warn"}">'
        f'{_esc(o.get("backend") or "?")}</span></td>'
        f'<td class="dim">{o.get("toolsChecked", "?")}</td>'
        f'<td class="dim">{len(o.get("skipped") or [])}</td></tr>'
        for n, o in sorted(_ran.items()) if isinstance(o, dict)) or \
        ('<tr><td colspan="4" class="dim">No verify has run yet. Nothing here means nothing was '
         'watched — not that nothing is wrong.</td></tr>')
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
                f'<button class="act-sm warn" name="act" value="protect" title="Install the '
                f'pre-execution hook so every MCP call from this agent is checked against your '
                f'baseline">Protect</button></form>')

    arows = "".join(
        f'<tr><td class="nm">{_esc(label)}</td><td><span class="chip '
        f'{"ok" if st == "on" else ("warn" if st == "off" else "dim")}">'
        f'{"protected" if st == "on" else ("not enabled" if st == "off" else "no hook point")}'
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
        f'<tr><td class="dim">{_esc(c.get("ts", "")[11:19])}</td>'
        f'<td><span class="chip {"bad" if c.get("decision") == "deny" else "dim"}">'
        f'{_esc(c.get("decision", ""))}</span></td>'
        f'<td class="nm">{_esc(c.get("server", ""))}.{_esc(c.get("tool", ""))}</td>'
        f'<td class="dim">{_esc(c.get("adapter", ""))}</td>'
        f'<td class="dim">{_esc(c.get("basis", ""))}</td></tr>'
        for c in calls[:30]) or \
        '<tr><td colspan="5" class="dim">No calls recorded yet — use your agent once.</td></tr>'

    # --- evidence -------------------------------------------------------------------------------
    runs = "".join(
        f'<tr><td class="dim">{_esc(str(getattr(r, "started_at", ""))[:19])}</td>'
        f'<td class="nm">{_esc(getattr(r, "kind", ""))}</td>'
        f'<td><span class="chip {"bad" if getattr(r, "status", "") == "error" else ("warn" if getattr(r, "status", "") == "findings" else "ok")}">'
        f'{_esc(getattr(r, "status", ""))}</span></td>'
        f'<td class="dim">{_esc(str(getattr(r, "target", "") or "—")[:56])}</td></tr>'
        for r in (d.get("runs") or [])) or \
        '<tr><td colspan="4" class="dim">Nothing recorded yet.</td></tr>'

    # THE FINDINGS THEMSELVES. Until 2026-07-30 a verify's convictions lived only in a subprocess
    # buffer, so a run that convicted 21 tools left every view except the result banner untouched —
    # "apart from the verify the fleet output nothing changed in the panel". Severity-first: a
    # suppressed finding is still SHOWN, marked, never silently dropped.
    _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    #: A muted finding stays listed and marked — never silently dropped (`mcpgawk wrong`).
    _MUTED = ' <span class="chip">muted by you</span>'
    fnd = "".join(
        f'<tr><td class="nm">{_esc(f.get("server"))}</td>'
        f'<td class="nm">{_esc(f.get("tool") or "—")}</td>'
        f'<td>{_esc(f.get("class") or f.get("code") or "?")}'
        f'{_MUTED if f.get("suppressed") else ""}</td>'
        f'<td><span class="chip {"bad" if f.get("severity") in ("critical", "high") else "warn"}">'
        f'{_esc(f.get("severity") or "?")}</span></td>'
        f'<td class="dim">{_esc(f.get("evidence") or "—")}</td>'
        f'<td class="dim">{_esc(f.get("repro"))}</td></tr>'
        for f in sorted(d.get("findings") or [],
                        key=lambda f: (_sev.get(str(f.get("severity")).lower(), 9),
                                       str(f.get("server"))))) or \
        ('<tr><td colspan="6" class="dim">No verify has run yet — click '
         '“Verify fleet (run &amp; watch)”. An empty table here is not a clean bill of health.'
         '</td></tr>')

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
    notable = [a for a in all_acts if a.get("decision") == "deny"]

    def _act_row(a: dict, expand_why: bool = False) -> str:
        deny = a.get("decision") == "deny"
        why = a.get("why") or ""
        if deny and why:
            why_cell = (f'<div class="whyfull">{_esc(why)}</div>' if expand_why else
                        f'<details><summary class="whysum">show</summary>'
                        f'<div class="whyfull">{_esc(why)}</div></details>')
        else:
            why_cell = _esc(why or "—")
        return (f'<tr><td class="dim">{_esc(str(a.get("when") or "")[:19])}</td>'
                f'<td class="dim">{_esc(a.get("agent") or "—")}</td>'
                f'<td class="nm">{_esc(a.get("server") or "")}.{_esc(a.get("tool") or "")}</td>'
                f'<td><span class="chip {"bad" if deny else "dim"}">'
                f'{_esc(a.get("decision") or "")}</span></td>'
                f'<td class="dim">{_esc(a.get("basis") or "")}</td><td>{why_cell}</td></tr>')

    act_summary = act if isinstance(act, dict) else {}
    span_first = all_acts[-1].get("when") if all_acts else None
    span_last = all_acts[0].get("when") if all_acts else None
    acts_notable = "".join(_act_row(a, expand_why=True) for a in notable) or \
        '<tr><td colspan="6" class="dim">No calls have been blocked. Nothing has drifted or ' \
        'overstepped its approved baseline.</td></tr>'
    acts_full = "".join(_act_row(a) for a in all_acts[:500]) or \
        '<tr><td colspan="6" class="dim">Nothing recorded yet — use your agent once.</td></tr>'

    def _dec_action(k: str) -> str:
        if not token:
            return '<span class="dim">approve in your terminal</span>'
        return (f'<form method="POST" action="/" class="rowact">'
                f'<input type="hidden" name="token" value="{_esc(token)}">'
                f'<input type="hidden" name="key" value="{_esc(k)}">'
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
        for t in rep.hostile[:2]:
            bits.append(f'<span class="nm">{_esc(t)}</span> <span class="dim">rewrote its own '
                        'description after you approved it — the rug-pull signature.</span>')
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

    dec = "".join(
        f'<tr><td class="nm">{_esc(_h.display_name(store, k))}</td>'
        f'<td>{_dec_what(k)}</td>'
        f'<td><span class="chip bad"><i></i>Blocked</span></td>'
        f'<td>{_dec_action(k)}</td></tr>'
        for k in pending) or \
        '<tr><td colspan="4" class="dim">Nothing is waiting on you.</td></tr>'

    # While an action runs, the page REFRESHES ITSELF. Telling the user to reload is not a progress
    # indicator: 0.1.20 completed its scan in ~100s and went on showing "Running scan…" forever
    # because nobody reloaded, which is indistinguishable from a hang and was reported as one.
    # A meta refresh (not script — the CSP forbids script) is the only mechanism available here.
    refresh = ('<meta http-equiv="refresh" content="5">'
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
    _ct_fnd = f'<span class="ct alert">{len(_f_real)}</span>' if _f_real else ""
    _ct_dec = f'<span class="ct alert">{len(pending)}</span>' if pending else ""
    _ct_agt = f'<span class="ct">{agent_gaps} gap(s)</span>' if agent_gaps else ""
    _span = (f'{str(span_first or "")[:10]} → {str(span_last or "")[:10]}'
             if span_first else "nothing recorded yet")
    return f"""<!doctype html><html><head><meta charset="utf-8">{refresh}
<title>mcpgawk</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* LIKE FOR LIKE with LiteLLM's admin console — DESIGN.md; the approved target is
   docs/mockups/panel-redesign-2026-07-31.html. Their grammar, our objects: pill tab rail on a
   grey track, one white card per view, filter row with a right-aligned count, uppercase heads on
   a tinted row, two-line primary cell, fully-rounded tinted tags. Royal blue #2A33C2 stays ours.
   No script — the CSP is `default-src 'none'` and the tabs are pure CSS. */
:root{{--page:#F7F7F8;--card:#FFF;--rail:#F1F1F3;--line:#E6E6EA;
--ink:#15161A;--mut:#5B5D66;--fai:#8A8D97;--acc:#2A33C2;--acc-soft:#EEEFFB;
--ok:#157A40;--ok-bg:#E7F4EC;--warn:#B26A00;--warn-bg:#FBF1E3;
--bad:#C0392B;--bad-bg:#FBEBE9;--unv:#6B7280;--unv-bg:#F0F1F3;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace;
--sans:system-ui,-apple-system,"Segoe UI",sans-serif;
--ease:cubic-bezier(.23,1,.32,1);
--srow:minmax(200px,1.6fr) .7fr 1.1fr .5fr .5fr .95fr minmax(80px,auto)}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--page);color:var(--ink);font-family:var(--sans);font-size:14px;
line-height:1.5}}
.sheet{{max-width:1160px;margin:0 auto;padding:26px 22px 90px}}
.bhead{{display:flex;align-items:baseline;gap:10px;margin-bottom:12px;flex-wrap:wrap}}
.brand{{font-weight:700;letter-spacing:-.02em;font-size:15px}}
.bsub{{font-family:var(--mono);font-size:10px;color:var(--fai)}}
input[type=radio]{{position:absolute;opacity:0;pointer-events:none}}
.rail{{display:flex;gap:4px;background:var(--rail);border:1px solid var(--line);
border-radius:10px;padding:4px;margin-bottom:14px;flex-wrap:wrap}}
.pill{{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--mut);
padding:6px 13px;border-radius:8px;border:1px solid transparent;cursor:pointer}}
.pill .dot{{width:6px;height:6px;border-radius:50%;background:var(--fai)}}
.pill .ct{{font-size:11.5px;color:var(--fai)}}
.ct.alert{{color:var(--bad);font-weight:600}}
#n0:checked~.sheet label[for=n0],#n1:checked~.sheet label[for=n1],
#n2:checked~.sheet label[for=n2],#n3:checked~.sheet label[for=n3],
#n4:checked~.sheet label[for=n4],#n5:checked~.sheet label[for=n5],
#n6:checked~.sheet label[for=n6]{{background:var(--card);color:var(--ink);font-weight:600;
border-color:var(--line);box-shadow:0 1px 2px rgba(20,22,30,.06)}}
#n0:checked~.sheet label[for=n0] .dot,#n1:checked~.sheet label[for=n1] .dot,
#n2:checked~.sheet label[for=n2] .dot,#n3:checked~.sheet label[for=n3] .dot,
#n4:checked~.sheet label[for=n4] .dot,#n5:checked~.sheet label[for=n5] .dot,
#n6:checked~.sheet label[for=n6] .dot{{background:var(--acc)}}
.pane{{display:none}}
#n0:checked~.sheet #p0,#n1:checked~.sheet #p1,#n2:checked~.sheet #p2,
#n3:checked~.sheet #p3,#n4:checked~.sheet #p4,#n5:checked~.sheet #p5,
#n6:checked~.sheet #p6{{display:block}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;
box-shadow:0 1px 2px rgba(20,22,30,.04);overflow:hidden;margin-bottom:16px}}
.chead{{display:flex;align-items:center;gap:12px;padding:14px 16px;flex-wrap:wrap}}
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
.abar:empty{{display:none}}
.abanner{{width:100%;padding:10px 13px;border-radius:10px;font-size:12.5px;margin:0 0 13px;
border:1px solid var(--warn);background:var(--warn-bg);color:var(--warn)}}
.abanner.done{{border-color:var(--ok);background:var(--ok-bg);color:var(--ok)}}
/* A result is coloured by WHAT IT FOUND, never by the fact that it finished — `.done.bad` and
   `.done.warn` come after `.done` so they win. */
.abanner.done.warn{{border-color:var(--warn);background:var(--warn-bg);color:var(--warn)}}
.abanner.done.bad{{border-color:var(--bad);background:var(--bad-bg);color:var(--bad)}}
.arows{{width:100%;border-collapse:collapse;margin-top:10px;font-size:12px}}
.arows td{{padding:5px 8px;border-top:1px solid var(--line);vertical-align:top}}
.arows td.nm{{font-family:var(--mono);white-space:nowrap;width:1%}}
.fixit{{margin-top:5px;padding:5px 8px;border-left:2px solid var(--acc);
background:var(--acc-soft);color:var(--ink);font-size:11.5px;line-height:1.5}}
.nba{{display:flex;gap:8px;align-items:baseline;margin:0 16px 13px;padding:11px 13px;
border-radius:10px;font-size:13px;border:1px solid var(--line);background:var(--card)}}
.nba.ok{{border-color:var(--ok);background:var(--ok-bg);color:var(--ok)}}
.nba.warn{{border-color:var(--warn);background:var(--warn-bg);color:var(--warn)}}
.nba.bad{{border-color:var(--bad);background:var(--bad-bg);color:var(--bad)}}
.filters{{display:flex;align-items:center;gap:9px;padding:0 16px 13px;flex-wrap:wrap;margin:0}}
.fq{{font:inherit;font-size:12.5px;padding:6px 11px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--ink);min-width:230px}}
.fq::placeholder{{color:var(--mut)}}
.filters select{{font:inherit;font-size:12.5px;padding:6px 11px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--ink)}}
.filter-btn{{font:inherit;font-size:12px;padding:6px 11px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--mut);cursor:pointer;
transition:border-color 160ms var(--ease),color 160ms var(--ease),transform 160ms var(--ease)}}
.filter-btn:active{{transform:scale(.97)}}
.clearf{{font-size:12px;color:var(--acc)}}
.count{{margin-left:auto;font-size:12.5px;color:var(--mut)}}
.count b{{color:var(--ink);font-weight:600}}
.thead{{display:grid;grid-template-columns:var(--srow);gap:12px;align-items:center;
padding:9px 16px;background:var(--rail);border-top:1px solid var(--line);
border-bottom:1px solid var(--line);font-size:10.5px;letter-spacing:.09em;
text-transform:uppercase;color:var(--fai);font-weight:500}}
.row{{display:grid;grid-template-columns:var(--srow);gap:12px;align-items:center;
padding:11px 16px;border-bottom:1px solid var(--line)}}
.thead.s3,.row.s3{{grid-template-columns:minmax(180px,1.6fr) .9fr .5fr}}
.row.sel{{background:var(--acc-soft)}}
.who{{display:flex;align-items:center;gap:10px;min-width:0}}
a.who{{color:inherit;text-decoration:none}}
.split{{display:grid;grid-template-columns:minmax(0,1fr) 380px}}
.side{{border-left:1px solid var(--line);border-top:1px solid var(--line);padding:16px 16px 20px}}
.side h3{{margin:0;font-size:14px;font-weight:640}}
.shead{{display:flex;align-items:center;justify-content:space-between;gap:8px}}
.dacts{{margin-top:10px}}
.kv{{display:grid;grid-template-columns:auto 1fr;gap:7px 14px;margin:14px 0 0;font-size:12.5px}}
.kv dt{{color:var(--fai)}}
.kv dd{{margin:0;font-variant-numeric:tabular-nums}}
/* the drawer is 380px; a four-column tool table only fits with a fixed layout and wrapping
   names — without this, long tool names push the verdict columns past the card edge */
.side .mini{{table-layout:fixed}}
.side .mini th,.side .mini td{{font-size:11px;padding:5px 4px 5px 0}}
.side .mini th:first-child,.side .mini td:first-child{{overflow-wrap:anywhere}}
.side .mini .chip{{font-size:10px;padding:2px 7px}}
.side .mini .dim{{font-size:10.5px}}
.mark{{width:26px;height:26px;border-radius:7px;background:var(--acc-soft);color:var(--acc);
display:grid;place-items:center;font-size:11px;font-weight:700;flex:none}}
.who .nm{{font-family:var(--sans);font-weight:600;font-size:13.5px;display:block;
line-height:1.3}}
.who .id{{font-family:var(--mono);font-size:11px;color:var(--fai);display:block}}
.n{{text-align:right;font-variant-numeric:tabular-nums;font-size:13px}}
.n b{{font-weight:650}}
.n s{{text-decoration:none;color:var(--fai);font-size:11.5px}}
.chip{{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:550;
padding:3px 10px;border-radius:999px;white-space:nowrap;color:var(--mut);
background:var(--unv-bg)}}
.chip i{{width:5px;height:5px;border-radius:50%;background:currentColor;flex:none}}
.chip.mode{{background:transparent;border:1px solid var(--line)}}
/* Finding evidence trail: every reproduction attempt, opened by a GET link (no script). */
.tll{{margin-left:10px;font-size:11.5px;color:var(--acc);text-decoration:none;white-space:nowrap}}
.tll:hover{{text-decoration:underline}}
.tlrow>td{{padding:0 0 14px 0;background:var(--acc-soft)}}
.tlbox{{margin:0 14px;padding:12px 14px;border:1px solid var(--line);border-radius:10px;
background:var(--card)}}
.tlhead{{font-size:11.5px;color:var(--mut);margin-bottom:8px}}
.tlt{{width:100%;table-layout:fixed}}
.tlt th{{font-size:10.5px}}
.tlt td{{vertical-align:top;padding:6px 8px;font-size:11.5px;overflow-wrap:anywhere}}
.tlfoot{{margin-top:8px;font-size:11px;overflow-wrap:anywhere}}
.tlnote{{margin-top:10px;padding:8px 10px;border-radius:8px;font-size:11.5px;
color:var(--warn);background:var(--warn-bg)}}
.mono{{font-family:var(--mono,ui-monospace,SFMono-Regular,Menlo,monospace)}}
.chip.ok{{color:var(--ok);background:var(--ok-bg)}}
.chip.warn{{color:var(--warn);background:var(--warn-bg)}}
.chip.bad{{color:var(--bad);background:var(--bad-bg)}}
.chip.unv{{color:var(--unv);background:var(--unv-bg)}}
.rowact{{display:inline-flex;gap:7px;justify-content:flex-end}}
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
.cbar .lb{{font-family:var(--mono);font-size:11.5px;color:var(--mut);overflow:hidden;
text-overflow:ellipsis;white-space:nowrap}}
.track{{height:9px;background:var(--rail);border-radius:999px;overflow:hidden}}
.fill{{height:100%;background:var(--acc);border-radius:999px}}
.cbar .vl{{font-size:12.5px;font-variant-numeric:tabular-nums;color:var(--ink)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--fai);
text-align:left;font-weight:500;padding:9px 16px;background:var(--rail);
border-top:1px solid var(--line);border-bottom:1px solid var(--line)}}
td{{padding:10px 16px;border-bottom:1px solid var(--line);vertical-align:middle}}
td.num{{text-align:right;font-variant-numeric:tabular-nums;width:60px}}
.nm{{font-family:var(--mono);font-size:12.5px}}
.dim{{color:var(--mut)}}
.dd{{border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:#FBFBFC;
padding:14px 16px}}
.ddgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px 20px;
font-size:12.5px;margin-bottom:12px}}
.ddgrid .k{{display:block;font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;
color:var(--fai)}}
.ddh{{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--fai);
font-weight:500;margin:14px 0 8px}}
.mini{{font-size:12.5px}}
.mini th{{background:none;border-top:none;padding:5px 0}}
.mini td{{padding:5px 0;background:none}}
.unobs{{background:var(--rail);border-radius:10px;padding:10px 12px;margin:0 0 8px;
font-size:12px;color:var(--mut);line-height:1.5}}
.note{{margin:0 16px 13px;padding:10px 12px;border-radius:10px;background:var(--rail);
font-size:12.5px;color:var(--mut);line-height:1.5}}
.note.ok{{background:var(--ok-bg);color:var(--ok)}}
.note.warn{{background:var(--warn-bg);color:var(--warn)}}
.whysum{{cursor:pointer;color:var(--acc);font-size:12px}}
.whyfull{{white-space:pre-wrap;font-size:11.5px;color:var(--mut);margin-top:6px;max-width:60ch;
line-height:1.5}}
h2{{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--fai);
font-weight:500;margin:18px 16px 8px}}
.gwrap{{padding:0 16px 13px}}
.gl{{display:inline-block;font-size:12px;padding:4px 11px;border:1px solid var(--line);
border-radius:8px;margin:0 5px 10px 0;color:var(--mut);cursor:pointer}}
.gt{{display:none;margin-bottom:8px}}
.gt td{{padding:6px 10px}}
#g0:checked~#gt0,#g1:checked~#gt1,#g2:checked~#gt2{{display:table}}
#g0:checked~label[for=g0],#g1:checked~label[for=g1],#g2:checked~label[for=g2]
{{color:var(--ink);border-color:var(--acc)}}
.barcell span{{display:block;height:6px;background:var(--acc);opacity:.45;border-radius:999px}}
.fr{{padding:20px 16px 24px;max-width:620px}}
.fr h2{{margin:0 0 7px;font-size:19px;font-weight:640;letter-spacing:-.02em;text-transform:none;
color:var(--ink)}}
.fr>p{{color:var(--mut);margin:0 0 20px;font-size:13px;max-width:62ch}}
.fr ol{{list-style:none;margin:0;padding:0;counter-reset:s}}
.fr li{{counter-increment:s;display:grid;grid-template-columns:26px 1fr;gap:12px;padding:14px 0;
border-top:1px solid var(--line)}}
.fr li::before{{content:counter(s);width:22px;height:22px;border-radius:7px;
background:var(--acc-soft);color:var(--acc);font-size:11px;font-weight:700;display:grid;
place-items:center}}
.fr b{{display:block;font-size:13.5px}}
/* the numbered pseudo-element is grid item 1; the description must stay in column 2 or it
   wraps one word per line inside the 26px number column (latent in the mockup's own CSS) */
.fr li span{{grid-column:2;color:var(--mut);font-size:12.5px}}
code{{font-family:var(--mono);font-size:11.5px;background:var(--rail);padding:2px 6px;
border-radius:6px}}
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
  .thead,.row{{grid-template-columns:minmax(140px,1.5fr) .8fr 1fr auto}}
  .thead.s3,.row.s3{{grid-template-columns:minmax(140px,1.5fr) .9fr .5fr}}
  .cl-agents,.cl-num{{display:none}}
  .split{{grid-template-columns:1fr}}
  .side{{border-left:none}}
}}
</style></head><body>
<input type="radio" name="nav" id="n0" checked><input type="radio" name="nav" id="n1">
<input type="radio" name="nav" id="n2"><input type="radio" name="nav" id="n3">
<input type="radio" name="nav" id="n4"><input type="radio" name="nav" id="n5">
<input type="radio" name="nav" id="n6">
<div class="sheet">
  <div class="bhead"><span class="brand">mcpgawk</span>
    <!-- WHICH BUILD AM I LOOKING AT. A running panel never reloads its code: on 2026-07-30 the
         founder read a 25-minute-old process three times and reported "nothing changed" —
         correctly, because that process predated the changes. -->
    <span class="bsub" title="when the code being served was last modified, and when this process started">
      local · this machine only · code {_esc(_CODE_AT)} · started {_esc(_STARTED)}</span></div>
  <div class="rail">
    <label class="pill" for="n0"><span class="dot"></span>Servers <span class="ct">{len(classified)}</span></label>
    <label class="pill" for="n6"><span class="dot"></span>Findings {_ct_fnd}</label>
    <label class="pill" for="n4"><span class="dot"></span>Activity</label>
    <label class="pill" for="n1"><span class="dot"></span>Agents {_ct_agt}</label>
    <label class="pill" for="n3"><span class="dot"></span>Decisions {_ct_dec}</label>
    <label class="pill" for="n5"><span class="dot"></span>Trust</label>
    <label class="pill" for="n2"><span class="dot"></span>Evidence</label>
  </div>
  {errs}
  <section class="pane" id="p0">
    {firstrun}
    <div class="card">
      <div class="chead"><h1>Servers</h1><div class="tools">
        <a class="gbtn" href="/export/servers.csv">Export .csv</a>
        {_action_buttons(token, action)}</div></div>
      {'' if token else
       '<div class="note">Read-only view — the state is open, the controls are not. The buttons '
       '(scan, verify, approve, protect) appear only through the link printed in the terminal '
       'that started the panel, which an agent that merely opens this page cannot supply. '
       'Lost the link? Restart <code>mcpgawk panel</code> and use the fresh one it prints.</div>'}
      <div class="abar">{_action_banner(action)}</div>
      {nba}
      {filterbar}
      {servers_table}
    </div>
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
      <table><thead><tr><th>server</th><th>tool</th><th>finding</th><th>severity</th>
      <th>what it contacted</th><th>reproduced</th></tr></thead><tbody>{frows}</tbody></table>
    </div>
  </section>

  <section class="pane" id="p1">
    <div class="card">
      <div class="chead"><h1>Agents</h1>
        <div class="tools"><span class="count">{covered} covered · {uncovered} not</span></div></div>
      <table><thead><tr><th>agent</th><th>coverage</th><th>servers</th><th>detail</th><th></th></tr>
      </thead><tbody>{arows}</tbody></table>
      <h2>sessions · one row per agent run</h2>
      <table><thead><tr><th>session</th><th>agent</th><th class="num">calls</th>
      <th class="num">denied</th><th class="num">servers</th><th>last</th></tr></thead>
      <tbody>{sess}</tbody></table>
      <h2>group by</h2>
      <div class="gwrap">{groups}</div>
      <h2>recent calls · arguments are never recorded</h2>
      <table><thead><tr><th>time</th><th>verdict</th><th>tool</th><th>agent</th><th>basis</th></tr>
      </thead><tbody>{log}</tbody></table>
    </div>
  </section>

  <section class="pane" id="p2">
    <div class="card">
      <div class="chead"><h1>Evidence</h1>{f'<div class="tools"><span class="count">verified {_esc(d.get("verify_at") or "")[:19]}</span></div>' if d.get("verify_at") else ''}</div>
      <!-- Findings moved to their own screen (2026-07-31). Evidence keeps PROVENANCE — what ran,
           when, and how it went. Rendering the same findings in two places is two answers. -->
      <div class="note">Findings live on their own screen. This page is provenance: what ran, when,
        and how it went.</div>
      <table><thead><tr><th>started</th><th>what</th><th>result</th><th>target</th></tr></thead>
      <tbody>{runs}</tbody></table>
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
      <table><thead><tr><th style="width:18%">server</th><th>what changed</th><th>severity</th>
      <th></th></tr></thead><tbody>{dec}</tbody></table>
    </div>
  </section>

  <!-- TRUST. A security product must be able to answer "where does this live and what actually
       ran" without the user reading our source. Every path is real and every backend is what the
       engine reported, not what a label claimed. -->
  <section class="pane" id="p5">
    <div class="card">
      <div class="chead"><h1>Trust</h1>
        <div class="tools"><a class="gbtn" href="/export/calls.jsonl">Export .jsonl</a>
          <a class="gbtn" href="/export/calls.csv">Export .csv</a></div></div>
      <h2>what actually ran</h2>
      <table><thead><tr><th>server</th><th>isolation used</th><th>tools checked</th>
      <th>not invoked</th></tr></thead><tbody>{isorows}</tbody></table>
      <h2>where everything lives</h2>
      <table><thead><tr><th>what</th><th>path</th></tr></thead><tbody>{pathrows}</tbody></table>
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
      <div class="filters"><span class="count" style="margin-left:0">
        <b>{act_summary.get('calls', '—') if isinstance(act_summary, dict) else '—'}</b> calls checked
        · {len(notable)} denied · {_esc(_span)}</span></div>
      <h2>Needs your attention — blocked calls, with the full reason</h2>
      <table><thead><tr><th>when</th><th>agent</th><th>server.tool</th><th>decision</th>
      <th>basis</th><th>why (verbatim)</th></tr></thead><tbody>{acts_notable}</tbody></table>
      <h2>The full record — every checked call, newest first</h2>
      <div class="note">Tool arguments are never recorded — the log is metadata, so it can never
      become the richest secret on your disk. <b>When</b> · <b>agent</b> (how &amp; who) ·
      <b>server.tool</b> (what &amp; where) · <b>decision</b> &amp; <b>basis</b> (why).</div>
      <table><thead><tr><th>when</th><th>agent</th><th>server.tool</th><th>decision</th>
      <th>basis</th><th>why</th></tr></thead><tbody>{acts_full}</tbody></table>
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

def state() -> dict[str, Any]:
    """The whole panel payload, JSON-safe. One request, because the panel has one view of the
    machine and splitting it into six endpoints would let them disagree mid-refresh."""
    d = collect()
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
        "agents": [{"label": lbl, "state": st, "servers": n, "detail": det}
                   for lbl, st, n, det in _agent_rows(d)],
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


_ACTION: dict[str, Any] = {"running": False, "label": "", "message": "", "rows": [], "at": ""}


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


def _run_action_bg(kind: str, target: str | None = None) -> None:
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
            return                               # one at a time — a second click is a no-op
        _ACTION.update(running=True, label=(f"{kind} · {target}" if target else kind),
                       message="", rows=[], at=_now())

    def work():
        try:
            if kind == "scan":
                res = run_scan()
            elif kind == "verify":
                res = run_verify_fleet(target)
            else:
                res = {"ok": False, "message": f"unknown action {kind!r}"}
            msg = res.get("message") or ("done" if res.get("ok") else "failed")
            rows = res.get("rows") or []
        except Exception as exc:                  # noqa: BLE001 — an action must not kill the panel
            msg, rows = f"{type(exc).__name__}: {exc}", []
        with _ACTION_LOCK:
            _ACTION.update(running=False, message=msg, rows=rows, at=_now())
        _persist_action()

    threading.Thread(target=work, daemon=True).start()


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
    return "bad" if str(f.get("severity")).lower() in ("critical", "high") else "warn"


def _foldnote(f: dict) -> str:
    if f.get("suppressed"):
        return ' <span class="chip">muted by you</span>'
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
    import subprocess
    import sys as _sys
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
    local = {}
    for n, e in entries.items():
        if not (isinstance(e, dict) and e.get("command")):
            continue
        launchable = dxt.resolve_for_launch(e) or e
        local[n] = {k: launchable[k] for k in ("command", "args", "env") if k in launchable}
    # ONE SERVER AT A TIME IS THE DEFAULT SHAPE, not a special case. The fleet button made every
    # answer cost five silent minutes, so the founder clicked it, waited, and left the page. A row
    # action returns in seconds and is the unit a user actually thinks in: "what about THIS server?"
    if only:
        if only not in local:
            return {"ok": False, "message": f"{only} is not a local server on this machine"}
        local = {only: local[only]}
    if not local:
        return {"ok": False, "message": "no local servers to verify"}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     prefix="mcpgawk-panel-verify-") as fh:
        _json.dump({"mcpServers": local}, fh)
        cfg = fh.name
    try:
        # --out KEEPS THE FINDINGS. Without it the engine's 21 convictions existed only in this
        # subprocess's stdout: the banner showed a count until the panel restarted, and Evidence,
        # Decisions and every drill-down were untouched by a verify because nothing was persisted
        # for them to read. The founder: "apart from the verify the fleet output nothing changed in
        # the panel." The engine already writes the complete report atomically; we simply never
        # asked for it.
        report_path = behaviour_profile_path().parent / "last-verify.json"
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
            run_dir.mkdir(parents=True, exist_ok=True)
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
        rc, engine_output = _verify.run_captured(
            [cfg, "--isolate", *audit_args, "--out", str(report_path)], timeout=1200)
        prof_after = -1.0
        try:
            prof_after = behaviour_profile_path().stat().st_mtime
        except OSError:
            prof_after = -1.0
        profile_unwritten = prof_after == prof_before
        if audit_args:
            try:                                  # the report belongs with its audit stream
                _shutil.copyfile(report_path, run_dir / "report.json")
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
        real_map: dict[str, set] = {}             # server -> tools with non-first-party findings
        folded_map: dict[str, int] = {}           # server -> first-party findings folded
        report_readable = False
        try:
            _rep_doc = json.loads(report_path.read_text(encoding="utf-8"))
            report_readable = True
            for s in (_rep_doc.get("servers") or []):
                sname = str(s.get("server") or "")
                if not sname:
                    continue
                if s.get("sandboxDegradedReason"):
                    degraded_map[sname] = str(s["sandboxDegradedReason"])
                for f in (s.get("findings") or []):
                    if f.get("suppressed"):
                        continue
                    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
                    hosts = [str(x) for x in (ev.get("egress") or ev.get("hosts") or [])]
                    tool = str(f.get("tool") or (f.get("candidate") or {}).get("toolName") or "?")
                    if first_party(sname, hosts, local.get(sname)):
                        folded_map[sname] = folded_map.get(sname, 0) + 1
                    else:
                        real_map.setdefault(sname, set()).add(tool)
        except (OSError, ValueError):
            # Unreadable report: no degradation info, and fall back to RAW conviction counts from
            # the profile below — overcounting is the safe direction, silence is not.
            degraded_map, real_map, folded_map, report_readable = {}, {}, {}, False
        # A server counts as observed when a run EXERCISED it. Counting convictions instead meant a
        # clean fleet reported as an unverified one, and "observed 2 of 8" understated real work.
        seen = {n for n, o in ran_map.items()
                if isinstance(o, dict) and (o.get("toolsChecked") or 0) > 0} | set(seen_map)
        got = sorted(n for n in local if n in seen)
        missing = sorted(n for n in local if n not in seen)
        # Per-server rows for the PAGE. Sending the user to a terminal to find out which server
        # failed is the CLI-only habit this surface exists to replace.
        def _verdict(n: str) -> tuple[str, str, str]:
            """(outcome, level, detail) for a server a run exercised.

            "observed" is NOT a verdict — it says we managed to run, which is a fact about US. The
            founder watched this page award `browserstack` a green `observed` chip while the grey
            text beside it read "20 with findings": the chip said good news, the sentence said his
            most-used server was convicted on every tool checked. A verification tool whose green
            state contains 20 convictions tells the user the opposite of what it found.
            """
            o = ran_map.get(n) if isinstance(ran_map.get(n), dict) else {}
            checked = o.get("toolsChecked") or 0
            skipped = list(o.get("skipped") or [])
            errors = o.get("checkErrors") or 0
            hits = len(real_map.get(n) or ()) if report_readable else len(seen_map.get(n) or {})
            folded = folded_map.get(n, 0)

            bits = [f"{checked or hits} tool(s) watched"]
            if skipped:            # never let an untested tool read as a clean one
                bits.append(f"{len(skipped)} not invoked — absence there proves nothing")
            if errors:
                bits.append(f"{errors} check(s) never completed")
            if o.get("backend"):   # the truth about isolation, per server, instead of a claim
                bits.append(f"isolation: {o['backend']}")
            if degraded_map.get(n):  # container isolation was requested and did NOT run — say why
                bits.append(f"ran WITHOUT container isolation — {degraded_map[n].split('—')[0].strip()}")
            if folded:               # classified, never dropped — the list is on the Findings screen
                bits.append(f"{folded} first-party finding(s) folded (the vendor's own traffic)")
            detail = " · ".join(bits)

            if hits:               # convictions outrank everything: this is the headline, not an aside
                return (f"{hits} tool(s) with findings", "bad", detail)
            if errors:             # nothing proven wrong AND some checks never ran => not clean
                return ("incomplete — not clean", "warn", detail)
            if skipped:
                return (f"partial — {checked} of {checked + len(skipped)} checked", "warn", detail)
            return (f"clean — {checked} tool(s)", "ok", detail)

        rows = []
        for n in got:
            outcome, level, detail = _verdict(n)
            rows.append({"server": n, "outcome": outcome, "level": level, "detail": detail})
        needs_auth = 0
        for n in missing:
            note = _engine_note(engine_output, n)
            outcome, detail = _nothing_recorded_outcome(note, local[n])
            needs_auth += outcome == "needs your sign-in"
            rows.append({"server": n, "outcome": outcome, "level": "bad", "detail": detail,
                         "fix": _remedy(note, local[n])})

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
        if not parts:                       # genuinely nothing wrong and nothing left unchecked
            msg = f"clean — {len(clean)} local server(s) verified, no findings"
            tail = " · ".join(x for x in (folded_note, evidence_note) if x)
            return {"ok": True, "rows": rows, "level": "ok", "evidence_dir": evidence_dir,
                    "message": f"{msg} · {tail}" if tail else msg}
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
            # The record, downloadable. "Everything logged and available to download" — the raw
            # append-only log verbatim, or a spreadsheet-friendly CSV of the same rows. No token:
            # this is your own local record of your own machine, the same bytes `cat` would show.
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
            # The action token is served ONLY to a request that already carries it. Before this,
            # do_GET embedded the full token in every response while read views were open, so any
            # local process — including an agent, with no credential at all — could GET the page,
            # scrape the hidden field and POST actions. Proven 2026-07-30: an agent-marked process
            # scraped the token and its `act=scan` POST returned HTTP 200. That defeated the whole
            # point of the gate, which exists because an agent asked to approve its own unblocking
            # will do it. Reading stays open; holding the token is what buys the buttons.
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            shown = token if secrets.compare_digest(
                (q.get("t") or [""])[0], token) else ""
            body = render(collect(), token=shown, action=dict(_ACTION),
                          q=(q.get("q") or [""])[0][:80],
                          tier_filter=(q.get("tier") or [""])[0][:20],
                          sel=(q.get("sel") or [""])[0][:120],
                          tl=(q.get("tl") or [""])[0][:200]).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            # Actions are same-origin POST forms; keep the strict CSP but allow the form submit.
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
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
            if act in ("scan", "verify"):
                # `key` carries the server for a row action; absent = whole fleet.
                _run_action_bg(act, (form.get("key") or [""])[0] or None)
            elif act == "keep":
                # Leaving it blocked IS the decision — deliberately a no-op on state, exactly like
                # `decide`'s keep. The message confirms the consequence, not an action performed.
                _ACTION.update(message="Left blocked. Your agents still cannot call it.",
                               rows=[], level="ok", at=_now())
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
                    self.send_header("Location", f"/?t={urllib.parse.quote(token)}")
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
            self.send_header("Location", f"/?t={urllib.parse.quote(token)}")
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
