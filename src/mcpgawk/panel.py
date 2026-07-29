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
import os
from pathlib import Path
from typing import Any

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
    try:
        prof = Path.home() / ".gawk" / "behaviour.json"
        if prof.is_file():
            data["observed"] = (json.loads(prof.read_text(encoding="utf-8"))
                                .get("servers") or {})
    except Exception as exc:                       # noqa: BLE001
        data["errors"]["observed"] = f"{type(exc).__name__}: {exc}"

    try:
        from .verify import unavailable_reason
        data["verify_blocked"] = unavailable_reason()
    except Exception:                              # noqa: BLE001
        data["verify_blocked"] = "verification engine not available in this install"

    return data


def _agent_rows(d: dict[str, Any]) -> list[tuple[str, str, int, str]]:
    """(label, state, server_count, detail) per agent found on this machine."""
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
                rows.append((label, "on", n, "every MCP call checked against your baseline"))
            else:
                rows.append((label, "off", n, "can be covered — run `mcpgawk` to turn it on"))
        else:
            why = (d.get("no_hook") or {}).get(client, "no pre-execution hook point")
            rows.append((label, "none", n, why))
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
TIERS = (
    ("blocked", "Blocked", "a call was denied — the guard stopped something"),
    ("changed", "Changed", "moved since you approved it; your agents cannot call it"),
    ("unverified", "Unverified", "never watched in a sandbox — absence of a finding, not safety"),
    ("baseline", "At baseline", "matches what you approved, and behaviour was observed"),
)


def _classify(name: str, key: str | None, d: dict) -> str:
    """One server's tier. Ordered worst-first: the first thing that is true wins."""
    calls = [c for c in (d.get("recent_calls") or []) if c.get("server") == name]
    if any(c.get("decision") == "deny" for c in calls):
        return "blocked"
    if key and key in (d.get("pending") or []):
        return "changed"
    if name not in (d.get("observed") or {}):
        return "unverified"
    return "baseline"


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
    rows = []
    for tool in current:
        ann = annotations.get(tool) if isinstance(annotations.get(tool), dict) else {}
        ro = ann.get("readOnlyHint")
        declared = "read-only" if ro is True else ("writes" if ro is False else "undeclared")
        sig = obs.get(tool) if isinstance(obs.get(tool), dict) else {}
        seen = [k for k in ("source", "sink") if sig.get(k) is True]
        rows.append({
            "tool": tool,
            "baseline": "approved" if tool in approved else "added",
            "declared": declared,
            "observed": "+".join(seen) if seen else None,
        })
    for tool, sig in obs.items():
        if tool in current or not isinstance(sig, dict):
            continue
        seen = [k for k in ("source", "sink") if sig.get(k) is True]
        rows.append({"tool": tool, "baseline": "gone", "declared": "no longer exposed",
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


def render(d: dict[str, Any]) -> str:
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
    covered = sum(n for _, s, n, _ in rows if s == "on")
    uncovered = sum(n for _, s, n, _ in rows if s != "on")

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
    classified: list[tuple[str, dict, str | None, str]] = []
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        key = next((k for k, v in servers.items()
                    if name in ((v or {}).get("aliases") or [])), None)
        classified.append((name, entry, key, _classify(name, key, d)))
    order = {t: i for i, (t, _, _) in enumerate(TIERS)}
    classified.sort(key=lambda r: (order.get(r[3], 9), r[0]))
    counts = {t: sum(1 for r in classified if r[3] == t) for t, _, _ in TIERS}
    total = max(len(classified), 1)

    # --- metric cards. Three, and none of them invented to fill a slot ------------------------
    by_day: dict[str, int] = {}
    for c in calls:
        by_day[str(c.get("ts", ""))[:13]] = by_day.get(str(c.get("ts", ""))[:13], 0) + 1
    series = [by_day[k] for k in sorted(by_day)][-24:]

    fresh = act.get("last_seen") or "never"
    cards = f"""
<div class="cards">
  <div class="card">
    <div class="ck">servers</div><div class="cv">{len(classified)}</div>
    <div class="cs">{counts['blocked'] + counts['changed']} need you · {counts['unverified']} unverified</div>
  </div>
  <div class="card">
    <div class="ck">calls checked</div><div class="cv">{act.get('calls', '—')}</div>
    {_spark(series)}
    <div class="cs">{act.get('sessions', 0)} agent session(s) · {act.get('denied', 0)} denied</div>
  </div>
  <div class="card">
    <div class="ck">last seen</div><div class="cv sm">{_esc(str(fresh)[11:19] or '—')}</div>
    <div class="cs">{_esc(str(fresh)[:10])}</div>
  </div>
</div>"""

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
    srows = []
    for name, entry, key, tier in classified:
        detail = server_detail(store, key, calls) if key else None
        local = "local" if entry.get("command") else "remote"
        clients = ", ".join(entry.get("_clients") or []) or "—"
        seen = detail["calls_seen"] if detail else 0
        tools = len(detail["current_tools"]) if detail else "—"
        inner = ""
        if detail:
            tl = "".join(f'<tr><td class="nm">{_esc(t)}</td><td class="dim">{n} call(s)</td></tr>'
                         for t, n in detail["calls_by_tool"][:8]) or \
                 '<tr><td colspan="2" class="dim">no calls recorded for this server</td></tr>'
            dvo_parts = []
            for r in declared_vs_observed(detail, (d.get("observed") or {}).get(name)):
                base = {"approved": "ok", "added": "warn", "gone": "bad"}[r["baseline"]]
                if r["observed"]:
                    obs_cell = f'<span class="chip warn">{_esc(r["observed"])}</span>'
                elif r["baseline"] == "gone":
                    obs_cell = '<span class="dim">—</span>'
                else:
                    obs_cell = ('<span class="dim">not observed — absence is not a claim of '
                                'safety</span>')
                dvo_parts.append(
                    f'<tr><td class="nm">{_esc(r["tool"])}</td>'
                    f'<td><span class="chip {base}">{r["baseline"]}</span></td>'
                    f'<td class="dim">{_esc(r["declared"])}</td><td>{obs_cell}</td></tr>')
            dvo = "".join(dvo_parts) or \
                '<tr><td colspan="4" class="dim">no measured surface yet — run mcpgawk</td></tr>'
            inner = f"""<div class="dd">
  <div class="ddgrid">
    <div><span class="k">transport</span>{_esc(detail['transport'] or local)}</div>
    <div><span class="k">protocol</span>{_esc(detail['protocol'] or '—')}</div>
    <div><span class="k">tools now</span>{len(detail['current_tools'])}</div>
    <div><span class="k">approved</span>{len(detail['approved_tools'])}</div>
    <div><span class="k">context cost</span>{detail['cost_index']} tok</div>
    <div><span class="k">snapshots</span>{detail['snapshots']}</div>
    <div><span class="k">last measured</span>{_esc(detail['measured_at'][:19] or '—')}</div>
    <div><span class="k">also known as</span>{_esc(', '.join(detail['aliases']) or '—')}</div>
  </div>
  <div class="ddh">what the guard has seen</div>
  <table class="mini"><tbody>{tl}</tbody></table>
  <div class="ddh">declared vs observed · verdicts rest on observation, not names</div>
  <table class="mini"><thead><tr><th>tool</th><th>baseline</th><th>declared</th>
  <th>observed in the sandbox</th></tr></thead><tbody>{dvo}</tbody></table>
</div>"""
        srows.append(f"""<details class="row"><summary>
  <span class="tier {tier}"></span>
  <span class="nm">{_esc(name)}</span>
  <span class="dim">{local}</span>
  <span class="dim">{_esc(clients)}</span>
  <span class="dim">{tools} tools</span>
  <span class="dim">{seen} calls</span>
</summary>{inner}</details>""")

    # --- runtime: agents, then the call log with one Group by ----------------------------------
    arows = "".join(
        f'<tr><td class="nm">{_esc(label)}</td><td><span class="chip '
        f'{"ok" if st == "on" else ("warn" if st == "off" else "dim")}">'
        f'{"protected" if st == "on" else ("not enabled" if st == "off" else "no hook point")}'
        f'</span></td><td>{n}</td><td class="dim">{_esc(det)}</td></tr>'
        for label, st, n, det in rows) or '<tr><td colspan="4" class="dim">No agents found.</td></tr>'

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

    vb = d.get("verify_blocked")
    vnote = (f'<div class="note warn">Behavioural verification unavailable — {_esc(vb)}</div>'
             if vb else
             '<div class="note ok"><b>Behavioural verification is available.</b> '
             '<code>mcpgawk verify &lt;config.json&gt;</code> runs each server in a sandbox and '
             'reports what it actually contacts. Free.</div>')
    errs = "".join(f'<div class="note warn">Could not read {_esc(k)}: {_esc(v)} — this panel is '
                   f'showing less than the whole picture.</div>'
                   for k, v in (d.get("errors") or {}).items())

    dec = "".join(f'<tr><td class="nm">{_esc(_h.display_name(store, k))}</td>'
                  f'<td><span class="chip bad">blocked · waiting on you</span></td></tr>'
                  for k in pending) or \
          '<tr><td colspan="2" class="dim">Nothing is waiting on you.</td></tr>'

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>mcpgawk</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* Light paper-and-ink table language — founder decision 2026-07-29 (DESIGN.md): HTML product
   surfaces are light, royal-blue interaction accent, matching the site's instrument windows.
   No dark override: the product view is deliberately not black. */
:root{{--bg:#FAFAF6;--pane:#FFF;--side:#F2F1EA;--ink:#16160F;--mut:#6B6B5E;--fai:#717166;
--rule:#E7E6DE;--acc:#2A33C2;--ok:#157A40;--warn:#B26A00;--bad:#C0392B;--unv:#8B9098;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace;
--sans:system-ui,-apple-system,"Segoe UI",sans-serif}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;
line-height:1.5;display:grid;grid-template-columns:190px 1fr;min-height:100vh}}
nav{{background:var(--side);border-right:1px solid var(--rule);padding:18px 0}}
.brand{{font-weight:700;letter-spacing:-.02em;font-size:15px;padding:0 18px 4px}}
.sub{{font-family:var(--mono);font-size:10px;color:var(--fai);padding:0 18px 18px}}
nav label{{display:block;padding:8px 18px;font-size:13.5px;color:var(--mut);cursor:pointer;
border-left:2px solid transparent}}
main{{padding:22px 26px 70px;min-width:0}}
.top{{display:flex;align-items:baseline;justify-content:space-between;gap:16px;margin-bottom:18px;
flex-wrap:wrap}}
h1{{font-size:19px;font-weight:660;letter-spacing:-.02em;margin:0}}
.act{{font-family:var(--mono);font-size:11.5px;color:var(--mut);border:1px solid var(--rule);
padding:5px 11px;border-radius:3px;background:var(--pane)}}
input[type=radio]{{position:absolute;opacity:0;pointer-events:none}}
.pane{{display:none}}
#n0:checked~main #p0,#n1:checked~main #p1,#n2:checked~main #p2,#n3:checked~main #p3{{display:block}}
#n0:checked~nav label[for=n0],#n1:checked~nav label[for=n1],#n2:checked~nav label[for=n2],
#n3:checked~nav label[for=n3]{{color:var(--ink);border-left-color:var(--acc);font-weight:600;
background:var(--pane)}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;
margin-bottom:16px}}
.card{{background:var(--pane);border:1px solid var(--rule);border-radius:4px;padding:13px 15px}}
.ck{{font-size:11px;color:var(--fai);letter-spacing:.05em;text-transform:uppercase}}
.cv{{font-size:27px;font-weight:680;letter-spacing:-.02em;font-variant-numeric:tabular-nums;
line-height:1.2}}
.cv.sm{{font-size:19px;font-family:var(--mono)}}
.cs{{font-family:var(--mono);font-size:10.5px;color:var(--fai);margin-top:3px}}
.spark{{width:100%;height:26px;margin:4px 0 2px}}
.spark polyline{{fill:none;stroke:var(--acc);stroke-width:1.5;vector-effect:non-scaling-stroke}}
.bar{{display:flex;height:8px;border-radius:99px;overflow:hidden;background:var(--rule);
margin:2px 0 8px}}
.seg.blocked{{background:var(--bad)}}.seg.changed{{background:var(--warn)}}
.seg.unverified{{background:var(--unv)}}.seg.baseline{{background:var(--ok)}}
.legend{{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--mut);margin-bottom:18px}}
.sw{{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}}
.sw.blocked{{background:var(--bad)}}.sw.changed{{background:var(--warn)}}
.sw.unverified{{background:var(--unv)}}.sw.baseline{{background:var(--ok)}}
.legend b{{font-variant-numeric:tabular-nums}}
details.row{{background:var(--pane);border:1px solid var(--rule);border-radius:4px;
margin-bottom:6px}}
details.row summary{{display:grid;grid-template-columns:10px 1.6fr .5fr 1.2fr .6fr .6fr;
gap:12px;align-items:center;padding:10px 14px;cursor:pointer;list-style:none}}
details.row summary::-webkit-details-marker{{display:none}}
.tier{{width:8px;height:8px;border-radius:2px;display:inline-block}}
.tier.blocked{{background:var(--bad)}}.tier.changed{{background:var(--warn)}}
.tier.unverified{{background:var(--unv)}}.tier.baseline{{background:var(--ok)}}
.dd{{border-top:1px solid var(--rule);padding:14px 16px}}
.ddgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px 20px;
font-size:12.5px;margin-bottom:12px}}
.ddgrid .k{{display:block;font-size:10px;letter-spacing:.05em;text-transform:uppercase;
color:var(--fai)}}
.ddh{{font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--fai);margin:6px 0}}
table{{width:100%;border-collapse:collapse;font-size:13px;background:var(--pane)}}
th{{text-align:left;font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--fai);
font-weight:660;padding:7px 12px;border-bottom:1px solid var(--rule)}}
td{{padding:8px 12px;border-bottom:1px solid var(--rule)}}
td.num{{text-align:right;font-variant-numeric:tabular-nums;width:60px}}
.nm{{font-family:var(--mono);font-size:12.5px}}
.dim{{color:var(--fai)}}
.chip{{font-family:var(--mono);font-size:10px;letter-spacing:.04em;padding:2px 8px;
border-radius:99px;border:1px solid var(--rule);color:var(--mut);white-space:nowrap}}
.chip.ok{{border-color:var(--ok);color:var(--ok);background:rgba(21,122,64,.07)}}
.chip.warn{{border-color:var(--warn);color:var(--warn);background:rgba(178,106,0,.07)}}
.chip.bad{{border-color:var(--bad);color:var(--bad);background:rgba(192,57,43,.07)}}
.note{{border-left:3px solid var(--rule);background:var(--pane);padding:10px 14px;margin-bottom:14px;
font-size:13px}}
.note.ok{{border-left-color:var(--ok)}}.note.warn{{border-left-color:var(--warn)}}
h2{{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--fai);
margin:22px 0 8px;font-weight:660}}
.gl{{display:inline-block;font-size:12px;padding:4px 11px;border:1px solid var(--rule);
border-radius:3px;margin:0 5px 10px 0;color:var(--mut);cursor:pointer}}
.gt{{display:none;margin-bottom:8px}}
#g0:checked~#gt0,#g1:checked~#gt1,#g2:checked~#gt2{{display:table}}
#g0:checked~label[for=g0],#g1:checked~label[for=g1],#g2:checked~label[for=g2]
{{color:var(--ink);border-color:var(--acc)}}
.barcell span{{display:block;height:6px;background:var(--acc);opacity:.45;border-radius:2px}}
code{{font-family:var(--mono);font-size:.88em}}
@media(max-width:760px){{body{{grid-template-columns:1fr}}nav{{border-right:none;
border-bottom:1px solid var(--rule);display:flex;flex-wrap:wrap;padding:10px}}
nav .brand,nav .sub{{width:100%}}details.row summary{{grid-template-columns:10px 1fr;gap:8px}}
details.row summary .dim{{display:none}}}}
</style></head><body>
<input type="radio" name="nav" id="n0" checked><input type="radio" name="nav" id="n1">
<input type="radio" name="nav" id="n2"><input type="radio" name="nav" id="n3">
<nav>
  <div class="brand">mcpgawk</div>
  <div class="sub">local · this machine only</div>
  <label for="n0">Servers</label>
  <label for="n1">Runtime</label>
  <label for="n2">Evidence</label>
  <label for="n3">Decisions</label>
</nav>
<main>
  {errs}
  <div class="pane" id="p0">
    <div class="top"><h1>Servers</h1><span class="act">mcpgawk — re-scan</span></div>
    {cards}{coverage}{vnote}
    {''.join(srows) or '<div class="note">No MCP servers found on this machine.</div>'}
  </div>

  <div class="pane" id="p1">
    <div class="top"><h1>Runtime</h1><span class="act">{covered} covered · {uncovered} not</span></div>
    <table><thead><tr><th>agent</th><th>coverage</th><th>servers</th><th></th></tr></thead>
    <tbody>{arows}</tbody></table>
    <h2>sessions · one row per agent run</h2>
    <table><thead><tr><th>session</th><th>agent</th><th class="num">calls</th>
    <th class="num">denied</th><th class="num">servers</th><th>last</th></tr></thead>
    <tbody>{sess}</tbody></table>
    <h2>group by</h2>{groups}
    <h2>recent calls · arguments are never recorded</h2>
    <table><thead><tr><th>time</th><th>verdict</th><th>tool</th><th>agent</th><th>basis</th></tr>
    </thead><tbody>{log}</tbody></table>
  </div>

  <div class="pane" id="p2">
    <div class="top"><h1>Evidence</h1></div>
    <table><thead><tr><th>started</th><th>what</th><th>result</th><th>target</th></tr></thead>
    <tbody>{runs}</tbody></table>
  </div>

  <div class="pane" id="p3">
    <div class="top"><h1>Decisions</h1><span class="act">mcpgawk decide</span></div>
    <div class="note">Approving needs a human, so it cannot happen from this page — it lives in
    <code>mcpgawk decide</code>, behind a token printed to your terminal.</div>
    <table><thead><tr><th>server</th><th>state</th></tr></thead><tbody>{dec}</tbody></table>
  </div>
</main>
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
    for several of those. Subprocess rather than in-process because a scan launches servers and can
    take a minute; the panel must not block its own event loop on it.
    """
    import subprocess
    import sys as _sys

    try:
        proc = subprocess.run([_sys.executable, "-m", "mcpgawk.cli", "scan", "--track", "--yes"],
                              capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "scan timed out after 10 minutes"}
    except OSError as exc:
        return {"ok": False, "message": f"could not start a scan: {exc}"}
    # A scan exits non-zero when it FOUND something. That is not a failure of the scan.
    return {"ok": proc.returncode in (0, 1),
            "message": ("rescanned" if proc.returncode in (0, 1)
                        else (proc.stderr or "scan failed").strip().splitlines()[-1][:200])}


def serve(port: int = 7718, open_browser: bool = True, log=print) -> int:
    """Serve the panel. Read-only, so unlike `decide` it needs no token and no human gate —
    there is nothing here to authorise."""
    import threading
    import webbrowser
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def do_GET(self):                        # noqa: N802
            body = render(collect()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
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
