"""`mcpgawk decide` — the one screen a human is actually required for.

WHY A UI AT ALL, AND WHY ONLY THIS ONE. Everything else this product does is better as terminal
output or as something you never see: scanning, blocking, recording. The single moment that
genuinely needs a person is APPROVAL — deciding whether a server that changed after you trusted it
should be trusted again. Today that decision is made by reading a diff in a second terminal while
the agent sits blocked in the first, and the only UI in the product (`verify serve`) is paid, while
approval is free. So the free tier's hardest judgement call had no surface at all.

Deliberately NOT a dashboard. A dashboard is a thing you remember to visit; this opens *because
something is blocked*, shows ONE server at a time, and closes. Approving in bulk is how people
approve things they did not read.

SECURITY — the reason this file is more careful than it looks. `baseline.approval_blocked_reason`
refuses to let an agent approve: no agent-session marker, and a real TTY. A local web server
casually undoes that, because an agent with a shell can `curl localhost`. So:

  * every mutating request must carry a SESSION TOKEN printed once to the terminal, where a human
    reading their own screen sees it and an agent reading a hook denial does not;
  * the token never enters the spool, the audit log, the run registry, or any file the agent reads;
  * binds to 127.0.0.1 only — never a routable interface;
  * GET is read-only; approval is POST + token. A page load can never change trust.

This is a VIEW. It computes nothing: the pending list comes from `history.pending`, the diff from
`drift.compare`, the names from `history.display_name`. A second opinion about what changed is
exactly the drift this codebase keeps paying for.
"""
from __future__ import annotations

import html
import os
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote_plus

from . import baseline, drift, history

#: Loopback only. A security tool that opens a port on a routable interface has failed at its own
#: premise, and "it's only local" is how that happens.
HOST = "127.0.0.1"
DEFAULT_PORT = 7717


def pending_decisions(store: dict[str, Any]) -> list[dict[str, Any]]:
    """One entry per server awaiting a human. Pure — no I/O, no clock, so it is directly testable
    and the page cannot disagree with `mcpgawk status` about what is outstanding."""
    out: list[dict[str, Any]] = []
    for key in history.pending(store):
        approved, latest = history.approved(store, key), history.last(store, key)
        if not approved or not latest:
            continue
        report = drift.compare(approved, latest)
        if report is None:
            continue
        out.append({
            "key": key,
            "name": history.display_name(store, key),
            "report": report,
            "hostile": list(report.hostile),
            "seen_at": latest.get("seen") or "",
        })
    return out


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def _diff_block(report: drift.DriftReport) -> str:
    """The evidence, in the order a person needs it: what is dangerous, then what merely moved."""
    rows: list[str] = []
    for tool in report.hostile:
        before, after = report.texts.get(tool, ("", ""))
        rows.append(
            f'<div class="ev danger"><div class="lbl">⚠ {_esc(tool)} — '
            f'this is the rug-pull signature</div>'
            + (f'<div class="was">{_esc(before)}</div><div class="now">{_esc(after)}</div>'
               if before or after else "")
            + "</div>")
    for tool in report.added:
        rows.append(f'<div class="ev"><div class="lbl">+ {_esc(tool)} — a tool that did not exist '
                    f'when you approved this server</div></div>')
    for tool in report.removed:
        rows.append(f'<div class="ev"><div class="lbl">− {_esc(tool)} — removed</div></div>')
    for tool in report.changed:
        if tool in report.hostile:
            continue
        before, after = report.texts.get(tool, ("", ""))
        rows.append(f'<div class="ev"><div class="lbl">~ {_esc(tool)} — description changed</div>'
                    + (f'<div class="was">{_esc(before)}</div><div class="now">{_esc(after)}</div>'
                       if before or after else "") + "</div>")
    for tool in report.annotation_changed:
        rows.append(f'<div class="ev danger"><div class="lbl">⚠ {_esc(tool)} — safety annotations '
                    f'changed (a tool relabelled itself)</div></div>')
    for tool in report.schema_changed:
        rows.append(f'<div class="ev"><div class="lbl">~ {_esc(tool)} — inputs changed</div></div>')
    return "\n".join(rows) or '<div class="ev"><div class="lbl">No detail recorded.</div></div>'


def render_page(items: list[dict[str, Any]], token: str, note: str = "") -> str:
    """The whole UI. One file, no assets, no network — it must work on a machine with no internet
    and must never fetch anything, because a security tool that phones out to render itself is
    making a claim it cannot keep."""
    if not items:
        body = ('<div class="done"><h1>Nothing is waiting on you.</h1>'
                '<p>Every server your agents can reach matches the baseline you approved. '
                'This page opens when that stops being true.</p></div>')
    else:
        cards = []
        for it in items:
            r: drift.DriftReport = it["report"]
            danger = " danger" if it["hostile"] else ""
            cards.append(f"""
<section class="card{danger}">
  <div class="head">
    <h2>{_esc(it['name'])}</h2>
    <span class="pill">blocked · waiting on you</span>
  </div>
  <p class="sub">Changed after you approved it{(' · last seen ' + _esc(it['seen_at'])) if it['seen_at'] else ''}.
     Your agents cannot call it until you decide.</p>
  {_diff_block(r)}
  <form method="POST" action="/decide">
    <input type="hidden" name="token" value="{_esc(token)}">
    <input type="hidden" name="key" value="{_esc(it['key'])}">
    <button name="action" value="keep" class="btn danger-btn">Keep blocking</button>
    <button name="action" value="approve" class="btn">Trust this change</button>
  </form>
</section>""")
        body = "\n".join(cards)

    msg = f'<div class="note">{_esc(note)}</div>' if note else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>mcpgawk — decide</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{{--bg:#F6F6F4;--card:#FFF;--ink:#15181C;--muted:#5C6068;--rule:#DFDFDA;--accent:#A56A15;
--bad:#A83B31;--was:#EFEFEC;--mono:ui-monospace,SFMono-Regular,Menlo,monospace;
--sans:system-ui,-apple-system,"Segoe UI",sans-serif}}
@media(prefers-color-scheme:dark){{:root{{--bg:#101216;--card:#181B21;--ink:#E8EAED;--muted:#A0A5AE;
--rule:#2A2F38;--accent:#E0A33F;--bad:#E0665A;--was:#1E222A}}}}
*{{box-sizing:border-box}}
body{{background:var(--bg);color:var(--ink);font-family:var(--sans);margin:0;
padding:48px 20px 80px;line-height:1.55}}
.wrap{{max-width:760px;margin:0 auto}}
h1{{font-size:26px;letter-spacing:-.02em;margin:0 0 10px}}
h2{{font-size:20px;letter-spacing:-.015em;margin:0}}
.card{{background:var(--card);border:1px solid var(--rule);border-left:3px solid var(--rule);
padding:22px 24px;margin-bottom:18px}}
.card.danger{{border-left-color:var(--bad)}}
.head{{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}}
.pill{{font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;
padding:2px 8px;border-radius:99px;border:1px solid var(--bad);color:var(--bad)}}
.sub{{color:var(--muted);font-size:15px;margin:6px 0 16px}}
.ev{{border-top:1px solid var(--rule);padding:12px 0}}
.lbl{{font-family:var(--mono);font-size:12.5px}}
.ev.danger .lbl{{color:var(--bad)}}
.was,.now{{font-family:var(--mono);font-size:12px;padding:8px 10px;margin-top:6px;
background:var(--was);white-space:pre-wrap;word-break:break-word}}
.was{{color:var(--muted);text-decoration:line-through}}
.now{{color:var(--bad)}}
form{{margin-top:18px;display:flex;gap:10px;flex-wrap:wrap}}
.btn{{font-family:var(--sans);font-size:14px;font-weight:600;padding:9px 16px;
border:1px solid var(--rule);background:var(--bg);color:var(--ink);cursor:pointer;border-radius:3px}}
.btn.danger-btn{{border-color:var(--bad);color:var(--bad)}}
.note{{background:var(--card);border:1px solid var(--accent);padding:12px 16px;margin-bottom:18px;
font-size:15px}}
.done{{background:var(--card);border:1px solid var(--rule);padding:28px 26px}}
.done p{{color:var(--muted);margin:0}}
.foot{{color:var(--muted);font-size:13px;margin-top:26px;font-family:var(--mono)}}
</style></head><body><div class="wrap">{msg}{body}
<div class="foot">local only · nothing leaves this machine · close the tab when you are done</div>
</div></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "mcpgawk"

    def log_message(self, *_args):          # noqa: D102 - silence per-request stdout noise
        return

    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8") -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        # This page renders a hostile server's own prose. It must never be able to pull anything in.
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(raw)

    #: The refusal, in one line. Kept separate from `render_page` because a rejection is not a view
    #: of your fleet: returning the full page meant a curl user got 60 lines of CSS for a one-line
    #: answer, and — found in real use — the empty-state text rendered directly beneath "Refused",
    #: so the two read as contradicting each other.
    _REFUSAL = ("Refused: that request did not carry this session's token, so it did not come from "
                "the page. Approval needs the link printed in your terminal — this is what stops an "
                "agent approving its own unblocking.")

    def _wants_html(self) -> bool:
        """Answer in the caller's language. A browser form POST gets a page; curl gets a sentence.
        Absent/`*/*` Accept (curl's default) is treated as NOT a browser, deliberately."""
        return "text/html" in (self.headers.get("Accept") or "")

    def _refuse(self) -> None:
        if not self._wants_html():
            self._send(403, self._REFUSAL + "\n", "text/plain; charset=utf-8")
            return
        self._send(403, f"""<!doctype html><meta charset="utf-8"><title>mcpgawk — refused</title>
<style>body{{font-family:system-ui,-apple-system,sans-serif;background:#F6F6F4;color:#15181C;
margin:0;padding:64px 24px;line-height:1.55}}
@media(prefers-color-scheme:dark){{body{{background:#101216;color:#E8EAED}}}}
.b{{max-width:560px;margin:0 auto;border-left:3px solid #A83B31;padding:18px 22px}}
h1{{font-size:19px;margin:0 0 8px}} p{{margin:0;color:#5C6068}}
@media(prefers-color-scheme:dark){{p{{color:#A0A5AE}}}}</style>
<div class="b"><h1>Refused</h1><p>{html.escape(self._REFUSAL)}</p></div>""")

    def do_GET(self) -> None:               # noqa: N802 - BaseHTTPRequestHandler's API
        """READ-ONLY, always. A page load must never be able to change trust."""
        store = history.load(history.default_path())
        self._send(200, render_page(pending_decisions(store), self.server.token,
                                    getattr(self.server, "note", "")))

    def do_POST(self) -> None:              # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form: dict[str, str] = {}
        for pair in raw.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                form[unquote_plus(k)] = unquote_plus(v)

        # THE GATE. Without this, an agent with a shell approves its own unblocking by POSTing to
        # localhost — undoing baseline.approval_blocked_reason entirely.
        if not secrets.compare_digest(form.get("token", ""), self.server.token):
            self._refuse()
            return

        key, action = form.get("key", ""), form.get("action", "")
        note = ""
        if action == "approve" and key:
            rec = history.approve(key, path=history.default_path())
            note = (f"Approved. {key} is trusted again and your agents can call it."
                    if rec else f"Nothing recorded for {key} yet — scan it first.")
        elif action == "keep":
            note = "Left blocked. Your agents still cannot call it."
        self.server.note = note
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def serve(port: int = DEFAULT_PORT, open_browser: bool = True, log=print) -> int:
    """Start the decide screen. Returns an exit code.

    Refuses in an agent session for the same reason `approve` does: this screen exists to put a
    HUMAN in front of the decision, and an agent that can start it can drive it."""
    blocked = baseline.approval_blocked_reason()
    if blocked and os.environ.get(baseline.APPROVE_OVERRIDE_ENV) != "1":
        log(f"mcpgawk decide: refusing — {blocked}")
        return 4

    token = secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer((HOST, port), _Handler)
    httpd.token = token                     # type: ignore[attr-defined]
    httpd.note = ""                         # type: ignore[attr-defined]
    url = f"http://{HOST}:{port}/?t={token[:6]}"

    store = history.load(history.default_path())
    waiting = len(pending_decisions(store))
    log(f"\n  {waiting} server(s) waiting on a decision." if waiting
        else "\n  Nothing is waiting on you — opening anyway so you can see the state.")
    # The token is printed HERE and nowhere else: a human reading their own terminal sees it, and
    # an agent reading a hook denial or the spool never does.
    log(f"  {url}\n  Ctrl-C when you are done.\n")

    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("  closed.")
    finally:
        httpd.server_close()
    return 0
