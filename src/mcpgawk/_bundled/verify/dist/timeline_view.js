import { REPORT_CSS } from "./html.js";
import { formatDuration, durationSeconds, groupByDay, shortenTarget, summaryChips, timelineTotals, } from "./timeline.js";
/**
 * The local timeline view — "what has run on this machine, and how did it go".
 *
 * Server-rendered on purpose: the data already exists as a completed JSON document by the time the
 * page is built, so a client-side fetch would add a loading state, a failure mode and a second
 * copy of the status vocabulary for no gain. It also keeps this a pure `Timeline -> string`
 * function, which is what makes it testable without a browser.
 *
 * Design: reuses the existing Observatory-dark tokens from REPORT_CSS rather than introducing a
 * second palette. Status is carried by a coloured dot and a mono label — no emoji, matching the
 * convention already established in serve's console view.
 *
 * The honesty rule the layout has to respect: `running` and `incomplete` must never READ as
 * success. They get their own colour and an explicit line under the header, because a timeline
 * whose open runs look finished is worse than no timeline — it invites the reader to conclude
 * that everything completed.
 */
function esc(s) {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
/** Status → (css class, human label). Deliberately explicit rather than derived from the string:
 * `findings` reads as "found something", not as a failure, and `incomplete` must not read as ok. */
const STATUS = {
    ok: { cls: "st-ok", label: "ok" },
    findings: { cls: "st-find", label: "findings" },
    error: { cls: "st-err", label: "error" },
    running: { cls: "st-open", label: "running" },
    incomplete: { cls: "st-open", label: "incomplete" },
};
const KIND_LABEL = {
    scan: "scan", verify: "verify", enforce: "enforce", monitor: "monitor", guard: "guard",
};
function timeOfDay(iso) {
    // Render in the viewer's local zone: the registry stores UTC, but "when did I run this" is a
    // question about the user's day, not about UTC.
    const d = new Date(iso);
    if (Number.isNaN(d.getTime()))
        return "--:--";
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
function dayHeading(day) {
    const d = new Date(`${day}T00:00:00`);
    if (Number.isNaN(d.getTime()))
        return day;
    const today = new Date();
    const isSame = (a, b) => a.toDateString() === b.toDateString();
    const yesterday = new Date(today.getTime() - 86_400_000);
    if (isSame(d, today))
        return "Today";
    if (isSame(d, yesterday))
        return "Yesterday";
    return d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" });
}
function renderRow(run) {
    const status = STATUS[run.status] ?? { cls: "st-open", label: esc(run.status) };
    const chips = summaryChips(run)
        .map((c) => `<span class="tchip"><b>${esc(c.value)}</b> ${esc(c.label)}</span>`)
        .join("");
    // Shortened keeping the TAIL — the full value stays in `title` so nothing is lost. A null target
    // is meaningful ("the whole fleet"), not missing data, so it is never rendered as blank.
    const target = run.target
        ? esc(shortenTarget(run.target))
        : `<span class="dimmed">whole fleet</span>`;
    const duration = run.ended_at ? formatDuration(durationSeconds(run)) : "in progress";
    return `<tr>
    <td class="t-time">${esc(timeOfDay(run.started_at))}</td>
    <td class="t-kind">${esc(KIND_LABEL[run.kind] ?? run.kind)}</td>
    <td class="t-status"><span class="dot ${status.cls}"></span>${status.label}</td>
    <td class="t-target" title="${run.target ? esc(run.target) : "no single target"}">${target}</td>
    <td class="t-chips">${chips}</td>
    <td class="t-dur">${esc(duration)}</td>
  </tr>`;
}
function renderDay(group) {
    return `<section class="tday">
    <h2>${esc(dayHeading(group.day))}<span class="tday-date">${esc(group.day)}</span></h2>
    <table class="ttable">
      <thead><tr>
        <th>Time</th><th>Pillar</th><th>Result</th><th>Target</th><th></th><th>Took</th>
      </tr></thead>
      <tbody>${group.runs.map(renderRow).join("")}</tbody>
    </table>
  </section>`;
}
/** The empty state and the unreadable state are DIFFERENT and must never look alike. */
function renderUnavailable(reason) {
    return `<div class="banner banner-err">
    <span>The run registry could not be read.</span>
    <span>${esc(reason)}</span>
    <span>This is not the same as "nothing has run" — the history may exist and be unreadable.</span>
  </div>`;
}
function renderEmpty() {
    return `<div class="banner">
    <span>No runs recorded yet.</span>
    <span>Run <code>mcpgawk scan</code>, or start a guarded session, and it will appear here.</span>
  </div>`;
}
export const TIMELINE_CSS = `
  .thead{display:flex;align-items:baseline;justify-content:space-between;gap:16px;flex-wrap:wrap;
    margin:22px 0 0;padding-top:18px;border-top:1px solid var(--line)}
  .tsub{margin:14px 0 0;color:var(--muted);font-size:12.5px;line-height:1.6;max-width:640px}
  .tback{color:var(--accent);text-decoration:none;font-family:var(--mono);font-size:10.5px;
    letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
  .tback:hover{text-decoration:underline}
  .ttotals{display:flex;gap:18px;font-family:var(--mono);font-size:11px;letter-spacing:.06em;
    text-transform:uppercase;color:var(--muted)}
  .ttotals b{color:var(--ink);font-weight:500}
  .topen{margin:14px 0 0;font-size:12.5px;color:var(--regress)}
  .tday{margin:26px 0 0}
  .tday h2{display:flex;align-items:baseline;gap:10px;margin:0 0 8px;font-family:var(--mono);
    font-size:11px;font-weight:500;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
  .tday-date{color:var(--dim);letter-spacing:.04em}
  .ttable{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:6px;
    background:var(--panel);overflow:hidden}
  .ttable th{text-align:left;font-family:var(--mono);font-size:9.5px;font-weight:500;
    letter-spacing:.09em;text-transform:uppercase;color:var(--muted);padding:9px 13px;
    border-bottom:1px solid var(--line-strong);background:var(--head)}
  .ttable td{padding:10px 13px;border-bottom:1px solid var(--line);font-size:12.5px;
    vertical-align:middle}
  .ttable tr:last-child td{border-bottom:0}
  .t-time,.t-dur{font-family:var(--mono);font-size:11.5px;color:var(--muted);white-space:nowrap}
  .t-kind{font-family:var(--mono);font-size:11px;letter-spacing:.06em;text-transform:uppercase;
    color:var(--ink);white-space:nowrap}
  .t-status{font-family:var(--mono);font-size:11px;white-space:nowrap;color:var(--muted)}
  /* Truncation is done in the DATA (shortenTarget), keeping the tail — CSS text-overflow can only
     cut the end, which hid the one part that distinguishes two stdio servers. */
  /* ellipsis kept as a SAFETY NET: the data-side shortening does the meaningful work, but a
     narrow window must degrade to "…" rather than clipping a character in half. */
  .t-target{color:var(--ink);font-family:var(--mono);font-size:11.5px;max-width:380px;
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .dimmed{color:var(--dim)}
  .dot{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:8px;
    vertical-align:middle}
  .st-ok{background:var(--clean)} .st-find{background:var(--warn)}
  .st-err{background:var(--bad)} .st-open{background:var(--regress)}
  .tchip{font-family:var(--mono);font-size:10px;letter-spacing:.04em;color:var(--muted);
    border:1px solid var(--line-strong);border-radius:2px;padding:2px 7px;margin-right:6px;
    white-space:nowrap}
  .tchip b{color:var(--ink);font-weight:500}
  .banner-err{border-color:rgba(239,68,68,.45)}
  .banner-err span:first-child{color:var(--bad)}
  @media (max-width:720px){.t-chips,.t-dur{display:none}}
`;
export function renderTimelineBody(timeline) {
    if (!timeline.available)
        return renderUnavailable(timeline.reason ?? "unknown reason");
    if (timeline.runs.length === 0)
        return renderEmpty();
    const totals = timelineTotals(timeline.runs);
    const openNote = totals.open
        ? `<p class="topen">${totals.open} run${totals.open === 1 ? "" : "s"} still open —
       a run only counts once it closes, so these are not results.</p>`
        : "";
    return `<div class="thead">
      <div class="ttotals">
        <span><b>${totals.total}</b> runs</span>
        <span><b>${totals.findings}</b> with findings</span>
        <span><b>${totals.errors}</b> errored</span>
      </div>
    </div>
    ${openNote}
    ${groupByDay(timeline.runs).map(renderDay).join("")}`;
}
export function renderTimelinePage(timeline) {
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>mcpgawk — run timeline</title>
<style>${REPORT_CSS}${TIMELINE_CSS}</style>
</head><body><div class="wrap">
  <header class="brand"><b>mcpgawk</b> · run timeline
    <a class="tback" style="float:right" href="/">← Back to verify</a></header>
  <p class="tsub">
    Everything this machine has run — scans, verifies, guarded sessions and monitor passes.
    Read from <code>~/.mcpgawk/runs.db</code>; nothing is uploaded anywhere.
  </p>
  ${renderTimelineBody(timeline)}
</div></body></html>`;
}
//# sourceMappingURL=timeline_view.js.map