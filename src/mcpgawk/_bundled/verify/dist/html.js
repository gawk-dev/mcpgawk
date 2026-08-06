import { groupEgressByHost, } from "./report.js";
function esc(s) {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
const STATUS_LABEL = {
    clean: "Clean",
    "at-risk": "At risk",
    vulnerable: "Vulnerable",
    incomplete: "Incomplete",
};
function evidence(f) {
    const e = f.evidence;
    if (Array.isArray(e.egress))
        return `sent data to ${esc(e.egress.join(", "))}`;
    if (typeof e.canary === "string")
        return "fetched an attacker-controlled URL from input";
    if (typeof e.snippet === "string")
        return `output: “${esc(e.snippet)}”`;
    return esc(JSON.stringify(e));
}
function findingRow(f) {
    return `<tr>
    <td><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
    <td class="cls">${esc(f.class)}</td>
    <td class="mono">${esc(f.tool)}</td>
    <td>${evidence(f)}</td>
    <td class="mono nums">${f.reproOk}/${f.reproTotal}</td>
    <td class="mono id">${esc(f.findingId)}</td>
  </tr>`;
}
function serverCard(s) {
    const remote = s.transport !== "stdio";
    // Undeclared-egress findings are clustered by host (anomaly-first) so a server's own upstream —
    // one finding per tool — doesn't bury the single-tool outlier. Non-egress findings stay in the
    // table. Machine formats keep every finding; this is the human report only.
    const activeEgress = s.findings.filter((f) => f.class === "undeclared-egress" && !f.suppressed);
    const rest = s.findings.filter((f) => !(f.class === "undeclared-egress" && !f.suppressed));
    const egressBlock = egressCard(activeEgress);
    const findings = rest.length
        ? `<table class="findings">
        <thead><tr><th>severity</th><th>class</th><th>tool</th><th>evidence</th><th>N/N</th><th>id</th></tr></thead>
        <tbody>${rest.map(findingRow).join("")}</tbody>
      </table>`
        : s.findings.length > 0
            ? "" // egress-only findings — rendered in the cluster above, no empty table or false clean-note
            : // The green "nothing reproduced" note belongs ONLY to a server that completed — it used to
                // be printed (in --clean colour) beside a 4-failed-check run, with the warning demoted to a
                // grey note. Derived from the same `complete` field as the pill, the exit code and SARIF.
                s.complete
                    ? `<p class="clean-note">nothing reproduced across ${s.toolsChecked} tool(s).</p>`
                    : `<p class="note" style="color:var(--warn)"><strong>INCOMPLETE</strong> — ${s.checksCompleted}/${s.checksPlanned} check(s) completed. Nothing was reproduced in the checks that DID complete, which is not a clean result: ${esc(s.incompleteReasons.join("; "))}</p>`;
    const skipped = s.skipped.length
        ? `<p class="note">Not invoked (safe mode): ${s.skipped.map((k) => `${esc(k.tool)} (${esc(k.class)})`).join(", ")}</p>`
        : "";
    const checkErrors = s.checkErrors.length
        ? `<p class="note" style="color:var(--warn)">${s.checkErrors.length} check(s) never completed (infra failure, NOT clean): ${s.checkErrors.map((c) => `${esc(c.tool)}::${esc(c.code)}`).join(", ")}</p>`
        : "";
    const remoteNote = remote
        ? `<p class="note">Remote server — can’t be sandboxed; egress checks not applicable. Ran: ${s.checksRun.map(esc).join(", ")}.</p>`
        : "";
    const dispatchNote = dispatchCard(s);
    const sandboxNote = s.sandboxBackend === "proxy"
        ? `<p class="note" style="color:var(--warn)">ran under the proxy-only sandbox (degraded): ${esc(s.sandboxDegradedReason ?? "Docker unavailable")}</p>`
        : s.sandboxBackend === "docker"
            ? `<p class="note">ran under the OS-level Docker sandbox (--network none) — full isolation.</p>`
            : "";
    return `<section class="server">
    <div class="server-head">
      <h2>${esc(s.server)} <span class="transport">${esc(s.transport)}</span></h2>
      <span class="pill pill-${s.status}">${STATUS_LABEL[s.status]}</span>
    </div>
    ${remoteNote}${sandboxNote}${dispatchNote}${skipped}${checkErrors}${egressBlock}${findings}
  </section>`;
}
/** F4: the hidden catalog, each tool marked probed vs NOT probed — so the HTML report (not just the
 * CLI) shows exactly what was reached through the executor and what still keeps a server incomplete. */
/** Undeclared-egress, clustered by host (anomaly-first) — the HTML twin of the CLI cluster. A host
 * reached by many tools reads as "probably the server's own upstream, declare it"; one reached by a
 * single (hidden) tool is the outlier to verify. */
function egressCard(egressFindings) {
    const groups = groupEgressByHost(egressFindings);
    if (groups.length === 0)
        return "";
    const toolTotal = new Set(egressFindings.map((f) => f.tool)).size;
    const rows = groups
        .map((g) => `<li><span class="mono">${esc(g.host)}</span> ← <b>${g.tools.length}</b> tool(s): <span class="mono">${g.tools.slice(0, 12).map(esc).join(", ")}${g.tools.length > 12 ? `, +${g.tools.length - 12} more` : ""}</span></li>`)
        .join("");
    return `<div class="note" style="color:var(--warn)">
    <p><span class="mono" style="color:var(--bad);font-size:10px;letter-spacing:.08em">EGRESS</span> — ${toolTotal} tool(s) contacted ${groups.length} undeclared host(s). Declare expected upstreams in <span class="mono">allowedHosts</span>; a host reached by MANY tools is usually the server's own backend, one reached by a SINGLE tool is the outlier to verify.</p>
    <ul class="hidden-catalog">${rows}</ul>
  </div>`;
}
function dispatchCard(s) {
    const dispatch = s.dynamicDispatch ?? [];
    if (dispatch.length === 0)
        return "";
    const catalog = s.hiddenCatalog ?? [];
    if (catalog.length === 0) {
        return `<p class="note" style="color:var(--warn)">dynamic dispatch via ${dispatch.map(esc).join(", ")} — hidden catalog could NOT be enumerated (no readable discover tool). A clean result is not proof of a clean server.</p>`;
    }
    const probed = new Set(s.hiddenProbed ?? []);
    const items = catalog
        .map((h) => {
        const ok = probed.has(h.name);
        const mark = ok ? "probed" : "not probed";
        const colour = ok ? "var(--clean)" : "var(--warn)";
        return `<li><span class="mono">${esc(h.name)}</span> <span style="color:${colour}">${mark}</span></li>`;
    })
        .join("");
    const unprobed = catalog.filter((h) => !probed.has(h.name)).length;
    const fully = unprobed === 0 && !s.hiddenCatalogPartial;
    const head = fully
        ? `dynamic dispatch via ${dispatch.map(esc).join(", ")} — all ${catalog.length} hidden tool(s) enumerated AND probed through the executor.`
        : s.hiddenCatalogPartial
            ? `dynamic dispatch via ${dispatch.map(esc).join(", ")} — query-driven discover: only a PARTIAL catalog could be surfaced (${catalog.length - unprobed}/${catalog.length} of ${catalog.length} found were probed). There may be hidden tools no query returned — never a clean pass.`
            : `dynamic dispatch via ${dispatch.map(esc).join(", ")} — ${catalog.length - unprobed}/${catalog.length} hidden tool(s) probed; ${unprobed} not probed (no schema, or a safe-mode-skipped mutator) keep this incomplete.`;
    return `<div class="note"><p style="${fully ? "" : "color:var(--warn)"}">${head}</p><ul class="hidden-catalog">${items}</ul></div>`;
}
/** The report's visual language — shared by the static HTML report and the `serve` web UI. */
export const REPORT_CSS = `
  /* Observatory-dark — the sanctioned .gawk product skin (Nativerse Design System, tokens/colors.css).
     Interactive accent (teal) is kept distinct from status colour; structure is hairline-first. */
  :root{--bg:#06080a;--panel:#0b0f12;--panel-2:#0d1115;--head:#0a0d10;
    --line:#1a2026;--line-strong:#2b343b;--ink:#d8e2e6;--muted:#7a8a90;--dim:#4a565c;
    --accent:#2dd4bf;--accent-dim:#0d9488;--accent-glow:rgba(45,212,191,.35);
    --clean:#22c55e;--warn:#f59e0b;--regress:#eab308;--bad:#ef4444;--unknown:#71717a;
    --eco-anthropic:#2dd4bf;--eco-openai:#4ade80;--eco-google:#60a5fa;--eco-meta:#a78bfa;--eco-ms:#f59e0b;
    --mono:"Tabular",ui-monospace,"SF Mono","Roboto Mono",Menlo,Consolas,monospace;
    --sans:"Supreme",-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    --serif:"Sentient","Iowan Old Style",Palatino,Georgia,"Times New Roman",serif;
    --ease:cubic-bezier(.2,0,0,1);--ease-out:cubic-bezier(.16,1,.3,1);--dur:200ms;--dur-fast:120ms;}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
    line-height:1.6;-webkit-font-smoothing:antialiased}
  .wrap{max-width:900px;margin:0 auto;padding:40px 22px 72px}
  .brand{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
  .brand b{color:var(--accent);font-weight:500}
  /* Product is sans-dominant (brief C3): Sentient serif stays a marketing voice, not a product hero. */
  h1{font-family:var(--sans);font-weight:600;font-size:27px;letter-spacing:-.014em;margin:16px 0 4px;color:#eef4f5}
  .ts{color:var(--dim);font-size:12px;font-family:var(--mono);letter-spacing:.02em}
  /* verdict banner — a panel with a hairline status pill, no glow */
  .banner{margin:22px 0 8px;padding:15px 17px;border-radius:6px;border:1px solid var(--line-strong);
    background:var(--panel);display:flex;align-items:baseline;gap:13px}
  .banner .big{font-family:var(--mono);font-size:11px;font-weight:500;letter-spacing:.12em;text-transform:uppercase;
    border:1px solid currentColor;border-radius:2px;padding:3px 9px}
  .banner span:last-child{color:var(--muted);font-size:13.5px}
  .banner-clean .big{color:var(--clean)}.banner-clean{border-color:rgba(34,197,94,.34)}
  .banner-at-risk .big{color:var(--warn)}.banner-at-risk{border-color:rgba(245,158,11,.34)}
  .banner-vulnerable .big{color:var(--bad)}.banner-vulnerable{border-color:rgba(239,68,68,.38)}
  .banner-incomplete .big{color:var(--regress)}.banner-incomplete{border-color:rgba(234,179,8,.34)}
  .chips{margin:14px 0 8px;display:flex;flex-wrap:wrap;gap:7px}
  .chip{font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);
    border:1px solid var(--line-strong);border-radius:2px;padding:3px 9px}
  .chip-find{color:var(--ink)}.chip-crit{color:var(--bad);border-color:rgba(239,68,68,.45)}.chip-high{color:var(--warn);border-color:rgba(245,158,11,.45)}
  .server{margin:22px 0 0;border:1px solid var(--line);border-radius:6px;background:var(--panel);overflow:hidden}
  .server-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;background:var(--head);border-bottom:1px solid var(--line)}
  .server-head h2{margin:0;font-family:var(--mono);font-size:13px;font-weight:500;letter-spacing:.04em;color:var(--ink)}
  .transport{font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);border:1px solid var(--line-strong);border-radius:2px;padding:2px 6px;margin-left:8px;vertical-align:middle}
  /* status pill — the canonical Observatory pill: hairline currentColor border, 2px radius, faint tint */
  .pill{font-family:var(--mono);font-size:9.5px;font-weight:500;letter-spacing:.1em;text-transform:uppercase;
    border:1px solid currentColor;border-radius:2px;padding:3px 8px;white-space:nowrap}
  .pill-clean{color:var(--clean);background:rgba(34,197,94,.08)}
  .pill-at-risk{color:var(--warn);background:rgba(245,158,11,.08)}
  .pill-vulnerable{color:var(--bad);background:rgba(239,68,68,.09)}
  .pill-incomplete{color:var(--regress);background:rgba(234,179,8,.08)}
  .note{margin:10px 16px 0;color:var(--muted);font-size:12.5px;line-height:1.6}
  .hidden-catalog{margin:6px 0 0;padding-left:18px;font-size:12.5px;color:var(--muted)}
  .hidden-catalog li{margin:2px 0}
  .clean-note{margin:13px 16px 15px;color:var(--clean);font-size:13.5px}
  table.findings{width:100%;border-collapse:collapse;font-size:12.5px}
  .findings th{text-align:left;color:var(--muted);font-weight:500;font-size:10px;letter-spacing:.08em;text-transform:uppercase;font-family:var(--mono);padding:11px 14px;border-bottom:1px solid var(--line-strong)}
  .findings td{padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}
  .findings tr:last-child td{border-bottom:none}
  .mono{font-family:var(--mono)}.nums{white-space:nowrap;font-variant-numeric:tabular-nums}.id{color:var(--dim);font-size:10.5px;font-family:var(--mono)}
  .cls{color:var(--ink)}
  /* severity marks — hairline, like the pill; colour is the whole signal */
  .sev{font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;border:1px solid currentColor;border-radius:2px;padding:2px 6px;text-transform:uppercase}
  .sev-critical{color:var(--bad)}
  .sev-high{color:var(--warn)}
  .sev-medium{color:var(--regress)}
  .sev-low{color:var(--muted)}
  .foot{margin:32px 0 0;color:var(--dim);font-size:11.5px;border-top:1px solid var(--line);padding-top:16px;line-height:1.7}
  .foot code{font-family:var(--mono);color:var(--muted)}
  .tblwrap{overflow-x:auto}`;
/** The report body (banner + chips + server cards + coverage) — no <head>, no page chrome. */
export function renderReportBody(report) {
    const { summary } = report;
    const sev = summary.bySeverity;
    const chips = [
        `<span class="chip">${summary.servers} server(s)</span>`,
        `<span class="chip">${summary.toolsChecked} tool(s) checked</span>`,
        `<span class="chip chip-find">${summary.findings} finding(s)</span>`,
        sev.critical ? `<span class="chip chip-crit">${sev.critical} critical</span>` : "",
        sev.high ? `<span class="chip chip-high">${sev.high} high</span>` : "",
    ]
        .filter(Boolean)
        .join("");
    const errorCards = report.errors
        .map((e) => `<section class="server"><div class="server-head"><h2>${esc(e.server)} <span class="transport">error</span></h2>
        <span class="pill pill-at-risk">Could not verify</span></div>
        <p class="note" style="margin-bottom:14px">${esc(e.message)}</p></section>`)
        .join("");
    return `<div class="ts">schema ${esc(report.schemaVersion)} · ${esc(report.generatedAt)}</div>
  <div class="banner banner-${summary.status}">
    <span class="big">${summary.servers === 0 && summary.errors > 0 ? "Could not verify" : STATUS_LABEL[summary.status]}</span>
    <span>${summary.servers === 0 && summary.errors > 0
        ? `${summary.errors} server(s) could not be verified — nothing was probed. See the error(s) below.`
        : `${summary.findings} reproduced finding(s) across ${summary.servers} server(s)${summary.errors > 0 ? ` · ${summary.errors} could not be verified` : ""}. ${summary.complete
            ? `${summary.checksCompleted}/${summary.checksPlanned} check(s) completed.`
            : `NOT a clean pass — only ${summary.checksCompleted}/${summary.checksPlanned} check(s) completed: ${esc(summary.incompleteReasons.join("; "))}`}`}</span>
  </div>
  <div class="chips">${chips}</div>
  <div class="tblwrap">${report.servers.map(serverCard).join("")}${errorCards}</div>
  <p class="note" style="margin:22px 0 0;border-left:2px solid var(--warn);padding-left:12px;color:var(--warn)">
    <strong>Coverage:</strong> ${esc(report.coverage)}</p>`;
}
/** Render a self-contained HTML report page. All tool-provided text is escaped. */
export function renderHtml(report) {
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>gawk-verify report — ${esc(report.servers.map((s) => s.server).join(", ") || "MCP servers")}</title>
<style>${REPORT_CSS}</style></head>
<body><div class="wrap">
  <div class="brand"><b>gawk-verify</b> · behavioural MCP verification report</div>
  <h1>Verification report</h1>
  ${renderReportBody(report)}
  <p class="foot">Behavioural verification: each tool was run and reproduced N/N in a sandbox (local stdio) or over
  HTTP/SSE (remote). Local servers get egress + output checks; remote servers get output checks only. Generated by
  <code>gawk-verify</code> (schema ${esc(report.schemaVersion)}).</p>
</div></body></html>`;
}
//# sourceMappingURL=html.js.map