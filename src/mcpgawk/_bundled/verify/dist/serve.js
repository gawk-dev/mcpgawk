import { createServer } from "node:http";
import { dockerAvailable } from "@gawk/sandbox";
import { CHECKS } from "./checks.js";
import { serversOf, toConfig } from "./config.js";
import { FLEET_STATES, discoverFleet, stateStatus } from "./fleet.js";
import { REPORT_CSS, renderReportBody } from "./html.js";
import { buildReport } from "./report.js";
import { loadTimeline } from "./timeline.js";
import { renderTimelinePage } from "./timeline_view.js";
import { verifyServer } from "./verify.js";
/** The check catalogue the UI shows under "What we check" — sourced from the real checks. */
const CHECK_CATALOG = CHECKS.map((c) => ({
    code: c.code,
    label: c.label.trim(),
    severity: c.severity,
    applicability: c.applicability,
    detects: c.detects,
}));
/**
 * Verify every server in a parsed config document. A server that can't be reached is recorded as an
 * error, never thrown — the caller always gets one {@link VerificationReport}.
 */
export async function verifyDoc(doc, unsafe, now = new Date().toISOString(), isolate = false) {
    const reports = [];
    const errors = [];
    const audit = [];
    for (const [name, raw] of Object.entries(serversOf(doc))) {
        try {
            reports.push(await verifyServer(toConfig(name, raw), {
                mode: unsafe ? "unsafe" : "safe",
                isolate,
                onEvent: (e) => audit.push(e),
            }));
        }
        catch (e) {
            errors.push({ server: name, message: e.message });
        }
    }
    return { report: buildReport(reports, now, {}, errors), audit };
}
const EXAMPLE_CONFIG = JSON.stringify({
    mcpServers: {
        myserver: {
            command: "node",
            args: ["path/to/server.js"],
            allowedHosts: ["api.myservice.com"],
        },
    },
}, null, 2);
function page(unsafeAllowed) {
    const unsafeControl = unsafeAllowed
        ? `<label class="toggle"><input type="checkbox" id="unsafe"/> <span>Unsafe mode — invoke <em>every</em> tool, including mutating ones (only against a server you control or a test account)</span></label>`
        : `<p class="note" style="margin:12px 0 0">Safe mode: only tools classified read-only are invoked. Start with <code>serve --unsafe</code> to enable full-coverage runs.</p>`;
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>mcpgawk verify — behavioural MCP verification</title>
<style>${REPORT_CSS}
  form{margin:18px 0 0}
  textarea{width:100%;min-height:170px;background:var(--panel-2);color:var(--ink);border:1px solid var(--line-strong);
    border-radius:6px;padding:14px;font-family:var(--mono);font-size:12.5px;line-height:1.55;resize:vertical}
  textarea:focus{outline:none;border-color:var(--accent-dim);box-shadow:0 0 0 3px var(--accent-glow)}
  .row{display:flex;align-items:center;gap:14px;margin:14px 0 0;flex-wrap:wrap}
  /* primary action — teal, the interactive accent (kept distinct from status colour) */
  button{font-family:var(--sans);font-weight:600;font-size:13.5px;color:#04120f;background:var(--accent);border:0;
    border-radius:4px;padding:9px 18px;cursor:pointer;transition:background var(--dur) var(--ease)}
  button:hover{background:#4fe0d1}
  button:disabled{opacity:.5;cursor:progress}
  .toggle{display:flex;align-items:flex-start;gap:9px;color:var(--muted);font-size:12.5px;max-width:640px;line-height:1.55}
  .toggle input{margin-top:3px;accent-color:var(--accent)}
  .err{margin:16px 0 0;padding:12px 14px;border-radius:6px;border:1px solid rgba(239,68,68,.4);
    background:rgba(239,68,68,.08);color:var(--bad);font-size:12.5px;font-family:var(--mono)}
  .spin{color:var(--muted);font-size:12.5px}
  .brand-link{float:right;color:var(--accent);text-decoration:none;font-family:var(--mono);
    font-size:10.5px;letter-spacing:.08em;text-transform:uppercase}
  .brand-link:hover{text-decoration:underline}
  .panel{margin:18px 0 0;border:1px solid var(--line);border-radius:6px;background:var(--panel);padding:15px 18px}
  .panel h3{margin:0 0 10px;font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}
  .steps{margin:0;padding-left:18px;font-size:13px;color:var(--muted)}
  .steps li{margin:4px 0}
  .steps b{color:var(--ink);font-weight:600}
  .checks{display:grid;gap:11px}
  .check{display:flex;gap:11px;align-items:flex-start;font-size:12.5px}
  .badge{font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;border:1px solid currentColor;
    border-radius:2px;padding:2px 7px;white-space:nowrap;color:var(--warn)}
  .check .d{color:var(--ink)}
  .check .ap{font-family:var(--mono);font-size:9.5px;color:var(--muted);border:1px solid var(--line-strong);border-radius:2px;padding:1px 6px;white-space:nowrap}
  .console{margin:18px 0 0;background:#05070a;border:1px solid var(--line);border-radius:6px;padding:14px 16px;
    font-family:var(--mono);font-size:12px;line-height:1.85;max-height:440px;overflow:auto}
  .console:empty{display:none}
  .ln{white-space:pre-wrap;opacity:0;animation:fade var(--dur-fast) var(--ease-out) forwards}
  @keyframes fade{to{opacity:1}}
  @media (prefers-reduced-motion:reduce){.ln{animation:none;opacity:1}}
  /* status-dot markers — no emoji; the dot's colour is the outcome */
  .ln-server::before,.ln-ok::before,.ln-hit::before,.ln-skip::before{content:"";display:inline-block;
    width:6px;height:6px;border-radius:50%;margin-right:10px;vertical-align:baseline}
  .ln-ok::before{background:var(--clean)}.ln-hit::before{background:var(--bad)}.ln-skip::before{background:var(--unknown)}
  .ln-server::before{background:var(--accent);box-shadow:0 0 6px var(--accent-glow)}
  .ln-server{color:var(--ink);font-weight:600;margin-top:10px}
  .ln-tool{color:var(--muted);padding-left:16px}
  .ln-ok{color:var(--clean);padding-left:16px}
  .ln-hit{color:var(--bad);font-weight:600;padding-left:16px}
  .ln-skip{color:var(--muted);padding-left:16px}
  .ln-approach{color:var(--muted);margin-bottom:9px;padding-bottom:9px;border-bottom:1px solid var(--line)}
  #result{margin-top:8px}
  /* ---- Fleet hub (Observatory dark) ---- */
  .fleet-head{display:flex;align-items:baseline;gap:12px;margin:22px 0 4px;flex-wrap:wrap}
  .fleet-head h2{margin:0;font-family:var(--sans);font-weight:600;font-size:19px;letter-spacing:-.012em;color:#eef4f5}
  .fleet-head .sub{color:var(--muted);font-size:13px}
  .fleet-head .refresh{margin-left:auto;display:inline-flex;align-items:center;gap:7px;font-family:var(--mono);
    font-size:11px;letter-spacing:.04em;color:var(--muted);background:transparent;border:1px solid var(--line-strong);
    border-radius:4px;padding:6px 12px;cursor:pointer;transition:border-color var(--dur) var(--ease),color var(--dur) var(--ease)}
  .fleet-head .refresh:hover{border-color:var(--accent-dim);color:var(--ink)}
  .refresh svg,.vbtn svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:1.6;flex:none}
  .fleet-summary{display:flex;gap:8px;flex-wrap:wrap;margin:13px 0 4px}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 14px;min-width:94px}
  .stat .k{font-family:var(--mono);font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
  .stat .v{font-family:var(--mono);font-size:21px;font-weight:500;margin-top:4px;font-variant-numeric:tabular-nums;color:var(--ink)}
  .fgroup{margin:18px 0 0}
  .fgroup .gh{font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
    margin:0 2px 9px;display:flex;gap:9px;align-items:center}
  /* per-tool group gets its ecosystem tint — the system's own token, used to mean something */
  .fgroup .gh::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--eco,var(--accent));flex:none}
  .fgroup .gh b{color:var(--ink);font-weight:500;letter-spacing:.04em}
  .fgroup .gh .ct{color:var(--dim)}
  .srv{display:grid;grid-template-columns:auto 1fr auto auto;gap:13px;align-items:center;background:var(--panel);
    border:1px solid var(--line);border-left:2px solid var(--line-strong);border-radius:6px;padding:11px 14px;margin-bottom:7px}
  .srv.r-clean{border-left-color:var(--clean)} .srv.r-risk{border-left-color:var(--warn)}
  .srv.r-vuln{border-left-color:var(--bad)} .srv.r-incomplete{border-left-color:var(--regress)} .srv.r-muted{border-left-color:var(--line-strong)}
  .srv .nm{font-family:var(--mono);font-size:13px;color:var(--ink);letter-spacing:.02em}
  .srv .dt{color:var(--muted);font-size:12px}
  .srv .vbtn{display:inline-flex;align-items:center;gap:7px;font-family:var(--sans);font-weight:600;font-size:12px;
    color:var(--accent);background:transparent;border:1px solid var(--accent-dim);border-radius:4px;padding:6px 12px;
    cursor:pointer;white-space:nowrap;transition:background var(--dur) var(--ease),color var(--dur) var(--ease)}
  .srv .vbtn:hover{background:var(--accent);color:#04120f}
  .srv .vbtn:disabled{opacity:.45;cursor:progress}
  .srv .vslot{min-width:1px}
  /* status pill — same hairline language as the report pill */
  .fpill{font-family:var(--mono);font-size:9.5px;font-weight:500;letter-spacing:.1em;text-transform:uppercase;
    border:1px solid currentColor;border-radius:2px;padding:3px 8px;white-space:nowrap}
  .fp-clean{color:var(--clean);background:rgba(34,197,94,.08)} .fp-risk{color:var(--warn);background:rgba(245,158,11,.08)}
  .fp-vuln{color:var(--bad);background:rgba(239,68,68,.09)} .fp-incomplete{color:var(--regress);background:rgba(234,179,8,.08)}
  .fp-muted{color:var(--muted);background:rgba(122,138,144,.08)}
  .fleet-empty{color:var(--muted);font-size:13.5px;border:1px dashed var(--line-strong);border-radius:6px;padding:16px 18px;line-height:1.6}
  .fleet-note{color:var(--muted);font-size:13px;border:1px solid var(--line-strong);border-left:2px solid var(--warn);border-radius:6px;padding:10px 14px;margin:0 0 12px;line-height:1.55}
  .fleet-empty code{color:var(--ink);font-family:var(--mono)}
  .srv .dt code{font-family:var(--mono);font-size:11px;color:var(--ink);background:var(--panel-2);
    border:1px solid var(--line);border-radius:2px;padding:1px 5px}
  /* session verify annotation — a note beside the pill, never a replacement for the scan state:
     the pill stays exactly what the CLI reports (the fleet and terminal must not disagree) */
  .vnote{font-family:var(--mono);font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;
    border:1px solid currentColor;border-radius:2px;padding:2px 7px;margin-left:8px;vertical-align:middle}
  .vn-clean{color:var(--clean)} .vn-at-risk{color:var(--warn)} .vn-vulnerable{color:var(--bad)} .vn-incomplete{color:var(--regress)}
  /* operate strip — after a verdict, the next motion in the product: gate, enforce, watch */
  .ops{margin:20px 0 0;border:1px solid var(--line);border-radius:6px;background:var(--panel);overflow:hidden}
  .ops .oh{padding:11px 16px;background:var(--head);border-bottom:1px solid var(--line);
    font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
  .ops .orow{display:grid;grid-template-columns:130px 1fr;gap:14px;padding:13px 16px;border-bottom:1px solid var(--line);align-items:baseline}
  .ops .orow:last-child{border-bottom:none}
  .ops .ok{font-family:var(--sans);font-weight:600;font-size:12.5px;color:var(--ink)}
  .ops .oc{display:block;font-family:var(--mono);font-size:12px;color:var(--accent);
    overflow-wrap:break-word;line-height:1.7}
  .ops .oc+.oc{margin-top:2px}
  .ops .od{color:var(--muted);font-size:12px;margin-top:3px;line-height:1.55}
  @media (max-width:560px){.ops .orow{grid-template-columns:1fr}}
  .brand{display:inline-flex;align-items:center;gap:9px}
  .bdot{width:6px;height:6px;border-radius:50%;background:var(--accent);box-shadow:0 0 6px var(--accent-glow)}
  .divider{margin:34px 0 0;border:0;border-top:1px solid var(--line)}
</style></head>
<body><div class="wrap">
  <div class="brand"><span class="bdot"></span><b>gawk</b> · local control surface for MCP security
    <a class="brand-link" href="/timeline">Run timeline →</a></div>

  <div class="fleet-head">
    <h2>Your MCP servers</h2>
    <span class="sub">every server configured on this machine, across your AI tools</span>
    <button class="refresh" id="refresh" type="button"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 4v5h-5"/></svg>Refresh</button>
    <button class="refresh" id="scanLocal" type="button" title="Launches each local server so its tools can be listed. This runs their code on this machine.">Scan local servers too</button>
  </div>
  <div id="fleet"><p class="spin" style="margin:10px 2px">Discovering the servers on this machine…</p></div>

  <hr class="divider"/>
  <h1 style="margin-top:26px">Verify a server in depth</h1>
  <p class="note" style="margin:6px 0 0">mcpgawk verify doesn't read tool descriptions and
  guess — it <strong>runs</strong> each tool in a no-egress sandbox and watches what it actually does. Nothing leaves this machine.</p>
  <div class="panel">
    <h3>The approach — behavioural, reproduction-gated</h3>
    <ol class="steps">
      <li>Spawn the server in a disposable <b>no-egress sandbox</b> — every outbound connection is blocked and recorded.</li>
      <li>Enumerate its tools; in safe mode, <b>skip</b> anything that could mutate state or move money.</li>
      <li><b>Invoke</b> each tool with synthesised inputs and observe its real behaviour — egress and output.</li>
      <li>Convict only when the bad behaviour <b>reproduces N/N</b>. An infra failure never convicts.</li>
    </ol>
  </div>
  <div class="panel">
    <h3>What we check</h3>
    <div class="checks" id="catalog"></div>
  </div>
  <form id="f">
    <textarea id="cfg" spellcheck="false" aria-label="MCP server config JSON"
      placeholder="${EXAMPLE_CONFIG.replace(/"/g, "&quot;")}"></textarea>
    ${unsafeControl}
    <label class="toggle" id="isolateLabel"><input type="checkbox" id="isolate" disabled/> <span>Isolate — run local servers in the OS-level Docker sandbox (--network none) instead of the default proxy-only one. Blocks raw-socket/DNS/UDP exfil outright, but also cuts off any legitimate allowlisted host, so SSRF-canary checks lose signal. Requires Docker + a plain node/python launch command; degrades with a warning otherwise.</span><span class="dt" id="isolateNote"> · checking Docker…</span></label>
    <div class="row">
      <button type="submit" id="go">Run verification</button>
      <span class="spin" id="status"></span>
    </div>
  </form>
  <div id="err"></div>
  <div class="console" id="audit"></div>
  <div id="result"></div>
  <div class="ops" id="next" hidden>
    <div class="oh">Operate this verdict — a report is a snapshot; these keep it true</div>
    <div class="orow"><span class="ok">Gate merges</span>
      <span><span class="oc">mcpgawk verify mcp.json --json --out report.json</span>
      <div class="od">Exit code 1 whenever findings exist — wire it into CI and a risky server can't merge quietly.</div></span></div>
    <div class="orow"><span class="ok">Enforce live</span>
      <span><span class="oc">mcpgawk verify mcp.json --behaviour-profile behaviour.json</span><span class="oc">mcpgawk enforce serve --config mcp.json --behaviour-profile behaviour.json --audit-db</span>
      <div class="od">Front the server with the live policy gateway. The behaviour profile carries what verification <em>observed</em>, so toxic-flow blocking follows behaviour, not tool names; <span class="mono">--audit-db</span> keeps a hash-chained record of every decision.</div></span></div>
    <div class="orow"><span class="ok">Watch for drift</span>
      <span><span class="oc">mcpgawk monitor run --config monitor.json</span>
      <div class="od">A clean verdict only holds until the server changes. The monitor daemon re-pins its surface 24/7 and alerts on rug-pulls — a webhook away from your alert channel.</div></span></div>
  </div>
  <p class="foot">Local behavioural verification. Bound to this machine only — do not expose this port. Egress detection
  covers HTTP(S) from synthesised args; raw-socket / DNS / UDP and input-conditional behaviour are out of scope.</p>
</div>
<script>
var CATALOG=${JSON.stringify(CHECK_CATALOG)};
var f=document.getElementById('f'),cfg=document.getElementById('cfg'),go=document.getElementById('go');
var statusEl=document.getElementById('status'),errEl=document.getElementById('err');
var resEl=document.getElementById('result'),conEl=document.getElementById('audit');
var unsafeEl=document.getElementById('unsafe'),isolateEl=document.getElementById('isolate');
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}

// ---- Fleet hub: the real servers on this machine, from mcpgawk discovery ----
// GENERATED from fleet.ts's stateStatus — the one definition. This used to be a hand-written
// second copy that had already drifted from it, which is exactly how two surfaces come to
// disagree about whether a server was checked.
var STATE_MAP=${JSON.stringify(Object.fromEntries(FLEET_STATES.map((s) => {
        const { label, role } = stateStatus(s);
        return [s, [label, role]];
    })))};
// Each AI tool takes its ecosystem's identity tint (Nativerse DS --eco-* tokens); unknown tools fall back to accent.
var ECO={'claude-code':'--eco-anthropic','claude-desktop':'--eco-anthropic','claude-desktop-extension':'--eco-anthropic',
  'claude.ai':'--eco-anthropic','codex':'--eco-openai','gemini-cli':'--eco-google','antigravity':'--eco-google',
  'chrome':'--eco-google','vscode':'--eco-ms'};
function ecoStyle(c){var t=ECO[c];return t?' style="--eco:var('+t+')"':'';}
// Unknown state => incomplete, never muted. Same rule as stateStatus's default branch: muted is
// the deliberate 'we chose not to scan this', so using it as the fallback files anything new or
// unexpected under 'nothing to see here'.
function stateOf(s){return STATE_MAP[String(s||'').toUpperCase()]||[String(s||'').toLowerCase(),'incomplete'];}
function fleetRow(sv){
  var st=stateOf(sv.state),label=st[0],role=st[1];
  // A Verify action only where a launch spec is available (sv.scannable). Clicking it launches the
  // server's code in the no-egress sandbox — the click IS the consent a passive scan withholds.
  var action=sv.scannable
    ? '<button class="vbtn" data-verify="'+esc(sv.name)+'" title="Run '+esc(sv.name)+' in the no-egress sandbox and probe every tool"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>Verify</button>'
    : '<span class="vslot"></span>';
  // A "needs auth" row must not be a dead end: say HOW to sign in (the CLI batches it).
  var authHint=(String(sv.state||'').toUpperCase()==='AUTH')
    ? '<div class="dt">sign in: run <code>mcpgawk scan</code> in a terminal — it batches sign-in for every server that needs it — then Refresh here</div>'
    : '';
  return '<div class="srv r-'+role+'" data-srv="'+esc(sv.name)+'">'+
    '<span class="fpill fp-'+role+'">'+esc(label)+'</span>'+
    '<span><span class="nm">'+esc(sv.name)+'</span>'+(sv.url?' <span class="dt">'+esc(sv.url)+'</span>':'')+
      '<div class="dt">'+esc(sv.detail||'')+'</div>'+authHint+'</span>'+
    '<span class="dt">'+esc((sv.clients||[]).join(', '))+'</span>'+
    action+
    '</div>';
}
function renderFleet(f){
  var el=document.getElementById('fleet');
  if(!f.available){
    el.innerHTML='<div class="fleet-empty">'+esc(f.reason||'Fleet discovery unavailable.')+
      '<br><br>You can still verify any server in depth below by pasting its config.</div>';
    return;
  }
  var servers=f.servers||[];
  if(!servers.length){el.innerHTML='<div class="fleet-empty">No MCP servers found in any AI-tool config on this machine.</div>';return;}
  // group by client (a server can appear in several)
  var groups={};
  servers.forEach(function(sv){(sv.clients&&sv.clients.length?sv.clients:['(unattributed)']).forEach(function(c){
    (groups[c]=groups[c]||[]).push(sv);});});
  // summary counts by role
  // EVERY role gets a stat. 'incomplete' had none, so a SKIPPED server was counted into a role
  // that was never rendered and simply vanished from the summary — the totals then read as though
  // the fleet were fully accounted for, with a green Clean tally sitting next to the gap.
  var counts={};servers.forEach(function(sv){var r=stateOf(sv.state)[1];counts[r]=(counts[r]||0)+1;});
  var STATS=[['vuln','Vulnerable','--bad'],['risk','Review','--warn'],
             ['incomplete','Not checked','--warn'],['clean','Clean','--clean'],
             ['muted','Not scanned','--muted']];
  var shown=0;
  var cells=STATS.map(function(s){
    var n=counts[s[0]]||0;if(!n)return '';shown+=n;
    return '<div class="stat"><div class="k">'+s[1]+'</div><div class="v" style="color:var('+s[2]+')">'+n+'</div></div>';
  }).join('');
  // A role we forgot to list must surface as a visible discrepancy, not disappear silently.
  var unaccounted=servers.length-shown;
  var summary='<div class="fleet-summary">'+
    '<div class="stat"><div class="k">Servers</div><div class="v">'+servers.length+'</div></div>'+
    cells+
    (unaccounted>0?'<div class="stat"><div class="k">Unaccounted</div><div class="v" style="color:var(--warn)">'+unaccounted+'</div></div>':'')+
    '</div>';
  var body=Object.keys(groups).sort().map(function(c){
    return '<div class="fgroup"><div class="gh"'+ecoStyle(c)+'><b>'+esc(c)+'</b> <span class="ct">'+groups[c].length+' server(s)</span></div>'+
      groups[c].map(fleetRow).join('')+'</div>';
  }).join('');
  var skipped=servers.filter(function(sv){return String(sv.state||'').toUpperCase()==='SKIPPED'}).length;
  var prompt=skipped?'<div class="fleet-note" id="skippedNote">'+skipped+' local server(s) were not launched, so their tools are unknown. '+
    '<b>Scan local servers too</b> launches them to list their tools — this runs their code on this machine.'+
    '</div>':'';
  el.innerHTML=summary+prompt+body;
}
function loadFleet(launchLocal){
  var el=document.getElementById('fleet');
  el.innerHTML='<p class="spin" style="margin:10px 2px">'+(launchLocal
    ? 'Launching each local server and listing its tools…'
    : 'Discovering the servers on this machine…')+'</p>';
  fetch('/api/capabilities').then(function(r){return r.json();}).then(function(c){
  var note=document.getElementById('isolateNote');
  if(c&&c.docker){ isolateEl.disabled=false; note.textContent=''; }
  else { isolateEl.disabled=true; isolateEl.checked=false;
         note.textContent=' · unavailable — Docker is not running, so OS-level isolation cannot be used'; }
}).catch(function(){
  var note=document.getElementById('isolateNote');
  isolateEl.disabled=true; isolateEl.checked=false;
  note.textContent=' · unavailable — could not check Docker';
});
fetch('/api/fleet'+(launchLocal?'?launchLocal=1':'')).then(function(r){return r.json();}).then(renderFleet).catch(function(e){
    el.innerHTML='<div class="fleet-empty">Could not reach the local fleet endpoint: '+esc(e.message)+'</div>';});
}
document.getElementById('refresh').addEventListener('click',function(){loadFleet(false)});
document.getElementById('scanLocal').addEventListener('click',function(){loadFleet(true)});
loadFleet(false);

(function(){
  document.getElementById('catalog').innerHTML=CATALOG.map(function(c){
    var ap=c.applicability==='output'?'output · local + remote':'sandbox egress · local only';
    return '<div class="check"><span class="badge">'+esc(c.label)+' · '+esc(c.severity)+'</span>'+
      '<span><span class="d">'+esc(c.detects)+'</span> <span class="ap">'+esc(ap)+'</span></span></div>';
  }).join('');
})();
function evSummary(ev){
  var e=ev.evidence||{};
  if(e.egress)return '→ '+e.egress.join(', ');
  if(e.canary)return 'fetched an attacker URL taken from input';
  if(e.snippet)return 'output: "'+e.snippet+'"';
  if(e.leaked)return 'leaked a '+e.leaked;
  return '';
}
function lineFor(ev){
  if(ev.type==='server')return{cls:'ln-server',txt:ev.server+'   ['+ev.transport+']   '+ev.mode+' mode'};
  if(ev.type==='enumerated')return{cls:'ln-tool',txt:'enumerated '+ev.tools.length+' tool(s): '+ev.tools.map(function(t){return t.name}).join(', ')};
  if(ev.type==='skip')return{cls:'ln-skip',txt:ev.tool+' — skipped ('+ev.klass+"; safe mode won't invoke a mutating tool)"};
  if(ev.type==='sandbox-degraded')return{cls:'ln-hit',txt:'sandbox degraded: '+ev.reason};
  if(ev.type==='check'){
    if(ev.outcome==='reproduced')return{cls:'ln-hit',txt:ev.tool+' · '+ev.label+' — REPRODUCED '+ev.attemptsOk+'/'+ev.attemptsRun+'   '+evSummary(ev)};
    if(ev.outcome==='error')return{cls:'ln-skip',txt:ev.tool+' · '+ev.label+' — could not verify (infra)'};
    return{cls:'ln-ok',txt:ev.tool+' · '+ev.label+' — clean'};
  }
  return{cls:'',txt:''};
}
function sleep(ms){return new Promise(function(r){setTimeout(r,ms)})}
async function playAudit(audit){
  conEl.innerHTML='';
  var a=document.createElement('div');a.className='ln ln-approach';
  a.textContent='approach → run each tool in a disposable no-egress sandbox; convict only on N/N reproduction';
  conEl.appendChild(a);await sleep(300);
  for(var i=0;i<audit.length;i++){
    var l=lineFor(audit[i]);if(!l.txt)continue;
    var d=document.createElement('div');d.className='ln '+l.cls;d.textContent=l.txt;
    conEl.appendChild(d);conEl.scrollTop=conEl.scrollHeight;
    await sleep(audit[i].type==='check'?180:240);
  }
}
function currentFlags(){return{unsafe:!!(unsafeEl&&unsafeEl.checked),isolate:!!(isolateEl&&isolateEl.checked)};}
// One verify path, shared by the in-depth form and every fleet-row button — same audit playback,
// same report render, same error handling. The fleet button posts a NAME; the spec stays server-side.
async function runVerify(url,payload,statusText){
  errEl.innerHTML='';resEl.innerHTML='';conEl.innerHTML='';
  document.getElementById('next').hidden=true;
  go.disabled=true;statusEl.textContent=statusText;
  try{
    var r=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
    var data=await r.json();
    if(!r.ok){errEl.innerHTML='<div class="err">'+(data&&data.error?data.error:('HTTP '+r.status))+'</div>';return null}
    if(data.audit)await playAudit(data.audit);
    resEl.innerHTML=data.bodyHtml;
    document.getElementById('next').hidden=false;  // the verdict is in — show the next motion
    resEl.scrollIntoView({behavior:'smooth',block:'start'});
    return data;
  }catch(ex){errEl.innerHTML='<div class="err">Request failed: '+ex.message+'</div>';return null}
  finally{go.disabled=false;statusEl.textContent='';}
}
// The run's verdict, as the SERVER derived it. This used to re-implement deriveStatus's precedence
// here as a hard-coded array — a third copy of the status algebra — and it read only
// report.servers, so it ignored report.errors AND ignored the completeness half entirely: a run
// with zero servers and N errors returned null and showed no annotation at all. summary.status is
// already in the payload and is the only value the exit code, the HTML banner and SARIF agree on.
function runStatus(report){
  return (report&&report.summary&&report.summary.status)||null;
}
function configProblem(text){
  if(!text.trim()) return 'Paste an MCP server config to verify — the shape is shown in the box.';
  var p;
  try{p=JSON.parse(text)}catch(ex){return 'Config is not valid JSON: '+ex.message}
  var servers=p&&p.mcpServers;
  if(!servers||typeof servers!=='object'||!Object.keys(servers).length) return 'No servers in this config: expected an "mcpServers" object with at least one entry.';
  return null;
}
function syncGo(){ go.disabled = configProblem(cfg.value)!==null; }
cfg.addEventListener('input',function(){ syncGo(); errEl.innerHTML=''; });
syncGo();
f.addEventListener('submit',function(e){
  e.preventDefault();
  var problem=configProblem(cfg.value);
  if(problem){errEl.innerHTML='<div class="err">'+problem+'</div>';return}
  var parsed;
  try{parsed=JSON.parse(cfg.value)}catch(ex){errEl.innerHTML='<div class="err">Config is not valid JSON: '+ex.message+'</div>';return}
  var fl=currentFlags();
  runVerify('/api/verify',{config:parsed,unsafe:fl.unsafe,isolate:fl.isolate},'Auditing — spawning and probing each tool…');
});
// Delegated: #fleet is re-rendered on every refresh, but the listener sits on the stable container.
document.getElementById('fleet').addEventListener('click',function(e){
  var b=e.target&&e.target.closest?e.target.closest('[data-verify]'):null;if(!b)return;
  var name=b.getAttribute('data-verify');var fl=currentFlags();
  runVerify('/api/verify-server',{name:name,unsafe:fl.unsafe,isolate:fl.isolate},
    'Verifying '+name+' — spawning it in the sandbox and probing each tool…').then(function(data){
    // Close the loop on the row itself. An ANNOTATION beside the pill, never a pill rewrite:
    // the pill is the CLI's scan state and the two surfaces must not disagree.
    var st=data&&runStatus(data.report);if(!st)return;
    var row=document.querySelector('[data-srv="'+(window.CSS&&CSS.escape?CSS.escape(name):name)+'"]');if(!row)return;
    var nm=row.querySelector('.nm');if(!nm)return;
    var old=row.querySelector('.vnote');if(old)old.remove();
    var tag=document.createElement('span');tag.className='vnote vn-'+st;
    tag.textContent='verified just now — '+st.replace('-',' ');
    nm.insertAdjacentElement('afterend',tag);
  });
});
</script>
</body></html>`;
}
const MAX_BODY = 512 * 1024; // a config is small; cap the request body defensively
function readBody(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on("data", (c) => {
            size += c.length;
            if (size > MAX_BODY) {
                reject(new Error("request body too large"));
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        req.on("error", reject);
    });
}
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
/**
 * Extra hostnames permitted for the Host/Origin guard, from `GAWK_SERVE_ALLOW_HOSTS`
 * (comma-separated). Off by default. Intended for a trusted local tunnel host such as
 * `bs-local.com` when driving the UI from a cross-browser cloud (e.g. BrowserStack Local),
 * which resolves only to loopback. The default posture stays strict-localhost.
 */
function allowedHostnames() {
    const extra = (process.env.GAWK_SERVE_ALLOW_HOSTS ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    return new Set([...LOOPBACK_HOSTS, ...extra]);
}
/** Reject anything but a same-origin local request — this endpoint can spawn processes. */
function isLocalRequest(req) {
    const allowed = allowedHostnames();
    const host = (req.headers.host ?? "").split(":")[0] ?? "";
    if (!allowed.has(host))
        return false;
    const origin = req.headers.origin;
    if (origin) {
        try {
            if (!allowed.has(new URL(origin).hostname))
                return false;
        }
        catch {
            return false;
        }
    }
    return true;
}
function send(res, code, type, body) {
    res.writeHead(code, { "content-type": type, "cache-control": "no-store" });
    res.end(body);
}
/** Build the HTTP server (exposed for tests). Does not call `.listen()`. */
export function createVerifyServer(opts) {
    const unsafeAllowed = opts.unsafeAllowed ?? false;
    const html = page(unsafeAllowed);
    // Launch specs live HERE, server-side, keyed by server name — refreshed on every /api/fleet call.
    // The browser triggers a verify by NAME only; the spec (which can carry an `env` secret from the
    // user's config) is never sent to it. This is what makes click-to-verify safe.
    let fleetSpecs = new Map();
    return createServer(async (req, res) => {
        if (!isLocalRequest(req)) {
            send(res, 403, "text/plain", "forbidden: mcpgawk verify serve accepts only local requests");
            return;
        }
        if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
            send(res, 200, "text/html; charset=utf-8", html);
            return;
        }
        if (req.method === "GET" && (req.url === "/timeline" || req.url?.startsWith("/timeline?"))) {
            // Server-rendered: the registry read is already a complete document by the time the page is
            // built, so a client fetch would only add a loading state and a second failure mode.
            const limit = Number(new URL(req.url ?? "/", "http://localhost").searchParams.get("limit") ?? 100);
            const timeline = await loadTimeline(Number.isFinite(limit) ? limit : 100);
            send(res, 200, "text/html; charset=utf-8", renderTimelinePage(timeline));
            return;
        }
        if (req.method === "GET" &&
            (req.url === "/api/timeline" || req.url?.startsWith("/api/timeline?"))) {
            const limit = Number(new URL(req.url ?? "/", "http://localhost").searchParams.get("limit") ?? 100);
            send(res, 200, "application/json", JSON.stringify(await loadTimeline(Number.isFinite(limit) ? limit : 100)));
            return;
        }
        if (req.method === "GET" && req.url === "/api/capabilities") {
            if (dockerUsable === undefined) {
                try {
                    dockerUsable = await dockerAvailable("docker");
                }
                catch {
                    dockerUsable = false; // a probe that throws is not evidence Docker works
                }
            }
            send(res, 200, "application/json", JSON.stringify({ docker: dockerUsable }));
            return;
        }
        if (req.method === "GET" && (req.url === "/api/fleet" || req.url?.startsWith("/api/fleet?"))) {
            // launchLocal is an explicit, per-click opt-in — never sticky, never a default. Launching a
            // local server runs its code, so the choice is made in the UI each time it is wanted.
            const launchLocal = new URL(req.url ?? "/", "http://localhost").searchParams.get("launchLocal") === "1";
            // The real fleet on this machine, via the canonical mcpgawk discovery. Never throws.
            const fleet = await discoverFleet(60_000, launchLocal);
            // Cache the specs server-side and STRIP them from what the browser sees — it gets only the
            // secret-free `scannable` flag. Rebuilt every call so a config change is picked up on refresh.
            fleetSpecs = new Map();
            const servers = fleet.servers.map((s) => {
                const { spec, ...rest } = s;
                if (spec)
                    fleetSpecs.set(s.name, spec);
                return rest;
            });
            send(res, 200, "application/json", JSON.stringify({ ...fleet, servers }));
            return;
        }
        if (req.method === "POST" && req.url === "/api/verify-server") {
            // Verify a discovered fleet server BY NAME — the spec never round-trips through the browser.
            try {
                const body = JSON.parse((await readBody(req)) || "{}");
                const name = String(body.name ?? "");
                const spec = fleetSpecs.get(name);
                if (!spec) {
                    send(res, 404, "application/json", JSON.stringify({
                        error: `'${name}' isn't a verifiable server in the current fleet — hit Refresh and try again.`,
                    }));
                    return;
                }
                if (body.unsafe === true && !unsafeAllowed) {
                    send(res, 403, "application/json", JSON.stringify({
                        error: "unsafe mode not enabled; restart with: mcpgawk verify serve --unsafe",
                    }));
                    return;
                }
                const unsafe = unsafeAllowed && body.unsafe === true;
                const { report, audit } = await verifyDoc({ mcpServers: { [name]: spec } }, unsafe, undefined, body.isolate === true);
                send(res, 200, "application/json", JSON.stringify({ report, audit, bodyHtml: renderReportBody(report) }));
            }
            catch (e) {
                send(res, 400, "application/json", JSON.stringify({ error: e.message }));
            }
            return;
        }
        if (req.method === "POST" && req.url === "/api/verify") {
            try {
                const body = JSON.parse((await readBody(req)) || "{}");
                const unsafe = unsafeAllowed && body.unsafe === true;
                if (body.unsafe === true && !unsafeAllowed) {
                    send(res, 403, "application/json", JSON.stringify({
                        error: "unsafe mode not enabled; restart with: mcpgawk verify serve --unsafe",
                    }));
                    return;
                }
                const { report, audit } = await verifyDoc(body.config, unsafe, undefined, body.isolate === true);
                send(res, 200, "application/json", JSON.stringify({ report, audit, bodyHtml: renderReportBody(report) }));
            }
            catch (e) {
                send(res, 400, "application/json", JSON.stringify({ error: e.message }));
            }
            return;
        }
        send(res, 404, "text/plain", "not found");
    });
}
/** Start the local web UI. Resolves once the server is listening. */
/** Cached Docker probe result — undefined until first asked. The probe runs a real container,
 * so it is not free; the answer does not meaningfully change while the server is up. */
let dockerUsable;
export function serve(opts) {
    const host = opts.host ?? "127.0.0.1";
    const log = opts.log ?? console.log;
    const server = createVerifyServer(opts);
    return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(opts.port, host, () => {
            log(`mcpgawk verify: web UI on http://${host}:${opts.port}  (safe mode${opts.unsafeAllowed ? " + unsafe enabled" : ""})`);
            log("  bound to this machine only — do not expose this port. Ctrl-C to stop.");
            resolve(server);
        });
    });
}
//# sourceMappingURL=serve.js.map