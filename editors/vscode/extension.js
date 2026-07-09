// mcpgawk — VS Code / Cursor extension.
// Runs the local mcpgawk CLI on your workspace MCP config and shows what each
// server costs and exposes. Nothing leaves your machine.
const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

let statusBar;
let resolvedCmd; // cache: the invocation that worked, e.g. "mcpgawk" or "uvx mcpgawk"

function activate(context) {
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = "mcpgawk.scan";
  context.subscriptions.push(statusBar);
  context.subscriptions.push(vscode.commands.registerCommand("mcpgawk.scan", () => scan(true)));
  scan(false); // quiet pass to populate the status bar
}

function cfg(key, dflt) {
  return vscode.workspace.getConfiguration("mcpgawk").get(key, dflt);
}

function workspaceRoot() {
  const f = vscode.workspace.workspaceFolders;
  return f && f.length ? f[0].uri.fsPath : undefined;
}

// GUI apps on macOS often don't inherit the shell PATH, so `mcpgawk`/`uvx` in
// ~/.local/bin etc. aren't found. Prepend the usual install locations.
function childEnv() {
  const extra = [
    path.join(os.homedir(), ".local", "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
    path.join(os.homedir(), ".cargo", "bin"),
  ];
  const env = Object.assign({}, process.env);
  env.PATH = extra.join(":") + ":" + (env.PATH || "");
  return env;
}

function tryHelp(cmd) {
  return new Promise((resolve) => {
    cp.exec(`${cmd} --help`, { env: childEnv(), timeout: 60000 }, (err) => resolve(!err));
  });
}

// Resolve how to call the CLI: explicit setting → mcpgawk → uvx mcpgawk → python -m mcpgawk.
async function resolveCommand() {
  const explicit = (cfg("command", "") || "").trim();
  if (explicit) return explicit;
  if (resolvedCmd) return resolvedCmd;
  for (const cand of ["mcpgawk", "uvx mcpgawk", "python3 -m mcpgawk", "python -m mcpgawk"]) {
    if (await tryHelp(cand)) { resolvedCmd = cand; return cand; }
  }
  return undefined; // not found anywhere
}

function findConfig(root) {
  const explicit = cfg("configPath", "");
  if (explicit) return path.isAbsolute(explicit) ? explicit : path.join(root, explicit);
  for (const rel of ["mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"]) {
    const p = path.join(root, rel);
    if (fs.existsSync(p)) return p;
  }
  return undefined;
}

function extractJson(text) {
  const m = text.match(/(\[[\s\S]*\]|\{[\s\S]*\})/);
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch (_) { return null; }
}

async function promptInstall() {
  const pick = await vscode.window.showErrorMessage(
    "mcpgawk CLI not found. The easiest fix needs no install — run it with uvx.",
    "Use uvx", "pip install", "Docs");
  if (pick === "Use uvx") {
    await vscode.workspace.getConfiguration("mcpgawk").update("command", "uvx mcpgawk", vscode.ConfigurationTarget.Global);
    vscode.window.showInformationMessage("Set mcpgawk to run via `uvx mcpgawk`. Run the scan again.");
  } else if (pick === "pip install") {
    const t = vscode.window.createTerminal("Install mcpgawk");
    t.show(); t.sendText("pip install mcpgawk");
  } else if (pick === "Docs") {
    vscode.env.openExternal(vscode.Uri.parse("https://mcp.gawk.dev"));
  }
}

async function scan(interactive) {
  const root = workspaceRoot();
  if (!root) { if (interactive) vscode.window.showWarningMessage("mcpgawk: open a folder with an mcp.json first."); return; }
  const config = findConfig(root);
  if (!config) {
    statusBar.hide();
    if (interactive) vscode.window.showWarningMessage("mcpgawk: no mcp.json found in this workspace.");
    return;
  }

  if (interactive) statusBar.text = "$(sync~spin) mcpgawk…";
  const base = await resolveCommand();
  if (!base) { statusBar.hide(); if (interactive) await promptInstall(); return; }

  const cmd = `${base} scan ${JSON.stringify(config)} --json`;
  const result = await new Promise((resolve) => {
    cp.exec(cmd, { cwd: root, env: childEnv(), timeout: 120000, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout, stderr) => resolve({ err, stdout: stdout || "", stderr: stderr || "" }));
  });
  const data = extractJson(result.stdout);

  if (!data) {
    statusBar.hide();
    const notFound = /not found|ENOENT|No module named|No such file/i.test((result.err && result.err.message) || result.stderr);
    if (notFound) { resolvedCmd = undefined; await promptInstall(); }
    else if (interactive) vscode.window.showErrorMessage("mcpgawk: scan failed. " + ((result.stderr || "").trim().split("\n").pop() || ""));
    return;
  }

  const servers = Array.isArray(data) ? data : [data];
  const rows = servers.map((s) => {
    const x = s["x-mcpgawk"] || {};
    return {
      name: s.name || "?",
      tools: x.tool_count || 0,
      tokens: x.cost_index_tokens || 0,
      flagged: (x.tools || []).filter((t) => t.write || t.exfil_capable).length,
      signals: (x.bounded_signals || []).length,
    };
  });
  const total = rows.reduce((a, r) => a + r.tokens, 0);

  statusBar.text = `$(shield) ${total.toLocaleString()} tok`;
  statusBar.tooltip = `mcpgawk — ${rows.length} MCP server(s) load ${total.toLocaleString()} tokens at connect. Click for the breakdown.`;
  statusBar.show();

  if (interactive) showPanel(rows, total, path.basename(config));
}

function showPanel(rows, total, configName) {
  const panel = vscode.window.createWebviewPanel("mcpgawk", "mcpgawk — MCP scan", vscode.ViewColumn.Active, {});
  const tr = rows.map((r) => `<tr>
      <td class="name">${esc(r.name)}</td>
      <td class="num">${r.tools}</td>
      <td class="num tok">${r.tokens.toLocaleString()}</td>
      <td class="num">${r.flagged}</td>
      <td class="num ${r.signals ? "warn" : ""}">${r.signals}</td>
    </tr>`).join("");
  panel.webview.html = `<!doctype html><meta charset="utf-8">
  <style>
    body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);padding:20px 24px}
    h1{font-size:18px;margin:0 0 2px}
    .sub{color:var(--vscode-descriptionForeground);font-size:12px;margin:0 0 18px}
    .accent{color:#7B83F0;font-weight:600}
    table{border-collapse:collapse;width:100%;font-size:13px}
    th,td{padding:8px 10px;border-bottom:1px solid var(--vscode-panel-border);text-align:right}
    th:first-child,td:first-child{text-align:left}
    th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--vscode-descriptionForeground)}
    td.name{font-weight:600}.num{font-variant-numeric:tabular-nums}
    .tok{color:#7B83F0}.warn{color:var(--vscode-editorWarning-foreground)}
    .foot{margin-top:16px;color:var(--vscode-descriptionForeground);font-size:11.5px}
    code{background:var(--vscode-textCodeBlock-background);padding:1px 5px;border-radius:4px}
  </style>
  <h1>mcpgawk</h1>
  <p class="sub">${esc(configName)} · <span class="accent">${total.toLocaleString()} tokens</span> loaded at connect, across ${rows.length} server(s).</p>
  <table>
    <thead><tr><th>Server</th><th>Tools</th><th>Tokens&#64;connect</th><th>Write/exfil</th><th>Signals</th></tr></thead>
    <tbody>${tr}</tbody>
  </table>
  <p class="foot">Measured locally by mcpgawk — nothing left your machine. Full scan in a terminal: <code>mcpgawk scan mcp.json</code></p>`;
}

function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

function deactivate() {}
module.exports = { activate, deactivate };
