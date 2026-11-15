// PerchBot bug-repro runner for GitHub-hosted Windows and macOS machines.
//
// Reads a job spec from $JOB, tries the real Perch CLI and/or Perch Terminal on this OS, signed
// out and from empty folders, and writes out/result.bin: the result and screenshots, gzipped and
// encrypted for the bot (AES-256-GCM, key wrapped with the bot's RSA public key in
// bot-public.pem). The workflow logs only say which step ran, never what came out.
//
// Job spec: { cli?: { version, acp? }, tui?: { version, cols, rows, steps } (Windows), desktop?: { seconds? } }

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const DOWNLOADS = {
  windows: 'https://download.perchai.app/desktop/latest/windows-x64.exe',
  'mac-arm64': 'https://download.perchai.app/desktop/latest/mac-arm64.dmg',
  'mac-x64': 'https://download.perchai.app/desktop/latest/mac-x64.dmg'
};
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const clip = (s, n = 200) => { const t = String(s || '').replace(/\s+/g, ' ').trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };
const NOISE = /^npm (warn|notice)|ExperimentalWarning|trace-warnings|^\s*$/i;
const firstLine = (s) => String(s || '').split('\n').map(l => l.trim()).find(l => !NOISE.test(l)) || '';
const CRASH = /\b(TypeError|ReferenceError|SyntaxError|RangeError|Cannot find module|ERR_[A-Z_]+|Unhandled|Segmentation fault)\b/;
const log = (msg) => console.log(`[repro] ${msg}`);

function run(cmd, args, { env = process.env, cwd = os.tmpdir(), ms = 60000, input = null } = {}) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let out = '';
    let killed = false;
    const child = spawn(cmd, args, { cwd, env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const add = (d) => { if (out.length < 200000) out += d; };
    child.stdout.on('data', add);
    child.stderr.on('data', add);
    child.on('error', (e) => { out += e.message; });
    const timer = setTimeout(() => { killed = true; try { child.kill('SIGKILL'); } catch (e) { /* gone */ } }, ms);
    child.on('close', (code) => { clearTimeout(timer); resolve({ code: typeof code === 'number' ? code : 1, killed, ms: Date.now() - t0, out }); });
    child.stdin.on('error', () => {});
    if (input != null) child.stdin.end(input); else child.stdin.end();
  });
}

function freshHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'perch-home-'));
  fs.mkdirSync(path.join(home, 'work'), { recursive: true });
  return home;
}

/** Perch Terminal's own log (<app data>/Perch AI Desktop/desktop-runtime.log): crashes, load failures, console errors. */
function readRuntimeLog(files) {
  const file = files.find(f => f && fs.existsSync(f));
  if (!file) return null;
  let text = '';
  try { text = fs.readFileSync(file, 'utf8').slice(-400000); } catch (e) { return null; }
  const events = text.split('\n').map(l => { try { return JSON.parse(l); } catch (e) { return null; } }).filter(e => e && typeof e.kind === 'string');
  const counts = {};
  for (const e of events) counts[e.kind] = (counts[e.kind] || 0) + 1;
  const notable = [];
  for (const e of events) {
    if (e.kind === 'render-process-gone') notable.push(`the app's window process died: ${e.reason} (exit ${e.exitCode})`);
    else if (e.kind === 'did-fail-load') notable.push(`the app's page failed to load: ${e.errorDescription || '?'} (${e.errorCode})${e.retried ? ', after a retry' : ''}`);
    else if (e.kind === 'perch-mcp-server-start-failed') notable.push(`Perch's MCP server failed to start: ${e.error}`);
    else if (e.kind === 'renderer-console' && Number(e.level) >= 3) notable.push(`console error: ${e.message}`);
  }
  return { counts, notable: [...new Set(notable.map(n => clip(n, 220)))].slice(0, 6) };
}

const homeEnv = (home) => ({ ...process.env, HOME: home, USERPROFILE: home, APPDATA: path.join(home, 'AppData', 'Roaming'), LOCALAPPDATA: path.join(home, 'AppData', 'Local'), NO_COLOR: '1', CI: '1' });

// ---------------------------------------------------------------------------
// Perch CLI
// ---------------------------------------------------------------------------

function acpHandshake(bin, env, cwd) {
  return new Promise((resolve) => {
    const res = { started: true };
    let buf = '', err = '', done = false;
    const child = spawn(process.execPath, [bin, 'acp'], { cwd, env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const finish = (extra) => {
      if (done) return;
      done = true;
      Object.assign(res, extra);
      const e = err.split('\n').map(l => l.trim()).filter(l => l && !NOISE.test(l));
      if (e.length) res.stderr = clip(e.slice(0, 3).join(' | '), 240);
      try { child.kill('SIGKILL'); } catch (x) { /* gone */ }
      resolve(res);
    };
    const send = (o) => { try { child.stdin.write(`${JSON.stringify(o)}\n`); } catch (e) { /* closed */ } };
    child.stdin.on('error', () => {});
    child.stdout.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch (e) { res.nonJson = res.nonJson || clip(line, 160); continue; }
        if (msg.id === 1 && !msg.method) {
          if (msg.error) return finish({ initialize: { error: clip(`${msg.error.code} ${msg.error.message}`, 200) } });
          const r = msg.result || {};
          res.initialize = { protocolVersion: r.protocolVersion, agent: clip([r.agentInfo?.name, r.agentInfo?.version].filter(Boolean).join(' '), 60), authMethods: (r.authMethods || []).map(a => a.id || a.name).filter(Boolean).slice(0, 4), loadSession: Boolean(r.agentCapabilities?.loadSession) };
          send({ jsonrpc: '2.0', id: 2, method: 'session/new', params: { cwd, mcpServers: [] } });
        } else if (msg.id === 2 && !msg.method) {
          return finish({ sessionNew: msg.error ? { error: clip(`${msg.error.code} ${msg.error.message}`, 200) } : { ok: true } });
        } else if (msg.method && msg.id != null) {
          send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Not available in the repro runner' } });
        }
      }
    });
    child.stderr.on('data', (d) => { if (err.length < 20000) err += d; });
    child.on('error', (e) => finish({ started: false, error: e.message }));
    child.on('close', (code, signal) => finish({ exited: { code, signal } }));
    setTimeout(() => finish({ timeout: true }), 30000);
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: 1, clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false }, clientInfo: { name: 'perchbot-repro', version: '1' } } });
  });
}

function npmCli() {
  const dir = path.dirname(process.execPath);
  const found = [path.join(dir, 'node_modules', 'npm', 'bin', 'npm-cli.js'), path.join(dir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js')].find(f => fs.existsSync(f));
  if (!found) throw new Error('npm not found next to node');
  return found;
}

// One global install per job (a GitHub machine is new every time), exactly like a user's `npm i -g`.
const globalCli = { version: null, bin: null, install: null };
async function ensureGlobalCli(version) {
  if (globalCli.version === version && globalCli.bin) return globalCli;
  log(`npm install -g perchai-cli@${version}`);
  // npm through node itself: Windows won't start npm.cmd without a shell, and no shell means no quoting trouble.
  const install = await run(process.execPath, [npmCli(), 'install', '-g', `perchai-cli@${version}`, '--no-audit', '--no-fund', '--loglevel=error'], { ms: 300000 });
  const root = (await run(process.execPath, [npmCli(), 'root', '-g'], { ms: 30000 })).out.trim().split('\n').pop().trim();
  const bin = path.join(root, 'perchai-cli', 'bin', 'perch');
  Object.assign(globalCli, { version, install, bin: install.code === 0 && fs.existsSync(bin) ? bin : null, root });
  return globalCli;
}

async function cliCheck(spec) {
  const version = String(spec.version || 'latest');
  if (!/^(latest|\d+\.\d+\.\d+(-[\w.]+)?)$/.test(version)) throw new Error('bad version');
  const g = await ensureGlobalCli(version);
  const out = { node: process.version, install: { code: g.install.code, ms: g.install.ms, global: true } };
  if (!g.bin) {
    out.install.code = out.install.code || 1;
    out.install.err = clip(String(g.install.out).split('\n').find(l => /ERR!|error/i.test(l)) || firstLine(g.install.out) || 'the perch command was not installed', 300);
    return out;
  }
  out.version = JSON.parse(fs.readFileSync(path.join(g.root, 'perchai-cli', 'package.json'), 'utf8')).version;
  const cwd = path.join(freshHome(), 'work');
  const env = { ...process.env, NO_COLOR: '1', CI: '1' };
  log('perch --help / status');
  const help = await run(process.execPath, [g.bin, '--help'], { env, cwd, ms: 30000 });
  const status = await run(process.execPath, [g.bin, 'status'], { env, cwd, ms: 30000 });
  out.help = { code: help.code, killed: help.killed, crash: CRASH.test(help.out), out: clip(firstLine(help.out), 160) };
  out.status = { code: status.code, killed: status.killed, crash: CRASH.test(status.out), out: clip(firstLine(status.out), 160) };
  if (IS_WIN) {
    // How Windows users actually start it: the npm shims from cmd and PowerShell, and PowerShell
    // under Windows 11's default script policy, which blocks npm's unsigned perch.ps1.
    log('perch from cmd and PowerShell');
    const shell = async (cmd, args) => {
      const r = await run(cmd, args, { env, cwd, ms: 45000 });
      return { code: r.code, out: clip(firstLine(r.out), 160), blocked: /running scripts is disabled|cannot be loaded because|not digitally signed/i.test(r.out), notFound: /is not recognized|CommandNotFound/i.test(r.out) };
    };
    const where = await run('where.exe', ['perch'], { env, cwd, ms: 15000 });
    out.shells = {
      onPath: where.code === 0,
      cmd: await shell('cmd.exe', ['/d', '/c', 'perch --help']),
      powershell: await shell('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', 'perch --help']),
      powershellDefault: await shell('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Restricted', '-Command', 'perch --help'])
    };
  }
  if (spec.acp) { log('ACP handshake'); out.acp = await acpHandshake(g.bin, env, cwd); }
  return out;
}

// ---------------------------------------------------------------------------
// Perch CLI interactive screen in a real Windows console (conhost)
// ---------------------------------------------------------------------------

// The bot's key names (tmux style) as SendKeys codes.
const SENDKEYS = { Enter: '{ENTER}', Tab: '{TAB}', BTab: '+{TAB}', Escape: '{ESC}', Up: '{UP}', Down: '{DOWN}', Left: '{LEFT}', Right: '{RIGHT}', BSpace: '{BACKSPACE}', DC: '{DELETE}', Home: '{HOME}', End: '{END}', PageUp: '{PGUP}', PageDown: '{PGDN}', Space: ' ', 'M-Enter': '%{ENTER}' };
for (const c of 'cdlraekuwotpnj') SENDKEYS[`C-${c}`] = `^${c}`;
const sendKeysText = (t) => String(t).replace(/[+^%~(){}[\]]/g, (m) => `{${m}}`);
const psq = (t) => String(t).replace(/'/g, "''");

const WIN_API = `
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
Add-Type @"
using System; using System.Runtime.InteropServices;
public struct RECT { public int Left, Top, Right, Bottom; }
public static class W {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int hh, bool r);
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, System.Text.StringBuilder b, int n);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  // A visible top-level window whose title contains the text (Windows Terminal hosts many windows in one process).
  public static long Find(string part) { long found = 0; EnumWindows((h, l) => { var b = new System.Text.StringBuilder(512); GetWindowTextW(h, b, 512);
    if (IsWindowVisible(h) && b.ToString().Contains(part)) { found = (long)h; return false; } return true; }, IntPtr.Zero); return found; }
}
"@
function Get-Win([int]$id) { $p = Get-Process -Id $id -ErrorAction SilentlyContinue; if ($p -and $p.MainWindowHandle -ne 0) { return $p.MainWindowHandle }
  $q = Get-Process | Where-Object { $_.MainWindowTitle -match 'perch' -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1; if ($q) { return $q.MainWindowHandle }; return [IntPtr]::Zero }
function Front($h) { [W]::ShowWindow($h, 9) | Out-Null; [W]::SetForegroundWindow($h) | Out-Null; Start-Sleep -Milliseconds 300 }
`;

// Reads the text a console shows (its active screen buffer, the alternate one included) by attaching
// to it, like any console program would. Screenshots of conhost miss full-screen TUIs.
const READ_CONSOLE_CS = `
using System; using System.IO; using System.Text; using System.Runtime.InteropServices;
public static class CON {
  [DllImport("kernel32.dll")] static extern bool FreeConsole();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sec, uint d, uint f, IntPtr t);
  [StructLayout(LayoutKind.Sequential)] public struct COORD { public short X, Y; }
  [StructLayout(LayoutKind.Sequential)] public struct SR { public short Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct CSBI { public COORD Size; public COORD Cursor; public ushort Attr; public SR Win; public COORD Max; }
  [DllImport("kernel32.dll")] static extern bool GetConsoleScreenBufferInfo(IntPtr h, out CSBI i);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern bool ReadConsoleOutputCharacterW(IntPtr h, StringBuilder b, uint n, COORD c, out uint r);
  public static void Dump(uint pid, string file) {
    FreeConsole();
    if (!AttachConsole(pid)) { File.WriteAllText(file, "ATTACH FAILED " + Marshal.GetLastWin32Error()); return; }
    IntPtr h = CreateFileW("CONOUT$", 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
    CSBI i; if (!GetConsoleScreenBufferInfo(h, out i)) { FreeConsole(); File.WriteAllText(file, "INFO FAILED"); return; }
    var sb = new StringBuilder();
    for (short y = i.Win.Top; y <= i.Win.Bottom; y++) { var line = new StringBuilder(i.Size.X + 1); uint r; ReadConsoleOutputCharacterW(h, line, (uint)i.Size.X, new COORD { X = 0, Y = y }, out r); sb.AppendLine(line.ToString(0, (int)Math.Min(r, (uint)line.Length)).TrimEnd()); }
    FreeConsole(); File.WriteAllText(file, sb.ToString(), Encoding.UTF8);
  }
}`;

async function readConsole(cmdPid) {
  const file = path.join(os.tmpdir(), `con-${cmdPid}-${Date.now()}.txt`);
  await PS(`Add-Type -TypeDefinition @"
${READ_CONSOLE_CS}
"@
[CON]::Dump([uint32]${Number(cmdPid)}, '${psq(file)}')`, 45000);
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); fs.rmSync(file, { force: true }); } catch (e) { /* none */ }
  return text.split('\n').map(l => l.replace(/\s+$/, '')).join('\n').replace(/\n{3,}/g, '\n\n').trim().slice(0, 5000);
}

async function tuiWindows(spec, outDir) {
  const version = String(spec.version || 'latest');
  if (!/^(latest|\d+\.\d+\.\d+(-[\w.]+)?)$/.test(version)) throw new Error('bad version');
  const g = await ensureGlobalCli(version);
  if (!g.bin) return { ok: false, error: 'perchai-cli did not install' };
  const cols = Math.min(110, Math.max(40, Number(spec.cols) || 100));
  const rows = Math.min(40, Math.max(12, Number(spec.rows) || 32));
  const work = path.join(freshHome(), 'work');
  const marker = `perch-tui-${crypto.randomBytes(3).toString('hex')}`;
  // Windows Terminal (Windows 11's default) when it's there, else the classic console (conhost,
  // Windows 10's default); perch runs in an empty folder at the asked size.
  const hasWt = (await PS('if (Get-Command wt.exe -ErrorAction SilentlyContinue) { "yes" }')).out.includes('yes');
  const terminal = spec.terminal === 'conhost' || !hasWt ? 'conhost' : 'wt';
  // GitHub sets CI=true and GITHUB_ACTIONS; CLI renderers (Ink and friends) then skip the live
  // screen and only print final output, so perch runs without them, like on a user's machine.
  const unsetCi = ['CI', 'CONTINUOUS_INTEGRATION', 'BUILD_NUMBER', 'BUILD_ID', 'RUN_ID', 'GITHUB_ACTIONS', 'TF_BUILD', 'RUNNER_TEMP']
    .map(v => `set ${v}=`).join('& ');
  const inner = `${unsetCi}& title ${marker} & cd /d ${work} & perch`; // the temp path has no spaces
  await PS(terminal === 'wt'
    ? `Start-Process wt.exe -ArgumentList '-w new --size ${cols},${rows} --title ${marker} --suppressApplicationTitle cmd.exe /k "${psq(inner)}"'`
    : `Start-Process conhost.exe -ArgumentList 'cmd.exe /k mode con: cols=${cols} lines=${rows} & ${psq(inner)}'`, 30000);
  // The cmd.exe that runs perch (to read its console) and the window showing it (for keys and pictures).
  let cmdPid = 0, hwnd = 0;
  for (let i = 0; i < 20 && !(cmdPid && hwnd); i++) {
    await sleep(1000);
    const found = await PS(`${WIN_API}
$c = Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '${marker}' } | Select-Object -First 1
$w = [W]::Find('${marker}')
# conhost: the window belongs to the cmd process, and cmd retitles it while perch runs.
if (-not $w -and $c) { $q = Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue; if ($q) { $w = [int64]$q.MainWindowHandle } }
"IDS:$($c.ProcessId):$w"`, 30000);
    const m = found.out.match(/IDS:(\d*):(\d*)/);
    if (m) { cmdPid = Number(m[1]) || cmdPid; hwnd = Number(m[2]) || hwnd; }
  }
  if (!cmdPid || !hwnd) {
    const seen = await PS(`${WIN_API}
Get-Process | Where-Object { $_.MainWindowTitle } | ForEach-Object { "$($_.ProcessName): $($_.MainWindowTitle)" } | Select-Object -First 8`, 30000);
    return { ok: false, error: `the ${terminal === 'wt' ? 'Windows Terminal' : 'console'} window did not open (cmd ${cmdPid ? 'found' : 'not found'}, window ${hwnd ? 'found' : 'not found'}; windows: ${clip(seen.out.replace(/\s*\n\s*/g, ' | '), 300)})` };
  }
  await sleep(Math.min(20000, Math.max(4000, Number(spec.startMs) || 8000)));
  const frames = [];
  let shotN = 0, curCols = cols, curRows = rows;
  const capture = async (label) => {
    if (shotN >= 8) return;
    const file = path.join(outDir, `tui-${++shotN}.png`);
    await PS(`${WIN_API}
$h = [IntPtr]${hwnd}; $b = [System.Windows.Forms.SystemInformation]::VirtualScreen; $x=$b.Left; $y=$b.Top; $w=$b.Width; $hh=$b.Height
if ($h -ne [IntPtr]::Zero) { Front $h; $r = New-Object RECT; if ([W]::GetWindowRect($h, [ref]$r)) { $x=$r.Left; $y=$r.Top; $w=$r.Right-$r.Left; $hh=$r.Bottom-$r.Top } }
# The CLI redraws its screen often (animations), so a capture can land mid-repaint and come out
# black: take up to 5 and keep the first with text on it (or the brightest).
$best = $null; $bestScore = -1
for ($k = 0; $k -lt 5; $k++) {
  $i = New-Object System.Drawing.Bitmap $w, $hh; $gr = [System.Drawing.Graphics]::FromImage($i); $gr.CopyFromScreen($x, $y, 0, 0, $i.Size); $gr.Dispose()
  $lit = 0; $tot = 0
  for ($py = 40; $py -lt $hh; $py += 12) { for ($px = 4; $px -lt $w; $px += 12) { $c = $i.GetPixel($px, $py); $tot++; if (($c.R + $c.G + $c.B) -gt 90) { $lit++ } } }
  $score = $lit / [Math]::Max(1, $tot)
  if ($score -gt $bestScore) { if ($best) { $best.Dispose() }; $best = $i; $bestScore = $score } else { $i.Dispose() }
  if ($score -gt 0.01) { break }
  Start-Sleep -Milliseconds 450
}
$best.Save('${psq(file)}', [System.Drawing.Imaging.ImageFormat]::Png)`, 60000);
    frames.push({ label: clip(label, 80), shot: fs.existsSync(file) ? path.basename(file) : null, screen: await readConsole(cmdPid) });
  };
  try {
    await capture('start');
    for (const st of (spec.steps || []).slice(0, 12)) {
      const v = String(st.value ?? '');
      let label = '', keys = null;
      if (st.type === 'text' && v) { keys = sendKeysText(v.slice(0, 200)); label = `typed "${v.slice(0, 60)}"`; }
      else if (st.type === 'key' && SENDKEYS[v]) { const n = Math.min(10, Math.max(1, Number(st.repeat) || 1)); keys = SENDKEYS[v].repeat(n); label = n > 1 ? `${v} x${n}` : v; }
      else if (st.type === 'resize' && /^\d{2,3}x\d{2}$/.test(v)) {
        const [c, r] = v.split('x').map(Number);
        // Same cell size as now, new number of columns and rows; Windows reflows the console like a user dragging its edge.
        await PS(`${WIN_API}
$h = [IntPtr]${hwnd}; if ($h -ne [IntPtr]::Zero) { $c = New-Object RECT; $wr = New-Object RECT; [W]::GetClientRect($h, [ref]$c) | Out-Null; [W]::GetWindowRect($h, [ref]$wr) | Out-Null
$cw = ($c.Right - $c.Left) / ${curCols}; $ch = ($c.Bottom - $c.Top) / ${curRows}; $bw = ($wr.Right - $wr.Left) - ($c.Right - $c.Left); $bh = ($wr.Bottom - $wr.Top) - ($c.Bottom - $c.Top)
[W]::MoveWindow($h, 0, 0, [int]($bw + $cw * ${c}), [int]($bh + $ch * ${r}), $true) | Out-Null }`, 30000);
        curCols = c; curRows = r;
        label = `resized to ${c}x${r}`;
      } else if (st.type === 'wait') { await sleep(Math.min(15000, Math.max(200, Number(v) || 500))); continue; }
      else continue;
      if (keys != null) await PS(`${WIN_API}
$h = [IntPtr]${hwnd}; if ($h -ne [IntPtr]::Zero) { Front $h }; [System.Windows.Forms.SendKeys]::SendWait('${psq(keys)}')`, 30000);
      await sleep(Math.min(8000, Math.max(400, Number(st.settleMs) || 1800)));
      await capture(label);
    }
    return { ok: true, version: g.version === 'latest' ? null : g.version, size: `${cols}x${rows}`, console: terminal === 'wt' ? 'Windows Terminal' : 'conhost', frames };
  } finally {
    // Only perch and its cmd: the window closes by itself. Never stop a terminal process, since
    // Windows Terminal is one process for every window, the runner's own console included.
    await PS(`Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -match 'perchai-cli' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Stop-Process -Id ${cmdPid} -Force -ErrorAction SilentlyContinue`);
  }
}

// ---------------------------------------------------------------------------
// Perch Terminal
// ---------------------------------------------------------------------------

async function download(url, file) {
  const r = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(900000) });
  if (!r.ok || !r.body) throw new Error(`download returns ${r.status}`);
  const w = fs.createWriteStream(file);
  for await (const chunk of r.body) if (!w.write(chunk)) await new Promise(res => w.once('drain', res));
  await new Promise(res => w.end(res));
  return fs.statSync(file).size;
}

function findFile(dir, name, depth = 4) {
  if (depth < 0 || !fs.existsSync(dir)) return null;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isFile() && e.name.toLowerCase() === name.toLowerCase()) return p;
    if (e.isDirectory() && !e.isSymbolicLink()) { const f = findFile(p, name, depth - 1); if (f) return f; }
  }
  return null;
}

const PS = (script, ms = 30000) => run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { ms });
// Brings the app's main window to the front and captures just that window (the whole screen if
// there is none): the runner's own console sits on top of the desktop otherwise.
const SHOT_PS = (file) => `
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
Add-Type @"
using System; using System.Runtime.InteropServices;
public struct RECT { public int Left, Top, Right, Bottom; }
public static class W { [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n); }
"@
$p = Get-Process | Where-Object { $_.ProcessName -match 'Perch' -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1
$b = [System.Windows.Forms.SystemInformation]::VirtualScreen
$x = $b.Left; $y = $b.Top; $w = $b.Width; $h = $b.Height
if ($p) { [W]::ShowWindow($p.MainWindowHandle, 9) | Out-Null; [W]::SetForegroundWindow($p.MainWindowHandle) | Out-Null; Start-Sleep -Milliseconds 700
  $r = New-Object RECT; if ([W]::GetWindowRect($p.MainWindowHandle, [ref]$r) -and ($r.Right - $r.Left) -gt 200) { $x = $r.Left; $y = $r.Top; $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top } }
$i = New-Object System.Drawing.Bitmap $w, $h; $g = [System.Drawing.Graphics]::FromImage($i); $g.CopyFromScreen($x, $y, 0, 0, $i.Size)
$i.Save('${file.replace(/'/g, "''")}', [System.Drawing.Imaging.ImageFormat]::Png)`;

async function screenshot(file) {
  if (IS_WIN) await PS(SHOT_PS(file));
  else if (IS_MAC) await run('screencapture', ['-x', '-t', 'png', file], { ms: 30000 });
  return fs.existsSync(file) && fs.statSync(file).size > 1000 ? path.basename(file) : null;
}

async function windowTitles(match) {
  if (IS_WIN) {
    const r = await PS(`Get-Process | Where-Object { $_.MainWindowTitle -and $_.ProcessName -match '${match}' } | ForEach-Object { $_.MainWindowTitle }`);
    return r.out.split('\n').map(s => s.trim()).filter(Boolean).slice(0, 4);
  }
  // Needs Accessibility access, which a runner may not have: null means "couldn't tell".
  const r = await run('osascript', ['-e', `tell application "System Events" to get name of every window of (every process whose name contains "Perch")`], { ms: 15000 });
  return r.code === 0 ? r.out.split(',').map(s => s.trim()).filter(Boolean).slice(0, 4) : null;
}

/** Download and install Perch Terminal; { exe, mount } with res.version / res.size / res.install filled in. */
async function installApp(work, res) {
  const plat = res.platform;
  let exe = null, mount = null;
  {
    log(`downloading the ${plat} build`);
    const file = path.join(work, IS_WIN ? 'setup.exe' : 'app.dmg');
    res.size = await download(DOWNLOADS[plat], file);
    if (IS_WIN) {
      log('installing silently');
      const inst = await run(file, ['/S'], { ms: 300000 });
      res.install = { code: inst.code, ms: inst.ms };
      // A one-click installer may open the app when it finishes: close it so the launch below is ours.
      await sleep(3000);
      await PS("Get-Process | Where-Object { $_.ProcessName -match 'Perch' } | Stop-Process -Force -ErrorAction SilentlyContinue");
      const roots = [path.join(process.env.LOCALAPPDATA || '', 'Programs'), process.env.ProgramFiles || 'C:\\Program Files'];
      for (const r of roots) { exe = findFile(r, 'Perch Terminal.exe', 2) || findFile(r, 'perch-terminal.exe', 2); if (exe) break; }
      if (exe) res.version = clip((await PS(`(Get-Item '${exe.replace(/'/g, "''")}').VersionInfo.ProductVersion`)).out, 30).replace(/^(\d+\.\d+\.\d+)\.0$/, '$1');
    } else {
      mount = path.join(work, 'mnt');
      fs.mkdirSync(mount);
      const at = await run('hdiutil', ['attach', '-nobrowse', '-readonly', '-mountpoint', mount, file], { ms: 180000 });
      res.install = { code: at.code, ms: at.ms };
      const app = fs.readdirSync(mount).find(n => n.endsWith('.app'));
      if (app) {
        const plist = fs.readFileSync(path.join(mount, app, 'Contents', 'Info.plist'), 'utf8');
        const key = (k) => (plist.match(new RegExp(`<key>${k}</key>\\s*<string>([^<]+)</string>`)) || [])[1];
        exe = path.join(mount, app, 'Contents', 'MacOS', key('CFBundleExecutable') || '');
        res.version = key('CFBundleShortVersionString') || '';
      }
    }
  }
  return { exe, mount };
}

async function desktopCheck(spec, outDir) {
  const seconds = Math.min(60, Math.max(12, Number(spec.seconds) || 25));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'perch-desk-'));
  const plat = IS_WIN ? 'windows' : (process.arch === 'arm64' ? 'mac-arm64' : 'mac-x64');
  const res = { platform: plat, seconds };
  let exe = null, child = null, mount = null;
  try {
    ({ exe, mount } = await installApp(work, res));
    if (!exe || !fs.existsSync(exe)) { res.error = 'the app was not installed'; return res; }
    log('launching the app');
    const home = freshHome();
    let exited = null;
    let logText = '';
    // Each GitHub machine is brand new, so the normal profile is already a first launch. (Pointing
    // APPDATA at an empty folder makes Electron fail with "Failed to get 'appData' path" on Windows.)
    child = spawn(exe, [], { env: { ...(IS_WIN ? process.env : homeEnv(home)), ELECTRON_ENABLE_LOGGING: '1' }, cwd: home, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', d => { if (logText.length < 200000) logText += d; });
    child.stderr.on('data', d => { if (logText.length < 200000) logText += d; });
    child.on('exit', (code, signal) => { exited = { code, signal }; });
    await sleep(8000);
    const s1 = await screenshot(path.join(outDir, 'desktop-1.png'));
    await sleep((seconds - 8) * 1000);
    res.windows = await windowTitles('Perch');
    const s2 = await screenshot(path.join(outDir, 'desktop-2.png'));
    res.alive = !exited;
    res.exit = exited ? exited.code : null;
    // Nothing changed between the two captures: keep only the later one.
    const p1 = path.join(outDir, 'desktop-1.png'), p2 = path.join(outDir, 'desktop-2.png');
    if (s1 && s2 && fs.readFileSync(p1).equals(fs.readFileSync(p2))) fs.rmSync(p1);
    res.shots = [s1, s2].filter(n => n && fs.existsSync(path.join(outDir, n)));
    res.errors = [...new Set(logText.split('\n').map(l => l.trim()).filter(l => /\b(error|fatal|uncaught|exception|crash|cannot|failed)\b/i.test(l) && !/dbus|gpu|viz|GLES|Electron Security Warning|DevTools/i.test(l)).map(l => clip(l.replace(/^\[[^\]]*\]\s*/, ''), 200)))].slice(0, 5);
    const rel = ['Perch AI Desktop', 'desktop-runtime.log'];
    res.runtime = readRuntimeLog(IS_WIN
      ? [path.join(process.env.APPDATA || '', ...rel)]
      : [path.join(home, 'Library', 'Application Support', ...rel), path.join(os.homedir(), 'Library', 'Application Support', ...rel)]);
    return res;
  } finally {
    if (child && child.exitCode == null) { try { child.kill('SIGKILL'); } catch (e) { /* gone */ } }
    if (IS_WIN) await PS("Get-Process | Where-Object { $_.ProcessName -match 'Perch' } | Stop-Process -Force -ErrorAction SilentlyContinue");
    if (mount) await run('hdiutil', ['detach', mount, '-force'], { ms: 60000 });
  }
}

// ---------------------------------------------------------------------------
// App agent session: the bot's AI drives Perch Terminal here, one action at a time
// ---------------------------------------------------------------------------
// Neither side can reach the other directly, so messages go through a throwaway branch of this
// repo (s-<job id>, made and deleted by the bot). Everything on it is encrypted: this runner makes a
// session key that only the bot can unwrap (RSA-OAEP), and every command and screen after that is
// AES-256-GCM with that key, so commands that don't come from the bot are rejected.

const APP_BLOCKED = /billing|checkout|payment|stripe|paypal|alipay|subscribe|upgrade|pricing|\bpass=|delete.?account|logout|sign.?out/i;
const SNAPSHOT_JS = `(() => {
  const vis = (el) => { const r = el.getBoundingClientRect(); const st = getComputedStyle(el); return r.width > 2 && r.height > 2 && st.visibility !== 'hidden' && st.display !== 'none' && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth; };
  const sel = 'button, a[href], input:not([type=hidden]), textarea, select, [role=button], [role=link], [role=menuitem], [role=option], [role=tab], [role=checkbox], [role=switch], [role=combobox], [role=textbox], [contenteditable=true], [contenteditable=""]';
  const els = [...document.querySelectorAll(sel)].filter(vis).slice(0, 80);
  window.__perchEls = els;
  const clean = (t, n) => String(t || '').replace(/\\s+/g, ' ').trim().slice(0, n);
  const isField = (el) => el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) || /^(textbox|combobox)$/.test(el.getAttribute('role') || '');
  const label = (el) => clean(isField(el) ? (el.getAttribute('aria-label') || el.placeholder || el.getAttribute('data-placeholder') || el.title || el.name) : (el.getAttribute('aria-label') || el.innerText || el.value || el.title || el.getAttribute('alt') || el.name), 70);
  const value = (el) => (el.tagName === 'SELECT' ? (el.selectedOptions[0] || {}).text : el.isContentEditable ? el.innerText : el.value);
  const elements = els.map((el, i) => {
    const role = el.getAttribute('role') || (el.isContentEditable ? 'textbox' : el.tagName.toLowerCase()) + (el.type && el.tagName !== 'BUTTON' ? ':' + el.type : '');
    const state = [el.disabled || el.getAttribute('aria-disabled') === 'true' ? 'disabled' : '', el.checked || el.getAttribute('aria-checked') === 'true' ? 'checked' : '', el.getAttribute('aria-expanded') === 'true' ? 'expanded' : '', el.getAttribute('aria-selected') === 'true' ? 'selected' : '', document.activeElement === el ? 'focused' : ''].filter(Boolean).join(',');
    const v = isField(el) && el.type !== 'password' ? clean(value(el), 160) : '';
    return (i + 1) + '. ' + role + ': ' + (label(el) || '(no label)') + (state ? ' [' + state + ']' : '') + (isField(el) ? (v ? ' = "' + v + '"' : ' = (empty)') : '');
  });
  const overlay = [...document.querySelectorAll('[role=dialog], [role=alertdialog], [role=menu], [role=listbox], [aria-modal=true]')].filter(vis).map(e => e.innerText.replace(/\\s+/g, ' ').trim()).join(' | ').slice(0, 800);
  return JSON.stringify({ title: document.title, url: location.href, overlay, text: (document.body ? document.body.innerText : '').replace(/[ \\t]+/g, ' ').replace(/\\n{2,}/g, '\\n').trim().slice(0, 3000), elements });
})()`;
const VK = { Enter: 13, Escape: 27, Tab: 9, Backspace: 8, Delete: 46, Space: 32, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, PageUp: 33, PageDown: 34, Home: 36, End: 35 };

function cdpConnect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    let seq = 0;
    const pending = new Map();
    const listeners = [];
    ws.onopen = () => resolve({
      send: (method, params = {}) => new Promise((res, rej) => { const id = ++seq; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params })); }),
      on: (fn) => listeners.push(fn),
      close: () => { try { ws.close(); } catch (e) { /* closed */ } }
    });
    ws.onerror = () => reject(new Error('DevTools connection failed'));
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.id && pending.has(msg.id)) { const p = pending.get(msg.id); pending.delete(msg.id); if (msg.error) p.rej(new Error(msg.error.message)); else p.res(msg.result); } else if (msg.method) for (const fn of listeners) fn(msg);
    };
  });
}

async function pressKey(cdp, combo) {
  const parts = String(combo).split('+').map(x => x.trim()).filter(Boolean);
  const name = parts.pop();
  const mods = { Alt: 1, Control: 2, Ctrl: 2, Meta: 4, Cmd: 4, Shift: 8 };
  const modifiers = parts.reduce((m, p) => m | (mods[p] || 0), 0);
  const single = name.length === 1;
  const vk = VK[name] || (single ? name.toUpperCase().charCodeAt(0) : 0);
  if (!vk) throw new Error(`unknown key ${name}`);
  const key = name === 'Space' ? ' ' : name;
  const code = single ? (/[a-z]/i.test(name) ? `Key${name.toUpperCase()}` : `Digit${name}`) : name;
  const text = single && !modifiers ? name : name === 'Enter' ? '\r' : name === 'Space' ? ' ' : undefined;
  await cdp.send('Input.dispatchKeyEvent', { type: text ? 'keyDown' : 'rawKeyDown', key, code, windowsVirtualKeyCode: vk, modifiers, ...(text ? { text } : {}) });
  await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key, code, windowsVirtualKeyCode: vk, modifiers });
}
async function clickAt(cdp, x, y) {
  for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased']) await cdp.send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 });
}
async function elementCenter(cdp, n) {
  const r = await cdp.send('Runtime.evaluate', { returnByValue: true, expression: `(() => { const el = (window.__perchEls || [])[${Number(n) - 1}]; if (!el) return null; el.scrollIntoView({ block: 'center', inline: 'center' }); const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()` });
  return r?.result?.value || null;
}

export const boxed = (key, obj) => {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(zlib.gzipSync(Buffer.from(JSON.stringify(obj)))), c.final()]);
  return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') };
};
export const unboxed = (key, b) => {
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(b.iv, 'base64'));
  d.setAuthTag(Buffer.from(b.tag, 'base64'));
  return JSON.parse(zlib.gunzipSync(Buffer.concat([d.update(Buffer.from(b.data, 'base64')), d.final()])).toString('utf8'));
};

const ghHead = (raw) => ({ authorization: `Bearer ${process.env.GH_TOKEN}`, accept: raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'perch-repro-runner', 'cache-control': 'no-cache' });
async function mailPut(branch, name, obj) {
  const r = await fetch(`https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/contents/${name}`, { method: 'PUT', headers: { ...ghHead(false), 'content-type': 'application/json' }, body: JSON.stringify({ message: `session ${name}`, branch, content: Buffer.from(JSON.stringify(obj)).toString('base64') }), signal: AbortSignal.timeout(60000) });
  if (!r.ok) throw new Error(`mailbox write ${r.status}`);
}
async function mailGet(branch, name) {
  const r = await fetch(`https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/contents/${name}?ref=${branch}&t=${Date.now()}`, { headers: ghHead(true), signal: AbortSignal.timeout(30000) }).catch(() => null);
  if (!r || r.status === 404 || !r.ok) return null;
  try { return JSON.parse(await r.text()); } catch (e) { return null; }
}

async function appSession(spec, id) {
  const branch = `s-${id}`;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'perch-agent-'));
  const res = { platform: IS_WIN ? 'windows' : (process.arch === 'arm64' ? 'mac-arm64' : 'mac-x64') };
  let child = null, cdp = null, mount = null, exe = null;
  const errors = [], failed = [];
  try {
    ({ exe, mount } = await installApp(work, res));
    if (!exe || !fs.existsSync(exe)) throw new Error('the app was not installed');
    const port = 9333;
    const home = freshHome();
    log('launching the app with remote debugging');
    child = spawn(exe, [`--remote-debugging-port=${port}`], { env: { ...(IS_WIN ? process.env : homeEnv(home)) }, cwd: home, stdio: 'ignore' });
    let page = null;
    for (let i = 0; i < 90 && !page; i++) {
      await sleep(1000);
      try { page = (await (await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(2000) })).json()).find(t => t.type === 'page' && /^https?:/.test(t.url)) || null; } catch (e) { /* not up yet */ }
    }
    if (!page) throw new Error('Perch Terminal did not open a page for DevTools');
    cdp = await cdpConnect(page.webSocketDebuggerUrl);
    for (const d of ['Page', 'Runtime', 'Network']) await cdp.send(`${d}.enable`);
    cdp.on((m) => {
      const p = m.params || {};
      if (m.method === 'Runtime.exceptionThrown') errors.push(clip(p.exceptionDetails?.exception?.description || p.exceptionDetails?.text, 200));
      else if (m.method === 'Runtime.consoleAPICalled' && p.type === 'error') errors.push(clip((p.args || []).map(a => a.value ?? a.description ?? '').join(' '), 200));
      else if (m.method === 'Network.responseReceived' && p.response?.status >= 400 && /XHR|Fetch|Document/.test(p.type)) failed.push(`${p.response.status} ${clip(p.response.url, 120)}`);
    });
    await sleep(4000);
    const observe = async (n, note = '') => {
      const v = await cdp.send('Runtime.evaluate', { expression: SNAPSHOT_JS, returnByValue: true }).catch(() => null);
      let snap = {};
      try { snap = JSON.parse(v?.result?.value || '{}'); } catch (e) { /* page gone */ }
      if (snap.url && APP_BLOCKED.test(snap.url)) {
        await cdp.send('Page.navigate', { url: 'https://app.perchai.app/' }).catch(() => {});
        note = `blocked: tests never open ${clip(snap.url, 80)}; went back`;
      }
      const shot = await cdp.send('Page.captureScreenshot', { format: 'jpeg', quality: 70 }).catch(() => null);
      return { n, title: clip(snap.title, 100), url: clip(snap.url, 200), overlay: snap.overlay || '', text: snap.text || '', elements: (snap.elements || []).slice(0, 80), errors: errors.splice(0).slice(0, 5), failed: failed.splice(0).slice(0, 5), note, shot: shot?.data && n <= 40 ? { name: `app-${n}.jpg`, b64: shot.data } : null };
    };
    const key = crypto.randomBytes(32);
    const pem = fs.readFileSync(path.join(HERE, 'bot-public.pem'), 'utf8');
    const wrapped = crypto.publicEncrypt({ key: pem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key).toString('base64');
    await mailPut(branch, 'hello.json', { v: 1, id, key: wrapped, box: boxed(key, { obs: await observe(0), version: res.version || '' }) });
    log('session open, waiting for the bot');
    let steps = 0;
    for (let n = 1; n <= 40; n++) {
      let cmd = null;
      for (let w = 0; w < 160 && !cmd; w++) { // up to 4 minutes for the bot's next move
        const msg = await mailGet(branch, `cmd-${n}.json`);
        if (msg) { try { cmd = unboxed(key, msg); } catch (e) { throw new Error('a command that is not from the bot'); } }
        else await sleep(1500);
      }
      if (!cmd || cmd.action === 'end') break;
      steps += 1;
      let note = '';
      try {
        if (cmd.action === 'click') { const c = await elementCenter(cdp, cmd.target); if (!c) note = `no element ${cmd.target}`; else await clickAt(cdp, c.x, c.y); }
        else if (cmd.action === 'type') {
          if (cmd.target) { const c = await elementCenter(cdp, cmd.target); if (c) await clickAt(cdp, c.x, c.y); else note = `no element ${cmd.target}`; }
          if (!note) await cdp.send('Input.insertText', { text: String(cmd.text || '').slice(0, 500) });
        } else if (cmd.action === 'key') await pressKey(cdp, cmd.key || 'Enter');
        else if (cmd.action === 'scroll') await cdp.send('Runtime.evaluate', { expression: `window.scrollBy(0, ${/up/i.test(cmd.text || '') ? -600 : 600})` });
        else if (cmd.action === 'wait') await sleep(Math.min(15000, Math.max(300, Number(cmd.ms) || 2000)));
      } catch (e) { note = clip(e.message, 120); }
      await sleep(1200);
      await mailPut(branch, `obs-${n}.json`, boxed(key, { obs: await observe(n, note) }));
    }
    return { ok: true, steps, version: res.version || '' };
  } catch (e) {
    return { ok: false, error: clip(e.message, 200), version: res.version || '' };
  } finally {
    if (cdp) cdp.close();
    if (child && child.exitCode == null) { try { child.kill('SIGKILL'); } catch (e) { /* gone */ } }
    if (IS_WIN) await PS("Get-Process | Where-Object { $_.ProcessName -match 'Perch' } | Stop-Process -Force -ErrorAction SilentlyContinue");
    if (mount) await run('hdiutil', ['detach', mount, '-force'], { ms: 60000 });
  }
}

// ---------------------------------------------------------------------------
// Encrypted result
// ---------------------------------------------------------------------------

/** gzip + AES-256-GCM, the key wrapped with RSA-OAEP-SHA256 for the bot. */
export function sealFor(publicKeyPem, payload) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(zlib.gzipSync(Buffer.from(JSON.stringify(payload)))), c.final()]);
  const wrapped = crypto.publicEncrypt({ key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
  return Buffer.from(JSON.stringify({ v: 1, key: wrapped.toString('base64'), iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') }));
}

async function main() {
  const id = String(process.env.JOB_ID || '');
  if (!/^[a-z0-9][a-z0-9-]{5,40}$/.test(id)) throw new Error('bad job id');
  const job = JSON.parse(process.env.JOB || '{}');
  const outDir = path.join(HERE, 'out');
  const shotsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'perch-shots-'));
  fs.mkdirSync(outDir, { recursive: true });
  const result = { os: IS_WIN ? 'windows' : IS_MAC ? 'macos' : process.platform, osVersion: clip(os.release(), 40), arch: process.arch };
  if (IS_WIN) result.osName = clip((await PS('(Get-CimInstance Win32_OperatingSystem).Caption')).out, 60);
  if (IS_MAC) result.osName = `macOS ${clip(spawnSync('sw_vers', ['-productVersion']).stdout?.toString(), 20)}`;
  try { if (job.cli) result.cli = await cliCheck(job.cli); } catch (e) { result.cli = { error: clip(e.message, 200) }; }
  try { if (job.tui && IS_WIN) result.tui = await tuiWindows(job.tui, shotsDir); } catch (e) { result.tui = { ok: false, error: clip(e.message, 200) }; }
  try { if (job.desktop) result.desktop = await desktopCheck(job.desktop, shotsDir); } catch (e) { result.desktop = { error: clip(e.message, 200) }; }
  try { if (job.app?.session) result.app = await appSession(job.app, id); } catch (e) { result.app = { ok: false, error: clip(e.message, 200) }; }
  const files = fs.readdirSync(shotsDir).filter(n => /^[a-z0-9-]+\.png$/.test(n)).sort().slice(0, 10)
    .map(name => ({ name, b64: fs.readFileSync(path.join(shotsDir, name)).toString('base64') }));
  const pem = fs.readFileSync(path.join(HERE, 'bot-public.pem'), 'utf8');
  fs.writeFileSync(path.join(outDir, 'result.bin'), sealFor(pem, { id, result, files }));
  log(`done (${files.length} screenshots, sealed for the bot)`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error('[repro] failed:', e.message); process.exit(1); });
}
