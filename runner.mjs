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
  const inner = `title ${marker} & cd /d ${work} & perch`; // the temp path has no spaces
  await PS(terminal === 'wt'
    ? `Start-Process wt.exe -ArgumentList '-w new --size ${cols},${rows} --title ${marker} --suppressApplicationTitle cmd.exe /k "${psq(inner)}"'`
    : `Start-Process conhost.exe -ArgumentList 'cmd.exe /k mode con: cols=${cols} lines=${rows} & ${psq(inner)}'`, 30000);
  // The cmd.exe that runs perch (to read its console) and the window showing it (for keys and pictures).
  let cmdPid = 0, hwnd = 0;
  for (let i = 0; i < 20 && !(cmdPid && hwnd); i++) {
    await sleep(1000);
    const found = await PS(`${WIN_API}
$c = Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '${marker}' } | Select-Object -First 1
"IDS:$($c.ProcessId):$([W]::Find('${marker}'))"`, 30000);
    const m = found.out.match(/IDS:(\d*):(\d*)/);
    if (m) { cmdPid = Number(m[1]) || cmdPid; hwnd = Number(m[2]) || hwnd; }
  }
  if (!cmdPid || !hwnd) return { ok: false, error: `the ${terminal === 'wt' ? 'Windows Terminal' : 'console'} window did not open` };
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

async function desktopCheck(spec, outDir) {
  const seconds = Math.min(60, Math.max(12, Number(spec.seconds) || 25));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'perch-desk-'));
  const plat = IS_WIN ? 'windows' : (process.arch === 'arm64' ? 'mac-arm64' : 'mac-x64');
  const res = { platform: plat, seconds };
  let exe = null, child = null, mount = null;
  try {
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
    return res;
  } finally {
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
  const files = fs.readdirSync(shotsDir).filter(n => /^[a-z0-9-]+\.png$/.test(n)).sort().slice(0, 10)
    .map(name => ({ name, b64: fs.readFileSync(path.join(shotsDir, name)).toString('base64') }));
  const pem = fs.readFileSync(path.join(HERE, 'bot-public.pem'), 'utf8');
  fs.writeFileSync(path.join(outDir, 'result.bin'), sealFor(pem, { id, result, files }));
  log(`done (${files.length} screenshots, sealed for the bot)`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error('[repro] failed:', e.message); process.exit(1); });
}
