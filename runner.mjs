// PerchBot bug-repro runner for GitHub-hosted Windows and macOS machines.
//
// Reads a job spec from $JOB, tries the real Perch CLI and/or Perch Terminal on this OS, signed
// out and from empty folders, and writes out/result.bin: the result and screenshots, gzipped and
// encrypted for the bot (AES-256-GCM, key wrapped with the bot's RSA public key in
// bot-public.pem). The workflow logs only say which step ran, never what came out.
//
// Job spec: { cli?: { version, acp? }, desktop?: { seconds? } }

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

async function cliCheck(spec) {
  const version = String(spec.version || 'latest');
  if (!/^(latest|\d+\.\d+\.\d+(-[\w.]+)?)$/.test(version)) throw new Error('bad version');
  const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'perch-cli-'));
  const home = freshHome();
  const env = homeEnv(home);
  log(`installing perchai-cli@${version}`);
  // npm through node itself: Windows won't start npm.cmd without a shell, and no shell means no quoting trouble.
  const install = await run(process.execPath, [npmCli(), 'install', '--prefix', prefix, `perchai-cli@${version}`, '--no-audit', '--no-fund', '--loglevel=error'], { env, cwd: prefix, ms: 300000 });
  const bin = path.join(prefix, 'node_modules', 'perchai-cli', 'bin', 'perch');
  const out = { node: process.version, install: { code: install.code, ms: install.ms } };
  if (install.code !== 0 || !fs.existsSync(bin)) {
    out.install.err = clip(String(install.out).split('\n').find(l => /ERR!|error/i.test(l)) || firstLine(install.out) || 'the perch command was not installed', 300);
    return out;
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(prefix, 'node_modules', 'perchai-cli', 'package.json'), 'utf8'));
  out.version = pkg.version;
  const cwd = path.join(home, 'work');
  log('perch --help / status');
  const help = await run(process.execPath, [bin, '--help'], { env, cwd, ms: 30000 });
  const status = await run(process.execPath, [bin, 'status'], { env, cwd, ms: 30000 });
  out.help = { code: help.code, killed: help.killed, crash: CRASH.test(help.out), out: clip(firstLine(help.out), 160) };
  out.status = { code: status.code, killed: status.killed, crash: CRASH.test(status.out), out: clip(firstLine(status.out), 160) };
  if (spec.acp) { log('ACP handshake'); out.acp = await acpHandshake(bin, env, cwd); }
  return out;
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
  try { if (job.desktop) result.desktop = await desktopCheck(job.desktop, shotsDir); } catch (e) { result.desktop = { error: clip(e.message, 200) }; }
  const files = fs.readdirSync(shotsDir).filter(n => /^[a-z0-9-]+\.png$/.test(n)).slice(0, 4)
    .map(name => ({ name, b64: fs.readFileSync(path.join(shotsDir, name)).toString('base64') }));
  const pem = fs.readFileSync(path.join(HERE, 'bot-public.pem'), 'utf8');
  fs.writeFileSync(path.join(outDir, 'result.bin'), sealFor(pem, { id, result, files }));
  log(`done (${files.length} screenshots, sealed for the bot)`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error('[repro] failed:', e.message); process.exit(1); });
}
