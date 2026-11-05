#!/usr/bin/env node
// Local dashboard server: the React dashboard (reports/dashboard.html, built
// from dashboard/) plus a small JSON API over the run state.
//
//   node hooks/serve.js [--port <n>] [--no-open] [--background] [--idle-minutes <n>]
//
// It shows source snippets and file paths, so it is built to be reachable
// only by the person who started it:
//   - listens on 127.0.0.1 only;
//   - every API call needs a random per-run token, handed to the browser in
//     the URL fragment (#token=…), which browsers never send to servers, put
//     in Referer headers, or log;
//   - the Host header must name this server (stops DNS rebinding: a public
//     site re-pointing its own hostname at 127.0.0.1);
//   - POST needs the token header, JSON content type and a local Origin, so
//     another site cannot submit a form or fetch to it; no CORS headers are
//     ever sent;
//   - the page gets a strict Content-Security-Policy that allows only its own
//     inline scripts (by hash) and no network access beyond this server.
// The only action is "rescan" (scan.js --all). Nothing writes source files.
// Zero dependencies, like the rest of the tools.
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { helpRequested, projectRoot, openPath } = require('./config');

const USAGE = `Usage: node hooks/serve.js [--port <n>] [--no-open] [--background] [--idle-minutes <n>]

Serves the security dashboard on http://127.0.0.1 (local only, token-protected).
  --port <n>           port to listen on (default: a free one)
  --no-open            print the URL instead of opening a browser
  --background         start detached, print the URL, and return
  --idle-minutes <n>   stop after n minutes without a request (background default: 60)`;

const DIR = path.resolve(__dirname, '..');
const PAGE = path.join(DIR, 'reports', 'dashboard.html');
const SCAN = path.join(DIR, 'hooks', 'scan.js');
const SCAN_TIMEOUT_MS = 10 * 60 * 1000;

function arg(argv, name, fallback) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : fallback;
}

// sha256 hashes of every inline <script> in the page, for its CSP.
function scriptHashes(html) {
  const out = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    if (/\bsrc\s*=/.test(m[1]) || /type\s*=\s*["']application\/json["']/i.test(m[1])) continue;
    out.push(`'sha256-${crypto.createHash('sha256').update(m[2], 'utf8').digest('base64')}'`);
  }
  return out;
}

function securityHeaders(extra = {}) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cache-Control': 'no-store',
    ...extra,
  };
}

function createServer({ token, getPort, onActivity = () => {} }) {
  let scanning = null; // Promise while a scan runs
  let lastScan = null;

  const tokenBuf = Buffer.from(token);
  const tokenOk = req => {
    const got = Buffer.from(String(req.headers['x-sc-token'] || ''));
    return got.length === tokenBuf.length && crypto.timingSafeEqual(got, tokenBuf);
  };
  const localNames = () => {
    const p = getPort();
    return new Set([`127.0.0.1:${p}`, `localhost:${p}`, `[::1]:${p}`]);
  };

  const send = (res, status, body, headers = {}) => {
    const isJson = typeof body !== 'string' && !Buffer.isBuffer(body);
    const data = isJson ? JSON.stringify(body) : body;
    res.writeHead(status, securityHeaders({
      'Content-Type': isJson ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
      'Content-Length': Buffer.byteLength(data),
      ...headers,
    }));
    res.end(data);
  };

  const runScan = () => {
    if (scanning) return scanning;
    scanning = new Promise(resolve => {
      const started = Date.now();
      const child = spawn(process.execPath, [SCAN, '--all'], {
        cwd: projectRoot(),
        env: { ...process.env, SECURE_CODING_REPORT: 'off' },
        stdio: ['ignore', 'ignore', 'pipe'],
        windowsHide: true,
      });
      let err = '';
      child.stderr.on('data', d => { if (err.length < 4000) err += d; });
      const timer = setTimeout(() => child.kill(), SCAN_TIMEOUT_MS);
      child.on('close', code => {
        clearTimeout(timer);
        // scan.js exits 2 when it finds something: that is a successful scan.
        lastScan = { at: new Date().toISOString(), ms: Date.now() - started, ok: code === 0 || code === 2, error: code === 0 || code === 2 ? null : (err.trim() || `exit ${code}`) };
        scanning = null;
        resolve(lastScan);
      });
      child.on('error', e => {
        clearTimeout(timer);
        lastScan = { at: new Date().toISOString(), ms: Date.now() - started, ok: false, error: e.message };
        scanning = null;
        resolve(lastScan);
      });
    });
    return scanning;
  };

  return http.createServer(async (req, res) => {
    onActivity();
    // DNS rebinding: a page on evil.example whose DNS now points at 127.0.0.1
    // still sends "Host: evil.example". Only our own names are served.
    if (!localNames().has(String(req.headers.host || '').toLowerCase())) {
      return send(res, 421, 'Misdirected request\n');
    }
    // Only the path is used for routing; the query string is ignored.
    const url = { pathname: String(req.url || '/').split('?')[0] };

    if (url.pathname === '/' && req.method === 'GET') {
      let html;
      try { html = fs.readFileSync(PAGE, 'utf8'); } catch {
        return send(res, 503, 'Dashboard not built. Run: npm --prefix dashboard ci && npm --prefix dashboard run build\n');
      }
      const csp = [
        "default-src 'none'",
        `script-src ${scriptHashes(html).join(' ') || "'none'"}`,
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
      ].join('; ');
      return send(res, 200, html, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': csp });
    }

    if (!url.pathname.startsWith('/api/')) return send(res, 404, 'Not found\n');
    if (!tokenOk(req)) return send(res, 401, { error: 'missing or wrong token' });

    if (url.pathname === '/api/snapshot' && req.method === 'GET') {
      let snap;
      try {
        delete require.cache[require.resolve('./data')];
        snap = require('./data').snapshot();
      } catch (e) {
        return send(res, 500, { error: e.message });
      }
      snap.server = { live: true, scanning: Boolean(scanning), lastScan };
      return send(res, 200, snap);
    }

    if (url.pathname === '/api/scan' && req.method === 'POST') {
      const origin = req.headers.origin;
      if (origin && !localNames().has(origin.replace(/^https?:\/\//, '').toLowerCase())) {
        return send(res, 403, { error: 'cross-origin request refused' });
      }
      if (!/^application\/json\b/i.test(String(req.headers['content-type'] || ''))) {
        return send(res, 415, { error: 'expected application/json' });
      }
      req.resume(); // no body is read; the request carries no parameters
      if (scanning) return send(res, 409, { error: 'a scan is already running' });
      const result = await runScan();
      return send(res, result.ok ? 200 : 500, result);
    }

    return send(res, 405, { error: 'method not allowed' });
  });
}

function start(argv) {
  const port = Number(arg(argv, '--port', 0)) || 0;
  const idleMin = Number(arg(argv, '--idle-minutes', argv.includes('--background-child') ? 60 : 0)) || 0;
  const token = crypto.randomBytes(24).toString('base64url');
  let actualPort = port;
  let idleTimer = null;
  const touch = () => {
    if (!idleMin) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => { server.close(); process.exit(0); }, idleMin * 60 * 1000);
    idleTimer.unref();
  };
  const server = createServer({ token, getPort: () => actualPort, onActivity: touch });
  server.listen(port, '127.0.0.1', () => {
    actualPort = server.address().port;
    const url = `http://127.0.0.1:${actualPort}/#token=${token}`;
    touch();
    const urlFile = arg(argv, '--url-file', null);
    if (urlFile) fs.writeFileSync(urlFile, url, { mode: 0o600 });
    else {
      process.stdout.write(`secure-coding dashboard: ${url}\n(local only; the token in the link is the key — do not share it. Ctrl+C to stop.)\n`);
      if (!argv.includes('--no-open')) openPath(url);
    }
  });
  server.on('error', e => { process.stderr.write(`serve: ${e.message}\n`); process.exit(1); });
  return server;
}

// --background: start a detached copy and wait for it to report its URL.
// Used by the MCP tool, which cannot keep a long-running child itself.
function background(argv) {
  const urlFile = path.join(require('os').tmpdir(), `sc-dashboard-${process.pid}-${crypto.randomBytes(4).toString('hex')}.url`);
  const rest = argv.filter(a => a !== '--background');
  const child = spawn(process.execPath, [__filename, ...rest, '--background-child', '--url-file', urlFile, '--no-open'], {
    cwd: process.cwd(), detached: true, stdio: 'ignore', windowsHide: true,
  });
  child.unref();
  const deadline = Date.now() + 10000;
  const sleeper = new Int32Array(new SharedArrayBuffer(4));
  while (Date.now() < deadline) {
    try {
      const url = fs.readFileSync(urlFile, 'utf8');
      if (url) {
        fs.unlinkSync(urlFile);
        process.stdout.write(`${url}\n`);
        if (!argv.includes('--no-open')) openPath(url);
        return 0;
      }
    } catch { /* not written yet */ }
    Atomics.wait(sleeper, 0, 0, 100);
  }
  process.stderr.write('serve: the dashboard did not start within 10s\n');
  return 1;
}

if (require.main === module) {
  const argv = process.argv.slice(2);
  if (!helpRequested(argv, USAGE)) {
    if (argv.includes('--background')) process.exit(background(argv));
    start(argv);
  }
}

module.exports = { createServer, scriptHashes };
