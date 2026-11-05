#!/usr/bin/env node
// Dependency guard. AI agents add packages by name, and some of those names
// do not exist: the model made them up. Attackers register such names
// ("slopsquatting") so the next agent that hallucinates the same name installs
// their code. This checks every dependency a change ADDS against its registry:
//
//   dep-not-found       the package does not exist                (critical)
//   dep-new-package     first published less than N days ago      (high)
//   dep-install-script  runs a script when installed (npm)        (medium)
//   dep-sdist-only      no wheel, so setup.py runs on install     (low)
//
// npm (package.json) and PyPI (requirements*.txt, pyproject.toml).
//
// What leaves the machine: the NAME of each newly added dependency, sent to
// the public registry it would be installed from. Names that would come from
// a private registry are never sent — querying the public registry for an
// internal name leaks it, and is exactly the reconnaissance a dependency-
// confusion attack starts with. Skipped:
//   - names matching "deps.private" globs in .securecodingrc.json
//   - npm scopes mapped to another registry in .npmrc (@acme:registry=...),
//     and everything when .npmrc sets a non-public default registry
//   - all PyPI names when pip is pointed at another index (--index-url / -i
//     in the requirements file, PIP_INDEX_URL, or pip.conf index-url)
// SECURE_CODING_DEPS_OFFLINE=1 or "deps": { "enabled": false } sends nothing.
//
// Usage: node hooks/deps.js [--staged | --file <manifest> | --diff <rev>] [--json] [--strict]
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const tls = require('tls');
const { execFileSync } = require('child_process');
const { helpRequested, loadConfig, projectRoot } = require('./config');

const USAGE = `Usage: node hooks/deps.js [--staged | --file <manifest> | --diff <rev>] [--json] [--strict]

Checks dependencies ADDED by a change against npm and PyPI: missing packages
(likely hallucinated names), packages first published recently, and install
scripts. Default compares the working tree with HEAD.
  --staged        compare the index with HEAD (pre-commit)
  --file <path>   one manifest, compared with HEAD
  --diff <rev>    compare the working tree with <rev> (CI: origin/main)
  --json          machine-readable output
  --strict        exit 2 when a package could not be checked (offline)
Env: SECURE_CODING_NPM_REGISTRY, SECURE_CODING_PYPI_URL, SECURE_CODING_DEPS_OFFLINE=1
Exit codes: 0 ok, 2 a critical/high finding (or unverifiable with --strict).`;

const NPM_REGISTRY = (process.env.SECURE_CODING_NPM_REGISTRY || 'https://registry.npmjs.org').replace(/\/$/, '');
const PYPI_URL = (process.env.SECURE_CODING_PYPI_URL || 'https://pypi.org').replace(/\/$/, '');
const TIMEOUT_MS = Number(process.env.SECURE_CODING_DEPS_TIMEOUT_MS) || 8000;
const DAY = 24 * 60 * 60 * 1000;

const isManifest = f => {
  const b = path.basename(f).toLowerCase();
  return b === 'package.json' || b === 'pyproject.toml' || /^requirements[\w.-]*\.(txt|in)$/.test(b);
};

// --- manifest parsing: name -> line ---

function npmDeps(text) {
  const out = new Map();
  let json;
  try { json = JSON.parse(text); } catch { return out; }
  const lines = text.split('\n');
  for (const sect of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, spec] of Object.entries(json[sect] || {})) {
      const v = String(spec);
      // Not from the registry by name: nothing to look up.
      if (/^(file:|link:|workspace:|portal:|git(\+|:)|github:|https?:|\.{0,2}\/)/.test(v)) continue;
      const alias = v.match(/^npm:((?:@[^/]+\/)?[^@]+)/);
      const real = alias ? alias[1] : name;
      const at = lines.findIndex(l => l.includes(`"${name}"`));
      out.set(real, at + 1);
    }
  }
  return out;
}

const pep503 = n => n.toLowerCase().replace(/[-_.]+/g, '-');

function requirementName(spec) {
  const s = spec.split('#')[0].split(';')[0].trim();
  if (!s || /^(-|https?:|git\+|\.|\/)/.test(s) || s.includes(' @ ')) return null;
  const m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
  return m ? pep503(m[1]) : null;
}

function pypiDeps(text, file) {
  const out = new Map();
  const lines = text.split('\n');
  if (/\.toml$/i.test(file)) {
    let section = '';
    let inList = false;
    lines.forEach((raw, i) => {
      const line = raw.trim();
      const sec = line.match(/^\[([^\]]+)\]/);
      if (sec) { section = sec[1]; inList = false; return; }
      if (section === 'project' && /^(dependencies|optional-dependencies)\s*=\s*\[/.test(line)) inList = true;
      if (inList || (section.startsWith('project.optional-dependencies'))) {
        for (const m of line.matchAll(/["']([^"']+)["']/g)) {
          const n = requirementName(m[1]);
          if (n) out.set(n, i + 1);
        }
        if (line.includes(']')) inList = false;
        return;
      }
      if (/^tool\.poetry\.(dev-)?dependencies$|^tool\.poetry\.group\.[^.]+\.dependencies$/.test(section)) {
        const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/);
        if (m && m[1].toLowerCase() !== 'python') out.set(pep503(m[1]), i + 1);
      }
    });
    return out;
  }
  lines.forEach((raw, i) => {
    const n = requirementName(raw);
    if (n) out.set(n, i + 1);
  });
  return out;
}

function depsOf(file, text) {
  if (!text) return new Map();
  return path.basename(file).toLowerCase() === 'package.json' ? npmDeps(text) : pypiDeps(text, file);
}

// --- HTTP, honouring HTTPS_PROXY / NO_PROXY ---

function noProxy(host) {
  const list = (process.env.NO_PROXY || process.env.no_proxy || '').split(',').map(s => s.trim()).filter(Boolean);
  return list.some(e => e === '*' || host === e || host.endsWith(e.startsWith('.') ? e : '.' + e));
}

function getJson(url, headers = {}) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
    const opts = { method: 'GET', headers: { 'user-agent': 'secure-coding-deps', accept: 'application/json', ...headers }, timeout: TIMEOUT_MS };
    const finish = (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', d => { body += d; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(body); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, json });
      });
    };
    const fail = err => resolve({ status: 0, error: err.message || String(err) });
    const lib = u.protocol === 'http:' ? http : https;
    if (u.protocol === 'https:' && proxy && !noProxy(u.hostname)) {
      // Tunnel through the proxy with CONNECT, then speak TLS to the registry.
      const p = new URL(proxy);
      const auth = p.username ? { 'proxy-authorization': 'Basic ' + Buffer.from(`${decodeURIComponent(p.username)}:${decodeURIComponent(p.password)}`).toString('base64') } : {};
      const req = (p.protocol === 'https:' ? https : http).request({
        host: p.hostname, port: p.port || (p.protocol === 'https:' ? 443 : 80), method: 'CONNECT',
        path: `${u.hostname}:${u.port || 443}`, headers: { host: `${u.hostname}:${u.port || 443}`, ...auth }, timeout: TIMEOUT_MS,
      });
      req.on('connect', (res, socket) => {
        if (res.statusCode !== 200) { socket.destroy(); return fail(new Error(`proxy CONNECT ${res.statusCode}`)); }
        const s = tls.connect({ socket, servername: u.hostname });
        const r2 = https.request({ ...opts, host: u.hostname, path: u.pathname + u.search, createConnection: () => s }, finish);
        r2.on('error', fail); r2.on('timeout', () => r2.destroy(new Error('timeout'))); r2.end();
      });
      req.on('error', fail);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.end();
      return;
    }
    const req = lib.request(u, opts, finish);
    req.on('error', fail);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.end();
  });
}

// --- registry checks ---

async function checkNpm(name, minAgeDays) {
  const enc = name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : encodeURIComponent(name);
  const r = await getJson(`${NPM_REGISTRY}/${enc}`, { accept: 'application/vnd.npm.install-v1+json' });
  if (r.status === 404) return [{ id: 'dep-not-found', severity: 'critical', detail: `"${name}" does not exist on npm — likely a hallucinated name that anyone could register` }];
  if (r.status !== 200 || !r.json) return null; // unverified
  const out = [];
  const latest = r.json['dist-tags'] && r.json['dist-tags'].latest;
  const versions = r.json.versions || {};
  if (latest && versions[latest] && versions[latest].hasInstallScript) {
    out.push({ id: 'dep-install-script', severity: 'medium', detail: `"${name}@${latest}" runs an install script` });
  }
  // The abbreviated document has no creation date. Only a package with few
  // versions can be new, so only then fetch the (small) full document.
  if (Object.keys(versions).length <= 5) {
    const full = await getJson(`${NPM_REGISTRY}/${enc}`);
    const created = full.json && full.json.time && full.json.time.created;
    if (created) {
      const days = (Date.now() - Date.parse(created)) / DAY;
      if (days < minAgeDays) out.push({ id: 'dep-new-package', severity: 'high', detail: `"${name}" was first published ${Math.max(0, Math.floor(days))} day(s) ago` });
    }
  }
  return out;
}

async function checkPypi(name, minAgeDays) {
  const r = await getJson(`${PYPI_URL}/pypi/${encodeURIComponent(name)}/json`);
  if (r.status === 404) return [{ id: 'dep-not-found', severity: 'critical', detail: `"${name}" does not exist on PyPI — likely a hallucinated name that anyone could register` }];
  if (r.status !== 200 || !r.json) return null;
  const out = [];
  let first = Infinity;
  for (const files of Object.values(r.json.releases || {})) {
    for (const f of files || []) {
      const t = Date.parse(f.upload_time_iso_8601 || f.upload_time || '');
      if (!Number.isNaN(t) && t < first) first = t;
    }
  }
  if (first !== Infinity) {
    const days = (Date.now() - first) / DAY;
    if (days < minAgeDays) out.push({ id: 'dep-new-package', severity: 'high', detail: `"${name}" was first published ${Math.max(0, Math.floor(days))} day(s) ago` });
  }
  const urls = r.json.urls || [];
  if (urls.length && !urls.some(u => u.packagetype === 'bdist_wheel')) {
    out.push({ id: 'dep-sdist-only', severity: 'low', detail: `"${name}" ships no wheel, so installing it runs its setup.py` });
  }
  return out;
}

// --- private names: never sent to a public registry ---

const PUBLIC_NPM = /^https?:\/\/registry\.(npmjs\.org|yarnpkg\.com)\/?$/i;
const PUBLIC_PYPI = /^https?:\/\/(pypi\.org|pypi\.python\.org)\/simple\/?$/i;

function readIf(f) { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } }

// Scopes that resolve elsewhere, and whether the default registry is private.
function npmPrivacy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const text = [path.join(projectRoot(), '.npmrc'), home && path.join(home, '.npmrc')].filter(Boolean).map(readIf).join('\n');
  const scopes = new Set();
  let privateDefault = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    let m = line.match(/^(@[^:\s]+):registry\s*=\s*(\S+)/);
    if (m && !PUBLIC_NPM.test(m[2])) scopes.add(m[1].toLowerCase());
    m = line.match(/^registry\s*=\s*(\S+)/);
    if (m && !PUBLIC_NPM.test(m[1])) privateDefault = true;
  }
  if (process.env.npm_config_registry && !PUBLIC_NPM.test(process.env.npm_config_registry)) privateDefault = true;
  return { scopes, privateDefault };
}

function pypiPrivate(manifestText) {
  const idx = [];
  for (const m of String(manifestText || '').matchAll(/^\s*(?:--index-url|-i)\s*=?\s*(\S+)/gm)) idx.push(m[1]);
  if (process.env.PIP_INDEX_URL) idx.push(process.env.PIP_INDEX_URL);
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const conf = [home && path.join(home, '.config', 'pip', 'pip.conf'), home && path.join(home, '.pip', 'pip.conf'), '/etc/pip.conf']
    .filter(Boolean).map(readIf).join('\n');
  for (const m of conf.matchAll(/^\s*index-url\s*=\s*(\S+)/gm)) idx.push(m[1]);
  return idx.some(u => !PUBLIC_PYPI.test(u));
}

function globMatch(glob, name) {
  const re = new RegExp('^' + String(glob).split('*').map(x => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$', 'i');
  return re.test(name);
}

// --- what changed ---

function git(args) {
  return execFileSync('git', args, { cwd: projectRoot(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
}
const gitShow = spec => { try { return git(['show', spec]); } catch { return ''; } };
const rel = f => path.relative(projectRoot(), path.resolve(f)).split(path.sep).join('/');

function targets(opts) {
  const root = projectRoot();
  if (opts.file) {
    const f = path.resolve(opts.file);
    return [{ file: f, before: gitShow(`HEAD:${rel(f)}`), after: fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : '' }];
  }
  let names = [];
  try {
    if (opts.staged) names = git(['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR']).split('\0');
    else names = git(['diff', '--name-only', '-z', '--diff-filter=ACMR', opts.diff || 'HEAD']).split('\0')
      .concat(git(['ls-files', '--others', '--exclude-standard', '-z']).split('\0'));
  } catch { names = []; }
  return names.filter(Boolean).filter(isManifest).map(n => ({
    file: path.join(root, n),
    before: gitShow(`${opts.staged ? 'HEAD' : (opts.diff || 'HEAD')}:${n}`),
    after: opts.staged ? gitShow(`:${n}`) : (fs.existsSync(path.join(root, n)) ? fs.readFileSync(path.join(root, n), 'utf8') : ''),
  }));
}

async function check(opts = {}) {
  const cfg = loadConfig() || {};
  const dcfg = cfg.deps || {};
  const minAge = Number(dcfg.minAgeDays) || 30;
  const allow = new Set((dcfg.allow || []).map(String));
  const findings = [];
  const unverified = [];
  const skipped = [];
  const jobs = [];
  const privateGlobs = (dcfg.private || []).map(String);
  // An explicit registry override (tests, mirrors) is the user's choice of
  // where to send names; otherwise honour the project's registry config.
  const npmCfg = process.env.SECURE_CODING_NPM_REGISTRY ? { scopes: new Set(), privateDefault: false } : npmPrivacy();
  for (const t of targets(opts)) {
    const before = depsOf(t.file, t.before);
    const after = depsOf(t.file, t.after);
    const eco = path.basename(t.file).toLowerCase() === 'package.json' ? 'npm' : 'pypi';
    const pyPrivate = eco === 'pypi' && !process.env.SECURE_CODING_PYPI_URL && pypiPrivate(t.after);
    for (const [name, line] of after) {
      if (before.has(name) || allow.has(name)) continue;
      const job = { eco, name, line, file: t.file };
      const scope = name.startsWith('@') ? name.split('/')[0].toLowerCase() : null;
      if (privateGlobs.some(g => globMatch(g, name))) skipped.push({ ...job, reason: 'listed in deps.private' });
      else if (eco === 'npm' && npmCfg.privateDefault) skipped.push({ ...job, reason: '.npmrc uses a private registry' });
      else if (eco === 'npm' && scope && npmCfg.scopes.has(scope)) skipped.push({ ...job, reason: `${scope} resolves from a private registry (.npmrc)` });
      else if (pyPrivate) skipped.push({ ...job, reason: 'pip uses a private index' });
      else jobs.push(job);
    }
  }
  if (process.env.SECURE_CODING_DEPS_OFFLINE === '1' || dcfg.enabled === false) {
    return { findings, unverified: jobs.map(j => ({ ...j, reason: 'offline' })), skipped, checked: 0 };
  }
  // A few at a time: polite to the registries, still quick for a big diff.
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) {
      const j = jobs[next++];
      const res = j.eco === 'npm' ? await checkNpm(j.name, minAge) : await checkPypi(j.name, minAge);
      if (res === null) unverified.push({ ...j, reason: 'registry unreachable' });
      else for (const f of res) findings.push({ ...f, ecosystem: j.eco, name: j.name, file: j.file, line: j.line });
    }
  };
  await Promise.all(Array.from({ length: Math.min(6, jobs.length) }, worker));
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.name.localeCompare(b.name));
  return { findings, unverified, skipped, checked: jobs.length };
}

function parseArgs(argv) {
  const o = { json: argv.includes('--json'), strict: argv.includes('--strict'), staged: argv.includes('--staged') };
  const fi = argv.indexOf('--file'); if (fi >= 0) o.file = argv[fi + 1];
  const di = argv.indexOf('--diff'); if (di >= 0) o.diff = argv[di + 1];
  return o;
}

const blocking = f => f.severity === 'critical' || f.severity === 'high';

async function main() {
  const argv = process.argv.slice(2);
  if (helpRequested(argv, USAGE)) return 0;
  const opts = parseArgs(argv);
  const res = await check(opts);
  if (opts.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + '\n');
  } else {
    if (res.checked === 0 && res.unverified.length === 0 && res.skipped.length === 0) process.stdout.write('secure-coding deps: no new dependencies\n');
    for (const f of res.findings) {
      process.stdout.write(`  [${f.severity.toUpperCase()}] ${f.id}  ${path.relative(process.cwd(), f.file)}:${f.line}  ${f.detail}\n`);
    }
    for (const u of res.unverified) {
      process.stdout.write(`  [UNVERIFIED] ${u.name} (${u.eco}) — ${u.reason}\n`);
    }
    for (const k of res.skipped) {
      process.stdout.write(`  [NOT SENT] ${k.name} (${k.eco}) — ${k.reason}\n`);
    }
    if (res.checked && !res.findings.length && !res.unverified.length) process.stdout.write(`secure-coding deps: ${res.checked} new dependenc${res.checked === 1 ? 'y' : 'ies'} checked, nothing found\n`);
  }
  if (res.findings.some(blocking)) return 2;
  if (opts.strict && res.unverified.length) return 2;
  return 0;
}

if (require.main === module) {
  main().then(code => process.exit(code), e => { process.stderr.write(`deps: ${e.message}\n`); process.exit(1); });
}

module.exports = { check, depsOf, npmDeps, pypiDeps, isManifest, getJson };
