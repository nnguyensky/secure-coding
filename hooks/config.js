#!/usr/bin/env node
// Reads, writes, or launches the interactive configuration wizard for .securecodingrc.json.
// Usage:
//   node hooks/config.js --ui          Open modern interactive UI wizard in browser
//   node hooks/config.js --init        Initialize default .securecodingrc.json
//   node hooks/config.js --get <key>   Get a config value
//   node hooks/config.js --json        Print full parsed config JSON
'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const DIR = path.resolve(__dirname, '..');
// Resolved per call against the project root, not frozen at load time against
// cwd. A constant here meant `cd packages/backend && scan.js x.js` looked for
// the config in the subdirectory, found none, and silently discarded every
// ignorePaths, failOn and taintTracking setting the project had declared.
// projectRoot() is a hoisted function declaration, so it is callable here.
function configFile() { return path.join(projectRoot(), '.securecodingrc.json'); }
const WIZARD_HTML = path.join(DIR, 'reports', 'config-wizard.html');

const DEFAULT_CONFIG = {
  failOn: 'high',
  entropyDetection: true,
  taintTracking: true,
  generateMarkdownPR: true,
  modules: {
    llm: true,
    jwt: true,
    cors: true,
    cleanCode: true,
    sbd: true,
    iot: true,
  },
  ignorePaths: [
    'tests/**',
    'fixtures/**',
    'scripts/seed/**',
    'e2e/**',
  ],
  ignorePatterns: [],
  audit: {
    ecosystems: ['npm', 'pnpm', 'pip', 'cargo', 'go', 'dotnet'],
    failOnAdvisory: 'high',
  },
};

function loadConfig() {
  if (!fs.existsSync(configFile())) return DEFAULT_CONFIG;
  try {
    const raw = fs.readFileSync(configFile(), 'utf8');
    return { ...DEFAULT_CONFIG, ...JSON.parse(raw) };
  } catch (e) {
    return DEFAULT_CONFIG;
  }
}

function saveConfig(cfg) {
  fs.writeFileSync(configFile(), JSON.stringify(cfg, null, 2) + '\n');
  console.log(`✅ Saved configuration to ${configFile()}`);
}

// Open a local file in the default app, without a shell: the path was
// interpolated into a shell string, so a quote in the install path broke
// out of it. explorer.exe on Windows, because `start` is a cmd.exe builtin.
function openPath(target) {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [target]]
    : process.platform === 'win32' ? ['explorer.exe', [target]]
      : ['xdg-open', [target]];
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => console.log(`Open manually: file://${target}`));
    child.unref();
  } catch {
    console.log(`Open manually: file://${target}`);
  }
}

function openBrowser(url) {
  openPath(url);
}

function main() {
  const args = process.argv.slice(2);

  if (args.includes('--ui')) {
    console.log(`Opening Secure Coding Configuration Wizard...`);
    openBrowser(WIZARD_HTML);
    return;
  }

  if (args.includes('--init')) {
    if (fs.existsSync(configFile())) {
      console.log(`Config already exists at ${configFile()}`);
      return;
    }
    saveConfig(DEFAULT_CONFIG);
    return;
  }

  if (args.includes('--json')) {
    console.log(JSON.stringify(loadConfig(), null, 2));
    return;
  }

  const getIdx = args.indexOf('--get');
  if (getIdx >= 0 && args[getIdx + 1]) {
    const key = args[getIdx + 1];
    const cfg = loadConfig();
    const val = key.split('.').reduce((o, i) => (o ? o[i] : undefined), cfg);
    if (val !== undefined) {
      console.log(typeof val === 'object' ? JSON.stringify(val) : val);
    } else {
      process.exit(1);
    }
    return;
  }

  console.log('Secure Coding Configuration Manager');
  console.log('Usage:');
  console.log('  node hooks/config.js --ui        Open browser configuration wizard');
  console.log('  node hooks/config.js --init      Create default .securecodingrc.json');
  console.log('  node hooks/config.js --json      Print current configuration');
  console.log('  node hooks/config.js --get <key> Get configuration parameter');
}

if (require.main === module) {
  main();
}

// Findings, audit results, gate answers and ignorePaths globs all describe the
// project being scanned, not the installed skill. Resolving them against the
// package directory made a downstream scan write findings into the skill and
// made every ignorePaths glob silently fail to match. Skill assets (patterns,
// fixes.md) stay with the package; everything project-shaped resolves here.
function projectRoot() {
  try {
    return require('child_process')
      .execFileSync('git', ['rev-parse', '--show-toplevel'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || process.cwd();
  } catch { return process.cwd(); } // not a git repo: cwd is the project
}

function stateDir() {
  return path.join(projectRoot(), 'checks');
}

// `name` is a bare filename such as 'findings.jsonl'. `env` names an
// environment variable that, when set, wins outright. Resolving a path never
// touches the filesystem -- writeState creates checks/ when it actually
// writes, so a read-only project fails at the write with a warning rather
// than crashing at module load.
function statePath(name, env) {
  if (env && process.env[env]) return process.env[env];
  return path.join(stateDir(), name);
}

// Recording a finding is bookkeeping, not the job. A project that cannot be
// written to -- read-only checkout, CI cache, container with a mounted source
// tree -- must still get its findings printed, so a failed write warns once
// and the scan carries on. Returns false when the write did not happen.
function writeState(file, data, { append = false } = {}) {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (append) fs.appendFileSync(file, data);
    else {
      // Write a sibling temp file and rename it into place, so a reader (the
      // report, another hook) never sees a half-written file.
      const tmp = `${file}.${process.pid}.tmp`;
      try {
        fs.writeFileSync(tmp, data);
        fs.renameSync(tmp, file);
      } catch (e) {
        try { fs.unlinkSync(tmp); } catch { /* nothing to clean up */ }
        throw e;
      }
    }
    return true;
  } catch (e) {
    if (!writeState._warned) {
      writeState._warned = true;
      console.error(`secure-coding: cannot record state at ${file} (${e.code || e.message}) — findings shown but not saved`);
    }
    return false;
  }
}

// Run fn while holding an exclusive lock on `file` (a sibling .lock file).
// Hooks run in parallel when an agent writes several files at once; without
// this, two read-modify-write cycles on findings.jsonl lost each other's
// records. Never blocks the scan: a lock that cannot be taken within a few
// seconds, or cannot be created at all (read-only tree), runs fn unlocked.
const LOCK_WAIT_MS = 5000;
const LOCK_STALE_MS = 15000;
function withFileLock(file, fn) {
  const lock = `${file}.lock`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  const sleeper = new Int32Array(new SharedArrayBuffer(4));
  let fd = null;
  try { fs.mkdirSync(path.dirname(file), { recursive: true }); } catch { return fn(); }
  while (fd === null) {
    try {
      fd = fs.openSync(lock, 'wx');
    } catch (e) {
      if (e.code !== 'EEXIST') return fn();
      try {
        // A holder that crashed leaves its lock behind; reclaim it.
        if (Date.now() - fs.statSync(lock).mtimeMs > LOCK_STALE_MS) { fs.unlinkSync(lock); continue; }
      } catch { continue; } // vanished between open and stat: retry now
      if (Date.now() > deadline) return fn();
      Atomics.wait(sleeper, 0, 0, 20);
    }
  }
  try {
    return fn();
  } finally {
    try { fs.closeSync(fd); } catch { /* ignore */ }
    try { fs.unlinkSync(lock); } catch { /* ignore */ }
  }
}

// One severity scale for every ecosystem. The tools disagree: npm says
// "moderate", cargo-audit gives a CVSS score ("7.5"), dotnet "High",
// pip-audit and govulncheck often give nothing. Before this, a score or an
// unrecognised word ranked as the lowest level, so a CVSS 9.8 cargo advisory
// never failed the build. A known advisory with no severity is treated as
// high: it is a confirmed vulnerability, and failing closed is the safe side.
function normalizeSeverity(sev) {
  const s = String(sev == null ? '' : sev).trim().toLowerCase();
  const score = parseFloat(s);
  if (/^\d+(\.\d+)?$/.test(s) && !Number.isNaN(score)) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }
  if (s === 'critical') return 'critical';
  if (s === 'high' || s === 'important') return 'high';
  if (s === 'medium' || s === 'moderate') return 'medium';
  if (s === 'low' || s === 'info' || s === 'informational' || s === 'none') return 'low';
  return 'high';
}

// `--help` must never do the thing. reset.js used to wipe the findings file
// when asked for help, and audit.js/sbom.js ran their full operation, so a
// user typing --help to learn what a tool does triggered it instead. Call this
// as the first statement of a CLI, before any work.
function helpRequested(argv, usage) {
  if (!argv.includes('--help') && !argv.includes('-h')) return false;
  process.stdout.write(usage.trimEnd() + '\n');
  return true;
}

module.exports = { loadConfig, DEFAULT_CONFIG, projectRoot, stateDir, statePath, writeState, withFileLock, helpRequested, normalizeSeverity, openPath };
