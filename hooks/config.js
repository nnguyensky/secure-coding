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
const { exec } = require('child_process');

const DIR = path.resolve(__dirname, '..');
const ROOT = process.cwd();
const CONFIG_FILE = path.join(ROOT, '.securecodingrc.json');
const WIZARD_HTML = path.join(DIR, 'reports', 'config-wizard.html');

const DEFAULT_CONFIG = {
  failOn: 'high',
  entropyDetection: true,
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
  if (!fs.existsSync(CONFIG_FILE)) return DEFAULT_CONFIG;
  try {
    const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
    return { ...DEFAULT_CONFIG, ...JSON.parse(raw) };
  } catch (e) {
    return DEFAULT_CONFIG;
  }
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + '\n');
  console.log(`✅ Saved configuration to ${CONFIG_FILE}`);
}

function openBrowser(url) {
  const start = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  exec(`${start} "${url}"`, (err) => {
    if (err) console.log(`Open wizard manually: file://${url}`);
  });
}

function main() {
  const args = process.argv.slice(2);

  if (args.includes('--ui')) {
    console.log(`Opening Secure Coding Configuration Wizard...`);
    openBrowser(WIZARD_HTML);
    return;
  }

  if (args.includes('--init')) {
    if (fs.existsSync(CONFIG_FILE)) {
      console.log(`Config already exists at ${CONFIG_FILE}`);
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

// Findings, audit results and gate answers describe the project being scanned,
// not the skill. Resolving them against the package directory made a downstream
// scan write its findings into the installed skill, where they leaked into
// every other project's reports. State follows the project; skill assets
// (patterns, fixes.md) stay with the package.
//
// Order: explicit env override, then the project's own checks/ directory, then
// the package -- so the skill scanning itself keeps working unchanged.
function stateDir() {
  let root = process.cwd();
  try {
    root = require('child_process')
      .execFileSync('git', ['rev-parse', '--show-toplevel'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || root;
  } catch { /* not a git repo: cwd is the project */ }
  return path.join(root, 'checks');
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
    else fs.writeFileSync(file, data);
    return true;
  } catch (e) {
    if (!writeState._warned) {
      writeState._warned = true;
      console.error(`secure-coding: cannot record state at ${file} (${e.code || e.message}) — findings shown but not saved`);
    }
    return false;
  }
}

module.exports = { loadConfig, DEFAULT_CONFIG, stateDir, statePath, writeState };
