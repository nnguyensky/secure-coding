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

module.exports = { loadConfig, DEFAULT_CONFIG };
