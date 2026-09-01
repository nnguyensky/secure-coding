#!/usr/bin/env node
// One-liner summary of findings.jsonl.
// Usage: node hooks/summary.js
// Env: SECURE_CODING_STATE (default: checks/findings.jsonl)
'use strict';

const fs = require('fs');
const path = require('path');

const STATE = process.env.SECURE_CODING_STATE || path.join(__dirname, '..', 'checks', 'findings.jsonl');

function load() {
  if (!fs.existsSync(STATE)) return [];
  return fs.readFileSync(STATE, 'utf8').split(/\r?\n/).filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

const findings = load();
const open = findings.filter(f => f.status === 'open');
const fixed = findings.filter(f => f.status === 'fixed');
const total = findings.length;

if (total === 0) {
  console.log('clean — no findings');
  process.exit(0);
}

// Group open by section
const bySec = {};
open.forEach(f => {
  const s = f.section || '?';
  bySec[s] = (bySec[s] || 0) + 1;
});

const secLabels = {
  '2': 'output', '3': 'auth', '4': 'session', '5': 'access',
  '6': 'crypto', '8': 'data', '9': 'tls', '10': 'config',
  '11': 'db', '12': 'files', '13': 'memory', '14': 'general',
  '15': 'api', '16': 'container', '19': 'logging', '20': 'password',
  '21': 'ssrf', '22': 'upload', '23': 'nosql', '24': 'oauth2',
  '25': 'session-fix', '26': 'websocket', '27': 'dockerfile', '28': 'supply',
  '29': 'shell', '30': 'terraform', '31': 'jwt', '32': 'secrets',
  '33': 'llm', '34': 'sbd', '35': 'iot',
};

const openBySection = Object.entries(bySec)
  .map(([k, v]) => `${secLabels[k] || k}:${v}`)
  .join(' ');

// Severity breakdown
const bySev = {};
open.forEach(f => {
  const s = f.severity || 'medium';
  bySev[s] = (bySev[s] || 0) + 1;
});
const sevOrder = ['critical', 'high', 'medium', 'low'];
const sevStr = sevOrder
  .filter(s => bySev[s])
  .map(s => `${bySev[s]} ${s}`)
  .join(', ');

console.log(`${open.length} open, ${fixed.length} fixed` + (sevStr ? ` [${sevStr}]` : '') + (openBySection ? ` (${openBySection})` : ''));

if (open.length > 0) {
  process.exit(2);
}

