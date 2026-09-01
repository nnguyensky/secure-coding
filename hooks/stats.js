#!/usr/bin/env node
// Pattern effectiveness stats from findings.jsonl.
// Usage: node hooks/stats.js [--top N] [--severity]
//   --top N       show top N patterns (default: 10)
//   --severity    break down by severity
// Reads project-local false-positives.json if present (see SKILL.md).
// Env: SECURE_CODING_STATE
'use strict';

const fs = require('fs');
const path = require('path');

const STATE = process.env.SECURE_CODING_STATE || path.join(__dirname, '..', 'checks', 'findings.jsonl');
const FP_FILE = path.join(process.cwd(), 'false-positives.json');

const args = process.argv.slice(2);
const topN = args.includes('--top') ? parseInt(args[args.indexOf('--top') + 1]) || 10 : 10;
const showSeverity = args.includes('--severity');

function load() {
  if (!fs.existsSync(STATE)) return [];
  return fs.readFileSync(STATE, 'utf8').split(/\r?\n/).filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

function loadFP() {
  if (!fs.existsSync(FP_FILE)) return new Set();
  try {
    const data = JSON.parse(fs.readFileSync(FP_FILE, 'utf8'));
    // Accepts: ["sql-concat", "eval"] or { "sql-concat": ["src/test/*"], "eval": "*" }
    if (Array.isArray(data)) return new Set(data);
    return new Set(Object.keys(data));
  } catch { return new Set(); }
}

const findings = load();
const falsePositives = loadFP();

if (findings.length === 0) {
  console.log('no findings');
  process.exit(0);
}

// Aggregate by pattern id
const byId = {};
for (const f of findings) {
  const id = f.id || '?';
  if (!byId[id]) byId[id] = { total: 0, open: 0, fixed: 0, fp: 0, severities: {}, files: new Set() };
  byId[id].total++;
  if (f.status === 'open') byId[id].open++;
  if (f.status === 'fixed') byId[id].fixed++;
  if (falsePositives.has(id)) byId[id].fp++;
  const sev = f.severity || 'medium';
  byId[id].severities[sev] = (byId[id].severities[sev] || 0) + 1;
  byId[id].files.add(f.file);
}

// Sort by total hits descending
const sorted = Object.entries(byId)
  .sort((a, b) => b[1].total - a[1].total)
  .slice(0, topN);

// Output
const sevOrder = ['critical', 'high', 'medium', 'low'];

console.log(`patterns: ${Object.keys(byId).length} | total findings: ${findings.length} | open: ${findings.filter(f => f.status === 'open').length} | fixed: ${findings.filter(f => f.status === 'fixed').length}`);
if (falsePositives.size > 0) console.log(`false positives marked: ${falsePositives.size}`);
console.log('');

for (const [id, s] of sorted) {
  const fp = s.fp > 0 ? ` fp:${s.fp}` : '';
  const sevs = showSeverity ? ' ' + sevOrder.filter(sev => s.severities[sev]).map(sev => `${sev}:${s.severities[sev]}`).join(' ') : '';
  console.log(`${id.padEnd(22)} ${String(s.total).padStart(4)} hits  ${String(s.open).padStart(3)} open  ${String(s.fixed).padStart(3)} fixed${fp}${sevs}`);
}
