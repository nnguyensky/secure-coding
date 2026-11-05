// Reads the run state (findings, audit, baseline) and the fix guidance into
// one shape. Shared by report.js (HTML / SARIF / Markdown) and serve.js (the
// dashboard), so the two never disagree about what a finding looks like.
'use strict';

const fs = require('fs');
const path = require('path');
const { statePath, projectRoot } = require('./config');

const DIR = path.resolve(__dirname, '..');
const FIXES = path.join(DIR, 'checks', 'fixes.md');

const SECTION_NAMES = {
  '2': 'Output Encoding', '3': 'Authentication & Password', '4': 'Session Management',
  '5': 'Access Control', '6': 'Cryptographic Practices', '7': 'Error Handling', '8': 'Data Protection',
  '9': 'Communication Security', '10': 'System Configuration', '11': 'Database Security',
  '12': 'File Management', '13': 'Memory Management', '14': 'General Coding',
  '15': 'API Security', '16': 'Container Security', '19': 'Logging Security',
  '20': 'Password Storage', '21': 'SSRF Prevention', '22': 'File Upload',
  '23': 'NoSQL Injection', '24': 'OAuth2 Security', '25': 'Session Fixation',
  '26': 'WebSocket Security', '27': 'Dockerfile Security', '28': 'Supply Chain',
  '29': 'Shell Scripting', '30': 'Terraform & IaC',
  '31': 'JWT Security', '32': 'Secrets & Credentials', '33': 'OWASP LLM Applications',
  '34': 'Secure by Design Architecture', '35': 'IoT & Embedded Security (AS ETSI EN 303 645)',
};

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#65a30d',
};

function sectionName(sec) {
  return SECTION_NAMES[String(sec).replace(/^0+/, '')] || 'Other';
}

// Read "OWASP: ... | CWE-89 | A05:2025" off a fixes.md block. SARIF consumers
// (GitHub code scanning included) key on CWE, so surface it as a real taxonomy.
// Read the version from package.json rather than hardcoding it; the literal
// had already drifted to 2.0.0 while the package was 2.1.0.
let PKG_VERSION = '0.0.0';
let PKG_HOMEPAGE = 'https://github.com/nnguyensky/secure-coding';
try {
  const pkg = require(path.join(DIR, 'package.json'));
  PKG_VERSION = pkg.version || PKG_VERSION;
  PKG_HOMEPAGE = pkg.homepage || PKG_HOMEPAGE;
} catch { /* defaults above */ }

// fixes.md is ~55KB and was re-read for every finding, twice (cweFor and
// fixText). Read and split it once per process.
let _fixText = null;
function fixesRaw() {
  if (_fixText === null) _fixText = fs.existsSync(FIXES) ? fs.readFileSync(FIXES, 'utf8') : '';
  return _fixText;
}

function cweFor(id) {
  const text = fixesRaw();
  if (!text) return null;
  // \r?: a Windows checkout with autocrlf has CRLF line endings.
  const m = text.match(new RegExp('^## ' + id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\r?\\n([^\\r\\n]*)', 'm'));
  if (!m) return null;
  const cwe = m[1].match(/CWE-(\d+)/);
  const cat = m[1].match(/(A\d\d):2025/);
  return cwe ? { cwe: cwe[1], category: cat ? cat[1] + ':2025' : null } : null;
}

// One fix block as structured fields: the dashboard renders Wrong / Right /
// Watch separately, the HTML report and SARIF use the flattened text.
let _fixIndex = null;
function fixBlocks() {
  if (_fixIndex) return _fixIndex;
  _fixIndex = new Map();
  for (const part of fixesRaw().split(/^## /m).slice(1)) {
    const lines = part.split(/\r?\n/);
    const id = (lines.shift() || '').trim();
    if (!id || id.startsWith('#')) continue;
    const block = { id, owasp: '', cwe: null, category: null, summary: '', wrong: '', right: '', watch: '' };
    const prose = [];
    for (const l of lines) {
      const m = l.match(/^(OWASP|Wrong|Right|Watch):\s*(.*)$/);
      if (m) {
        const key = m[1].toLowerCase();
        if (key === 'owasp') {
          block.owasp = m[2];
          const cwe = m[2].match(/CWE-(\d+)/);
          const cat = m[2].match(/(A\d\d):2025/);
          block.cwe = cwe ? cwe[1] : null;
          block.category = cat ? `${cat[1]}:2025` : null;
        } else block[key] = m[2];
      } else if (l.trim() && !l.startsWith('#')) prose.push(l.trim());
    }
    block.summary = prose.join(' ');
    _fixIndex.set(id, block);
  }
  return _fixIndex;
}

function fixText(id) {
  const b = fixBlocks().get(id);
  if (!b) return '';
  return [b.owasp && `OWASP: ${b.owasp}`, b.summary, b.wrong && `Wrong: ${b.wrong}`, b.right && `Right: ${b.right}`, b.watch && `Watch: ${b.watch}`]
    .filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}

function loadFindings(stateFile = statePath('findings.jsonl', 'SECURE_CODING_STATE')) {
  if (!fs.existsSync(stateFile)) return [];
  return fs.readFileSync(stateFile, 'utf8').split(/\r?\n/).filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch (e) { return null; } })
    .filter(Boolean);
}

function loadAudit(auditFile = statePath('audit.json', 'SECURE_CODING_AUDIT')) {
  if (!fs.existsSync(auditFile)) return null;
  try { return JSON.parse(fs.readFileSync(auditFile, 'utf8')); } catch { return null; }
}

// The row shape the HTML report has always used.
function buildRows(findings) {
  return findings.map(f => ({
    id: f.id || '',
    section: f.section || '',
    secName: sectionName(f.section),
    severity: f.severity || 'medium',
    sevColor: SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.medium,
    status: f.status || '',
    line: Number(f.line) || 0,
    reason: f.reason || '',
    run_id: f.run_id || (f.first_seen ? f.first_seen.slice(0, 10) : 'run-1'),
    file: f.file || '',
    first: f.first_seen || '',
    resolved: f.resolved_at || '',
    fix: f.note || fixText(f.id),
  }));
}

// Everything the dashboard shows, as one JSON-safe object. File paths are
// made relative to the project so the page never displays the user's home
// directory layout.
function snapshot() {
  const root = projectRoot();
  const findings = loadFindings();
  const audit = loadAudit();
  const rel = f => {
    if (!f) return '';
    const r = path.relative(root, f);
    return (r && !r.startsWith('..') ? r : path.basename(f)).split(path.sep).join('/');
  };
  const used = new Set(findings.map(f => f.id));
  const fixes = {};
  for (const id of used) {
    const b = fixBlocks().get(id);
    if (b) fixes[id] = b;
  }
  return {
    tool: { name: 'secure-coding', version: PKG_VERSION, homepage: PKG_HOMEPAGE },
    project: path.basename(root),
    generatedAt: new Date().toISOString(),
    findings: findings.map(f => ({
      id: f.id || '',
      section: String(f.section || ''),
      sectionName: sectionName(f.section),
      severity: f.severity || 'medium',
      status: f.status || '',
      file: rel(f.file),
      line: Number(f.line) || 0,
      note: f.note || '',
      reason: f.reason || '',
      firstSeen: f.first_seen || '',
      resolvedAt: f.resolved_at || '',
    })),
    audit: { findings: (audit && audit.findings) || [], skipped: (audit && audit.skipped) || [], ts: audit && audit.ts || null },
    fixes,
  };
}

module.exports = {
  SECTION_NAMES, SEVERITY_COLORS, PKG_VERSION, PKG_HOMEPAGE,
  sectionName, cweFor, fixText, fixBlocks, loadFindings, loadAudit, buildRows, snapshot,
};
