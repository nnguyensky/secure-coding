#!/usr/bin/env node
// Renders reports/security.html from checks/findings.jsonl.
// Reads the scaffold from reports/security.html, injects data, writes to output.
// Self-contained HTML (inline CSS + vanilla JS, no CDN) so it opens offline.
'use strict';

const fs = require('fs');
const path = require('path');

const DIR = path.resolve(__dirname, '..');
const STATE = process.env.SECURE_CODING_STATE || path.join(DIR, 'checks', 'findings.jsonl');
const FIXES = path.join(DIR, 'checks', 'fixes.md');
const AUDIT = path.join(DIR, 'checks', 'audit.json');
const SCAFFOLD = path.join(DIR, 'reports', 'security.html');

function reportPath() {
  if (process.env.SECURE_CODING_REPORT_OUT) return process.env.SECURE_CODING_REPORT_OUT;
  const dir = path.join(process.cwd(), 'reports');
  const runId = process.env.SECURE_CODING_RUN_ID;
  if (runId) {
    return path.join(dir, `security-${runId}.html`);
  }
  const date = new Date().toISOString().slice(0, 10);
  return path.join(dir, `security-${date}.html`);
}

const SECTION_NAMES = {
  '2': 'Output Encoding', '3': 'Authentication & Password', '4': 'Session Management',
  '5': 'Access Control', '6': 'Cryptographic Practices', '8': 'Data Protection',
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

// fixes.md is ~55KB and was re-read for every finding, twice (cweFor and
// fixText). Read and split it once per process.
let _fixText = null;
function fixesRaw() {
  if (_fixText === null) _fixText = fs.existsSync(FIXES) ? fs.readFileSync(FIXES, 'utf8') : '';
  return _fixText;
}

// Read "OWASP: ... | CWE-89 | A05:2025" off a fixes.md block. SARIF consumers
// (GitHub code scanning included) key on CWE, so surface it as a real taxonomy.
function cweFor(id) {
  const text = fixesRaw();
  if (!text) return null;
  const m = text.match(new RegExp('^## ' + id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\n([^\\n]*)', 'm'));
  if (!m) return null;
  const cwe = m[1].match(/CWE-(\d+)/);
  const cat = m[1].match(/(A\d\d):2025/);
  return cwe ? { cwe: cwe[1], category: cat ? cat[1] + ':2025' : null } : null;
}

function fixText(id) {
  const text = fixesRaw();
  if (!text) return '';
  const parts = text.split(/^## /m);
  for (const part of parts) {
    const header = part.match(/^([^\n]+)/);
    if (header && header[1].trim() === id) {
      return part.replace(/^[^\n]*\n/, '').replace(/^#.*$/m, '').trim().replace(/\s+/g, ' ');
    }
  }
  return '';
}

function loadFindings() {
  if (!fs.existsSync(STATE)) return [];
  return fs.readFileSync(STATE, 'utf8').split(/\r?\n/).filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch (e) { return null; } })
    .filter(Boolean);
}

function loadAudit() {
  if (!fs.existsSync(AUDIT)) return null;
  try { return JSON.parse(fs.readFileSync(AUDIT, 'utf8')); } catch { return null; }
}

function generateMarkdown(rows, audit) {
  const openRows = rows.filter(r => r.status === 'open');
  const fixedRows = rows.filter(r => r.status === 'fixed');
  let md = '### 🛡️ Security Scan Summary\n\n';
  md += `**Findings:** ${openRows.length} open, ${fixedRows.length} resolved.\n\n`;

  if (openRows.length > 0) {
    md += '| Severity | Finding ID | Location | Remediation |\n';
    md += '|:---|:---|:---|:---|\n';
    for (const r of openRows) {
      const fileRel = path.relative(process.cwd(), r.file) || r.file;
      md += `| **${r.severity.toUpperCase()}** | \`${r.id}\` | \`${fileRel}\` | ${r.fix.replace(/\n/g, ' ').slice(0, 100)} |\n`;
    }
    md += '\n';
  } else {
    md += '✅ **No open security vulnerabilities found.**\n\n';
  }

  if (audit && audit.findings && audit.findings.length > 0) {
    md += '#### 📦 Dependency Vulnerabilities\n\n';
    md += '| Severity | Package | Ecosystem | Advisory |\n';
    md += '|:---|:---|:---|:---|\n';
    for (const d of audit.findings) {
      md += `| **${(d.severity || 'unknown').toUpperCase()}** | \`${d.package}\` | ${d.ecosystem} | ${d.title} |\n`;
    }
    md += '\n';
  }
  return md;
}

function generateSarif(rows) {
  const openRows = rows.filter(r => r.status === 'open');
  const levelMap = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
  };

  const ruleMap = new Map();
  for (const r of openRows) {
    if (!ruleMap.has(r.id)) {
      const meta = cweFor(r.id);
      const rule = {
        id: r.id,
        name: r.id,
        shortDescription: { text: `OWASP rule violation: ${r.id}` },
        fullDescription: { text: r.fix || `Remediation for ${r.id}` },
        defaultConfiguration: { level: levelMap[r.severity] || 'warning' },
        helpUri: meta ? `https://cwe.mitre.org/data/definitions/${meta.cwe}.html` : 'https://owasp.org',
      };
      if (meta) {
        rule.properties = {
          tags: ['security', `external/cwe/cwe-${meta.cwe}`].concat(meta.category ? [`OWASP-${meta.category}`] : []),
          'security-severity': ({ critical: '9.0', high: '7.0', medium: '5.0', low: '3.0' })[r.severity] || '5.0',
        };
      }
      ruleMap.set(r.id, rule);
    }
  }

  const results = openRows.map(r => {
    let startLine = 1;
    if (r.fix) {
      const lm = r.fix.match(/Line\s+(\d+)/i);
      if (lm) startLine = parseInt(lm[1], 10);
    }
    const relFile = path.isAbsolute(r.file) ? path.relative(process.cwd(), r.file) : r.file;
    return {
      ruleId: r.id,
      level: levelMap[r.severity] || 'warning',
      message: { text: `[${(r.severity || 'medium').toUpperCase()}] ${r.id}: ${r.fix}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: relFile.replace(/\\/g, '/'),
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: startLine > 0 ? startLine : 1,
            },
          },
        },
      ],
    };
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'secure-coding',
            semanticVersion: '2.0.0',
            informationUri: 'https://github.com/OWASP',
            rules: Array.from(ruleMap.values()),
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2) + '\n';
}

function main() {
  const findings = loadFindings();
  const audit = loadAudit();
  const rows = findings.map(f => ({
    id: f.id || '',
    section: f.section || '',
    secName: sectionName(f.section),
    severity: f.severity || 'medium',
    sevColor: SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.medium,
    status: f.status || '',
    run_id: f.run_id || (f.first_seen ? f.first_seen.slice(0, 10) : 'run-1'),
    file: f.file || '',
    first: f.first_seen || '',
    resolved: f.resolved_at || '',
    fix: f.note || fixText(f.id),
  }));

  if (process.argv.includes('--sarif')) {
    const sarif = generateSarif(rows);
    process.stdout.write(sarif);
    return;
  }

  if (process.argv.includes('--markdown') || process.argv.includes('-m')) {
    const md = generateMarkdown(rows, audit);
    process.stdout.write(md);
    return;
  }

  const gen = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  // Read scaffold
  let scaffold;
  try {
    scaffold = fs.readFileSync(SCAFFOLD, 'utf8');
  } catch (e) {
    process.stderr.write(`secure-coding: scaffold not found at ${SCAFFOLD}\n`);
    process.exit(1);
  }

  // Inject data into <script> tag. The </ escape prevents </script> breakout.
  const dataJson = rows.map(r => JSON.stringify(r)).join(',\n');
  const safeDataJson = dataJson.replace(/<\//gi, '<\\/');
  const auditJson = JSON.stringify(audit ? audit.findings : []).replace(/<\//gi, '<\\/');

  const html = scaffold
    .replace('<!--[GENERATED]-->', gen)
    .replace('/*FINDINGS_DATA*/', safeDataJson)
    .replace('/*AUDIT_DATA*/', auditJson);

  const OUT = reportPath();
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, html);
  process.stderr.write(`secure-coding: report written to ${OUT}\n`);
}

main();
