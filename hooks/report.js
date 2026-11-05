#!/usr/bin/env node
// Renders reports/security.html from checks/findings.jsonl.
// Reads the scaffold from reports/security.html, injects data, writes to output.
// Self-contained HTML (inline CSS + vanilla JS, no CDN) so it opens offline.
'use strict';

const fs = require('fs');
const path = require('path');
const { statePath, helpRequested, projectRoot } = require('./config');

// --help must print help, never run the tool. reset.js used to wipe the
// findings file when asked for help; audit.js and sbom.js ran in full.
const USAGE = `Usage: node hooks/report.js [--sarif] [--markdown] [--dashboard] [--out <file>]

Renders the findings file into an HTML report, SARIF v2.1.0, or Markdown.
Defaults to self-contained HTML under reports/.
  --dashboard   the interactive dashboard as one offline HTML file
                (live version: node hooks/serve.js)

Env: SECURE_CODING_STATE (default: <project>/checks/findings.jsonl)`;
if (helpRequested(process.argv.slice(2), USAGE)) process.exit(0);

const DIR = path.resolve(__dirname, '..');
const STATE = statePath('findings.jsonl', 'SECURE_CODING_STATE');
const AUDIT = statePath('audit.json', 'SECURE_CODING_AUDIT');
const SCAFFOLD = path.join(DIR, 'reports', 'security.html');

function reportPath() {
  if (process.env.SECURE_CODING_REPORT_OUT) return process.env.SECURE_CODING_REPORT_OUT;
  // The report belongs to the project, not to whichever directory the command
  // happened to run from: reports/ under src/ is not where anyone looks.
  // Display paths further down deliberately stay relative to cwd.
  const dir = path.join(projectRoot(), 'reports');
  const runId = process.env.SECURE_CODING_RUN_ID;
  if (runId) {
    return path.join(dir, `security-${runId}.html`);
  }
  const date = new Date().toISOString().slice(0, 10);
  return path.join(dir, `security-${date}.html`);
}

const { PKG_VERSION, PKG_HOMEPAGE, cweFor, fixText, loadFindings: loadState, loadAudit: loadAuditState, buildRows } = require('./data');
const loadFindings = () => loadState(STATE);
const loadAudit = () => loadAuditState(AUDIT);

function generateMarkdown(rows, audit) {
  const openRows = rows.filter(r => r.status === 'open');
  const fixedRows = rows.filter(r => r.status === 'fixed');
  const supRows = rows.filter(r => r.status === 'suppressed');
  const baseRows = rows.filter(r => r.status === 'baselined');
  let md = '### 🛡️ Security Scan Summary\n\n';
  md += `**Findings:** ${openRows.length} open, ${fixedRows.length} resolved`
    + (supRows.length ? `, ${supRows.length} suppressed inline` : '')
    + (baseRows.length ? `, ${baseRows.length} in the baseline` : '') + '.\n\n';

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

  // Suppressions are listed so a reviewer sees what was silenced and why.
  if (supRows.length > 0) {
    md += '<details><summary>Suppressed inline (' + supRows.length + ')</summary>\n\n';
    md += '| Finding ID | Location | Reason |\n|:---|:---|:---|\n';
    for (const r of supRows) {
      const fileRel = path.relative(process.cwd(), r.file) || r.file;
      const reason = (r.reason || '_no reason given_').replace(/\|/g, '\\|').slice(0, 100);
      md += `| \`${r.id}\` | \`${fileRel}:${r.line || 1}\` | ${reason} |\n`;
    }
    md += '\n</details>\n\n';
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
  // Suppressed findings are emitted too, marked as in-source suppressions:
  // code scanning then shows them as dismissed, with the reason, rather than
  // the finding vanishing without a trace.
  const openRows = rows.filter(r => r.status === 'open' || r.status === 'suppressed' || r.status === 'baselined');
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
        // The remediation block, not r.fix — that is the matched line, which
        // belongs in the result message, not in the rule's description.
        fullDescription: { text: fixText(r.id) || `Remediation for ${r.id}` },
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
    let startLine = r.line > 0 ? r.line : 1;
    if (!(r.line > 0) && r.fix) {
      const lm = r.fix.match(/Line\s+(\d+)/i);
      if (lm) startLine = parseInt(lm[1], 10);
    }
    const relFile = path.isAbsolute(r.file) ? path.relative(process.cwd(), r.file) : r.file;
    const suppression = r.status === 'suppressed'
      ? { suppressions: [{ kind: 'inSource', justification: r.reason || 'no reason given' }] }
      : r.status === 'baselined'
        ? { suppressions: [{ kind: 'external', justification: 'in .securecoding-baseline.json (known before adoption)' }] }
        : {};
    return {
      ...suppression,
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
            semanticVersion: PKG_VERSION,
            informationUri: PKG_HOMEPAGE,
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
  const rows = buildRows(findings);

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

  if (process.argv.includes('--dashboard')) {
    // The React dashboard with this run's data embedded: one file that opens
    // offline. The JSON goes in a type="application/json" script, which the
    // browser never executes; '<' is escaped so the data cannot close the tag.
    let page;
    try { page = fs.readFileSync(path.join(DIR, 'reports', 'dashboard.html'), 'utf8'); } catch {
      process.stderr.write('secure-coding: reports/dashboard.html is missing — build it with npm --prefix dashboard run build\n');
      process.exit(1);
    }
    const snap = JSON.stringify(require('./data').snapshot()).replace(/</g, '\\u003c');
    const marker = '<script id="sc-snapshot" type="application/json"></script>';
    if (!page.includes(marker)) {
      process.stderr.write('secure-coding: dashboard.html has no snapshot slot — rebuild it\n');
      process.exit(1);
    }
    const outIdx = process.argv.indexOf('--out');
    const out = outIdx >= 0 && process.argv[outIdx + 1] ? path.resolve(process.argv[outIdx + 1])
      : path.join(projectRoot(), 'reports', `dashboard-${new Date().toISOString().slice(0, 10)}.html`);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, page.replace(marker, () => `<script id="sc-snapshot" type="application/json">${snap}</script>`));
    process.stderr.write(`secure-coding: dashboard written to ${out}\n`);
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
