#!/usr/bin/env node
// Audits project dependencies for outdated packages and known vulnerabilities.
// Usage: node hooks/audit.js [dir]
// Output: JSON array of {ecosystem, package, installed, latest, severity, title}
// Env: AUDIT_OUT = "json" (default) or "summary"
// Gracefully skips if audit tool is not installed.
'use strict';

const fs = require('fs');
const path = require('path');
const { statePath, writeState, helpRequested, loadConfig } = require('./config');
const { execFileSync } = require('child_process');

// --help must print help, never run the tool. reset.js used to wipe the
// findings file when asked for help; audit.js and sbom.js ran in full.
const USAGE = `Usage: node hooks/audit.js [dir] [--help]

Audits project dependencies across supported ecosystems (npm, pnpm, yarn,
pip, cargo, go, dotnet, composer, bundler) for known advisories.
Prints a JSON array of {ecosystem, package, installed, latest, severity, title}.

Env: SECURE_CODING_AUDIT (default: <project>/checks/audit.json)`;
if (helpRequested(process.argv.slice(2), USAGE)) process.exit(0);

// argv[2] is a target directory, not a flag — a stray `--help` would otherwise
// be treated as a path and have the audit file written into it.
const ARG = process.argv[2];
const DIR = ARG && !ARG.startsWith('-') ? ARG : process.cwd();
const OUT = process.env.AUDIT_OUT || 'json';
const STATE = statePath('audit.json', 'SECURE_CODING_AUDIT');
const TIMEOUT = 15000; // 15s per tool

const ECOSYSTEMS = [
  {
    name: 'npm',
    files: ['package-lock.json'],
    audit: 'npm audit --json',
    parse: parseNpmAudit,
  },
  {
    name: 'pnpm',
    files: ['pnpm-lock.yaml'],
    audit: 'pnpm audit --json',
    parse: parseNpmAudit,
  },
  {
    name: 'yarn',
    files: ['yarn.lock'],
    audit: 'yarn audit --json',
    parse: parseNpmAudit,
  },
  {
    name: 'pip',
    files: ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile', 'poetry.lock'],
    audit: 'pip-audit --format json',
    parse: parsePipAudit,
  },
  {
    name: 'cargo',
    files: ['Cargo.lock'],
    audit: 'cargo audit --json',
    parse: parseCargoAudit,
  },
  {
    name: 'gomod',
    files: ['go.sum'],
    audit: 'govulncheck -json ./...',
    parse: parseGovulncheck,
  },
  {
    name: 'bundler',
    files: ['Gemfile.lock'],
    audit: 'bundle audit check --format json',
    parse: parseBundleAudit,
  },
  {
    name: 'composer',
    files: ['composer.lock'],
    audit: 'composer audit --format=json',
    parse: parseComposerAudit,
  },
  {
    name: 'dotnet',
    files: ['*.csproj', '*.sln', 'Directory.Build.props'],
    audit: 'dotnet list package --vulnerable --format json',
    parse: parseDotnetAudit,
  },
];

function hasTool(cmd) {
  try {
    const bin = process.platform === 'win32' ? 'where' : 'which';
    execFileSync(bin, [cmd.split(' ')[0]], { stdio: 'ignore' });
    return true;
  } catch { return false; }
}

function run(tool) {
  try {
    const args = tool.split(/\s+/);
    const cmd = args.shift();
    return execFileSync(cmd, args, { cwd: DIR, encoding: 'utf8', timeout: TIMEOUT, stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    // npm audit exits non-zero when vulnerabilities found; still outputs JSON
    if (e.stdout) return e.stdout;
    return null;
  }
}

// --- Parsers ---

function parseNpmAudit(raw) {
  try {
    const data = JSON.parse(raw);
    const results = [];
    const vuln = data.vulnerabilities || {};
    for (const [name, info] of Object.entries(vuln)) {
      const via = info.via || [];
      for (const v of via) {
        if (typeof v === 'string') continue; // advisory reference
        results.push({
          ecosystem: 'npm',
          package: name,
          installed: info.version || '',
          latest: info.fixAvailable ? (typeof info.fixAvailable === 'string' ? info.fixAvailable : info.fixAvailable.version || '') : '',
          severity: v.severity || info.severity || 'unknown',
          title: v.title || '',
        });
      }
      if (via.length === 0 && info.severity !== 'info') {
        results.push({
          ecosystem: 'npm',
          package: name,
          installed: info.version || '',
          latest: '',
          severity: info.severity || 'unknown',
          title: info.vulnerability || '',
        });
      }
    }
    return results;
  } catch { return []; }
}

function parsePipAudit(raw) {
  try {
    const data = JSON.parse(raw);
    return (data.dependencies || []).map(d => ({
      ecosystem: 'pip',
      package: d.name || '',
      installed: d.version || '',
      latest: '',
      severity: d.vulns?.[0]?.fix_versions?.length ? 'vulnerable' : 'unknown',
      title: (d.vulns || []).map(v => v.id || v.description || '').join('; ').slice(0, 120),
    }));
  } catch { return []; }
}

function parseCargoAudit(raw) {
  try {
    const data = JSON.parse(raw);
    return (data.vulnerabilities?.list || []).map(v => ({
      ecosystem: 'cargo',
      package: v.advisory?.package || '',
      installed: v.packages?.[0]?.version || '',
      latest: '',
      severity: v.advisory?.cvss?.score ? String(v.advisory.cvss.score) : 'unknown',
      title: v.advisory?.title || '',
    }));
  } catch { return []; }
}

function parseGovulncheck(raw) {
  try {
    const results = [];
    const lines = raw.split(/\r?\n/);
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (entry.osv) {
          for (const affected of entry.osv.affected || []) {
            for (const pkg of affected.package || []) {
              results.push({
                ecosystem: 'go',
                package: pkg.name || '',
                installed: '',
                latest: '',
                severity: entry.osv.database_specific?.severity || 'unknown',
                title: entry.osv.summary || '',
              });
            }
          }
        }
      } catch { /* not JSON, skip */ }
    }
    return results;
  } catch { return []; }
}

function parseBundleAudit(raw) {
  try {
    const data = JSON.parse(raw);
    return (data.results || []).map(r => ({
      ecosystem: 'ruby',
      package: r.gem || '',
      installed: r.version || '',
      latest: '',
      severity: r.advisory?.severity || 'unknown',
      title: r.advisory?.title || '',
    }));
  } catch { return []; }
}

function parseComposerAudit(raw) {
  try {
    const data = JSON.parse(raw);
    const results = [];
    for (const pkg of data.packages || []) {
      for (const v of pkg.advisories || []) {
        results.push({
          ecosystem: 'php',
          package: pkg.name || '',
          installed: pkg.version || '',
          latest: '',
          severity: v.severity || 'unknown',
          title: v.title || '',
        });
      }
    }
    return results;
  } catch { return []; }
}

function parseDotnetAudit(raw) {
  try {
    const data = JSON.parse(raw);
    const results = [];
    for (const project of data.projects || []) {
      for (const framework of project.frameworks || []) {
        for (const pkg of framework.topLevelPackages || []) {
          for (const vuln of pkg.vulnerabilities || []) {
            results.push({
              ecosystem: 'nuget',
              package: pkg.id || '',
              installed: pkg.resolvedVersion || '',
              latest: '',
              severity: vuln.severity || 'unknown',
              title: vuln.advisoryUrl || 'Vulnerable NuGet package',
            });
          }
        }
      }
    }
    return results;
  } catch { return []; }
}

// Users pick ecosystems by their common name; ECOSYSTEMS keys the Go entry as
// 'gomod' because that is the lockfile family, and the finding output already
// says 'go'. Map between the two rather than renaming either and breaking
// stored audit.json records.
const ECOSYSTEM_ALIASES = { gomod: 'go', go: 'gomod' };

// An ecosystem the project opted out of should not be run at all -- not run
// and then reported as "tool not installed", which is noise about a tool the
// user deliberately does not want. No configured list means audit everything.
function ecosystemEnabled(name, cfg) {
  const wanted = cfg && cfg.audit && Array.isArray(cfg.audit.ecosystems)
    ? cfg.audit.ecosystems : null;
  if (!wanted) return true;
  const alias = ECOSYSTEM_ALIASES[name];
  return wanted.includes(name) || (alias !== undefined && wanted.includes(alias));
}

function main() {
  const results = [];
  const skipped = [];
  const dirFiles = fs.existsSync(DIR) ? fs.readdirSync(DIR) : [];
  const cfg = loadConfig();

  for (const eco of ECOSYSTEMS) {
    if (!ecosystemEnabled(eco.name, cfg)) continue;
    const hasLock = eco.files.some(pattern => {
      if (pattern.startsWith('*.')) {
        const ext = pattern.slice(1);
        return dirFiles.some(f => f.endsWith(ext));
      }
      return fs.existsSync(path.join(DIR, pattern));
    });
    if (!hasLock) continue;

    const tool = eco.audit.split(' ')[0];
    if (!hasTool(tool)) {
      skipped.push({ ecosystem: eco.name, reason: `${tool} not installed` });
      continue;
    }

    const raw = run(eco.audit);
    if (!raw) {
      skipped.push({ ecosystem: eco.name, reason: 'audit failed or timed out' });
      continue;
    }

    const findings = eco.parse(raw);
    results.push(...findings);
  }

  // Write state file for report
  try {
    writeState(STATE, JSON.stringify({ findings: results, skipped, ts: new Date().toISOString() }));
  } catch { /* best effort */ }

  if (OUT === 'summary') {
    if (results.length === 0 && skipped.length === 0) {
      console.log('no dependencies audited (no lock files found)');
    } else {
      if (results.length > 0) {
        const bySev = {};
        results.forEach(r => { bySev[r.severity] = (bySev[r.severity] || 0) + 1; });
        console.log(`${results.length} vulnerability(ies): ${Object.entries(bySev).map(([k, v]) => `${k}:${v}`).join(' ')}`);
      }
      if (skipped.length > 0) {
        console.log(`skipped: ${skipped.map(s => s.ecosystem).join(', ')}`);
      }
    }
  } else {
    console.log(JSON.stringify({ findings: results, skipped }, null, 2));
  }

  const failThreshold = (cfg && cfg.audit && cfg.audit.failOnAdvisory) || (cfg && cfg.failOn) || 'high';
  const sevRank = { critical: 4, high: 3, medium: 2, low: 1, vulnerable: 3, unknown: 1 };
  const minFailRank = sevRank[failThreshold.toLowerCase()] || 3;

  const hasFailing = results.some(r => {
    const rank = sevRank[(r.severity || 'unknown').toLowerCase()] || 1;
    return rank >= minFailRank;
  });

  if (hasFailing) {
    process.exit(2);
  }
}

main();

