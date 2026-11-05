#!/usr/bin/env node
// ==============================================================================
// 🛡️ secure-coding: Software Bill of Materials (SBOM) & AI-SBOM Engine
// Generates CycloneDX v1.5 or SPDX v2.3 JSON manifests with BSI AI-SBOM 7 Clusters
// and ACSC/CISA Vulnerability Exploitability eXchange (VEX) integration.
// Supports 9 ecosystems: npm, pnpm, yarn, pip, poetry, cargo, go, composer, bundler, dotnet.
// Usage:
//   node hooks/sbom.js [--format cyclonedx|spdx] [--ai] [--vex] [--out <file>]
// ==============================================================================
'use strict';

const fs = require('fs');
const path = require('path');
const { statePath, helpRequested, normalizeSeverity } = require('./config');
const { randomUUID } = require('crypto');

// --help must print help, never run the tool. reset.js used to wipe the
// findings file when asked for help; audit.js and sbom.js ran in full.
const USAGE = `Usage: node hooks/sbom.js [--format cyclonedx|spdx] [--ai] [--vex] [--out <file>]

Generates a CycloneDX v1.5 or SPDX v2.3 manifest.
  --format     output specification (default: cyclonedx)
  --ai         include the BSI AI-SBOM 7 information clusters
  --vex        include VEX exploitability statements
  --out <f>    write to a file instead of stdout`;
if (helpRequested(process.argv.slice(2), USAGE)) process.exit(0);

// The project being described. Resolved from the git toplevel so lockfiles at
// the root are found when the command runs from a subdirectory.
const DIR = require('./config').projectRoot();
// DIR is the project being described; the tool's own identity comes from the
// installed package, not from whatever repository is being scanned.
const SELF_PKG = (() => {
  try { return require(path.join(__dirname, '..', 'package.json')); } catch { return {}; }
})();
const SELF_VENDOR = (SELF_PKG.author && SELF_PKG.author.name) || 'secure-coding';
const SELF_VERSION = SELF_PKG.version || '0.0.0';
const FINDINGS_FILE = statePath('findings.jsonl', 'SECURE_CODING_STATE');
const AUDIT_FILE = statePath('audit.json', 'SECURE_CODING_AUDIT');

// --- Package URLs ---
// purl spec: each namespace/name segment percent-encoded on its own, the
// version after '@' only when it is known. `@scope/pkg` is namespace
// "%40scope" + name "pkg" — encoding the whole string turned the separator
// into %2F, which no purl consumer resolves.
function purl(type, name, version) {
  const segs = String(name).split('/').filter(Boolean).map(encodeURIComponent);
  const v = version ? `@${encodeURIComponent(String(version))}` : '';
  return `pkg:${type}/${segs.join('/')}${v}`;
}

// --- Ecosystem Parsers ---

function parsePackageLock() {
  const file = path.join(DIR, 'package-lock.json');
  if (!fs.existsSync(file)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    const pkgs = [];
    if (data.packages) {
      for (const [pPath, pInfo] of Object.entries(data.packages)) {
        if (!pPath || pPath === '') continue;
        // node_modules/a/node_modules/lodash is lodash, nested under a.
        // Paths outside node_modules are workspace packages, not dependencies.
        if (!pPath.includes('node_modules/') || pInfo.link) continue;
        const name = pInfo.name || pPath.slice(pPath.lastIndexOf('node_modules/') + 'node_modules/'.length);
        pkgs.push({
          name,
          version: pInfo.version || undefined,
          ecosystem: 'npm',
          purl: purl('npm', name, pInfo.version),
        });
      }
    } else if (data.dependencies) {
      for (const [name, pInfo] of Object.entries(data.dependencies)) {
        pkgs.push({
          name,
          version: pInfo.version || undefined,
          ecosystem: 'npm',
          purl: purl('npm', name, pInfo.version),
        });
      }
    }
    return pkgs;
  } catch { return []; }
}

function parsePnpmLock() {
  const file = path.join(DIR, 'pnpm-lock.yaml');
  if (!fs.existsSync(file)) return [];
  try {
    const text = fs.readFileSync(file, 'utf8');
    const pkgs = [];
    const lines = text.split(/\r?\n/);
    for (const l of lines) {
      // pnpm format: '/@scope/name@version:' or '/name@version:'
      const m = l.match(/^\s*['"]?\/((?:@[^/@]+\/)?[^/@]+)@([0-9a-zA-Z_.-]+)['"]?:/);
      if (m) {
        const name = m[1];
        const version = m[2];
        pkgs.push({
          name,
          version,
          ecosystem: 'npm',
          purl: purl('npm', name, version),
        });
      }
    }
    return pkgs;
  } catch { return []; }
}

function parseYarnLock() {
  const file = path.join(DIR, 'yarn.lock');
  if (!fs.existsSync(file)) return [];
  try {
    const text = fs.readFileSync(file, 'utf8');
    const pkgs = [];
    const entries = text.split(/\n(?=[^\s#])/);
    for (const entry of entries) {
      const header = entry.split('\n')[0];
      const mName = header.match(/^"?(@?[^@\n,"]+)@/);
      const mVer = entry.match(/version\s+"?([^"\n]+)"?/);
      if (mName && mVer) {
        const name = mName[1].trim();
        const version = mVer[1].trim();
        pkgs.push({
          name,
          version,
          ecosystem: 'npm',
          purl: purl('npm', name, version),
        });
      }
    }
    return pkgs;
  } catch { return []; }
}

function parseRequirementsTxt() {
  const file = path.join(DIR, 'requirements.txt');
  if (!fs.existsSync(file)) return [];
  try {
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    const pkgs = [];
    for (const line of lines) {
      // Drop comments and environment markers (; python_version < "3.9").
      const clean = line.split('#')[0].split(';')[0].trim();
      if (!clean || clean.startsWith('-')) continue;
      const m = clean.match(/^([A-Za-z0-9_.-]+)(\[[^\]]*\])?\s*(.*)$/);
      if (!m) continue;
      const name = m[1].toLowerCase().replace(/[_.]+/g, '-'); // PEP 503 name
      const spec = m[3].trim();
      // Only an exact pin names the installed version. `>=2.0` is a range:
      // recording it as version 2.0 claimed a version that is not installed.
      const pin = spec.match(/^===?\s*([^,\s]+)$/);
      const comp = { name, version: pin ? pin[1] : undefined, ecosystem: 'pypi', purl: purl('pypi', name, pin ? pin[1] : undefined) };
      if (!pin && spec) comp.versionRange = spec;
      pkgs.push(comp);
    }
    return pkgs;
  } catch { return []; }
}

function parsePoetryLock() {
  const file = path.join(DIR, 'poetry.lock');
  if (!fs.existsSync(file)) return [];
  try {
    const text = fs.readFileSync(file, 'utf8');
    const pkgs = [];
    const blocks = text.split(/\[\[package\]\]/);
    for (const b of blocks.slice(1)) {
      const name = (b.match(/name\s*=\s*"([^"]+)"/) || [])[1];
      const version = (b.match(/version\s*=\s*"([^"]+)"/) || [])[1];
      if (name && version) {
        pkgs.push({
          name,
          version,
          ecosystem: 'pypi',
          purl: purl('pypi', name, version),
        });
      }
    }
    return pkgs;
  } catch { return []; }
}

function parseCargoLock() {
  const file = path.join(DIR, 'Cargo.lock');
  if (!fs.existsSync(file)) return [];
  try {
    const text = fs.readFileSync(file, 'utf8');
    const pkgs = [];
    const blocks = text.split(/\[\[package\]\]/);
    for (const b of blocks.slice(1)) {
      const name = (b.match(/name\s*=\s*"([^"]+)"/) || [])[1];
      const version = (b.match(/version\s*=\s*"([^"]+)"/) || [])[1];
      if (name && version) {
        pkgs.push({
          name,
          version,
          ecosystem: 'cargo',
          purl: purl('cargo', name, version),
        });
      }
    }
    return pkgs;
  } catch { return []; }
}

function parseGoSum() {
  const file = path.join(DIR, 'go.sum');
  if (!fs.existsSync(file)) return [];
  try {
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    const seen = new Set();
    const pkgs = [];
    for (const l of lines) {
      const parts = l.trim().split(/\s+/);
      if (parts.length >= 2) {
        const name = parts[0];
        const ver = parts[1].replace(/\/go\.mod$/, '');
        const key = `${name}@${ver}`;
        if (!seen.has(key)) {
          seen.add(key);
          pkgs.push({
            name,
            version: ver,
            ecosystem: 'golang',
            purl: purl('golang', name, ver),
          });
        }
      }
    }
    return pkgs;
  } catch { return []; }
}

function parseComposerLock() {
  const file = path.join(DIR, 'composer.lock');
  if (!fs.existsSync(file)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    const pkgs = [];
    for (const p of data.packages || []) {
      pkgs.push({
        name: p.name,
        version: p.version || '0.0.0',
        ecosystem: 'composer',
        purl: purl('composer', p.name, p.version),
      });
    }
    return pkgs;
  } catch { return []; }
}

function parseGemfileLock() {
  const file = path.join(DIR, 'Gemfile.lock');
  if (!fs.existsSync(file)) return [];
  try {
    const text = fs.readFileSync(file, 'utf8');
    const pkgs = [];
    const specsMatch = text.match(/specs:\s*\n((?:\s{4,}.*\n?)+)/);
    if (specsMatch) {
      const lines = specsMatch[1].split(/\r?\n/);
      for (const l of lines) {
        const m = l.match(/^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)/);
        if (m) {
          pkgs.push({
            name: m[1],
            version: m[2],
            ecosystem: 'gem',
            purl: purl('gem', m[1], m[2]),
          });
        }
      }
    }
    return pkgs;
  } catch { return []; }
}

function parseDotnetLock() {
  const pkgs = [];
  const lockFile = path.join(DIR, 'packages.lock.json');
  if (fs.existsSync(lockFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
      for (const tfm of Object.values(data.dependencies || {})) {
        for (const [name, info] of Object.entries(tfm)) {
          pkgs.push({
            name,
            version: info.resolved || '0.0.0',
            ecosystem: 'nuget',
            purl: purl('nuget', name, info.resolved),
          });
        }
      }
    } catch {}
  }
  return pkgs;
}

function getAllComponents() {
  const all = [
    ...parsePackageLock(),
    ...parsePnpmLock(),
    ...parseYarnLock(),
    ...parseRequirementsTxt(),
    ...parsePoetryLock(),
    ...parseCargoLock(),
    ...parseGoSum(),
    ...parseComposerLock(),
    ...parseGemfileLock(),
    ...parseDotnetLock(),
  ];
  // Deduplicate
  const seen = new Set();
  const unique = [];
  for (const c of all) {
    if (!seen.has(c.purl)) {
      seen.add(c.purl);
      unique.push(c);
    }
  }
  return unique;
}

// --- AI-SBOM 7-Cluster Generation (BSI Standard) ---

function detectAiComponents(components) {
  const aiNames = new Set([
    'langchain', 'langchain-core', 'openai', 'anthropic', 'transformers',
    'torch', 'pytorch', 'tensorflow', 'vllm', 'ollama', 'chromadb',
    'qdrant-client', 'weaviate-client', 'sentence-transformers', 'llama-cpp-python',
  ]);
  return components.some(c => aiNames.has(c.name.toLowerCase()));
}

// --- BSI/G7 "SBOM for AI" minimum elements ---
// All 7 clusters. Every element the document names is emitted, so nothing is
// silently missing; unknown values carry the TODO sentinel rather than a
// plausible-looking default that would ship as if it were real.
const AI_TODO = 'TODO';

// [cluster, element, value] — value null means "must be filled in by the author".
const BSI_ELEMENTS = [
  // 2.1 Metadata (about the SBOM itself, not the component)
  ['metadata', 'sbom_author', null],
  ['metadata', 'sbom_version', '1'],
  ['metadata', 'sbom_data_format_name', 'CycloneDX'],
  ['metadata', 'sbom_data_format_version', '1.5'],
  ['metadata', 'sbom_author_signature', null],
  ['metadata', 'sbom_generation_context', null],
  ['metadata', 'sbom_dependency_relationship', null],
  // 2.2 System Level Properties
  ['slp', 'system_name', null],
  ['slp', 'system_components', null],
  ['slp', 'system_producer', null],
  ['slp', 'system_version', null],
  ['slp', 'system_data_flow', null],
  ['slp', 'system_data_usage', null],
  ['slp', 'system_input_output_properties', null],
  ['slp', 'intended_application_area', null],
  // 2.3 Models
  ['models', 'model_name', null],
  ['models', 'model_identifier', null],
  ['models', 'model_version', null],
  ['models', 'model_producer', null],
  ['models', 'model_description', null],
  ['models', 'model_hash_value', null],
  ['models', 'model_hash_algorithm', null],
  ['models', 'model_properties', null],
  ['models', 'model_input_output_properties', null],
  ['models', 'model_training_properties', null],
  ['models', 'model_license', null],
  ['models', 'model_external_references', null],
  // 2.4 Dataset Properties
  ['dp', 'dataset_name', null],
  ['dp', 'dataset_description', null],
  ['dp', 'dataset_content', null],
  ['dp', 'dataset_identifier', null],
  ['dp', 'dataset_hash', null],
  ['dp', 'dataset_provenance', null],
  ['dp', 'dataset_statistical_properties', null],
  ['dp', 'dataset_sensitivity', null],
  ['dp', 'dataset_dependency_relationship', null],
  ['dp', 'dataset_license', null],
  // 2.5 Infrastructure
  ['infra', 'infrastructure_software', null],
  ['infra', 'infrastructure_hardware', null],
  // 2.6 Security Properties
  ['sp', 'security_controls', null],
  ['sp', 'security_compliance', null],
  ['sp', 'cybersecurity_policy_information', null],
  ['sp', 'vulnerability_referencing', null],
  // 2.7 Key Performance Indicators
  ['kpi', 'security_metrics', null],
  ['kpi', 'operational_performance_kpis', null],
];

function generateAiClusters(opts = {}) {
  const now = opts.timestamp || new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const properties = [];

  for (const [cluster, element, value] of BSI_ELEMENTS) {
    properties.push({
      name: `bsi:cluster:${cluster}:${element}`,
      value: value === null ? AI_TODO : value,
    });
  }
  // Timestamps are the elements we can legitimately fill in.
  for (const cluster of ['metadata', 'slp', 'models', 'dp']) {
    properties.push({ name: `bsi:cluster:${cluster}:timestamp`, value: now });
  }

  return [
    {
      type: 'machine-learning-model',
      'bom-ref': 'ai-model-primary',
      name: 'primary-ai-model',
      version: '1.0.0',
      description:
        'AI component scaffold covering all 7 BSI/G7 SBOM-for-AI clusters. ' +
        `Every element marked "${AI_TODO}" must be completed before this is a conformant AI-SBOM.`,
      modelCard: {
        modelParameters: { task: AI_TODO, architecture: AI_TODO },
        quantitativeAnalysis: { performanceMetrics: [] },
      },
      properties,
    },
  ];
}

// How many BSI elements are still unfilled. Lets the CLI warn instead of
// letting a scaffold be mistaken for a finished artifact.
function countAiTodos(components) {
  let todo = 0, total = 0;
  for (const c of components || []) {
    for (const p of c.properties || []) {
      if (!p.name.startsWith('bsi:cluster:')) continue;
      total++;
      if (p.value === AI_TODO) todo++;
    }
  }
  return { todo, total };
}

// --- ACSC & CISA VEX Generation ---

// bom-ref of the application itself; findings in its own code point here.
const ROOT_REF = 'root-application';

// Audit ecosystems use the package manager's name; purl uses its own.
const PURL_TYPE = { npm: 'npm', pnpm: 'npm', yarn: 'npm', pip: 'pypi', pypi: 'pypi', cargo: 'cargo',
  go: 'golang', golang: 'golang', ruby: 'gem', bundler: 'gem', gem: 'gem', php: 'composer',
  composer: 'composer', nuget: 'nuget', dotnet: 'nuget' };

// A CVE or GHSA id when the advisory text carries one.
function advisoryId(f) {
  const text = [f.id, f.title, f.advisory, f.url].filter(Boolean).join(' ');
  const m = text.match(/\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|RUSTSEC-\d{4}-\d{4}|PYSEC-\d{4}-\d+|GO-\d{4}-\d{4})\b/i);
  if (!m) return null;
  // GHSA ids are canonically lower-case after the prefix; the others upper.
  return /^ghsa-/i.test(m[1]) ? 'GHSA-' + m[1].slice(5).toLowerCase() : m[1].toUpperCase();
}

// VEX statements. Each `affects` ref is the bom-ref of a component in this
// BOM: refs to anything else (a file path, a purl with no matching
// component) leave the statement attached to nothing.
function generateVexVulnerabilities(components = []) {
  const vulns = [];
  const byKey = new Map();
  for (const c of components) {
    if (c.ecosystem) byKey.set(`${PURL_TYPE[c.ecosystem] || c.ecosystem}|${String(c.name).toLowerCase()}|${c.version || ''}`, c.purl);
  }
  const refFor = (eco, name, version) => {
    const type = PURL_TYPE[String(eco).toLowerCase()] || String(eco).toLowerCase();
    const n = String(name).toLowerCase();
    return byKey.get(`${type}|${n}|${version || ''}`)
      || [...byKey.entries()].find(([k]) => k.startsWith(`${type}|${n}|`))?.[1]
      || null;
  };

  // Load audit findings
  if (fs.existsSync(AUDIT_FILE)) {
    try {
      const audit = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8'));
      for (const f of audit.findings || []) {
        const ref = refFor(f.ecosystem, f.package, f.installed);
        vulns.push({
          id: advisoryId(f) || `ADVISORY-${f.ecosystem}-${f.package}`,
          description: f.title || undefined,
          ratings: [{ severity: normalizeSeverity(f.severity) }],
          analysis: {
            state: 'in_triage',
            detail: `Advisory reported by the ${f.ecosystem} audit for ${f.package}@${f.installed || 'unknown'}`,
            response: ['update'],
          },
          affects: [{ ref: ref || ROOT_REF }],
        });
      }
    } catch { /* unreadable audit file: no audit statements */ }
  }

  // Open findings in the application's own code.
  if (fs.existsSync(FINDINGS_FILE)) {
    try {
      const lines = fs.readFileSync(FINDINGS_FILE, 'utf8').split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        const item = JSON.parse(line);
        if (item.status === 'open') {
          const where = path.relative(DIR, item.file || '') || item.file || 'source';
          vulns.push({
            id: `RULE-${item.id}`,
            ratings: [{ severity: normalizeSeverity(item.severity) }],
            analysis: {
              state: 'exploitable',
              detail: `${where}${item.line ? ':' + item.line : ''} — ${item.note || `code pattern violation: ${item.id}`}`,
              response: ['update'],
            },
            affects: [{ ref: ROOT_REF }],
          });
        }
      }
    } catch { /* unreadable findings file: no code statements */ }
  }

  return vulns;
}

// --- CycloneDX & SPDX Exporters ---

function generateCycloneDX(components, options = {}) {
  const { includeAi = false, includeVex = false } = options;

  // bom-ref = purl: unique after de-duplication, and what VEX `affects`
  // points at. A requirement range is kept as a property, not as a version.
  let allComponents = components.map(c => {
    const comp = { type: 'library', 'bom-ref': c.purl, name: c.name };
    if (c.version) comp.version = c.version;
    comp.purl = c.purl;
    comp.scope = 'required';
    if (c.versionRange) comp.properties = [{ name: 'secure-coding:requirement', value: c.versionRange }];
    return comp;
  });

  if (includeAi || detectAiComponents(components)) {
    allComponents.push(...generateAiClusters());
  }

  const cdx = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${randomUUID()}`, // CycloneDX requires an RFC-4122 UUID
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: SELF_VENDOR,
          name: 'secure-coding-sbom',
          version: SELF_VERSION,
        },
      ],
      component: {
        type: 'application',
        'bom-ref': ROOT_REF,
        name: path.basename(DIR),
        version: '1.0.0',
      },
    },
    components: allComponents,
  };

  if (includeVex) {
    cdx.vulnerabilities = generateVexVulnerabilities(components);
  }

  return cdx;
}

function generateSPDX(components) {
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: path.basename(DIR),
    documentNamespace: `https://spdx.org/spdxdocs/${path.basename(DIR)}-${Date.now()}`,
    creationInfo: {
      creators: [`Tool: secure-coding-sbom-${SELF_VERSION}`],
      created: new Date().toISOString(),
    },
    packages: components.map((c, idx) => ({
      name: c.name,
      SPDXID: `SPDXRef-Package-${idx + 1}`,
      ...(c.version ? { versionInfo: c.version } : {}),
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: c.purl,
        },
      ],
    })),
  };
}

function main() {
  const args = process.argv.slice(2);
  const isSpdx = args.includes('--format') && args[args.indexOf('--format') + 1] === 'spdx';
  const includeAi = args.includes('--ai');
  const includeVex = args.includes('--vex');
  const outIdx = args.indexOf('--out');
  const outFile = outIdx >= 0 ? args[outIdx + 1] : null;

  const components = getAllComponents();
  const sbom = isSpdx
    ? generateSPDX(components)
    : generateCycloneDX(components, { includeAi, includeVex });
  const jsonStr = JSON.stringify(sbom, null, 2) + '\n';

  // Warn on stderr so it never corrupts piped JSON: a scaffold with unfilled
  // BSI elements is not a conformant AI-SBOM and should not be shipped as one.
  const { todo, total } = countAiTodos(sbom.components);
  if (todo > 0) {
    process.stderr.write(
      `secure-coding: AI-SBOM scaffold — ${todo}/${total} BSI elements still marked TODO. ` +
      `Fill them in (or mark not-applicable) before publishing.\n`);
  }

  if (outFile) {
    fs.writeFileSync(outFile, jsonStr);
    process.stderr.write(`secure-coding: SBOM written to ${outFile} (${components.length} components, AI: ${includeAi || detectAiComponents(components)}, VEX: ${includeVex})\n`);
  } else {
    process.stdout.write(jsonStr);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  getAllComponents,
  generateCycloneDX,
  generateSPDX,
  detectAiComponents,
  generateAiClusters,
  countAiTodos,
  BSI_ELEMENTS,
  generateVexVulnerabilities,
};
