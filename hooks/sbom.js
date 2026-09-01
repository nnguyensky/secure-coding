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
const { randomUUID } = require('crypto');

const DIR = process.cwd();
const FINDINGS_FILE = process.env.SECURE_CODING_STATE || path.join(__dirname, '..', 'checks', 'findings.jsonl');
const AUDIT_FILE = process.env.SECURE_CODING_AUDIT || path.join(__dirname, '..', 'checks', 'audit.json');

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
        const name = pInfo.name || pPath.replace(/^node_modules\//, '');
        pkgs.push({
          name,
          version: pInfo.version || '0.0.0',
          ecosystem: 'npm',
          purl: `pkg:npm/${name.startsWith('@') ? encodeURIComponent(name) : name}@${pInfo.version || '0.0.0'}`,
        });
      }
    } else if (data.dependencies) {
      for (const [name, pInfo] of Object.entries(data.dependencies)) {
        pkgs.push({
          name,
          version: pInfo.version || '0.0.0',
          ecosystem: 'npm',
          purl: `pkg:npm/${name.startsWith('@') ? encodeURIComponent(name) : name}@${pInfo.version || '0.0.0'}`,
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
          purl: `pkg:npm/${name.startsWith('@') ? encodeURIComponent(name) : name}@${version}`,
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
          purl: `pkg:npm/${name.startsWith('@') ? encodeURIComponent(name) : name}@${version}`,
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
      const clean = line.split('#')[0].trim();
      if (!clean) continue;
      const m = clean.match(/^([A-Za-z0-9_.-]+)(?:==|>=|<=|~=)(.+)$/);
      if (m) {
        pkgs.push({
          name: m[1],
          version: m[2].trim(),
          ecosystem: 'pypi',
          purl: `pkg:pypi/${m[1]}@${m[2].trim()}`,
        });
      }
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
          purl: `pkg:pypi/${name}@${version}`,
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
          purl: `pkg:cargo/${name}@${version}`,
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
            purl: `pkg:golang/${name}@${ver}`,
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
        purl: `pkg:composer/${p.name}@${p.version || '0.0.0'}`,
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
            purl: `pkg:gem/${m[1]}@${m[2]}`,
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
            purl: `pkg:nuget/${name}@${info.resolved || '0.0.0'}`,
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

function generateVexVulnerabilities() {
  const vulns = [];

  // Load audit findings
  if (fs.existsSync(AUDIT_FILE)) {
    try {
      const audit = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8'));
      for (const f of audit.findings || []) {
        vulns.push({
          id: f.title ? f.title.slice(0, 50) : `VULN-${f.package}`,
          ratings: [{ severity: f.severity || 'medium' }],
          analysis: {
            state: 'in_triage',
            detail: `Advisory detected in ${f.package}@${f.installed}`,
            responses: ['update'],
          },
          affects: [{ ref: `pkg:${f.ecosystem}/${f.package}@${f.installed}` }],
        });
      }
    } catch {}
  }

  // Load findings.jsonl open items
  if (fs.existsSync(FINDINGS_FILE)) {
    try {
      const lines = fs.readFileSync(FINDINGS_FILE, 'utf8').split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        const item = JSON.parse(line);
        if (item.status === 'open') {
          vulns.push({
            id: `RULE-${item.id}`,
            ratings: [{ severity: item.severity || 'high' }],
            analysis: {
              state: 'affected',
              detail: item.note || `Code pattern violation: ${item.id}`,
              responses: ['workaround_available'],
            },
            affects: [{ ref: path.relative(process.cwd(), item.file || 'source') }],
          });
        }
      }
    } catch {}
  }

  return vulns;
}

// --- CycloneDX & SPDX Exporters ---

function generateCycloneDX(components, options = {}) {
  const { includeAi = false, includeVex = false } = options;

  let allComponents = components.map(c => ({
    type: 'library',
    name: c.name,
    version: c.version,
    purl: c.purl,
    scope: 'required',
  }));

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
          vendor: 'OWASP',
          name: 'secure-coding-sbom',
          version: '2.1.0',
        },
      ],
      component: {
        type: 'application',
        name: path.basename(DIR),
        version: '1.0.0',
      },
    },
    components: allComponents,
  };

  if (includeVex) {
    cdx.vulnerabilities = generateVexVulnerabilities();
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
      creators: ['Tool: secure-coding-sbom-2.1.0'],
      created: new Date().toISOString(),
    },
    packages: components.map((c, idx) => ({
      name: c.name,
      SPDXID: `SPDXRef-Package-${idx + 1}`,
      versionInfo: c.version,
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
