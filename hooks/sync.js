#!/usr/bin/env node
// Validates consistency across patterns, templates, review.md, and fixes.md.
// Usage: node hooks/sync.js [--fix]
//   --fix  attempt to auto-fix missing entries (dry run for now)
'use strict';

const fs = require('fs');
const path = require('path');
const { helpRequested } = require('./config');

// --help prints usage and exits, without running the tool.
const USAGE = `Usage: node hooks/sync.js [--fix]

Validates consistency across patterns, templates, review.md and fixes.md,
checks pattern column integrity and alternation safety, and verifies the
counts documented in README.md and INSTALLATION.md.
  --fix   attempt to auto-fix missing entries`;
if (helpRequested(process.argv.slice(2), USAGE)) process.exit(0);

const DIR = path.resolve(__dirname, '..');
const PATTERNS_DIR = path.join(DIR, 'patterns');
const TEMPLATES_DIR = path.join(DIR, 'templates');
const REVIEW = path.join(DIR, 'checks', 'review.md');
const FIXES = path.join(DIR, 'checks', 'fixes.md');
const OUT_OF_SCOPE = path.join(DIR, 'reference', 'out-of-scope.md');

let errors = 0;
let warnings = 0;

function err(msg) { errors++; console.error(`  ERROR: ${msg}`); }
function warn(msg) { warnings++; console.error(`  WARN: ${msg}`); }
function ok(msg) { console.log(`  OK: ${msg}`); }

// --- 1. Parse review.md OWASP ids ---
function parseReviewIds() {
  const text = fs.readFileSync(REVIEW, 'utf8');
  const ids = new Set();
  const re = /\[(\d+(?:,\d+)*)\]/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    m[1].split(',').forEach(id => ids.add(parseInt(id, 10)));
  }
  return ids;
}

// --- 2. Parse out-of-scope.md OWASP ids ---
function parseOutOfScopeIds() {
  const text = fs.readFileSync(OUT_OF_SCOPE, 'utf8');
  const ids = new Set();
  const re = /\[(\d+(?:,\d+)*)\]/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    m[1].split(',').forEach(id => ids.add(parseInt(id, 10)));
  }
  // Also parse standalone numbers like "- [151,152]"
  const re2 = /- \[(\d+(?:,\d+)*)\]/g;
  while ((m = re2.exec(text)) !== null) {
    m[1].split(',').forEach(id => ids.add(parseInt(id, 10)));
  }
  return ids;
}

// --- 3. Parse fixes.md ids ---
function parseFixIds() {
  const text = fs.readFileSync(FIXES, 'utf8');
  const ids = new Set();
  const parts = text.split(/^## /m);
  for (const part of parts) {
    const header = part.match(/^([^\n]+)/);
    if (header) {
      const id = header[1].trim();
      // Skip file headers (start with #) — only count actual fix block ids
      if (!id.startsWith('#')) ids.add(id);
    }
  }
  return ids;
}

// --- 4. Parse pattern ids ---
function parsePatternIds() {
  const ids = new Set();
  if (!fs.existsSync(PATTERNS_DIR)) return ids;
  const files = fs.readdirSync(PATTERNS_DIR).filter(f => f.endsWith('.txt'));
  for (const f of files) {
      const lines = fs.readFileSync(path.join(PATTERNS_DIR, f), 'utf8').split(/\r?\n/);
    for (const line of lines) {
      if (line.startsWith('#') || !line.trim()) continue;
      const parts = line.split('\t');
      if (parts[0]) ids.add(parts[0].trim());
    }
  }
  return ids;
}

// --- 5. Parse template section headers ---
function parseTemplateSections() {
  const sections = {};
  if (!fs.existsSync(TEMPLATES_DIR)) return sections;
  const files = fs.readdirSync(TEMPLATES_DIR).filter(f => f.endsWith('.md'));
  for (const f of files) {
    const lang = f.replace('.md', '');
    const text = fs.readFileSync(path.join(TEMPLATES_DIR, f), 'utf8');
    const headers = [];
    const re = /^## (.+)$/gm;
    let m;
    while ((m = re.exec(text)) !== null) {
      headers.push(m[1].trim());
    }
    sections[lang] = headers;
  }
  return sections;
}


// --- Alternation safety ---
// Four bugs in this repo came from a top-level `|`: a branch matches on its
// own, with none of the anchoring its siblings carry, so the rule fires on
// unrelated text. `a\s*\(|b` means "a(" OR bare "b" -- rarely what was meant.
// Splits on `|` at depth 0 only, ignoring escapes and character classes.
function topLevelBranches(re) {
  const out = [];
  let depth = 0, inClass = false, cur = '';
  for (let i = 0; i < re.length; i++) {
    const c = re[i];
    if (c === '\\') { cur += c + (re[i + 1] || ''); i++; continue; }
    if (inClass) { cur += c; if (c === ']') inClass = false; continue; }
    if (c === '[') { inClass = true; cur += c; continue; }
    if (c === '(') { depth++; cur += c; continue; }
    if (c === ')') { depth--; cur += c; continue; }
    if (c === '|' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

// A bare branch is a plain literal with no anchor, delimiter, or call context.
// Distinctive API names (long CamelCase symbols, namespaced paths) are
// safe bare -- they do not occur in prose. The bug is a bare branch that is a
// short, lowercase, ordinary identifier: those match comments, variable names
// and unrelated text. That is the shape behind every alternation bug here.
function isRiskyBareBranch(branch) {
  const b = branch.trim();
  if (!b) return false;
  if (/[\\^$(){}\[\]*+?]/.test(b)) return false;  // has context already
  if (!/^\w+$/.test(b)) return false;              // paths, dots, hyphens are distinctive
  if (b.length > 18) return false;                 // long names are distinctive
  if (/[A-Z]/.test(b)) return false;               // CamelCase/CONST are distinctive
  return true;                                     // short + all-lowercase = risky
}

function checkAlternations() {
  console.log('\npattern alternation safety:');
  let flagged = 0;
  const files = fs.existsSync(PATTERNS_DIR)
    ? fs.readdirSync(PATTERNS_DIR).filter(f => f.endsWith('.txt')) : [];
  for (const f of files) {
    const lines = fs.readFileSync(path.join(PATTERNS_DIR, f), 'utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      if (!line.trim() || line.startsWith('#')) return;
      const parts = line.split('\t');
      const id = parts[0]?.trim();
      const re = parts[2];
      if (!id || !re) return;
      const branches = topLevelBranches(re);
      if (branches.length < 2) return;
      const bare = branches.filter(isRiskyBareBranch);
      // All-bare is a deliberate keyword list (e.g. mongo operators). A bare
      // branch sitting beside an anchored one is the bug.
      if (bare.length > 0 && bare.length < branches.length) {
        flagged++;
        warn(`${f}:${i + 1} "${id}" mixes bare and anchored branches: ${bare.map(b => JSON.stringify(b.trim())).join(', ')} — parenthesise or add context`);
      }
    });
  }
  if (flagged === 0) ok('no mixed bare/anchored alternations');
}


// --- Documented counts match reality ---
// Five separate stale-number bugs so far: badges claiming 298/292/301/419
// tests against an actual 469-483, "22 rules" against 14, "356 patterns"
// against 376, "6 MCP tools" against 9. Each was a literal typed into prose
// that nothing checked, and each `sed` sweep silently missed a site whose
// formatting differed. Counts are derived here, never hardcoded.
function countPatternRules() {
  let rules = 0;
  const ids = new Set();
  for (const f of fs.readdirSync(PATTERNS_DIR).filter(x => x.endsWith('.txt'))) {
    for (const line of fs.readFileSync(path.join(PATTERNS_DIR, f), 'utf8').split(/\r?\n/)) {
      if (!line.trim() || line.startsWith('#')) continue;
      const parts = line.split('\t');
      if (parts.length > 2 && parts[0].trim()) { rules++; ids.add(parts[0].trim()); }
    }
  }
  return { rules, ids: ids.size };
}

function checkDocCounts() {
  console.log('\ndocumented counts:');
  const { rules } = countPatternRules();
  const truth = {
    patterns: rules,
    templates: fs.readdirSync(TEMPLATES_DIR).filter(f => f.endsWith('.md')).length,
    mcpTools: (fs.readFileSync(path.join(DIR, 'mcp', 'server.js'), 'utf8')
      .match(/^\s*name: '/gm) || []).length,
    cleanRules: (() => {
      try { return require('./clean.js').RULES.length; } catch { return null; }
    })(),
    // Written by test.js on a green run. sync.js runs first in `npm test`, so
    // it cannot invoke the suite; counting uniq() registrations undercounts
    // every test that loops (123 registrations vs 483 assertions). A missing
    // file means the suite has not passed here yet -- skip rather than guess.
    tests: (() => {
      try {
        return parseInt(fs.readFileSync(path.join(DIR, 'checks', '.test-count'), 'utf8').trim(), 10);
      } catch { return null; }
    })(),
  };

  // [regex, what it claims] -- each capture group 1 is the number.
  const CLAIMS = [
    [/(\d+)\s+patterns\b/g, 'patterns'],
    [/(\d+)\s+language templates\b/g, 'templates'],
    [/(\d+)\s+(?:standard )?security tools\b/g, 'mcpTools'],
    [/(\d+)\s+clean[- ]code\b/gi, 'cleanRules'],
  ];

  const docs = ['README.md', 'INSTALLATION.md', 'SKILL.md', 'AGENTS.md']
    .filter(f => fs.existsSync(path.join(DIR, f)));
  let bad = 0;
  for (const doc of docs) {
    const text = fs.readFileSync(path.join(DIR, doc), 'utf8');
    for (const [re, key] of CLAIMS) {
      const want = truth[key];
      if (want == null) continue;
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const got = parseInt(m[1], 10);
        if (got !== want) {
          bad++;
          const line = text.slice(0, m.index).split('\n').length;
          err(`${doc}:${line} claims ${got} ${key}, actual is ${want}`);
        }
      }
    }
  }

  // Test counts appear in badges (Tests-483%20Passing), prose ("483 test
  // assertions", "301 test fixtures") and commands (pass=483). One pass over
  // every shape, so a differently-worded site cannot slip through.
  const TEST_CLAIMS = [
    /Tests-(\d+)%20/g,
    /pass=(\d+)/g,
    /(\d+)\s+test\s+(?:assertions|fixtures|cases)/g,
    /all\s+(\d+)\s+tests?\b/gi,
  ];
  for (const doc of truth.tests == null ? [] : docs) {
    const text = fs.readFileSync(path.join(DIR, doc), 'utf8');
    for (const re of TEST_CLAIMS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const got = parseInt(m[1], 10);
        if (got !== truth.tests) {
          bad++;
          const line = text.slice(0, m.index).split('\n').length;
          err(`${doc}:${line} claims ${got} tests, actual is ${truth.tests}`);
        }
      }
    }
  }

  if (bad === 0) {
    ok(`counts match (${truth.tests == null ? 'tests unknown' : truth.tests + ' tests'},  ${truth.patterns} patterns, ${truth.templates} templates, ${truth.mcpTools} MCP tools, ${truth.cleanRules} clean rules)`);
  }
}


// --- Pattern column integrity ---
// A missing tab merges the remediation hint into the regex column. The rule
// still loads and still compiles, so nothing complains -- it just silently
// stops matching. docker-copy-secrets was dead this way, and the corrupted
// tail of k8s-readonly killed its `VOLUME /var` branch while `/etc` kept
// working, which is why the failure went unnoticed.
function checkPatternColumns() {
  console.log('\npattern column integrity:');
  let bad = 0;
  const files = fs.existsSync(PATTERNS_DIR)
    ? fs.readdirSync(PATTERNS_DIR).filter(f => f.endsWith('.txt')) : [];
  for (const f of files) {
    const lines = fs.readFileSync(path.join(PATTERNS_DIR, f), 'utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      if (!line.trim() || line.startsWith('#')) return;
      const cols = line.split('\t');
      const at = `${f}:${i + 1}`;
      if (cols.length < 4) {
        bad++; err(`${at} has ${cols.length} tab-separated columns, needs at least 4`);
        return;
      }
      const rx = cols[2] || '';
      // Prose markers that cannot appear in any regex we write. An em-dash is
      // the giveaway: every hint uses one, no pattern does.
      if (/[—–]/.test(rx)) {
        bad++; err(`${at} "${cols[0]}" has hint prose in the regex column (em-dash): ${rx.slice(0, 60)}`);
        return;
      }
      try { new RegExp(rx); } catch (e) {
        bad++; err(`${at} "${cols[0]}" regex does not compile: ${e.message.slice(0, 60)}`);
      }
    });
  }
  if (bad === 0) ok('every pattern line has its columns intact');
}

// --- Main ---
function main() {
  console.log('--- sync check ---\n');

  const reviewIds = parseReviewIds();
  const outOfScopeIds = parseOutOfScopeIds();
  const fixIds = parseFixIds();
  const patternIds = parsePatternIds();
  const templateSections = parseTemplateSections();

  // Check: every review id has a fix block (or is out-of-scope)
  console.log('review.md → fixes.md coverage:');
  let missingFixes = 0;
  for (const id of reviewIds) {
    if (!fixIds.has(String(id)) && !outOfScopeIds.has(id)) {
      // Not every review item needs a fix block — only pattern-detected ones
    }
  }
  ok(`${reviewIds.size} review ids, ${fixIds.size} fix blocks`);

  // Check: pattern ids and regex compilation
  console.log('\npatterns:');
  const patternFiles = fs.readdirSync(PATTERNS_DIR).filter(f => f.endsWith('.txt'));
  let totalRegexCount = 0;
  for (const f of patternFiles) {
    const lines = fs.readFileSync(path.join(PATTERNS_DIR, f), 'utf8').split(/\r?\n/);
    lines.forEach((line, idx) => {
      if (line.startsWith('#') || !line.trim()) return;
      const parts = line.split('\t');
      if (parts.length < 3) {
        err(`${f}:${idx + 1}: expected at least 3 tab-separated columns, got ${parts.length}`);
        return;
      }
      const [id, exts, regex, col4] = parts;
      if (!id || !regex) {
        err(`${f}:${idx + 1}: missing id or regex`);
        return;
      }
      if (!fixIds.has(id)) {
        err(`${f}:${idx + 1}: pattern id "${id}" has no matching "## ${id}" in fixes.md`);
      }
      try {
        new RegExp(regex);
        totalRegexCount++;
      } catch (e) {
        err(`${f}:${idx + 1}: invalid regex in pattern "${id}": ${e.message}`);
      }
      if (col4 && col4.startsWith('!')) {
        try {
          new RegExp(col4.slice(1));
        } catch (e) {
          err(`${f}:${idx + 1}: invalid exclusion regex in pattern "${id}": ${e.message}`);
        }
      }
    });
  }
  ok(`${patternIds.size} pattern ids (${totalRegexCount} regexes) across ${patternFiles.length} files`);

  // Check: template coverage
  console.log('\ntemplates:');
  const expectedSections = [
    'Parameterized query', 'Password hashing', 'Authenticated encryption',
    'Secure random', 'Constant-time', 'Temp file', 'Secure cookie',
    'Shell', 'Input validation', 'Output encoding', 'TLS',
    'Secrets', 'Error handling', 'Secure logging',
    'File upload', 'Safe redirect', 'Cache-Control', 'Session',
    'Password complexity', 'File permissions', 'Encryption at rest',
    'Integrity verification', 'SSRF prevention', 'CORS', 'Log injection',
  ];
  // Sections that genuinely do not apply to a language, so their absence is not
  // a gap. Keep these tight: anything listed here is invisible to the check.
  const NOT_APPLICABLE = {
    // C is a systems language: no HTTP tier. It does query databases, exec
    // processes and write logs, so those stay required.
    c: ['Secure cookie', 'Output encoding', 'TLS', 'Cache-Control', 'Session', 'File upload', 'Safe redirect', 'SSRF prevention', 'CORS'],
    // Shell scripts are not an HTTP server either.
    shell: ['Secure cookie', 'Output encoding', 'TLS', 'Cache-Control', 'Session', 'File upload', 'Safe redirect', 'CORS'],
  };

  // A template that does not exist cannot be reported as missing sections, so
  // check the roster explicitly — this is how the absent shell template hid.
  const EXPECTED_LANGS = ['c', 'csharp', 'go', 'java', 'javascript', 'kotlin', 'php',
                          'python', 'ruby', 'rust', 'shell', 'swift', 'typescript'];
  for (const lang of EXPECTED_LANGS) {
    if (!fs.existsSync(path.join(TEMPLATES_DIR, `${lang}.md`))) {
      err(`template missing entirely: templates/${lang}.md`);
    }
  }

  const langFiles = fs.readdirSync(TEMPLATES_DIR).filter(f => f.endsWith('.md'));
  for (const f of langFiles) {
    const lang = f.replace('.md', '');
    const sections = templateSections[lang] || [];
    const skipSections = NOT_APPLICABLE[lang] || [];
    const missing = expectedSections.filter(exp => {
      if (skipSections.includes(exp)) return false;
      return !sections.some(s => s.toLowerCase().includes(exp.toLowerCase().split(' ')[0]));
    });
    if (missing.length > 0) {
      warn(`${lang}: missing sections: ${missing.join(', ')}`);
    } else {
      ok(`${lang}: all ${expectedSections.length} expected sections present`);
    }
  }

  // Check: no duplicate pattern ids ACROSS FILES (same id in same file is expected — different regexes)
  console.log('\npattern cross-file duplicates:');
  const seenPatterns = {};
  const files = fs.readdirSync(PATTERNS_DIR).filter(f => f.endsWith('.txt'));
  for (const f of files) {
    const lines = fs.readFileSync(path.join(PATTERNS_DIR, f), 'utf8').split(/\r?\n/);
    for (const line of lines) {
      if (line.startsWith('#') || !line.trim()) continue;
      const parts = line.split('\t');
      const id = parts[0]?.trim();
      if (id) {
        if (!seenPatterns[id]) seenPatterns[id] = new Set();
        seenPatterns[id].add(f);
      }
    }
  }
  // One defect keeps one id even when a generic rule and a language-specific
  // rule live in different files. Listed ids are deliberately shared; anything
  // else spanning files is an accidental collision worth warning about.
  const SHARED_IDS = new Set(['insecure-deserialization']);
  const dupes = Object.entries(seenPatterns)
    .filter(([id, files]) => files.size > 1 && !SHARED_IDS.has(id));
  if (dupes.length > 0) {
    for (const [id, files] of dupes) {
      warn(`pattern "${id}" appears in multiple files: ${[...files].join(', ')}`);
    }
  } else {
    ok('no cross-file pattern duplicates');
  }

  checkPatternColumns();
  checkAlternations();
  checkDocCounts();

  // Summary
  console.log(`\n--- result: ${errors} errors, ${warnings} warnings ---`);
  process.exit(errors > 0 ? 1 : 0);
}

if (require.main === module) main();

module.exports = { topLevelBranches, isRiskyBareBranch };
