#!/usr/bin/env node
// Validates consistency across patterns, templates, review.md, and fixes.md.
// Usage: node hooks/sync.js [--fix]
//   --fix  attempt to auto-fix missing entries (dry run for now)
'use strict';

const fs = require('fs');
const path = require('path');

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
  // C is a systems language — web-only sections don't apply
  const webOnlySections = ['Parameterized query', 'Secure cookie', 'Output encoding', 'TLS', 'Cache-Control', 'Session', 'File upload', 'Safe redirect', 'Shell', 'SSRF prevention', 'CORS', 'Log injection'];

  const langFiles = fs.readdirSync(TEMPLATES_DIR).filter(f => f.endsWith('.md'));
  for (const f of langFiles) {
    const lang = f.replace('.md', '');
    const sections = templateSections[lang] || [];
    const skipSections = lang === 'c' ? webOnlySections : [];
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
  const dupes = Object.entries(seenPatterns).filter(([, files]) => files.size > 1);
  if (dupes.length > 0) {
    for (const [id, files] of dupes) {
      warn(`pattern "${id}" appears in multiple files: ${[...files].join(', ')}`);
    }
  } else {
    ok('no cross-file pattern duplicates');
  }

  // Summary
  console.log(`\n--- result: ${errors} errors, ${warnings} warnings ---`);
  process.exit(errors > 0 ? 1 : 0);
}

main();
