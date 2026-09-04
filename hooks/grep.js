#!/usr/bin/env node
// Targeted search: find pattern hits across the project.
// Usage:
//   node hooks/grep.js <pattern-id> [path]    search by pattern id
//   node hooks/grep.js --regex <re> [path]    search by custom regex
//   node hooks/grep.js --list                  list all pattern ids
//   node hooks/grep.js --hints                 show fix hints for all patterns
//
// Requires Node.js (any modern version). No dependencies.
'use strict';

const fs = require('fs');
const path = require('path');
const { helpRequested } = require('./config');

// --help prints usage and exits, without running the tool.
const USAGE = `Usage: node hooks/grep.js <pattern-id> [path]

Searches the project for occurrences of one pattern id.
  <pattern-id>  a rule id such as sql-concat or weak-rng
  [path]        limit the search to a path (default: whole project)`;
if (helpRequested(process.argv.slice(2), USAGE)) process.exit(0);

const DIR = path.resolve(__dirname, '..');
const PATTERNS_DIR = path.join(DIR, 'patterns');
const FIXES = path.join(DIR, 'checks', 'fixes.md');

const SKIP_EXT = new Set(['md', 'txt', 'json', 'lock', 'csv', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'pdf', 'min.js']);
const SKIP_SEG = ['node_modules', 'vendor', '.git', 'dist', 'build', 'target'];

function main() {
  const args = process.argv.slice(2);

  if (args[0] === '--list') {
    const patterns = loadPatterns();
    const ids = [...new Set(patterns.map(p => p.id))].sort();
    for (const id of ids) {
      const ps = patterns.filter(p => p.id === id);
      const hint = ps.find(p => p.hint)?.hint || '';
      console.log(`${id.padEnd(20)} ${hint}`);
    }
    return;
  }

  if (args[0] === '--hints') {
    const patterns = loadPatterns();
    const byId = {};
    for (const p of patterns) {
      if (!byId[p.id]) byId[p.id] = { hint: p.hint || '', exts: p.exts };
    }
    for (const [id, info] of Object.entries(byId).sort()) {
      console.log(`${id}: ${info.hint || '(no hint)'}`);
    }
    return;
  }

  if (args.length === 0) {
    process.stderr.write('Usage:\n');
    process.stderr.write('  grep.js <pattern-id> [path]    search by pattern id\n');
    process.stderr.write('  grep.js --regex <re> [path]    search by custom regex\n');
    process.stderr.write('  grep.js --list                 list all pattern ids\n');
    process.stderr.write('  grep.js --hints                show fix hints\n');
    process.exit(1);
  }

  let searchPath = process.cwd();
  let re = null;
  let patternId = null;

  if (args[0] === '--regex') {
    if (!args[1]) { process.stderr.write('Missing regex\n'); process.exit(1); }
    const input = args[1];
    // Reject patterns likely to cause catastrophic backtracking (ReDoS)
    if (input.length > 200) { process.stderr.write('Regex too long (max 200 chars)\n'); process.exit(1); }
    // Detect nested quantifiers: (x+)+ (x*)* (x+)* (x*)+  or  )+ )*
    if (/[+*]\)[+*]/.test(input) || /\([^)]*[+*][^)]*\)[+*]/.test(input)) {
      process.stderr.write('Regex contains nested quantifiers — likely ReDoS risk\n');
      process.exit(1);
    }
    try { re = new RegExp(input); } catch (e) { process.stderr.write(`Bad regex: ${e.message}\n`); process.exit(1); }
    if (args[2]) searchPath = path.resolve(args[2]);
  } else {
    patternId = args[0];
    if (args[1]) searchPath = path.resolve(args[1]);
  }

  const patterns = loadPatterns();
  if (patternId) {
    const matched = patterns.filter(p => p.id === patternId);
    if (matched.length === 0) {
      process.stderr.write(`Unknown pattern id: ${patternId}\n`);
      process.stderr.write('Run with --list to see available ids.\n');
      process.exit(1);
    }
  }

  const files = collectFiles(searchPath);
  let hits = 0;

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split(/\r?\n/);
    const ext = path.extname(file).slice(1).toLowerCase();

    for (const p of patterns) {
      if (patternId && p.id !== patternId) continue;
      if (re && p.re.source !== re.source) continue;
      if (p.exts !== '*' && !p.exts.split(',').includes(ext)) continue;

      for (let i = 0; i < lines.length; i++) {
        if (!p.re.test(lines[i])) continue;
        if (p.exclRe && p.exclRe.test(lines[i])) continue;
        const rel = path.relative(process.cwd(), file);
        const hint = p.hint ? `  → ${p.hint}` : '';
        console.log(`${rel}:${i + 1}: [${p.id}] ${lines[i].trim()}${hint}`);
        hits++;
        break; // one hit per pattern per file
      }
    }
  }

  if (hits === 0) {
    console.log('No matches found.');
  } else {
    console.log(`\n${hits} match${hits === 1 ? '' : 'es'} across ${files.length} files.`);
  }
}

function collectFiles(dir) {
  const out = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_SEG.includes(entry.name)) continue;
        out.push(...collectFiles(full));
      } else {
        const ext = path.extname(entry.name).slice(1).toLowerCase();
        if (!SKIP_EXT.has(ext)) out.push(full);
      }
    }
  } catch (e) { /* skip unreadable dirs */ }
  return out;
}

function loadPatterns() {
  const out = [];
  let files;
  try { files = fs.readdirSync(PATTERNS_DIR).filter(f => f.endsWith('.txt')); }
  catch (e) { return out; }
  for (const f of files) {
    const section = (f.match(/^(\d+)-/) || [])[1] || '';
      const lines = fs.readFileSync(path.join(PATTERNS_DIR, f), 'utf8').split(/\r?\n/);
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const cols = line.split('\t');
      const [id, exts, regex] = cols;
      if (!id || !regex) continue;
      const extsLower = exts ? exts.toLowerCase() : exts;
      // 4th col: exclusion (!re) or hint; 5th col: hint if 4th is exclusion
      let exclRe = null;
      let hint = '';
      if (cols.length >= 4 && cols[3]) {
        if (cols[3].startsWith('!')) {
          try { exclRe = new RegExp(cols[3].slice(1)); } catch (e) { exclRe = null; }
          if (cols[4]) hint = cols[4];
        } else {
          hint = cols[3];
        }
      }
      if (!hint && cols[5]) hint = cols[5];
      let re;
      try { re = new RegExp(regex); } catch (e) { continue; }
      out.push({ id, exts: extsLower, re, exclRe, section, hint });
    }
  }
  return out;
}

main();
