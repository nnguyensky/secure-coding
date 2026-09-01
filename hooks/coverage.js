#!/usr/bin/env node
// Verifies every OWASP SCP item (1-213) is either checked in review.md or
// explicitly recorded as out of scope. Fails if an item is unaccounted for.
// Also verifies the OWASP ids on fixes.md blocks stay consistent with
// review.md, so the two sources of truth cannot drift.
'use strict';

const fs = require('fs');
const path = require('path');

const DIR = path.resolve(__dirname, '..');
const REVIEW = path.join(DIR, 'checks', 'review.md');
const SCOPE = path.join(DIR, 'reference', 'out-of-scope.md');
const FIXES = path.join(DIR, 'checks', 'fixes.md');

// Extract all ids from [1,2,3] style brackets in a file.
function bracketIds(file) {
  if (!fs.existsSync(file)) return new Set();
  const text = fs.readFileSync(file, 'utf8');
  const out = new Set();
  for (const m of text.matchAll(/\[([0-9,]+)\]/g)) {
    for (const n of m[1].split(',')) {
      const v = parseInt(n, 10);
      if (!isNaN(v)) out.add(v);
    }
  }
  return out;
}

// Extract ids from "OWASP: 30,105" lines in fixes.md.
function fixIds(file) {
  if (!fs.existsSync(file)) return new Set();
  const text = fs.readFileSync(file, 'utf8');
  const out = new Set();
  for (const m of text.matchAll(/OWASP:\s*([0-9,]+)/g)) {
    for (const n of m[1].split(',')) {
      const v = parseInt(n, 10);
      if (!isNaN(v)) out.add(v);
    }
  }
  return out;
}

const covered = bracketIds(REVIEW);
const scoped = bracketIds(SCOPE);
const known = new Set([...covered, ...scoped]);
const fixes = fixIds(FIXES);

const missing = [];
for (let id = 1; id <= 213; id++) if (!known.has(id)) missing.push(id);

const fixBad = [];
for (const id of fixes) if (!covered.has(id)) fixBad.push(id);

console.log(`checked in review.md : ${covered.size}`);
console.log(`answered by team     : ${scoped.size}`);
console.log(`total accounted for  : ${known.size} / 213`);
console.log(`fixes.md ids         : ${fixes.size}`);

let fail = false;
if (missing.length) { console.log(`UNACCOUNTED: ${missing.join(' ')}`); fail = true; }
if (fixBad.length) { console.log(`FIXES DRIFT: fixes.md references ids not checked in review.md: ${fixBad.join(' ')}`); fail = true; }
if (fail) process.exit(1);
console.log('OK - every OWASP SCP item is accounted for, fixes.md ids consistent');
