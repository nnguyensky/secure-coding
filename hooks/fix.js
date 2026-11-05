#!/usr/bin/env node
// Reads findings.jsonl and fixes.md, outputs fix guidance for open items.
// Usage: node hooks/fix.js [--print] [--id <id>] [--file <file>] [--count]
//   --print     show fix blocks with "apply manually" hint (display only)
//   --id <id>   only show fixes for this pattern id
//   --file <f>  only show fixes for findings in this file
//   --count     print only the count of open findings
//   (no flags)  print fix blocks for all open items
// Env: SECURE_CODING_STATE, SECURE_CODING_REPORT=off
'use strict';

const fs = require('fs');
const path = require('path');
const { statePath, helpRequested } = require('./config');

// --help must print help, never run the tool. reset.js used to wipe the
// findings file when asked for help; audit.js and sbom.js ran in full.
const USAGE = `Usage: node hooks/fix.js [--print] [--id <id>] [--file <file>] [--count]

Prints remediation guidance for open findings, from checks/fixes.md.
  --print      show what would change, without writing (display only)
  --apply      rewrite files in place
  --dry-run    same as --print
  --id <id>    guidance for one pattern id
  --file <f>   guidance for findings in one file
  --count      print the number of open findings only`;
if (helpRequested(process.argv.slice(2), USAGE)) process.exit(0);

const DIR = path.resolve(__dirname, '..');
const STATE = statePath('findings.jsonl', 'SECURE_CODING_STATE');
const FIXES = path.join(DIR, 'checks', 'fixes.md');

const args = process.argv.slice(2);
// --print is display-only, as its name and the usage text say. It used to be
// OR-ed into APPLY, so asking to see the guidance rewrote the source files on
// disk -- and printed "Autofix Applied" while doing it.
const APPLY = args.includes('--apply');
const PRINT = args.includes('--print');
const COUNT = args.includes('--count');
const JSON_OUT = args.includes('--json');
const idIdx = args.indexOf('--id');
const fileIdx = args.indexOf('--file');
const suggestIdx = args.indexOf('--suggest');
const filterId = idIdx >= 0 ? args[idIdx + 1] : null;
const filterFile = fileIdx >= 0 ? args[fileIdx + 1] : null;
const suggestId = suggestIdx >= 0 ? args[suggestIdx + 1] : null;

function loadFindings() {
  if (!fs.existsSync(STATE)) return [];
  return fs.readFileSync(STATE, 'utf8').split(/\r?\n/).filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

function loadFixBlocks() {
  if (!fs.existsSync(FIXES)) return {};
  const text = fs.readFileSync(FIXES, 'utf8');
  const blocks = {};
  const parts = text.split(/^## /m);
  for (const part of parts) {
    const header = part.match(/^([^\n]+)/);
    if (!header) continue;
    const id = header[1].trim();
    const body = part.replace(/^[^\n]*\n/, '').trim();
    blocks[id] = body;
  }
  return blocks;
}

// --- Autofix ---
// Each rule rewrites ONE line: a line the scanner reports for that id right
// now (re-scanned, so stale line numbers after an edit do not matter, and a
// suppressed line is never touched). A rule returns the new line, or null
// when it cannot fix that line safely — the finding then stays manual.
//
// The previous engine ran a global regex over the whole file. It rewrote
// lines that were never flagged (Math.random() in a dice roll became a hex
// string, so the roll was NaN), put timeout= inside a nested call
// (requests.get(build_url(host, timeout=10.0))), and appended Python keyword
// syntax to JavaScript calls.

const JS_EXT = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']);
const PY_EXT = new Set(['py']);
const extOf = f => path.extname(f).slice(1).toLowerCase();

// Index of the ')' that closes the '(' at `open`, skipping strings; -1 when
// the call does not close on this line.
function closeParen(line, open) {
  let depth = 0;
  for (let i = open; i < line.length; i++) {
    const c = line[i];
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < line.length && line[j] !== c) j += line[j] === '\\' ? 2 : 1;
      i = j;
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return i;
  }
  return -1;
}

// Add an argument before the closing paren of the first call matching `callRe`.
function addArgument(line, callRe, arg, alreadyRe) {
  const m = callRe.exec(line);
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  const close = closeParen(line, open);
  if (close === -1) return null;
  const inside = line.slice(open + 1, close);
  if (alreadyRe.test(inside)) return null;
  const sep = inside.trim() ? ', ' : '';
  return line.slice(0, close).replace(/\s*$/, '') + sep + arg + line.slice(close);
}

const AUTOFIX_RULES = {
  // Same type as Math.random() (a float in [0, 1)), from the CSPRNG — so
  // Math.floor(Math.random() * 6) keeps working.
  'weak-rng': (line, ext) => {
    if (JS_EXT.has(ext)) {
      if (!/Math\.random\s*\(\s*\)/.test(line)) return null;
      return line.replace(/Math\.random\s*\(\s*\)/g, "(require('crypto').randomBytes(6).readUIntBE(0, 6) / 2 ** 48)");
    }
    if (PY_EXT.has(ext)) {
      if (!/\brandom\.(random|randint|choice|randrange|uniform|sample|shuffle)\s*\(/.test(line)) return null;
      return line.replace(/\brandom\.(random|randint|choice|randrange|uniform|sample|shuffle)\s*\(/g, 'secrets.SystemRandom().$1(');
    }
    return null;
  },
  'jwt-no-verify': (line) => {
    if (!/jwt|decode|verify/i.test(line)) return null;
    const out = line
      .replace(/(["']?verify_signature["']?\s*:\s*)False/g, '$1True')
      .replace(/\bverify\s*=\s*False/g, 'verify=True')
      .replace(/verifySignature\s*:\s*false/g, 'verifySignature: true');
    return out === line ? null : out;
  },
  'llm-unbounded-tokens': (line, ext) => {
    const already = /max_tokens|max_completion_tokens|max_output_tokens|maxOutputTokens|maxTokens/;
    const call = /\b(client|openai|anthropic)\s*\.\s*(chat\s*\.\s*completions|completions|messages|responses)\s*\.\s*create\s*\(/;
    if (PY_EXT.has(ext)) return addArgument(line, call, 'max_tokens=1024', already);
    if (JS_EXT.has(ext)) {
      // Only an inline options object can take the key safely.
      const m = call.exec(line);
      if (!m) return null;
      const open = m.index + m[0].length - 1;
      const close = closeParen(line, open);
      if (close === -1) return null;
      const inside = line.slice(open + 1, close);
      if (already.test(inside) || !/^\s*\{/.test(inside)) return null;
      const brace = line.indexOf('{', open);
      return line.slice(0, brace + 1) + ' max_tokens: 1024,' + line.slice(brace + 1);
    }
    return null;
  },
  'sbd-legacy-tls': (line, ext) => {
    if (!PY_EXT.has(ext)) return null;
    const out = line
      .replace(/PROTOCOL_TLSv1(_[01])?\b/g, 'PROTOCOL_TLS_CLIENT')
      .replace(/(min(imum)?_version\s*=\s*ssl\.TLSVersion\.)TLSv1(_[01])?\b/g, '$1TLSv1_2');
    return out === line ? null : out;
  },
  'iot-debug-interface': (line) => {
    const out = line
      .replace(/\b(DEBUG_UART|ENABLE_JTAG|CONFIG_BOOT_SWD)(\s*[:=]\s*)(1|true|TRUE|enabled)\b/g, '$1$2false')
      .replace(/(#define\s+(?:DEBUG_UART|ENABLE_JTAG|CONFIG_BOOT_SWD)\s+)1\b/g, '$10');
    return out === line ? null : out;
  },
  'sbd-missing-timeout': (line, ext) => {
    if (!PY_EXT.has(ext)) return null;
    return addArgument(line, /\brequests\s*\.\s*(get|post|put|delete|patch|head|request)\s*\(/, 'timeout=10', /\btimeout\s*=/);
  },
};

// `import secrets` for the Python weak-rng rewrite, after any shebang,
// encoding line, module docstring and __future__ imports.
function ensurePythonImport(lines, mod) {
  if (lines.some(l => new RegExp(`^\\s*(import\\s+${mod}\\b|from\\s+${mod}\\s+import)`).test(l))) return -1;
  let at = 0;
  while (at < lines.length && /^#/.test(lines[at])) at++;
  if (at < lines.length && /^\s*[rRuU]?("""|''')/.test(lines[at])) {
    const q = lines[at].match(/("""|''')/)[1];
    const rest = lines[at].slice(lines[at].indexOf(q) + 3);
    if (!rest.includes(q)) { at++; while (at < lines.length && !lines[at].includes(q)) at++; }
    at++;
  }
  while (at < lines.length && /^from\s+__future__\s+import/.test(lines[at])) at++;
  lines.splice(at, 0, `import ${mod}`);
  return at; // 0-based line the import went in at
}

let _scanner = null;
function scanner() {
  if (!_scanner) {
    const s = require('./scan');
    _scanner = { matchContent: s.matchContent, patterns: s.loadPatterns() };
  }
  return _scanner;
}

function applyAutofix(file, ruleId, dryRun) {
  if (!fs.existsSync(file)) return false;
  const rule = AUTOFIX_RULES[ruleId];
  if (!rule) return false;
  const ext = extOf(file);
  const content = fs.readFileSync(file, 'utf8');
  const eol = content.includes('\r\n') ? '\r\n' : '\n';
  const lines = content.split(/\r?\n/);
  const { matchContent, patterns } = scanner();
  const targets = [...new Set(matchContent(content, file, patterns)
    .filter(h => h.id === ruleId).map(h => h.line))];

  const changes = [];
  for (const n of targets) {
    const before = lines[n - 1];
    if (before === undefined) continue;
    const after = rule(before, ext);
    if (after == null || after === before) continue;
    lines[n - 1] = after;
    changes.push({ n, before, after });
  }
  if (changes.length === 0) return false;

  const importAt = ruleId === 'weak-rng' && PY_EXT.has(ext) ? ensurePythonImport(lines, 'secrets') : -1;

  const rel = path.relative(process.cwd(), file) || file;
  console.log(`${dryRun ? '🔍 [Autofix Dry-Run]' : '✅ [Autofix Applied]'} ${ruleId} -> ${rel}`);
  if (importAt >= 0) console.log(`  + ${importAt + 1}: import secrets`);
  for (const c of changes) {
    const n = importAt >= 0 && importAt < c.n ? c.n + 1 : c.n;
    console.log(`  - ${n}: ${c.before.trim()}`);
    console.log(`  + ${n}: ${c.after.trim()}`);
  }
  if (!dryRun) fs.writeFileSync(file, lines.join(eol));
  return true;
}

function main() {
  const fixes = loadFixBlocks();

  // Direct suggestion mode: node hooks/fix.js --suggest <id>
  if (suggestId) {
    const fix = fixes[suggestId];
    if (!fix) {
      process.stderr.write(`secure-coding: no fix block found for pattern "${suggestId}"\n`);
      process.exit(1);
    }
    if (JSON_OUT) {
      console.log(JSON.stringify({ id: suggestId, fix }, null, 2));
    } else {
      console.log(`\n## ${suggestId}\n${fix}\n`);
    }
    return;
  }

  const findings = loadFindings();

  const open = findings.filter(f => f.status === 'open')
    .filter(f => !filterId || f.id === filterId)
    .filter(f => !filterFile || f.file === filterFile);

  if (COUNT) {
    const byFile = {};
    for (const f of open) {
      const name = path.relative(process.cwd(), f.file) || f.file;
      byFile[name] = (byFile[name] || 0) + 1;
    }
    if (open.length === 0) {
      console.log('0 open findings.');
    } else {
      for (const [file, n] of Object.entries(byFile).sort()) {
        console.log(`${n}\t${file}`);
      }
      console.log(`\nTotal: ${open.length} open finding(s)`);
    }
    return;
  }

  if (open.length === 0) {
    console.log('No open findings to fix.');
    return;
  }

  // Deduplicate by id+file
  const seen = new Set();
  const unique = open.filter(f => {
    const key = f.id + '|' + f.file;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // --print and --dry-run both show what would change without writing.
  const isDryRun = args.includes('--dry-run') || PRINT;
  if (APPLY || isDryRun) {
    console.log(`--- Applying autofixes (${unique.length} finding(s)) ---`);
    let autofixedCount = 0;
    for (const f of unique) {
      const success = applyAutofix(f.file, f.id, isDryRun);
      if (success) autofixedCount++;
      else {
        const fix = fixes[f.id];
        const file = path.relative(process.cwd(), f.file) || f.file;
        console.log(`\n## ${f.id} (${file}) — Manual Fix Required:`);
        if (fix) console.log(fix);
      }
    }
    console.log(`\nAutofixed: ${autofixedCount}/${unique.length}`);
    return;
  }

  console.log(`--- ${unique.length} open finding(s) ---`);
  for (const f of unique) {
    const fix = fixes[f.id];
    const file = path.relative(process.cwd(), f.file) || f.file;
    if (!fix) {
      console.log(`\n## ${f.id} (${file})\nNo fix block in fixes.md.`);
      continue;
    }
    console.log(`\n## ${f.id} (${file})`);
    console.log(fix);
  }

  // Summary
  const openIds = [...new Set(open.map(f => f.id))];
  const openFiles = [...new Set(open.map(f => f.file))];
  console.log(`\n--- summary ---`);
  console.log(`${unique.length} finding(s), ${openIds.length} pattern(s), ${openFiles.length} file(s)`);
}

main();
