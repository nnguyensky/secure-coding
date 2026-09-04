#!/usr/bin/env node
// Clean code linter. Checks files for common violations.
// Usage:
//   echo '{"file_path":"..."}' | node hooks/clean.js          (hook mode)
//   node hooks/clean.js --file <path>                          (CLI mode)
//   node hooks/clean.js --file <path> --json                   (JSON output)
//   node hooks/clean.js --list                                 (list all rules)
//   node hooks/clean.js --count                                (count violations)
//
// No dependencies. Regex-based. 14 automated rules; checks/clean-code.md has the full 23-item checklist.
'use strict';

const fs = require('fs');
const path = require('path');
const { loadConfig, projectRoot } = require('./config');

const DIR = path.resolve(__dirname, '..');
const FIXES = path.join(DIR, 'checks', 'fixes.md');
const STATE = process.env.SECURE_CODING_STATE || path.join(DIR, 'checks', 'findings.jsonl');
const REPORT = (process.env.SECURE_CODING_REPORT || 'on') === 'on';

// Clean-code rules describe executable code. Config and markup have no
// functions to keep small and no constants to name, so linting them only
// produces noise — a YAML version pin is not a magic number.
const SKIP_EXT = new Set(['md', 'txt', 'json', 'lock', 'csv', 'svg', 'png', 'jpg', 'jpeg', 'gif',
  'pdf', 'min.js', 'map', 'yml', 'yaml', 'toml', 'xml', 'html', 'htm', 'css', 'scss', 'ini', 'cfg', 'conf']);
const SKIP_SEG = ['node_modules', 'vendor', '.git', 'dist', 'build', 'target'];

// Rules: { id, re, severity, hint }
// re is tested per-line unless global flag is set
const RULES = [
  // N3: Magic numbers — numeric literals that aren't 0, 1, -1, 2 (common)
  // Excludes: import paths, version strings, port numbers, array indices, hex
  {
    id: 'cc-magic-number',
    re: null,
    severity: 'medium',
    hint: 'Extract magic numbers to named constants.',
    check: (line) => {
      const trimmed = line.trim();
      // Skip comments
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return false;
      // Skip constant definitions (const/let/var ALL_CAPS = ...)
      if (/(?:const|let|var|define|def)\s+[A-Z][A-Z0-9_]*\s*[:=]/.test(trimmed)) return false;
      // Also skip standalone ALL_CAPS = ...
      if (/^[A-Z][A-Z0-9_]*\s*[:=]/.test(trimmed)) return false;
      // Skip import/require paths
      if (/import|require|from/.test(trimmed) && /['"]/.test(trimmed)) return false;
      // Skip version strings and port numbers
      if (/\d+\.\d+/.test(trimmed) || /:\d{2,5}/.test(trimmed)) return false;
      // A number inside a message or a regex is not a magic number:
      // console.log("All 298 tests passed") names nothing. Blank the literals
      // out before looking for constants.
      const code = trimmed
        .replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""')
        .replace(/\/(?:[^\/\\\n]|\\.)+\/[gimsuy]*/g, '//');
      // Find numeric literals > 2 that aren't part of larger numbers
      const re = /(?<![0-9a-fx."])\b(?!0\b|1\b|2\b|10\b|-1\b)\d{2,}\b(?!\.\d)/g;
      const matches = code.match(re);
      if (!matches) return false;
      // Allowed common status codes and time units
      const allowed = new Set([0, 1, 2, 10, -1, 60, 64, 100, 200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503, 1000, 3600, 5000, 10000, 15000, 30000, 86400]);
      return matches.some(m => {
        const n = parseInt(m, 10);
        return !allowed.has(n);
      });
    },
  },
  // F1: Function with "and" in the name (e.g. validateAndSave)
  {
    id: 'cc-multi-responsibility',
    re: /(?:function\s+[a-z0-9]+(?:And|_and_)[A-Za-z0-9]+|(?:const|let|var)\s+[a-z0-9]+(?:And|_and_)[A-Za-z0-9]+\s*=\s*(?:async\s+)?(?:function|\())|(?:(?:def|func|fn|fun|sub)\s+[a-z0-9]+(?:And|_and_)[A-Za-z0-9]+)/,
    severity: 'medium',
    hint: 'Function name contains "and" — likely doing multiple things. Split it.',
  },
  // F2: Function with too many parameters (>3)
  {
    id: 'cc-too-many-params',
    re: /(?:function\s+\w*\s*\(|(?:const|let|var)\s+\w*\s*=\s*(?:async\s+)?function\s*\(|(?:def|func|fn|fun|sub)\s+\w*\s*\(|=>\s*\{)/,
    severity: 'low',
    hint: 'More than 3 parameters. Bundle into a config/options object.',
    // Checked in logic, not just regex
    check: (line) => {
      // Match function signatures with >3 commas in params
      const m = line.match(/(?:function\s+\w*\s*\(|=(?:\s*async)?\s*function\s*\(|(?:def|func|fn|fun)\s+\w*\s*\()(?:[^)]*)\)/);
      if (!m) return false;
      const params = m[0].replace(/^[^(]*\(/, '').replace(/\)$/, '').split(',');
      return params.filter(p => p.trim()).length > 3;
    },
  },
  // N5: Unneeded context — property repeats type/object name (e.g. user.userName)
  {
    id: 'cc-unneeded-context',
    re: null,
    severity: 'low',
    hint: 'Property name repeats object/type name. Use shorter name.',
    check: (line) => {
      const m = line.match(/(?:const|let|var|class|type|interface)?\s*(\w+)\s*[:=]\s*\{([^}]*)\}/i);
      if (!m) return false;
      const objName = m[1].toLowerCase();
      if (objName.length < 3) return false;
      const body = m[2];
      const propRegex = /\b([a-zA-Z0-9_]+)\s*:/g;
      let propMatch;
      while ((propMatch = propRegex.exec(body)) !== null) {
        const prop = propMatch[1].toLowerCase();
        if (prop !== objName && prop.startsWith(objName) && prop.length > objName.length) {
          return true;
        }
      }
      return false;
    },
  },
  // C2: Commented-out code (3+ consecutive commented lines with code-like content)
  {
    id: 'cc-commented-code',
    re: null, // checked in logic
    severity: 'low',
    hint: 'Commented-out code. Delete it — version control has history.',
    multiLine: true,
  },
  // C1: Dead code — code after return/throw/continue/break
  {
    id: 'cc-dead-code',
    re: null,
    severity: 'medium',
    hint: 'Unreachable code after return/throw/continue/break.',
    multiLine: true,
  },
  // E1: Swallowed errors — empty catch blocks
  {
    id: 'cc-swallowed-error',
    re: /catch\s*\([^)]*\)\s*\{\s*\}/,
    severity: 'high',
    hint: 'Empty catch block. Handle or propagate the error.',
  },
  {
    id: 'cc-swallowed-error-comment',
    re: /catch\s*\([^)]*\)\s*\{[^}]*\/\/\s*(?:ignore|todo|fixme|hack|silent|noop|nothing)[^}]*\}/i,
    severity: 'medium',
    hint: 'Catch block with only a comment. Handle or propagate the error.',
  },
  // N1: Single-letter variable names (outside loops)
  {
    id: 'cc-single-letter-var',
    re: /(?:^|[\s;,=])(?:const|let|var)\s+([a-z])\s*[=;]/,
    severity: 'low',
    hint: 'Single-letter variable name. Use a meaningful name.',
  },
  // F5: Boolean flag parameter
  {
    id: 'cc-boolean-flag',
    re: /(?:function|def|func|fn|fun)\s+\w*\s*\([^)]*\b(?:is|has|can|should|enable|disable|show|hide|temp|dry|verbose|debug|force|strict|async|sync|append|overwrite)\w*\s*[:=]?\s*(?:bool|boolean|True|False|true|false|\?|:\s*boolean)/i,
    severity: 'low',
    hint: 'Boolean flag parameter. Split into separate functions.',
  },
  // S4: Negative conditional (e.g. !isNotValid, !isDisabled)
  {
    id: 'cc-negative-conditional',
    re: /(?:if|elsif|elif|else\s+if|when|case)\s*\(\s*!(?:isNot|hasNo|isInvalid|isDisabled|isInactive)\w+/i,
    severity: 'low',
    hint: 'Double negative conditional. Rename to positive form.',
  },
  // T2: Global mutable state
  {
    id: 'cc-mutable-global',
    re: /^(?:var|let)\s+\w+\s*=/m,
    severity: 'low',
    hint: 'Global mutable variable. Scope it to a function or module.',
  },
  // E2: Error with no context
  {
    id: 'cc-empty-throw',
    re: /(?:throw|raise|panic|fatal|die|abort)\s*\(\s*['"]\s*['"]\s*\)/,
    severity: 'medium',
    hint: 'Error with empty message. Include context about what failed.',
  },
  // N2: Inconsistent naming (camelCase vs snake_case mixed)
  {
    id: 'cc-mixed-naming',
    re: null,
    severity: 'low',
    hint: 'Mixed naming conventions. Pick one style and stick to it.',
    multiLine: true,
  },
];

function readFile(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); } catch (e) { return ''; }
}

// Honour .securecodingrc.json ignorePaths, the same list scan.js uses, so
// generated output and fixtures are not linted by one tool and skipped by
// the other.
let _ignoreGlobs = null;
function ignoreGlobs() {
  if (_ignoreGlobs) return _ignoreGlobs;
  _ignoreGlobs = [];
  try {
    // loadConfig reads the scanned project's .securecodingrc.json. Reading it
    // from DIR meant a consumer repository's ignorePaths were never applied.
    const cfg = loadConfig();
    if (Array.isArray(cfg.ignorePaths)) _ignoreGlobs = cfg.ignorePaths;
  } catch { /* no config */ }
  return _ignoreGlobs;
}

// Same inline suppression scan.js honours, so a reviewed exception documented
// on the line is respected by both tools. Accepts the rule id with or without
// the cc- prefix: `// secure-coding-ignore: swallowed-error`.
function isSuppressed(line, ruleId) {
  const m = line.match(/(?:\/\/|#|\/\*)\s*(?:secure-coding-ignore|nosec):\s*([A-Za-z0-9_,\s-]+?)(?:--|\*\/|$)/i);
  if (!m) return false;
  const ids = m[1].split(/[,\s]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
  const id = ruleId.toLowerCase();
  const short = id.replace(/^cc-/, '');
  // scan.js and clean.js name the same defect differently. A reader writing
  // one id means the defect, not the tool, so accept either spelling.
  const ALIASES = {
    'swallowed-error': ['swallowed-exception'],
    'swallowed-error-comment': ['swallowed-exception'],
    'empty-throw': ['swallowed-exception'],
    'dead-code': ['unreachable'],
  };
  const alts = ALIASES[short] || [];
  return ids.includes(id) || ids.includes(short) || alts.some(a => ids.includes(a)) || ids.includes('all');
}

// A directory argument used to be handed straight to readFile, which threw
// EISDIR, was swallowed, and exited 0 having linted nothing -- a silent pass
// on an entire tree. Expand directories the way scan.js does.
function expand(target) {
  let stat;
  try { stat = fs.statSync(target); } catch { return []; }
  if (!stat.isDirectory()) return [target];
  const out = [];
  const walk = (dir) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (SKIP_SEG.includes(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile()) out.push(full);
    }
  };
  walk(target);
  return out;
}

function shouldSkip(filePath) {
  const ext = path.extname(filePath).slice(1).toLowerCase();
  if (SKIP_EXT.has(ext)) return true;
  const segs = filePath.split(path.sep);
  if (segs.some(s => SKIP_SEG.includes(s))) return true;
  const rel = path.relative(projectRoot(), path.resolve(filePath)).split(path.sep).join('/');
  if (!rel.startsWith('..')) {
    for (const g of ignoreGlobs()) {
      const re = new RegExp('^' + g.split('/').map(part =>
        part === '**' ? '.*' : part.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*')
      ).join('/').replace(/\.\*\//g, '(?:.*/)?') + '$');
      if (re.test(rel)) return true;
    }
  }
  return false;
}

// Blank the inside of multi-line template literals, preserving newlines so
// line numbers stay exact. Rules run line by line, so prose inside a `...`
// block reads as code: "OWASP SCP item (1-213)" in a USAGE literal was
// reported as a magic number.
//
// This needs a scanner, not a regex. A backtick also appears inside line
// comments and regex literals, and pairing those blanked 419 lines of real
// code -- including two genuine findings in this very file. Block comments
// are left intact because isSuppressed() honours `/* secure-coding-ignore */`.
function blankTemplateLiterals(src) {
  const out = src.split('');
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const next = src[i + 1];
    if (c === '\\') { i += 2; continue; }
    if (c === '/' && next === '/') {                     // line comment
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && next === '*') {                     // block comment
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'") {                        // quoted string
      const quote = c;
      i++;
      while (i < n && src[i] !== quote) { if (src[i] === '\\') i++; i++; }
      i++;
      continue;
    }
    if (c === '`') {                                     // template literal
      const start = i;
      i++;
      while (i < n && src[i] !== '`') { if (src[i] === '\\') i++; i++; }
      const end = i;
      for (let k = start + 1; k < end && k < n; k++) {
        if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' ';
      }
      i++;
      continue;
    }
    i++;
  }
  return out.join('');
}

function checkFile(filePath) {
  const content = readFile(filePath);
  if (!content) return [];

  const lines = content.split(/\r?\n/);
  // Rules match against code with template-literal bodies blanked; suppression
  // comments and snippets always come from the original line.
  const codeLines = blankTemplateLiterals(content).split(/\r?\n/);
  const hits = [];

  for (const rule of RULES) {
    if (rule.multiLine) {
      // Multi-line checks
      if (rule.id === 'cc-commented-code') {
        let consecutive = 0;
        let startLine = 0;
        for (let i = 0; i < lines.length; i++) {
          const trimmed = lines[i].trim();
          // Detect commented-out code: starts with // or # and contains code-like content
          const isCommentedCode = /^\/\/\s*(?:const|let|var|function|if|else|for|while|return|import|export|class|def|func|fn|fun|pub|priv|protected|this|self|super|new|delete|typeof|instanceof|\w+\s*[=(){}\[\];])/i.test(trimmed) ||
            /^#\s*(?:def|func|fn|fun|class|if|else|for|while|return|import|from|print|echo|puts|require|include|use|package|module)/i.test(trimmed) ||
            /^\/\*\s*(?:const|let|var|function)/i.test(trimmed);
          if (isCommentedCode) {
            if (consecutive === 0) startLine = i + 1;
            consecutive++;
          } else {
            if (consecutive >= 3) {
              hits.push({
                id: rule.id,
                severity: rule.severity,
                hint: rule.hint,
                line: startLine,
                endLine: startLine + consecutive - 1,
                snippet: lines.slice(startLine - 1, startLine + consecutive - 1).join('\n'),
              });
            }
            consecutive = 0;
          }
        }
        if (consecutive >= 3) {
          hits.push({
            id: rule.id,
            severity: rule.severity,
            hint: rule.hint,
            line: startLine,
            endLine: startLine + consecutive - 1,
            snippet: lines.slice(startLine - 1, startLine + consecutive - 1).join('\n'),
          });
        }
      } else if (rule.id === 'cc-dead-code') {
        for (let i = 0; i < lines.length - 1; i++) {
          const trimmed = lines[i].trim();
          const nextTrimmed = lines[i + 1] ? lines[i + 1].trim() : '';
          // Code after return/throw/continue/break (not in nested blocks)
          // A statement that continues on the next line is not followed by dead
          // code: `return xs.map(x => {` opens a callback, it does not end the
          // function. Without this the linter flags its own source.
          // A continuation marker can sit at the end of this line (`map(x => {`)
          // or the start of the next (`? left`, `.filter(...)`, `&& more`).
          const continues = /[[{(+\-*&|?:.]$/.test(trimmed) || /=>\s*$/.test(trimmed) || trimmed.endsWith(',')
            || /^[?:.+\-*&|)\]}]|^(?:and|or|not)\b/.test(nextTrimmed);
          if (/^(?:return|throw|continue|break)\b/.test(trimmed) && !continues) {
            // Check next line isn't a closing brace, comment, empty, or label
            // Indentation-scoped languages (Python et al.) close a block by
            // dedenting, so a next line at the same or lower indent has left it.
            const indent = lines[i].length - lines[i].replace(/^\s*/, '').length;
            const nextIndent = lines[i + 1].length - lines[i + 1].replace(/^\s*/, '').length;
            if (nextTrimmed && nextIndent >= indent && !/^[})\]\/]/.test(nextTrimmed) && !/^\/[\/\*]/.test(nextTrimmed)) {
              hits.push({
                id: rule.id,
                severity: rule.severity,
                hint: rule.hint,
                line: i + 2,
                snippet: lines[i + 1],
              });
            }
          }
        }
      } else if (rule.id === 'cc-mixed-naming') {
        // Detect mixed camelCase and snake_case in function/variable declarations
        const camelFuncs = [];
        const snakeFuncs = [];
        for (let i = 0; i < lines.length; i++) {
          const l = lines[i];
          // Function declarations
          const camelMatch = l.match(/(?:function|const|let|var)\s+([a-z][a-zA-Z0-9]*)\s*[=(]/);
          const snakeMatch = l.match(/(?:function|const|let|var)\s+([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\s*[=(]/);
          if (camelMatch) camelFuncs.push(i + 1);
          if (snakeMatch) snakeFuncs.push(i + 1);
        }
        // Only flag if significant mixing (3+ of each)
        if (camelFuncs.length >= 3 && snakeFuncs.length >= 3) {
          hits.push({
            id: rule.id,
            severity: rule.severity,
            hint: rule.hint + ` (${camelFuncs.length} camelCase, ${snakeFuncs.length} snake_case)`,
            line: 1,
          });
        }
      }
    } else if (rule.check) {
      // Custom check function
      for (let i = 0; i < lines.length; i++) {
        if (rule.check(codeLines[i]) && !isSuppressed(lines[i], rule.id)) {
          hits.push({
            id: rule.id,
            severity: rule.severity,
            hint: rule.hint,
            line: i + 1,
            snippet: lines[i].trim(),
          });
          break; // one hit per rule per file
        }
      }
    } else if (rule.re) {
      // Simple regex match
      for (let i = 0; i < lines.length; i++) {
        if (rule.re.test(codeLines[i]) && !isSuppressed(lines[i], rule.id)) {
          hits.push({
            id: rule.id,
            severity: rule.severity,
            hint: rule.hint,
            line: i + 1,
            snippet: lines[i].trim(),
          });
          break; // one hit per rule per file
        }
      }
    }
  }

  return hits;
}

function formatOutput(filePath, hits, jsonMode) {
  if (hits.length === 0) return '';

  if (jsonMode) {
    return JSON.stringify(hits.map(h => ({
      file: filePath,
      id: h.id,
      severity: h.severity,
      line: h.line,
      hint: h.hint,
      snippet: h.snippet || '',
    })), null, 2);
  }

  // Display relative to the project, not the installed skill: anchoring to DIR
  // printed paths like ../../../../private/tmp/proj/src/a.js downstream.
  let rel = path.relative(projectRoot(), path.resolve(filePath));
  if (rel.startsWith('..')) rel = filePath; // outside the project: show as given
  const lines = [`Clean code issues in ${rel}:\n`];
  for (const h of hits) {
    const loc = h.endLine ? `:${h.line}-${h.endLine}` : `:${h.line}`;
    lines.push(`  [${h.severity}] ${h.id}${loc} — ${h.hint}`);
    if (h.snippet) lines.push(`    ${h.snippet.split('\n')[0]}`);
  }
  return lines.join('\n');
}

function main() {
  const args = process.argv.slice(2);

  // --list: list all rules
  if (args.includes('--list')) {
    for (const r of RULES) {
      console.log(`${r.id}\t${r.severity}\t${r.hint}`);
    }
    return;
  }

  // Hook mode: read payload from stdin
  if (args.length === 0 && !process.stdin.isTTY) {
    // Reading fd 0 can fail with EAGAIN when stdin is inherited but has no
    // data — an npm script or CI runner. scan.js already guards this.
    let payload = '';
    try { payload = fs.readFileSync(0, 'utf8'); } catch { return; }
    const m = payload.match(/"file_path"\s*:\s*"([^"]*)"/);
    if (!m) return;
    const file = m[1];
    if (!fs.existsSync(file) || shouldSkip(file)) return;

    const hits = checkFile(file);
    if (hits.length === 0) return;

    console.log(formatOutput(file, hits, false));
    process.exit(2);
    return;
  }

  // CLI mode. Accepts --file <path> or bare paths: the pre-commit framework
  // sets pass_filenames, so it invokes this as `clean.js a.js b.js`.
  const fileIdx = args.indexOf('--file');
  const jsonMode = args.includes('--json');
  const countMode = args.includes('--count');

  const files = [];
  if (args.includes('--all')) {
    // Lint every tracked file. git ls-files respects .gitignore.
    try {
      const { execFileSync } = require('child_process');
      const root = execFileSync('git', ['rev-parse', '--show-toplevel'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || process.cwd();
      for (const f of execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' }).split(/\r?\n/)) {
        if (f) files.push(path.resolve(root, f));
      }
    } catch { /* not a repo */ }
  } else if (fileIdx !== -1 && args[fileIdx + 1]) {
    files.push(...expand(args[fileIdx + 1]));
  } else {
    for (const a of args) {
      if (!a.startsWith('-') && fs.existsSync(a)) files.push(...expand(a));
    }
  }

  // An explicit --help is a request that succeeded, not a usage error: exit 0
  // so `secure-coding-clean --help && ...` works. Missing arguments stay 64.
  const USAGE = 'Usage: node hooks/clean.js [--file] <path...> | --all [--json] [--count]\n';
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(USAGE);
    process.exit(0);
  }

  if (files.length === 0) {
    process.stderr.write(USAGE);
    process.exit(64);
  }

  const results = [];
  let total = 0;
  for (const file of files) {
    if (!fs.existsSync(file)) {
      process.stderr.write(`File not found: ${file}\n`);
      process.exit(1);
    }
    if (shouldSkip(file)) continue;
    const hits = checkFile(file);
    total += hits.length;
    results.push({ file, hits });
  }

  if (countMode) {
    console.log(total);
    return;
  }

  if (jsonMode) {
    console.log(JSON.stringify(results.flatMap(r =>
      JSON.parse(formatOutput(r.file, r.hits, true))), null, 2));
    return;
  }

  for (const r of results) {
    if (r.hits.length > 0) console.log(formatOutput(r.file, r.hits, false));
  }
  // Report everything, but only block on what .securecodingrc.json says is
  // blocking. scan.js already honours failOn; a linter that fails a commit
  // over a single-letter variable name gets bypassed, and then it catches
  // nothing at all.
  const SEV_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1 };
  let failOn = 'high';
  try {
    const cfg = loadConfig();
    if (cfg.failOn) failOn = String(cfg.failOn).toLowerCase();
  } catch { /* default */ }
  const minWeight = SEV_WEIGHT[failOn] || SEV_WEIGHT.high;
  const blocking = results.reduce((n, r) =>
    n + r.hits.filter(h => (SEV_WEIGHT[h.severity] || SEV_WEIGHT.medium) >= minWeight).length, 0);

  if (blocking > 0) process.exit(2);
}

if (require.main === module) {
  main();
}

module.exports = { checkFile, shouldSkip, isSuppressed, RULES };
