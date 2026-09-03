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

const DIR = path.resolve(__dirname, '..');
const FIXES = path.join(DIR, 'checks', 'fixes.md');
const STATE = process.env.SECURE_CODING_STATE || path.join(DIR, 'checks', 'findings.jsonl');
const REPORT = (process.env.SECURE_CODING_REPORT || 'on') === 'on';

const SKIP_EXT = new Set(['md', 'txt', 'json', 'lock', 'csv', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'pdf', 'min.js', 'map']);
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
      // Find numeric literals > 2 that aren't part of larger numbers
      const re = /(?<![0-9a-fx."])\b(?!0\b|1\b|2\b|10\b|-1\b)\d{2,}\b(?!\.\d)/g;
      const matches = trimmed.match(re);
      if (!matches) return false;
      // Allowed common status codes and time units
      const allowed = new Set([0, 1, 2, 10, -1, 60, 100, 200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503, 1000, 3600, 5000, 10000, 15000, 30000, 86400]);
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

function shouldSkip(filePath) {
  const ext = path.extname(filePath).slice(1).toLowerCase();
  if (SKIP_EXT.has(ext)) return true;
  const segs = filePath.split(path.sep);
  if (segs.some(s => SKIP_SEG.includes(s))) return true;
  return false;
}

function checkFile(filePath) {
  const content = readFile(filePath);
  if (!content) return [];

  const lines = content.split(/\r?\n/);
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
          if (/^(?:return|throw|continue|break)\b/.test(trimmed) && !trimmed.endsWith(',')) {
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
        if (rule.check(lines[i])) {
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
        if (rule.re.test(lines[i])) {
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

  const rel = path.relative(DIR, filePath);
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
    const payload = fs.readFileSync(0, 'utf8');
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
  if (fileIdx !== -1 && args[fileIdx + 1]) {
    files.push(args[fileIdx + 1]);
  } else {
    for (const a of args) {
      if (!a.startsWith('-') && fs.existsSync(a)) files.push(a);
    }
  }

  if (files.length === 0) {
    process.stderr.write('Usage: node hooks/clean.js [--file] <path...> [--json] [--count]\n');
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
  // Exit non-zero so a pre-commit hook actually blocks on violations.
  if (total > 0) process.exit(2);
}

main();
