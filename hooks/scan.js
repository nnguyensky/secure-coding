#!/usr/bin/env node
// PostToolUse hook for Write|Edit. Reads the hook payload on stdin.
// Scans the written file against patterns/*.txt, tracks findings in
// checks/findings.jsonl, regenerates the HTML report, and prints the
// matching fix blocks. Silent when nothing matches — that is the common case.
//
// Requires Node.js (any modern version). No dependencies.
'use strict';

const fs = require('fs');
const path = require('path');

const DIR = path.resolve(__dirname, '..');
const PATTERNS_DIR = path.join(DIR, 'patterns');
const FIXES = path.join(DIR, 'checks', 'fixes.md');
const STATE = process.env.SECURE_CODING_STATE || path.join(DIR, 'checks', 'findings.jsonl');
const REPORT = (process.env.SECURE_CODING_REPORT || 'on') === 'on';
const MAX_HITS = 4;
// Occurrences reported per id per file. Beyond this the count is truncated —
// the finding is still reported, you just stop getting every line.
const MAX_OCCURRENCES = Number(process.env.SECURE_CODING_MAX_OCCURRENCES) || 20;

// Extensions we never scan (non-code).
const SKIP_EXT = new Set(['md', 'txt', 'json', 'lock', 'csv', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'pdf', 'min.js']);
// Path segments we never scan (vendored / generated).
const SKIP_SEG = ['node_modules', 'vendor', '.git', 'dist', 'build', 'target'];

// Same-line duplicates: when both IDs fire on one line they describe the same
// defect with the same fix, so the more specific finding supersedes the generic
// one. Keyed by the winner; values are the IDs it absorbs.
// Only for genuine overlap — two real bugs on one line must both still report
// (e.g. tls-off + sbd-missing-timeout are separate defects).
const SUPERSEDES = {
  'eval': ['sbd-dynamic-eval-reflection'],
  'secret-aws-key': ['secret', 'secret-entropy'],
  'secret-entropy': ['secret'],
  'jwt-none-alg': ['jwt'],
};

// Drop findings that a more specific finding on the SAME line already covers.
function dropSupersededHits(hits) {
  const losers = new Set();
  for (const hit of hits) {
    const absorbed = SUPERSEDES[hit.id];
    if (!absorbed) continue;
    for (const other of hits) {
      if (other !== hit && other.line === hit.line && absorbed.includes(other.id)) {
        losers.add(other);
      }
    }
  }
  return hits.filter(h => !losers.has(h));
}

// Parse patterns/*.txt into [{id, exts, re, exclRe, section, hint, severity}]. Filename prefix = section.
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
      let exclRe = null;
      let hint = '';
      let severity = 'medium';
      if (cols.length >= 4 && cols[3]) {
        if (cols[3].startsWith('!')) {
          try { exclRe = new RegExp(cols[3].slice(1)); } catch (e) { exclRe = null; }
          if (cols[4]) hint = cols[4];
        } else {
          hint = cols[3];
        }
      }
      if (!hint && cols[5]) hint = cols[5];
      const sevCol = (cols[5] || cols[4] || '').trim().toLowerCase();
      if (/^(critical|high|medium|low)$/.test(sevCol)) {
        severity = sevCol;
      }
      let re;
      try { re = new RegExp(regex); } catch (e) { continue; }
      out.push({ id, exts: extsLower, re, exclRe, section, hint, severity });
    }
  }
  return out;
}

function isSuppressed(line, id) {
  const m = line.match(/(?:\/\/|#|\/\*)\s*(?:secure-coding-ignore|nosec):\s*([A-Za-z0-9_,\s-]+?)(?:\*\/|$)/i);
  if (!m) return false;
  const ignored = m[1].split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  return ignored.includes(id.toLowerCase()) || ignored.includes('all');
}

function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const map = {};
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    map[c] = (map[c] || 0) + 1;
  }
  let entropy = 0;
  for (const c in map) {
    const p = map[c] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function loadConfig() {
  const cfgFile = path.join(process.cwd(), '.securecodingrc.json');
  if (!fs.existsSync(cfgFile)) return null;
  try { return JSON.parse(fs.readFileSync(cfgFile, 'utf8')); } catch { return null; }
}

function maskSecret(snippet, id) {
  if (!snippet) return '';
  // Mask entropy secrets and credential assignments
  const secretKeyRegex = /(password|passwd|api_?key|secret|token|auth_?key|private_?key|signing_?key|crypto_?key|master_?key)\s*([:=])\s*(["'])([^"']{6,})\3/gi;
  let masked = snippet.replace(secretKeyRegex, (match, key, eq, quote, val) => {
    if (val.length <= 8) {
      return `${key} ${eq} ${quote}******${quote}`;
    }
    const start = val.slice(0, 4);
    const end = val.slice(-3);
    return `${key} ${eq} ${quote}${start}******${end}${quote}`;
  });

  // Mask AWS keys (AKIA... 20 chars total: AKIA + 10 masked + 4 end)
  masked = masked.replace(/\b(AKIA[0-9A-Z]{2})[0-9A-Z]{10}([0-9A-Z]{4})\b/g, '$1******$2');

  // Mask private key headers/bodies if matched
  masked = masked.replace(/(-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----)[\s\S]*(-----END[ A-Z0-9_-]+PRIVATE KEY-----)/g, '$1 ... [REDACTED KEY MATERIAL] ... $2');

  // Mask Bearer tokens
  masked = masked.replace(/(Bearer\s+)([A-Za-z0-9._-]{6,})/gi, (match, prefix, token) => {
    return `${prefix}${token.slice(0, 4)}******${token.slice(-3)}`;
  });

  return masked;
}

// --- multi-line taint ---
// Regex patterns only match when untrusted input sits INSIDE the sink call.
// `$f = $_GET["f"]; readfile($f);` is the same bug split over two lines and
// slips past. This pass tracks `var = <source>` then `sink(var)` within one
// function, straight-line only. Deliberately conservative: a missed edge case
// costs less than a false positive on safe code.

// Request-controlled values. Anchored to the framework accessors the pattern
// files already treat as untrusted.
const TAINT_SOURCE = /(?:\breq(?:uest)?\s*\.\s*(?:query|body|params|args|form|GET|POST|cookies|headers)\b|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[|\br\s*\.\s*(?:FormValue|PostFormValue)\s*\(|\bparams\s*\[|getParameter\s*\()/;

// Sinks where request data causes a named vulnerability, and what to call it.
const TAINT_SINKS = [
  { id: 'taint-path-traversal', severity: 'critical', section: '12',
    re: /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|sendFile|open|readfile|file_get_contents|fopen|File\.read|File\.open|os\.Open|os\.ReadFile|Paths\.get)\s*\(/,
    hint: 'request data reaches a filesystem call — resolve the path and verify it stays inside the intended directory' },
  { id: 'taint-ssrf', severity: 'critical', section: '21',
    re: /\b(?:fetch|(?:axios|requests|httpx|session|urllib3)\s*\.\s*(?:get|post|put|patch|delete|head|request)|request|urlopen|urlretrieve|curl_setopt|http\.Get|HttpClient|WebClient|got|superagent)\s*\(/,
    hint: 'request data reaches an outbound HTTP call — allowlist the host and block internal ranges' },
  { id: 'taint-command', severity: 'critical', section: '29',
    re: /\b(?:exec|execSync|spawn|spawnSync|system|popen|shell_exec|passthru|proc_open|Runtime\.getRuntime|subprocess\.(?:run|call|Popen))\s*\(/,
    hint: 'request data reaches a process call — pass an argument array and never a shell string' },
  { id: 'taint-sql', severity: 'critical', section: '02',
    re: /\.\s*(?:query|execute|exec|raw|prepare)\s*\(/,
    hint: 'request data reaches a query call — use a parameterized query' },
];

// Any of these on the assignment or the sink line means the value was handled.
const TAINT_SANITIZED = /\b(?:sanitiz|escape|validate|allowlist|whitelist|basename|realpath|resolve|normaliz|encodeURI|parseInt|parseFloat|Number|Boolean|String|schema|zod|joi|yup|isSafe|is_safe|safe_path|assert|check)\w*\s*\(|\?\?|\|\||\bparameteriz/i;

// Function/block boundary — taint does not cross it.
const TAINT_BOUNDARY = /^\s*(?:(?:export\s+)?(?:async\s+)?function\b|def\b|func\b|(?:public|private|protected)\s|class\b|\}\s*$)/;

function findTaintFlows(fileLines) {
  const found = [];
  let tainted = new Map(); // varName -> line it was assigned on

  for (let i = 0; i < fileLines.length; i++) {
    const line = fileLines[i];
    if (line.trim().startsWith('//') || line.trim().startsWith('#')) continue;

    // A new function resets what we know.
    if (TAINT_BOUNDARY.test(line)) tainted = new Map();

    // Assignment from an untrusted source: `const x = req.query.y`
    const assign = line.match(/(?:const|let|var|my)?\s*\$?([A-Za-z_]\w*)\s*(?::=|=)\s*(.+)$/);
    if (assign && !/[=!<>]=/.test(assign[2].slice(0, 2))) {
      const [, name, rhs] = assign;
      if (TAINT_SOURCE.test(rhs)) {
        if (TAINT_SANITIZED.test(rhs)) tainted.delete(name);
        else tainted.set(name, i + 1);
        continue;
      }
      // Propagate one hop: `const full = `/data/${p}`` where p is tainted.
      // Interpolation/concatenation of a tainted value stays tainted.
      let carried = null;
      for (const [t, srcLine] of tainted) {
        const used = new RegExp('[${(,\\s\\[`+.]\\$?' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
        if (used.test(rhs)) { carried = srcLine; break; }
      }
      if (carried !== null && !TAINT_SANITIZED.test(rhs)) { tainted.set(name, carried); continue; }
      // Reassigned from something else — no longer tainted.
      if (tainted.has(name)) tainted.delete(name);
    }

    if (tainted.size === 0) continue;

    for (const sink of TAINT_SINKS) {
      if (!sink.re.test(line)) continue;
      if (TAINT_SANITIZED.test(line)) continue;
      for (const [name, srcLine] of tainted) {
        // The variable must actually appear as an argument on this line.
        const used = new RegExp('[(,\\s\\[`+.]\\$?' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
        if (!used.test(line)) continue;
        found.push({ sink, line: i + 1, snippet: line.trim(), varName: name, srcLine });
        break;
      }
    }
  }
  return found;
}

function matchContent(content, filenameOrExt, patterns) {
  const fileLines = content.split(/\r?\n/);
  const ext = (path.extname(filenameOrExt || '').slice(1) || filenameOrExt || '').toLowerCase();
  const base = path.basename(filenameOrExt || '');
  const seen = new Set();
  const hits = [];
  const cfg = loadConfig();

  // Pattern matching
  for (const p of patterns) {
    if (seen.has(p.id)) continue;
    if (cfg && Array.isArray(cfg.ignorePatterns) && cfg.ignorePatterns.includes(p.id)) continue;
    // exts are lowercased at load; match the basename case-insensitively so
    // `Dockerfile` scoping works. Extensionless files (Dockerfile, Makefile)
    // must still be filtered — matching on basename only, not skipped.
    if (p.exts !== '*') {
      const want = p.exts.split(',');
      const lowerBase = base.toLowerCase();
      // Dockerfile.prod / api.Dockerfile are Dockerfiles too.
      const named = want.some(w => lowerBase === w || lowerBase.startsWith(w + '.') || lowerBase.endsWith('.' + w));
      if (!want.includes(ext) && !named) continue;
    }

    let matchedLineNum = null;
    let matchedSnippet = '';
    let lineMatchedAndSuppressed = false;
    // Every line this pattern hits, not just the first — one finding per occurrence.
    const occurrences = [];

    for (let i = 0; i < fileLines.length; i++) {
      const line = fileLines[i];
      if (p.re.test(line)) {
        if (p.exclRe && p.exclRe.test(line)) continue;
        if (isSuppressed(line, p.id)) {
          lineMatchedAndSuppressed = true;
          continue;
        }
        if (matchedLineNum === null) {
          matchedLineNum = i + 1;
          matchedSnippet = line.trim();
        }
        if (occurrences.length < MAX_OCCURRENCES) {
          occurrences.push({ line: i + 1, snippet: line.trim() });
        }
      }
    }

    // Fallback: check whole content only if pattern spans multiple lines and was not suppressed on single lines
    if (!matchedLineNum && !lineMatchedAndSuppressed && p.re.test(content)) {
      if (!p.exclRe || !p.exclRe.test(content)) {
        // Check if content has suppression for this id
        if (!content.split(/\r?\n/).some(l => isSuppressed(l, p.id))) {
          for (let i = 0; i < fileLines.length; i++) {
            if (p.re.test(fileLines[i])) {
              matchedLineNum = i + 1;
              matchedSnippet = fileLines[i].trim();
              break;
            }
          }
          if (!matchedLineNum) {
            matchedLineNum = 1;
            matchedSnippet = fileLines[0]?.trim() || '';
          }
        }
      }
    }

    if (matchedLineNum) {
      seen.add(p.id);
      // Multi-line fallback matches produce no per-line occurrence; use the anchor.
      const found = occurrences.length ? occurrences : [{ line: matchedLineNum, snippet: matchedSnippet }];
      for (const occ of found) {
        hits.push({
          id: p.id,
          section: p.section,
          hint: p.hint || '',
          severity: p.severity || 'medium',
          line: occ.line,
          snippet: maskSecret(occ.snippet, p.id),
        });
      }
    }
  }

  // Shannon Entropy Secret Detection
  if (!seen.has('secret-entropy') && (!cfg || cfg.entropyDetection !== false)) {
    const entropyRegex = /(password|passwd|api_?key|secret|token|auth_?key|private_?key|signing_?key|crypto_?key|master_?key)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{20,})["']/i;
    for (let i = 0; i < fileLines.length; i++) {
      const line = fileLines[i];
      const m = line.match(entropyRegex);
      if (m && m[2]) {
        if (isSuppressed(line, 'secret-entropy') || isSuppressed(line, 'secret')) continue;
        const secretStr = m[2];
        const entropy = calculateShannonEntropy(secretStr);
        if (entropy >= 3.5) {
          seen.add('secret-entropy');
          hits.push({
            id: 'secret-entropy',
            section: '06',
            hint: `high-entropy string detected (Shannon entropy ${entropy.toFixed(2)} bits/byte); move to secret manager`,
            severity: 'critical',
            line: i + 1,
            snippet: maskSecret(line.trim(), 'secret-entropy'),
          });
          // Every hardcoded secret needs rotating, so report each one.
          if (hits.filter(h => h.id === 'secret-entropy').length >= MAX_OCCURRENCES) break;
        }
      }
    }
  }

  // Multi-line taint: source assigned to a variable, then used in a sink.
  if (!cfg || cfg.taintTracking !== false) {
    for (const flow of findTaintFlows(fileLines)) {
      if (seen.has(flow.sink.id)) continue;
      if (isSuppressed(fileLines[flow.line - 1], flow.sink.id)) continue;
      // Skip only when a pattern already reported this same vulnerability on
      // this line; an unrelated finding on the line must not hide the taint.
      if (hits.some(h => h.line === flow.line && h.section === flow.sink.section)) continue;
      seen.add(flow.sink.id);
      hits.push({
        id: flow.sink.id,
        section: flow.sink.section,
        hint: `${flow.sink.hint} (tainted \`${flow.varName}\` from line ${flow.srcLine})`,
        severity: flow.sink.severity,
        line: flow.line,
        snippet: maskSecret(flow.snippet, flow.sink.id),
      });
    }
  }

  return dropSupersededHits(hits);
}

function matchFile(file, patterns) {
  const content = fs.readFileSync(file, 'utf8');
  return matchContent(content, file, patterns);
}

function scanSingleFile(file, patterns) {
  if (!fs.existsSync(file)) return [];
  // git can list directories (submodules, extensionless dirs); never read one.
  try { if (!fs.statSync(file).isFile()) return []; } catch (e) { return []; }
  const ext = path.extname(file).slice(1).toLowerCase();
  if (SKIP_EXT.has(ext)) return [];
  const segs = file.split(path.sep);
  if (segs.some(s => SKIP_SEG.includes(s))) return [];

  const hits = matchFile(file, patterns);
  updateState(file, hits);
  return hits;
}

const USAGE = `secure-coding scanner

Usage:
  node hooks/scan.js --staged              scan git staged files
  node hooks/scan.js --diff                scan modified working-tree files
  node hooks/scan.js --file <path>         scan one file
  node hooks/scan.js --files <p> [p...]    scan specific files
  node hooks/scan.js --find <id> <file>    record a manual finding
  node hooks/scan.js                       hook mode (PostToolUse JSON on stdin)

Options:
  --json                                   machine-readable output
  --help                                   show this message

Exit codes: 0 clean, 2 findings found.
`;

function main() {
  const args = process.argv.slice(2);
  const patterns = loadPatterns();

  // Manual finding mode: node hooks/scan.js --find <id> <file> [note]
  if (args[0] === '--find') {
    const id = args[1];
    const file = args[2] || '';
    const note = args.slice(3).join(' ');
    if (!id) { process.stderr.write('Usage: scan.js --find <id> <file> [note]\n'); process.exit(1); }
    const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const runId = process.env.SECURE_CODING_RUN_ID || now.slice(0, 10);
    const rec = JSON.stringify({ file, id, section: 'manual', severity: 'medium', status: 'open', run_id: runId, first_seen: now, resolved_at: '', note });
    fs.mkdirSync(path.dirname(STATE), { recursive: true });
    fs.appendFileSync(STATE, rec + '\n');
    if (REPORT) {
      try {
        const { execFileSync } = require('child_process');
        execFileSync(process.execPath, [path.join(DIR, 'hooks', 'report.js')], {
          env: process.env, stdio: 'ignore', timeout: 10000,
        });
      } catch (e) { /* report is best-effort */ }
    }
    process.stdout.write(`Recorded: ${id}${file ? ' in ' + path.basename(file) : ''}\n`);
    return;
  }

  // CLI Mode: --staged or --diff or --files
  if (args[0] === '--staged' || args[0] === '--diff' || args[0] === '--files' || args[0] === '--file') {
    let filesToScan = [];
    const { execFileSync } = require('child_process');

    if (args[0] === '--staged') {
      try {
        const out = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'], { encoding: 'utf8' });
        filesToScan = out.split(/\r?\n/).filter(Boolean).map(f => path.resolve(f));
      } catch { filesToScan = []; }
    } else if (args[0] === '--diff') {
      try {
        const out = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACM'], { encoding: 'utf8' });
        filesToScan = out.split(/\r?\n/).filter(Boolean).map(f => path.resolve(f));
      } catch { filesToScan = []; }
    } else if (args[0] === '--file' && args[1]) {
      filesToScan = [path.resolve(args[1])];
    } else if (args[0] === '--files') {
      filesToScan = args.slice(1).map(f => path.resolve(f));
    }

    let allHits = [];
    for (const f of filesToScan) {
      const hits = scanSingleFile(f, patterns);
      if (hits.length > 0) {
        allHits.push({ file: f, hits });
      }
    }

    if (REPORT) {
      try { require(path.join(DIR, 'hooks', 'report.js')); } catch (e) {}
    }

    if (args.includes('--json')) {
      process.stdout.write(JSON.stringify(allHits, null, 2) + '\n');
      process.exit(allHits.length > 0 ? 2 : 0);
    }

    if (allHits.length === 0) {
      process.stdout.write(`secure-coding: clean — scanned ${filesToScan.length} file(s)\n`);
      process.exit(0);
    }

    process.stdout.write(`Security patterns found across ${allHits.length} file(s):\n\n`);
    for (const item of allHits) {
      process.stdout.write(`--- ${path.relative(process.cwd(), item.file)} ---\n`);
      for (const h of item.hits) {
        process.stdout.write(`  [${h.severity.toUpperCase()}] ${h.id} (line ${h.line})\n`);
        if (h.snippet) process.stdout.write(`    > ${h.snippet.slice(0, 100)}\n`);
        if (h.hint) process.stdout.write(`    Hint: ${h.hint}\n`);
      }
      process.stdout.write('\n');
    }
    process.exit(2);
  }

  if (args[0] === '--help' || args[0] === '-h') {
    process.stdout.write(USAGE);
    return;
  }

  // Anything else flag-shaped is a typo, not hook input — fail loudly instead
  // of falling through and blocking forever on a stdin read.
  if (args[0] && args[0].startsWith('-')) {
    process.stderr.write(`scan.js: unknown option '${args[0]}'\n\n${USAGE}`);
    process.exit(64); // EX_USAGE
  }

  // Hook Mode: PostToolUse payload on stdin. Only valid when stdin is piped;
  // on a terminal there is nothing to read and we would hang waiting.
  if (process.stdin.isTTY) {
    process.stderr.write(`scan.js: no input — stdin is a terminal.\n\n${USAGE}`);
    process.exit(64);
  }

  let payload = '';
  try { payload = fs.readFileSync(0, 'utf8'); } catch (e) { return; }
  const m = payload.match(/"file_path"\s*:\s*"([^"]*)"/);
  if (!m) return;
  const file = m[1];
  if (!fs.existsSync(file)) return;

  const hits = scanSingleFile(file, patterns);
  if (REPORT) {
    try { require(path.join(DIR, 'hooks', 'report.js')); } catch (e) { /* report is best-effort */ }
  }

  if (hits.length === 0) return;

  const blocks = hits.slice(0, MAX_HITS)
    .map(h => {
      const loc = h.line ? ` (Line ${h.line})` : '';
      const snippet = h.snippet ? `\n> ${h.snippet.slice(0, 120)}` : '';
      const block = fixBlock(h.id);
      if (block) {
        const formatted = block.replace(`## ${h.id}`, `## ${h.id}${loc} [${(h.severity || 'medium').toUpperCase()}]`);
        return `${formatted}${snippet}`;
      }
      return `## ${h.id}${loc} [${(h.severity || 'medium').toUpperCase()}]\n${h.hint || 'Review and fix this security finding.'}${snippet}`;
    })
    .filter(Boolean)
    .join('\n\n');
  if (!blocks) return;

  process.stdout.write(`Security patterns found in ${path.basename(file)}. Fix these before continuing:\n\n${blocks}\n`);
  process.exit(2);
}

// Track findings: open for current hits, fixed for previously-open ids that
// no longer match. Preserves fixed history. Rewrites the JSONL state file.
function updateState(file, hits) {
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const runId = process.env.SECURE_CODING_RUN_ID || now.slice(0, 10);

  // Findings are tracked per occurrence: the same id on two different lines is
  // two findings. Identity is (file, id, line) so one can be fixed while the
  // other stays open.
  const keyOf = (id, line) => `${id}@${line || 0}`;
  const hitByKey = new Map();
  for (const h of hits) hitByKey.set(keyOf(h.id, h.line), h);

  const lines = fs.existsSync(STATE) ? fs.readFileSync(STATE, 'utf8').split(/\r?\n/).filter(Boolean) : [];
  const kept = [];
  const openRecs = [];
  const fixedRecs = [];

  for (const line of lines) {
    let rec;
    try { rec = JSON.parse(line); } catch (e) { continue; }
    if (rec.file !== file) { kept.push(line); continue; }
    if (rec.status === 'open') openRecs.push(rec);
    else fixedRecs.push(rec);
  }

  const out = [...kept];
  for (const rec of fixedRecs) out.push(JSON.stringify(rec));

  const seenKeys = new Set();
  for (const rec of openRecs) {
    // Records written before per-occurrence tracking have no line; match on id.
    const key = rec.line == null
      ? [...hitByKey.keys()].find(k => k.startsWith(`${rec.id}@`))
      : keyOf(rec.id, rec.line);
    const hit = key ? hitByKey.get(key) : undefined;
    if (hit) {
      seenKeys.add(key);
      if (!rec.run_id) rec.run_id = runId;
      rec.line = hit.line;
      if (hit.snippet) rec.note = `Line ${hit.line}: ${hit.snippet.slice(0, 100)}`;
      out.push(JSON.stringify(rec));
    } else {
      rec.status = 'fixed';
      rec.resolved_at = now;
      out.push(JSON.stringify(rec));
    }
  }

  for (const [key, h] of hitByKey) {
    if (seenKeys.has(key)) continue;
    out.push(JSON.stringify({
      file, id: h.id, section: h.section || '',
      severity: h.severity || 'medium',
      status: 'open', run_id: runId, first_seen: now, resolved_at: '',
      line: h.line || 0,
      note: h.line && h.snippet ? `Line ${h.line}: ${h.snippet.slice(0, 100)}` : '',
    }));
  }

  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  fs.writeFileSync(STATE, out.join('\n') + (out.length ? '\n' : ''));
}

// Extract the `## id` block from fixes.md (including the `## id` header).
function fixBlock(id) {
  if (!fs.existsSync(FIXES)) return '';
  const text = fs.readFileSync(FIXES, 'utf8');
  const parts = text.split(/^## /m);
  for (const part of parts) {
    const header = part.match(/^([^\n]+)/);
    if (header && header[1].trim() === id) {
      return `## ${id}\n${part.replace(/^[^\n]*\n/, '').trim()}`;
    }
  }
  return '';
}

if (require.main === module) {
  main();
}

module.exports = { main, loadPatterns, scanSingleFile, matchContent, fixBlock, dropSupersededHits };
