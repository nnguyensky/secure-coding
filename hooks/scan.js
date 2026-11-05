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
const { statePath, writeState, withFileLock, projectRoot, canonicalPath, loadConfig, helpRequested } = require('./config');
const { execFileSync } = require('child_process');

const DIR = path.resolve(__dirname, '..');
const PATTERNS_DIR = path.join(DIR, 'patterns');
const FIXES = path.join(DIR, 'checks', 'fixes.md');
const STATE = statePath('findings.jsonl', 'SECURE_CODING_STATE');
const REPORT = (process.env.SECURE_CODING_REPORT || 'on') === 'on';
const MAX_HITS = 4;
// Lines a multi-line pattern may span (see the fallback in matchContentDetailed).
const FALLBACK_WINDOW = 6;
// Occurrences reported per id per file. Beyond this the count is truncated —
// the finding is still reported, you just stop getting every line.
const MAX_OCCURRENCES = Number(process.env.SECURE_CODING_MAX_OCCURRENCES) || 20;

// Extensions we never scan (non-code).
const SKIP_EXT = new Set(['md', 'txt', 'lock', 'csv', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'pdf']);
// Data files scanned for leaked credentials only. credentials.json,
// appsettings.json and GCP service-account keys are where secrets actually
// get committed; code patterns on JSON would only produce noise.
const SECRETS_ONLY_EXT = new Set(['json']);
const isSecretPattern = id => /^secret(?:-|$)/.test(id);

// Extensions that are the same language as one a pattern names. Patterns say
// `js,ts`; without this, .tsx/.jsx/.mjs/.cjs (most React, Next.js and ESM
// code) and .vue/.svelte components only ever saw the `*` patterns.
const EXT_ALIASES = {
  jsx: ['js'], mjs: ['js'], cjs: ['js'],
  tsx: ['ts', 'js'], mts: ['ts', 'js'], cts: ['ts', 'js'],
  vue: ['js', 'ts'], svelte: ['js', 'ts'], astro: ['js', 'ts'],
  kts: ['kt'], pyw: ['py'], pyi: ['py'], phtml: ['php'],
  hh: ['hpp', 'h'], hxx: ['hpp', 'h'], cxx: ['cpp'], 'c++': ['cpp'],
  // Same platform APIs, different syntax: the JVM rules apply to Scala and
  // the .NET rules to VB.NET, on top of their own patterns.
  scala: ['java'], sc: ['scala', 'java'], vb: ['cs'],
  mm: ['m', 'cpp'], psm1: ['ps1'], psd1: ['ps1'], gvy: ['groovy'],
  pls: ['sql'], pks: ['sql'], pkb: ['sql'], plsql: ['sql'], tsql: ['sql'],
  cob: ['cbl'], cpy: ['cbl'], cobol: ['cbl'], exs: ['ex'],
};
const extFamily = ext => [ext, ...(EXT_ALIASES[ext] || [])];
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
  'secret-github-token': ['secret', 'secret-entropy'],
  'secret-stripe-key': ['secret', 'secret-entropy'],
  'secret-google-key': ['secret', 'secret-entropy'],
  'secret-private-key': ['secret', 'secret-entropy'],
  'secret-slack-webhook': ['secret', 'secret-entropy'],
  'secret-db-url': ['secret', 'secret-entropy'],
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
      let exclFileRe = null;
      let hint = '';
      let severity = 'medium';
      if (cols.length >= 4 && cols[3]) {
        if (cols[3].startsWith('!')) {
          // `!!re` excludes on the whole file, `!re` on the matched line. The
          // file form is for a fix that sits on another line: an XML factory
          // hardened with setFeature(...) two lines further down.
          if (cols[3].startsWith('!!')) {
            try { exclFileRe = new RegExp(cols[3].slice(2)); } catch (e) { exclFileRe = null; }
          } else {
            try { exclRe = new RegExp(cols[3].slice(1)); } catch (e) { exclRe = null; }
          }
          if (cols[4]) hint = cols[4];
        } else {
          hint = cols[3];
        }
      }
      // Column 5 is the severity. Only fall back to it as a hint when it is
      // not one — otherwise the hint printed was the bare word "critical".
      if (!hint && cols[5] && !/^(critical|high|medium|low)$/i.test(cols[5].trim())) hint = cols[5];
      const sevCol = (cols[5] || cols[4] || '').trim().toLowerCase();
      if (/^(critical|high|medium|low)$/.test(sevCol)) {
        severity = sevCol;
      }
      let re;
      try { re = new RegExp(regex); } catch (e) { continue; }
      // A call-shaped pattern (`name\s*\(`) describes code, so a match inside
      // a string or comment is ignored. Patterns about string contents — they
      // mention a quote, a URL scheme or are secrets — must see inside literals
      // (SQL text, an MQTT URL, "crypto/des"), so they are left alone.
      const codeOnly = /\\\(/.test(regex) && !/["'`]/.test(regex)
        && !/:(\\)?\/(\\)?\//.test(regex) && !/^secret/.test(id);
      let reG = null;
      try { reG = new RegExp(regex, 'g'); } catch (e) { reG = null; }
      out.push({ id, exts: extsLower, re, reG, exclRe, exclFileRe, codeOnly, section, hint, severity });
    }
  }
  return out;
}

// Inline suppression: `// secure-coding-ignore: <id>[, <id>] [-- reason]`.
// Returns the suppression ({ reason }) when this line silences `id`, else null.
//
// Ids must be named. `all` used to silence every rule on the line, which let
// the agent this tool polices switch the scanner off with one comment. Each
// suppression is recorded (status "suppressed") so it shows in the report and
// in SARIF instead of disappearing.
function suppressionFor(line, id) {
  if (!line) return null;
  const m = line.match(/(?:\/\/|#|\/\*|<!--)\s*(?:secure-coding-ignore|nosec):\s*(.*?)(?:\*\/|-->|$)/i);
  if (!m) return null;
  const [idPart, ...rest] = m[1].split('--');
  const ignored = idPart.split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  if (!ignored.includes(id.toLowerCase())) return null;
  return { reason: rest.join('--').trim() };
}

function isSuppressed(line, id) {
  return suppressionFor(line, id) !== null;
}

// --- strings and comments ---
// `"Do not call eval() in production"` is not a call to eval. For languages
// with C-like or hash-style literals, code-only patterns must match at a
// position that is code, not inside a quoted string or a comment.
// Deliberately simple and single-line: backtick templates are treated as code
// (their ${...} parts are code), and an unterminated quote is treated as code
// from that point on, so a lexing mistake costs a false positive, never a miss.
const C_LIKE = { line: ['//'], block: true, quotes: '"\'' };
const HASH = { line: ['#'], block: false, quotes: '"\'' };
const LEXICAL = {
  js: C_LIKE, jsx: C_LIKE, ts: C_LIKE, tsx: C_LIKE, mjs: C_LIKE, cjs: C_LIKE,
  java: C_LIKE, kt: C_LIKE, cs: C_LIKE, go: { line: ['//'], block: true, quotes: '"' },
  c: { line: ['//'], block: true, quotes: '"' }, h: { line: ['//'], block: true, quotes: '"' },
  cpp: { line: ['//'], block: true, quotes: '"' }, cc: { line: ['//'], block: true, quotes: '"' },
  hpp: { line: ['//'], block: true, quotes: '"' }, swift: { line: ['//'], block: true, quotes: '"' },
  rs: { line: ['//'], block: true, quotes: '"' },
  php: { line: ['//', '#'], block: true, quotes: '"\'' },
  py: HASH, rb: HASH, pl: HASH, pm: HASH, r: HASH, ex: HASH,
  scala: C_LIKE, dart: C_LIKE, groovy: C_LIKE, gradle: C_LIKE, sol: C_LIKE, m: C_LIKE,
  cls: { line: ['//'], block: true, quotes: "'" }, apex: { line: ['//'], block: true, quotes: "'" },
  ps1: { line: ['#'], block: false, quotes: '"\'' },
  lua: { line: ['--'], block: false, quotes: '"\'' },
  sql: { line: ['--'], block: true, quotes: "'" },
  vb: { line: ["'"], block: false, quotes: '"' },
  cbl: { line: ['*>'], block: false, quotes: '"\'' },
  abap: { line: ['"'], block: false, quotes: "'`" },
};

// Boolean per character: true where the character is code.
function codeMask(line, lang) {
  const mask = new Array(line.length).fill(true);
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (lang.line.some(t => line.startsWith(t, i))) {
      for (let k = i; k < line.length; k++) mask[k] = false;
      break;
    }
    if (lang.block && line.startsWith('/*', i)) {
      const end = line.indexOf('*/', i + 2);
      const stop = end === -1 ? line.length : end + 2;
      for (let k = i; k < stop; k++) mask[k] = false;
      i = stop;
      continue;
    }
    if (lang.quotes.includes(c)) {
      let j = i + 1;
      while (j < line.length && line[j] !== c) j += line[j] === '\\' ? 2 : 1;
      if (j >= line.length) { i++; continue; } // unterminated: leave as code
      for (let k = i; k <= j; k++) mask[k] = false;
      i = j + 1;
      continue;
    }
    i++;
  }
  return mask;
}

function matchesInCode(p, line, lang) {
  if (!p.reG) return true;
  const mask = codeMask(line, lang);
  p.reG.lastIndex = 0;
  let m;
  while ((m = p.reG.exec(line)) !== null) {
    if (mask[m.index]) return true;
    if (m[0].length === 0) p.reG.lastIndex++;
  }
  return false;
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
const TAINT_SOURCE = /(?:\breq(?:uest)?\s*\.\s*(?:query|body|params|args|form|json|get_json|values|GET|POST|cookies|headers)\b|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[|\br\s*\.\s*(?:FormValue|PostFormValue|PathValue)\s*\(|\br\s*\.\s*URL\s*\.\s*Query\s*\(\s*\)|\bmux\s*\.\s*Vars\s*\(|\bc\s*\.\s*(?:Query|Param|PostForm|FormValue|QueryParam|DefaultQuery)\s*\(|\bctx\s*\.\s*(?:query|params|request\s*\.\s*body)\b|\bRequest\s*\.\s*(?:Query|Form|QueryString|Headers|Cookies|RouteValues)\b|\bcall\s*\.\s*(?:parameters|receive\w*|request\s*\.\s*queryParameters)\b|\bparams\s*\[|getParameter\s*\()/;

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
    // queryForObject / executeQuery / prepareStatement (JDBC, Spring) too,
    // but not the DOM's querySelector.
    re: /\.\s*(?:query(?!Selector)\w*|execute\w*|exec|raw|prepare\w*|createQuery|createNativeQuery|createSQLQuery)\s*\(/,
    hint: 'request data reaches a query call — use a parameterized query' },
  // Request text placed in a system message gets the operator's authority:
  // "ignore previous instructions" then reads as an instruction, not data.
  // Everything after `role: "system"` on the line counts, not one argument.
  { id: 'taint-prompt-injection', severity: 'high', section: '33', rest: true, dedupe: ['llm-prompt-injection'],
    re: /["']?role["']?\s*[:=]\s*["']system["']|\bsystem\s*[:=]\s*(?=[^=])|\b(?:system_prompt|systemPrompt|system_message|systemMessage|instructions)\s*[:=]\s*(?=[^=])/,
    hint: 'request text reaches the system prompt — put user input in a user message and treat it as data' },
  { id: 'taint-xss', severity: 'high', section: '02',
    re: /\b(?:res|response|reply)\s*\.\s*(?:send|write|end)\s*\(/,
    hint: 'request data is written into the HTTP response unescaped — render through an escaping template, or send JSON' },
];

// Any of these on the assignment or the sink line means the value was handled.
// Stems take a suffix (sanitize/sanitizer, validate/validated); casts and
// names must match exactly. `joi\w*` used to match `join(`, so
// path.join(__dirname, req.query.file) counted as sanitized, and
// `String\w*` matched JSON.stringify(.
const TAINT_SANITIZED = /\b(?:sanitiz\w*|escape\w*|validat\w*|allowlist\w*|whitelist\w*|basename|realpath\w*|resolve|normaliz\w*|encodeURI(?:Component)?|parseInt|parseFloat|Number|Boolean|String|isSafe\w*|is_safe\w*|safe_path|assert\w*|check\w*)\s*\(|\b(?:joi|zod|yup|schema)\s*\.|\?\?|\|\||\bparameteriz/i;

// Function/block boundary — taint does not cross it.
const TAINT_BOUNDARY = /^\s*(?:(?:export\s+)?(?:async\s+)?function\b|def\b|func\b|(?:public|private|protected)\s|class\b|\}\s*$)/;

// Text of the first argument of the call whose '(' is at `open`, or null
// when the line does not hold it. Skips strings so a comma inside a literal
// does not end the argument.
function firstArgument(line, open) {
  if (line[open] !== '(') return null;
  let depth = 0;
  for (let i = open; i < line.length; i++) {
    const c = line[i];
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < line.length && line[j] !== c) j += line[j] === '\\' ? 2 : 1;
      i = j;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return line.slice(open + 1, i);
    } else if (c === ',' && depth === 1) return line.slice(open + 1, i);
  }
  return line.slice(open + 1);
}

function findTaintFlows(fileLines) {
  const found = [];
  let tainted = new Map(); // varName -> line it was assigned on

  for (let i = 0; i < fileLines.length; i++) {
    const line = fileLines[i];
    if (line.trim().startsWith('//') || line.trim().startsWith('#')) continue;

    // A new function resets what we know.
    if (TAINT_BOUNDARY.test(line)) tainted = new Map();

    // Spring handler parameters are request data by declaration:
    // f(@RequestParam String name, @PathVariable("id") Long id).
    const annRe = /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|MatrixVariable)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w.<>,?\[\] ]*?\b(\w+)\s*(?=[,)])/g;
    let ann;
    while ((ann = annRe.exec(line)) !== null) tainted.set(ann[1], i + 1);

    // Source and sink on the same line, with the source wrapped in another
    // call: res.sendFile(path.join(__dirname, req.query.file)). The pattern
    // files only see the source when it is the sink's direct argument.
    for (const sink of TAINT_SINKS) {
      const sm = sink.re.exec(line);
      if (!sm) continue;
      // Only the first argument is the dangerous one: the query text, the
      // path, the URL, the command, the response body. A request value in a
      // later argument is a bound parameter, an argv entry or an options
      // object — db.query("... $1", [req.params.id]) is the safe form.
      const first = sink.rest ? line.slice(sm.index + sm[0].length)
        : firstArgument(line, sm.index + sm[0].length - 1);
      const src = first && first.match(TAINT_SOURCE);
      if (!src || TAINT_SANITIZED.test(first)) continue;
      found.push({ sink, line: i + 1, snippet: line.trim(), varName: src[0].replace(/\s+/g, ''), srcLine: i + 1 });
    }

    // A tainted variable reaching a sink. Checked before this line's own
    // assignment is processed, so `data, _ := os.ReadFile(f)` is judged with
    // f still tainted rather than skipped as a propagation step.
    if (tainted.size > 0) {
      for (const sink of TAINT_SINKS) {
        const sm = sink.re.exec(line);
        if (!sm) continue;
        if (TAINT_SANITIZED.test(line)) continue;
        // As above: only the first argument carries the vulnerability.
        const first = sink.rest ? line.slice(sm.index + sm[0].length)
          : firstArgument(line, sm.index + sm[0].length - 1);
        // Plain string literals are text, not variables: in
        // db.query("SELECT ... WHERE id = ?", [id]) the word id inside the
        // SQL is not the tainted variable. f-strings keep their {...}.
        const arg = '(' + (first === null ? line.slice(sm.index) : first)
          .replace(/(?<![fFrRbBuU])"(?:[^"\\]|\\.)*"|(?<![fFrRbBuU])'(?:[^'\\]|\\.)*'/g, '""');
        for (const [name, srcLine] of tainted) {
          // The variable must actually appear in that argument.
          const used = new RegExp('[(,:\\s\\[`+.{]\\$?' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
          if (!used.test(arg)) continue;
          found.push({ sink, line: i + 1, snippet: line.trim(), varName: name, srcLine });
          break;
        }
      }
    }

    // Destructuring is the dominant idiom in modern JS/TS:
    // `const { file } = req.query`. Handles renames (`{ a: b }`) and
    // defaults (`{ a = 1 }`); rest (`...r`) is skipped as it is not a scalar.
    const destructured = line.match(/(?:const|let|var)\s*\{\s*([^}]+?)\s*\}\s*=\s*(.+)$/);
    if (destructured && TAINT_SOURCE.test(destructured[2]) && !TAINT_SANITIZED.test(destructured[2])) {
      for (const part of destructured[1].split(',')) {
        const name = part.split(':').pop().split('=')[0].trim();
        if (/^[A-Za-z_$][\w$]*$/.test(name)) tainted.set(name, i + 1);
      }
      continue;
    }

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
  }
  return found;
}

// Returns { hits, suppressed }. `suppressed` lists every finding an inline
// comment silenced, with the reason given, so reports can show them.
function matchContentDetailed(content, filenameOrExt, patterns) {
  const fileLines = content.split(/\r?\n/);
  const ext = (path.extname(filenameOrExt || '').slice(1) || filenameOrExt || '').toLowerCase();
  const base = path.basename(filenameOrExt || '');
  const seen = new Set();
  const hits = [];
  const suppressed = new Map(); // `${id}@${line}` -> record
  const cfg = loadConfig();
  const secretsOnly = SECRETS_ONLY_EXT.has(ext);
  const maskLangs = extFamily(ext).map(e => LEXICAL[e]).find(Boolean) || null;

  const noteSuppressed = (id, section, severity, lineNo, sup) => {
    const key = `${id}@${lineNo}`;
    if (!suppressed.has(key)) suppressed.set(key, { id, section, severity, line: lineNo, reason: sup.reason });
  };

  // Several regexes share one id (e.g. eight `secret` lines). Occurrences are
  // collected per id across all of them: stopping at the first regex that
  // matched hid every other match — a Stripe key went unreported because a
  // private key header further down had already satisfied `secret`.
  const occById = new Map(); // id -> Map(line -> hit)

  for (const p of patterns) {
    if (cfg && Array.isArray(cfg.ignorePatterns) && cfg.ignorePatterns.includes(p.id)) continue;
    if (secretsOnly && !isSecretPattern(p.id)) continue;
    // exts are lowercased at load; match the basename case-insensitively so
    // `Dockerfile` scoping works. Extensionless files (Dockerfile, Makefile)
    // must still be filtered — matching on basename only, not skipped.
    if (p.exts !== '*') {
      const want = p.exts.split(',');
      const lowerBase = base.toLowerCase();
      // Dockerfile.prod / api.Dockerfile are Dockerfiles too.
      const named = want.some(w => lowerBase === w || lowerBase.startsWith(w + '.') || lowerBase.endsWith('.' + w));
      if (!extFamily(ext).some(e => want.includes(e)) && !named) continue;
    }

    if (p.exclFileRe && p.exclFileRe.test(content)) continue;
    if (!occById.has(p.id)) occById.set(p.id, new Map());
    const occ = occById.get(p.id);
    const add = (lineNo, snippet) => {
      if (occ.has(lineNo) || occ.size >= MAX_OCCURRENCES) return;
      occ.set(lineNo, {
        id: p.id,
        section: p.section,
        hint: p.hint || '',
        severity: p.severity || 'medium',
        line: lineNo,
        snippet: maskSecret(snippet, p.id),
      });
    };

    let lineMatched = false;
    let lineMatchedAndSuppressed = false;
    // Any single line the regex matches, before exclusions. The whole-file
    // fallback is only for patterns that span lines; a line-level match that
    // was excluded (by `!re`, a string or a comment) must stay excluded.
    let anyLineHit = false;

    for (let i = 0; i < fileLines.length; i++) {
      const line = fileLines[i];
      if (!p.re.test(line)) continue;
      anyLineHit = true;
      if (p.exclRe && p.exclRe.test(line)) continue;
      if (p.codeOnly && maskLangs && !matchesInCode(p, line, maskLangs)) continue;
      const sup = suppressionFor(line, p.id);
      if (sup) {
        lineMatchedAndSuppressed = true;
        noteSuppressed(p.id, p.section, p.severity, i + 1, sup);
        continue;
      }
      lineMatched = true;
      add(i + 1, line.trim());
    }

    // Fallback: the pattern spans lines (a Terraform block, a chained call).
    // Only when no single line matched and nothing was suppressed for this id.
    // Searched in windows of a few lines, anchored where the match starts:
    // over the whole file, `[^;]*` in a regex happily joined "token" in one
    // comment to Math.random() forty lines later.
    if (!anyLineHit && p.re.test(content)) {
      if ((!p.exclRe || !p.exclRe.test(content)) && !fileLines.some(l => isSuppressed(l, p.id))) {
        for (let i = 0; i < fileLines.length; i++) {
          const win = fileLines.slice(i, i + FALLBACK_WINDOW).join('\n');
          const m = p.re.exec(win);
          if (!m || win.slice(0, m.index).includes('\n')) continue; // starts on a later line
          if (p.codeOnly && maskLangs && /^\s*(\/\/|#|\/\*|\*)/.test(fileLines[i])) continue;
          add(i + 1, fileLines[i].trim());
          break;
        }
      }
    }
  }

  for (const [id, occ] of occById) {
    if (occ.size === 0) continue;
    seen.add(id);
    hits.push(...[...occ.values()].sort((a, b) => a.line - b.line));
  }

  // Shannon Entropy Secret Detection
  if (!seen.has('secret-entropy') && (!cfg || cfg.entropyDetection !== false)) {
    // `["']?` after the key: JSON and dict literals quote it ("token": "...").
    // `\w*` after the keyword: aws_secret_access_key, client_secret_value.
    // The entropy threshold below keeps the wider net from adding noise.
    const entropyRegex = /((?:password|passwd|api_?key|secret|token|auth_?key|private_?key|signing_?key|crypto_?key|master_?key)\w*)["']?\s*[:=]\s*["']([A-Za-z0-9+/=_-]{20,})["']/i;
    // A name that describes the secret rather than holding it: the form
    // field, header, env-var name or regex for a password is not one.
    const NOT_A_SECRET_NAME = /(field|header|name|param|env|var|path|file|url|label|prompt|regex|pattern|length|len|min|max|_id|type)$/i;
    let count = 0;
    for (let i = 0; i < fileLines.length && count < MAX_OCCURRENCES; i++) {
      const line = fileLines[i];
      const m = line.match(entropyRegex);
      if (!m || !m[2] || NOT_A_SECRET_NAME.test(m[1])) continue;
      const secretStr = m[2];
      // A placeholder in .env.example is high-entropy but is not a secret.
      // Flagging it as critical trains people to ignore the whole rule.
      if (/(?:^|[-_])(?:[Yy][Oo][Uu][Rr]|[Ee][Xx][Aa][Mm][Pp][Ll][Ee]|[Pp][Ll][Aa][Cc][Ee][Hh][Oo][Ll][Dd][Ee][Rr]|[Cc][Hh][Aa][Nn][Gg][Ee][Mm][Ee]|[Dd][Uu][Mm][Mm][Yy]|[Mm][Oo][Cc][Kk]|[Ff][Aa][Kk][Ee]|[Ss][Aa][Mm][Pp][Ll][Ee]|[Tt][Oo][Dd][Oo]|[Rr][Ee][Pp][Ll][Aa][Cc][Ee]|[Ii][Nn][Ss][Ee][Rr][Tt]|[Xx]{3,})(?:[-_]|$)/.test(secretStr)) continue;
      const entropy = calculateShannonEntropy(secretStr);
      if (entropy < 3.5) continue;
      const sup = suppressionFor(line, 'secret-entropy') || suppressionFor(line, 'secret');
      if (sup) { noteSuppressed('secret-entropy', '06', 'critical', i + 1, sup); continue; }
      // Every hardcoded secret needs rotating, so report each one.
      count++;
      hits.push({
        id: 'secret-entropy',
        section: '06',
        hint: `high-entropy string detected (Shannon entropy ${entropy.toFixed(2)} bits/byte); move to secret manager`,
        severity: 'critical',
        line: i + 1,
        snippet: maskSecret(line.trim(), 'secret-entropy'),
      });
    }
    if (count > 0) seen.add('secret-entropy');
  }

  // Multi-line taint: source assigned to a variable, then used in a sink.
  if (!secretsOnly && (!cfg || cfg.taintTracking !== false)) {
    for (const flow of findTaintFlows(fileLines)) {
      if (seen.has(flow.sink.id)) continue;
      const sup = suppressionFor(fileLines[flow.line - 1], flow.sink.id);
      if (sup) { noteSuppressed(flow.sink.id, flow.sink.section, flow.sink.severity, flow.line, sup); continue; }
      // Skip only when a pattern already reported this same vulnerability on
      // this line; an unrelated finding on the line must not hide the taint.
      // A sink with `dedupe` names the patterns that describe the same bug;
      // section alone would let llm-unbounded-tokens hide a prompt injection.
      const dup = flow.sink.dedupe
        ? hits.some(h => h.line === flow.line && flow.sink.dedupe.includes(h.id))
        : hits.some(h => h.line === flow.line && h.section === flow.sink.section);
      if (dup) continue;
      seen.add(flow.sink.id);
      hits.push({
        id: flow.sink.id,
        section: flow.sink.section,
        hint: flow.srcLine === flow.line
          ? `${flow.sink.hint} (\`${flow.varName}\` on the same line)`
          : `${flow.sink.hint} (tainted \`${flow.varName}\` from line ${flow.srcLine})`,
        severity: flow.sink.severity,
        line: flow.line,
        srcLine: flow.srcLine,
        snippet: maskSecret(flow.snippet, flow.sink.id),
      });
    }
  }

  return { hits: dropSupersededHits(hits), suppressed: [...suppressed.values()] };
}

function matchContent(content, filenameOrExt, patterns) {
  return matchContentDetailed(content, filenameOrExt, patterns).hits;
}

function matchFile(file, patterns) {
  const content = fs.readFileSync(file, 'utf8');
  return matchContentDetailed(content, file, patterns);
}

// Match a file against the config's ignorePaths globs (** and * only).
function isIgnoredPath(file) {
  const cfg = loadConfig();
  const globs = cfg && Array.isArray(cfg.ignorePaths) ? cfg.ignorePaths : [];
  if (globs.length === 0) return false;
  // Relative to the project being scanned, not the installed skill: resolving
  // against DIR made every downstream path start with '..', so ignorePaths
  // matched nothing at all outside this repository.
  const rel = path.relative(projectRoot(), canonicalPath(file)).split(path.sep).join('/');
  if (rel.startsWith('..')) return false; // genuinely outside the project
  return globs.some(g => {
    const re = new RegExp('^' + g.split('/').map(part =>
      part === '**' ? '.*' : part.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*')
    ).join('/').replace(/\.\*\//g, '(?:.*/)?') + '$');
    return re.test(rel);
  });
}

// git prints staged paths relative to the repo root, not to cwd. Resolving
// them against cwd silently produces paths that do not exist when run from a
// subdirectory, so every staged file gets skipped.
// Regenerate the HTML report in a child process. `require`-ing report.js runs
// it in-process, where it inherits scan.js's own process.argv -- so
// `scan.js --all --help` printed report.js's usage, and any flag scan.js
// accepts could change what the report did. One isolated call site instead of
// three divergent ones.
function regenerateReport() {
  try {
    const { execFileSync } = require('child_process');
    execFileSync(process.execPath, [path.join(DIR, 'hooks', 'report.js')], {
      env: process.env, stdio: 'ignore', timeout: 10000,
    });
  } catch (e) { /* report is best-effort */ }
}

function repoRoot() {
  try {
    return execFileSync('git', ['rev-parse', '--show-toplevel'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || process.cwd();
  } catch { return process.cwd(); }
}

// --- baseline ---
// A repository adopting the scanner already has findings. Without a baseline
// every one of them blocks the agent's next edit to that file and every
// commit that touches it, so the only way forward was suppressing them all.
// `scan.js --baseline` records what exists now; afterwards only findings that
// are not in the baseline block. Entries are keyed by file, rule and a hash
// of the line's text, not the line number, so code moving up or down does
// not resurrect them — and an edited line is a new finding.
const BASELINE_VERSION = 1;

function baselinePath() {
  const cfg = loadConfig();
  const rel = (cfg && typeof cfg.baseline === 'string' && cfg.baseline) || '.securecoding-baseline.json';
  return path.resolve(projectRoot(), rel);
}

function lineHash(text) {
  return require('crypto').createHash('sha256')
    .update(String(text || '').trim().replace(/\s+/g, ' ')).digest('hex').slice(0, 16);
}

function relToRoot(file) {
  return path.relative(projectRoot(), canonicalPath(file)).split(path.sep).join('/');
}

let _baseline;
function loadBaseline() {
  if (_baseline !== undefined) return _baseline;
  _baseline = null;
  if (process.env.SECURE_CODING_NO_BASELINE === '1') return _baseline;
  try {
    const data = JSON.parse(fs.readFileSync(baselinePath(), 'utf8'));
    const counts = new Map();
    for (const e of data.entries || []) {
      const key = `${e.file}|${e.id}|${e.hash}`;
      counts.set(key, (counts.get(key) || 0) + (Number(e.count) || 1));
    }
    _baseline = counts;
  } catch { /* no baseline, or unreadable: everything counts as new */ }
  return _baseline;
}

// Split hits into those that are new and those the baseline already knows.
// Counts matter: two identical lines in the baseline excuse two hits, not
// a third one added later.
function applyBaseline(file, hits) {
  const base = loadBaseline();
  if (!base || hits.length === 0) return { hits, baselined: [] };
  const left = new Map();
  const rel = relToRoot(file);
  const kept = [];
  const baselined = [];
  for (const h of hits) {
    const key = `${rel}|${h.id}|${lineHash(h.snippet)}`;
    const n = left.has(key) ? left.get(key) : (base.get(key) || 0);
    if (n > 0) { left.set(key, n - 1); baselined.push(h); }
    else kept.push(h);
  }
  return { hits: kept, baselined };
}

function writeBaseline(results) {
  const counts = new Map();
  for (const { file, hits } of results) {
    const rel = relToRoot(file);
    for (const h of hits) {
      const key = `${rel}|${h.id}|${lineHash(h.snippet)}`;
      const e = counts.get(key) || { file: rel, id: h.id, hash: lineHash(h.snippet), count: 0, severity: h.severity };
      e.count++;
      counts.set(key, e);
    }
  }
  const entries = [...counts.values()].sort((a, b) => (a.file + a.id).localeCompare(b.file + b.id));
  const out = { version: BASELINE_VERSION, generated: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), entries };
  fs.writeFileSync(baselinePath(), JSON.stringify(out, null, 2) + '\n');
  return entries.reduce((n, e) => n + e.count, 0);
}

// --- dependency guard ---
// Runs hooks/deps.js in a child (it is async and talks to registries) and
// returns its blocking findings shaped like scan hits. Only dependencies that
// the change ADDS are checked; offline means "not checked", never a failure.
function dependencyHits(argv) {
  try {
    const r = require('child_process').spawnSync(process.execPath, [path.join(__dirname, 'deps.js'), ...argv, '--json'],
      { encoding: 'utf8', timeout: 30000 });
    const res = JSON.parse(r.stdout || '{}');
    return (res.findings || [])
      .filter(f => f.severity === 'critical' || f.severity === 'high')
      .map(f => ({ id: f.id, section: '28', severity: f.severity, line: f.line || 1, hint: f.detail, snippet: f.name, file: f.file }));
  } catch { return []; }
}

// --- hook scope ---
// Lines an Edit or MultiEdit just wrote: every occurrence of each new_string
// in the file as it is now. A Write replaces the whole file, so it returns
// null, meaning "every line".
function changedLines(payload, content) {
  let data;
  try { data = JSON.parse(payload); } catch { return null; }
  const input = (data && data.tool_input) || {};
  const news = [];
  if (typeof input.new_string === 'string') news.push(input.new_string);
  if (Array.isArray(input.edits)) for (const e of input.edits) if (e && typeof e.new_string === 'string') news.push(e.new_string);
  if (news.length === 0) return null;
  const lines = new Set();
  for (const ns of news) {
    if (!ns) continue;
    let from = 0;
    let at;
    while ((at = content.indexOf(ns, from)) !== -1) {
      const start = content.slice(0, at).split('\n').length;
      const span = ns.split('\n').length;
      for (let k = 0; k < span; k++) lines.add(start + k);
      from = at + Math.max(ns.length, 1);
    }
  }
  return lines;
}

// Scan the index copy of a file rather than the working tree, so `--staged`
// reflects the commit. Falls back to the worktree if the blob cannot be read.
function scanStagedBlob(file, patterns) {
  if (skippedByName(file)) return [];
  if (isIgnoredPath(file)) return [];
  let content;
  try {
    const root = repoRoot();
    // git show wants a repo-root-relative path with forward slashes.
    const rel = (path.relative(root, file) || path.basename(file)).split(path.sep).join('/');
    content = execFileSync('git', ['show', `:${rel}`],
      { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return scanSingleFile(file, patterns);
  }
  const res = matchContentDetailed(content, file, patterns);
  const { hits, baselined } = applyBaseline(file, res.hits);
  updateState(file, hits, res.suppressed, baselined);
  return hits;
}

function scanSingleFile(file, patterns) {
  if (!fs.existsSync(file)) return [];
  // git can list directories (submodules, extensionless dirs); never read one.
  try { if (!fs.statSync(file).isFile()) return []; } catch (e) { return []; }
  if (skippedByName(file)) return [];
  // .securecodingrc.json ignorePaths — documented but previously unenforced.
  if (isIgnoredPath(file)) return [];

  const res = matchFile(file, patterns);
  const { hits, baselined } = applyBaseline(file, res.hits);
  updateState(file, hits, res.suppressed, baselined);
  _lastBaselined = baselined.length;
  return hits;
}
// How many hits the baseline absorbed in the last scanSingleFile call.
let _lastBaselined = 0;

// Non-code extensions and vendored/generated directories. `.min.js` is checked
// by suffix: extname() of app.min.js is "js", so the SKIP_EXT entry alone
// never matched.
function skippedByName(file) {
  const ext = path.extname(file).slice(1).toLowerCase();
  if (SKIP_EXT.has(ext) || /\.min\.js$/i.test(file)) return true;
  return file.split(/[\\/]/).some(s => SKIP_SEG.includes(s));
}

const USAGE = `secure-coding scanner

Usage:
  node hooks/scan.js --staged              scan git staged files
  node hooks/scan.js --diff                scan modified working-tree files
  node hooks/scan.js --file <path>         scan one file
  node hooks/scan.js --files <p> [p...]    scan specific files
  node hooks/scan.js --all                 scan every tracked file (baseline)
  node hooks/scan.js --find <id> <file>    record a manual finding
  node hooks/scan.js --baseline            record every current finding as known
  node hooks/scan.js --history [--since <rev>] [--all-refs]
                                           look for secrets in git history
  node hooks/scan.js                       hook mode (PostToolUse JSON on stdin)

Options:
  --json                                   machine-readable output
  --no-baseline                            report baselined findings too
  --help                                   show this message

Exit codes: 0 clean, 2 findings found.
`;

function main() {
  const args = process.argv.slice(2);

  // Before anything else: --help combined with a mode flag (--all --help) used
  // to run the whole scan, then print report.js's usage because the report was
  // require()d in-process and saw --help on argv.
  if (helpRequested(args, USAGE)) return;

  const patterns = loadPatterns();
  if (args.includes('--no-baseline')) {
    process.env.SECURE_CODING_NO_BASELINE = '1';
    args.splice(args.indexOf('--no-baseline'), 1);
  }

  // Record every current finding as known: node hooks/scan.js --baseline
  if (args[0] === '--baseline') {
    process.env.SECURE_CODING_NO_BASELINE = '1'; // capture everything, not the delta
    let files = [];
    try {
      const root = repoRoot();
      files = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' })
        .split('\0').filter(Boolean).map(f => path.resolve(root, f));
    } catch { files = []; }
    const results = [];
    for (const f of files) {
      const hits = scanSingleFile(f, patterns);
      if (hits.length) results.push({ file: f, hits });
    }
    const n = writeBaseline(results);
    process.stdout.write(`secure-coding: baseline written to ${path.relative(process.cwd(), baselinePath()) || baselinePath()} — ${n} finding(s) in ${results.length} file(s). Commit it; only new findings will block.\n`);
    return;
  }

  if (args[0] === '--history') {
    process.exit(require('./history').run(args.slice(1), patterns));
  }

  // Manual finding mode: node hooks/scan.js --find <id> <file> [note]
  if (args[0] === '--find') {
    const id = args[1];
    const file = args[2] || '';
    const note = args.slice(3).join(' ');
    if (!id) { process.stderr.write('Usage: scan.js --find <id> <file> [note]\n'); process.exit(1); }
    const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const runId = process.env.SECURE_CODING_RUN_ID || now.slice(0, 10);
    const rec = JSON.stringify({ file, id, section: 'manual', severity: 'medium', status: 'open', run_id: runId, first_seen: now, resolved_at: '', note });
    withFileLock(STATE, () => writeState(STATE, rec + '\n', { append: true }));
    if (REPORT) {
      regenerateReport();
    }
    process.stdout.write(`Recorded: ${id}${file ? ' in ' + path.basename(file) : ''}\n`);
    return;
  }

  // CLI Mode: --staged or --diff or --files
  // A bare path is treated as --files. Without this, `scan.js app.js` fell
  // through to stdin hook mode: with a piped stdin it read the wrong input,
  // and on a terminal it reported nothing and exited 0 -- a silent all-clear
  // on a file that may be full of findings.
  const positional = args.length > 0 && !args[0].startsWith('-');
  if (positional) args.unshift('--files');

  if (args[0] === '--staged' || args[0] === '--diff' || args[0] === '--files' || args[0] === '--file' || args[0] === '--all') {
    let filesToScan = [];
    const { execFileSync } = require('child_process');

    if (args[0] === '--staged') {
      try {
        // R and C included: a renamed or copied file with new content in it
        // must be scanned too, or `git mv` hides whatever is added alongside.
        // -z keeps paths with spaces or non-ASCII unquoted.
        const out = execFileSync('git', ['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR'], { encoding: 'utf8' });
        const root = repoRoot();
        filesToScan = out.split('\0').filter(Boolean).map(f => path.resolve(root, f));
      } catch { filesToScan = []; }
    } else if (args[0] === '--diff') {
      try {
        const out = execFileSync('git', ['diff', '--name-only', '-z', '--diff-filter=ACMR'], { encoding: 'utf8' });
        const root = repoRoot();
        filesToScan = out.split('\0').filter(Boolean).map(f => path.resolve(root, f));
      } catch { filesToScan = []; }
    } else if (args[0] === '--all') {
      // Baseline scan of everything tracked. git ls-files respects .gitignore,
      // so build output and node_modules stay out without a second filter.
      try {
        const root = repoRoot();
        const out = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' });
        filesToScan = out.split('\0').filter(Boolean).map(f => path.resolve(root, f));
      } catch { filesToScan = []; }
    } else if (args[0] === '--file' && args[1]) {
      filesToScan = [path.resolve(args[1])];
    } else if (args[0] === '--files') {
      // Drop flags: `--files app.js --json` used to resolve '--json' as a
      // filename, silently skip the missing file, and never apply --json.
      // Everything after a bare `--` is a path, even one starting with '-'.
      // Without this, a file named -x.js was dropped and reported "clean".
      const rest = args.slice(1);
      const dd = rest.indexOf('--');
      const before = dd === -1 ? rest : rest.slice(0, dd);
      const after = dd === -1 ? [] : rest.slice(dd + 1);
      filesToScan = before.filter(f => !f.startsWith('-')).concat(after).map(f => path.resolve(f));
    }

    let allHits = [];
    let baselinedTotal = 0;
    for (const f of filesToScan) {
      // --staged must judge what is being committed, not what happens to be on
      // disk. Reading the worktree lets an unstaged fix hide a staged flaw.
      _lastBaselined = 0;
      const hits = args[0] === '--staged'
        ? scanStagedBlob(f, patterns)
        : scanSingleFile(f, patterns);
      baselinedTotal += _lastBaselined;
      if (hits.length > 0) {
        allHits.push({ file: f, hits });
      }
    }
    if (args[0] === '--staged') {
      const deps = dependencyHits(['--staged']);
      const byFile = new Map();
      for (const d of deps) {
        if (!byFile.has(d.file)) byFile.set(d.file, []);
        byFile.get(d.file).push(d);
      }
      for (const [f, ds] of byFile) {
        const item = allHits.find(a => a.file === f);
        if (item) item.hits.push(...ds); else allHits.push({ file: f, hits: ds });
      }
    }
    const baseNote = baselinedTotal
      ? ` (${baselinedTotal} known finding(s) in the baseline not shown; --no-baseline to list them)` : '';

    if (REPORT) {
      regenerateReport();
    }

    if (args.includes('--json')) {
      process.stdout.write(JSON.stringify(allHits, null, 2) + '\n');
      process.exit(allHits.length > 0 ? 2 : 0);
    }

    if (allHits.length === 0) {
      process.stdout.write(`secure-coding: clean — scanned ${filesToScan.length} file(s)${baseNote}\n`);
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
    if (baseNote) process.stdout.write(`${baseNote.trim()}\n`);
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
  const file = hookFilePath(payload);
  if (!file) return;
  if (!fs.existsSync(file)) {
    // A deleted or moved file is normal; say so instead of a silent all-clear.
    process.stderr.write(`secure-coding: ${file} not found — nothing scanned\n`);
    return;
  }

  const allFileHits = scanSingleFile(file, patterns);
  if (REPORT) {
    regenerateReport();
  }

  // Block only on what this edit wrote. A finding elsewhere in the file was
  // there before the agent arrived; it is named, but it does not stop the
  // agent mid-task. Commit and CI scans still judge the whole file.
  // `"hookScope": "file"` in .securecodingrc.json restores whole-file blocking.
  const cfg = loadConfig();
  let scoped = null;
  if (!cfg || cfg.hookScope !== 'file') {
    try { scoped = changedLines(payload, fs.readFileSync(file, 'utf8')); } catch { scoped = null; }
  }
  const touches = h => !scoped || scoped.has(h.line) || (h.srcLine && scoped.has(h.srcLine));
  const hits = allFileHits.filter(touches);
  const elsewhere = allFileHits.length - hits.length;
  // A manifest the agent just edited: check the packages it added exist.
  if (require('./deps').isManifest(file)) hits.push(...dependencyHits(['--file', file]));

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

  const more = (hits.length > MAX_HITS
    ? `\n\n(+${hits.length - MAX_HITS} more — run: node hooks/scan.js --file ${JSON.stringify(file)})`
    : '') + (elsewhere > 0
    ? `\n\n(${elsewhere} other finding(s) in this file predate this edit; not blocking, but they will block the commit unless baselined)`
    : '');
  // stderr, not stdout: on exit code 2 Claude Code feeds only stderr back to
  // the agent. Written to stdout, the fix blocks never reached it.
  process.stderr.write(`Security patterns found in ${path.basename(file)}. Fix these before continuing:\n\n${blocks}${more}\n`);
  process.exit(2);
}

// The file a PostToolUse payload refers to. Parsed as JSON: a regex over the
// raw text broke on escaped characters and could pick up a "file_path" that
// appeared inside the written content. Relative paths resolve against the
// payload's cwd. NotebookEdit names its target notebook_path.
function hookFilePath(payload) {
  let data = null;
  try { data = JSON.parse(payload); } catch { /* fall through to the regex */ }
  if (data && typeof data === 'object') {
    const input = data.tool_input || {};
    const f = input.file_path || input.notebook_path || input.path
      || (data.tool_response && data.tool_response.filePath);
    if (typeof f !== 'string' || !f) return null;
    return path.resolve(typeof data.cwd === 'string' ? data.cwd : process.cwd(), f);
  }
  const m = payload.match(/"file_path"\s*:\s*"((?:[^"\\]|\\.)*)"/);
  if (!m) return null;
  try { return path.resolve(JSON.parse(`"${m[1]}"`)); } catch { return null; }
}

// Track findings: open for current hits, fixed for previously-open ids that
// no longer match, suppressed for those an inline comment silenced. Preserves
// fixed history. Rewrites the JSONL state file under a lock: the agent writes
// files in parallel, and two hooks doing read-modify-write at once lost
// each other's records.
function updateState(file, hits, suppressed = [], baselined = []) {
  withFileLock(STATE, () => updateStateLocked(file, hits, suppressed, baselined));
}

function updateStateLocked(file, hits, suppressed, baselined) {
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
    // Suppressions are re-derived from the file on every scan.
    if (rec.status === 'suppressed' || rec.status === 'baselined') continue;
    if (rec.status === 'open') openRecs.push(rec);
    else fixedRecs.push(rec);
  }

  const out = [...kept];
  for (const rec of fixedRecs) out.push(JSON.stringify(rec));

  const supByKey = new Map();
  for (const sp of suppressed) supByKey.set(keyOf(sp.id, sp.line), sp);
  const baseByKey = new Map();
  for (const b of baselined) baseByKey.set(keyOf(b.id, b.line), b);

  const seenKeys = new Set();
  for (const rec of openRecs) {
    // Silenced, not fixed: the suppressed record below replaces it.
    if (rec.line != null && supByKey.has(keyOf(rec.id, rec.line))) continue;
    // Known before (in the baseline), not fixed: re-recorded as baselined.
    if (rec.line != null && baseByKey.has(keyOf(rec.id, rec.line))) continue;
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

  for (const sp of supByKey.values()) {
    out.push(JSON.stringify({
      file, id: sp.id, section: sp.section || '',
      severity: sp.severity || 'medium',
      status: 'suppressed', run_id: runId, first_seen: now, resolved_at: '',
      line: sp.line || 0,
      reason: sp.reason || '',
      note: `Line ${sp.line}: suppressed inline${sp.reason ? ' — ' + sp.reason.slice(0, 100) : ' (no reason given)'}`,
    }));
  }

  for (const b of baseByKey.values()) {
    out.push(JSON.stringify({
      file, id: b.id, section: b.section || '',
      severity: b.severity || 'medium',
      status: 'baselined', run_id: runId, first_seen: now, resolved_at: '',
      line: b.line || 0,
      note: `Line ${b.line}: in the baseline (known before adoption)`,
    }));
  }

  writeState(STATE, out.join('\n') + (out.length ? '\n' : ''));
}

// Extract the `## id` block from fixes.md (including the `## id` header).
// fixes.md is ~55KB and was re-read and re-split for every finding. Parse it
// once per process into an id -> block map.
let _fixIndex = null;
function fixIndex() {
  if (_fixIndex) return _fixIndex;
  _fixIndex = new Map();
  if (!fs.existsSync(FIXES)) return _fixIndex;
  for (const part of fs.readFileSync(FIXES, 'utf8').split(/^## /m)) {
    const header = part.match(/^([^\n]+)/);
    if (header) _fixIndex.set(header[1].trim(), part.replace(/^[^\n]*\n/, '').trim());
  }
  return _fixIndex;
}

function fixBlock(id) {
  const body = fixIndex().get(id);
  return body ? `## ${id}\n${body}` : '';
}

// Exports before main(): hooks/history.js requires this module while main()
// is running, and would otherwise see an empty exports object.
module.exports = { EXT_ALIASES, lineHash, changedLines, applyBaseline, main, loadPatterns, scanSingleFile, matchContent, matchContentDetailed, suppressionFor, fixBlock, dropSupersededHits, hookFilePath };

if (require.main === module) {
  main();
}
