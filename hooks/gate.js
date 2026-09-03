#!/usr/bin/env node
// Done Gate: the manual review the scanner cannot perform.
//
// The four questions in SKILL.md cover exactly what patterns cannot see —
// IDOR, missing authz, multi-hop taint, fail-open. As prose they are easy to
// skim past, so this records the answers as an artifact and fails until every
// question is answered for the current commit.
//
// Usage:
//   node hooks/gate.js --answer ownership "scoped by db.find({id, userId})"
//   node hooks/gate.js --status
//   node hooks/gate.js --check           # exit 2 if any answer is missing
//   node hooks/gate.js --reset
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const DIR = path.join(__dirname, '..');
function defaultState() {
  try {
    const top = execFileSync('git', ['rev-parse', '--show-toplevel'],
      { cwd: process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (top) return path.join(top, '.git', 'secure-coding-gate.json');
  } catch { /* not a repo */ }
  return path.join(DIR, 'checks', 'gate.json');
}
const STATE = process.env.SECURE_CODING_GATE || defaultState();

// --- relevance ---
// The four questions are about request handling. A docs, config, or test-only
// change cannot answer them meaningfully, and a gate that fires on every commit
// trains people to bypass the hook — which would disable the scanner too, since
// they share it. So the gate asks only when the staged code actually contains
// the shapes the questions are about.

// Files that cannot contain a route or a data access.
const IRRELEVANT_EXT = new Set(['md', 'txt', 'json', 'yml', 'yaml', 'toml', 'lock',
  'csv', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'pdf', 'html', 'css', 'scss']);
const IRRELEVANT_SEG = ['node_modules', 'dist', 'build', 'vendor', '.git', 'docs',
  '__tests__', '__snapshots__', 'fixtures'];

// Code shapes the questions are actually about.
const RELEVANT_CODE = [
  // a route or handler is declared
  /\b(app|router|server|api)\s*\.\s*(get|post|put|patch|delete|use|all)\s*\(/i,
  /@(app|router|bp|blueprint)\.(route|get|post|put|patch|delete)\s*\(/,
  /@(Get|Post|Put|Patch|Delete|Request)Mapping\b/,
  /\b(http\.HandleFunc|mux\.Handle|r\.(Get|Post|Put|Delete)\s*\()/,
  /\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\b/,
  /\b(def|fn|func|function|async)\b[^\n]{0,60}\b(handler|handle_request|controller)\b/i,
  // a request value is read
  /\breq(uest)?\s*\.\s*(query|body|params|args|form|cookies|headers|GET|POST)\b/,
  /\$_(GET|POST|REQUEST|COOKIE|FILES)\b/,
  /\bgetParameter\s*\(|\bFormValue\s*\(/,
  // a record is fetched, or a query runs
  /\.(find|findOne|findById|findFirst|findUnique|get|fetch|load|select)\s*\(/i,
  /\b(SELECT|INSERT|UPDATE|DELETE)\b[^\n]{0,40}\b(FROM|INTO|SET|WHERE)\b/i,
  // an authorization or authentication decision
  /\b(authorize|authorise|authenticate|requireAuth|require_auth|isAdmin|is_admin|hasPermission|has_permission|checkAccess|check_access|canAccess|@login_required|@requires_auth)\b/i,
  /\b(401|403)\b/,
];

function relevantFiles(files) {
  const hits = [];
  for (const f of files) {
    const ext = path.extname(f).slice(1).toLowerCase();
    if (IRRELEVANT_EXT.has(ext)) continue;
    if (f.split(path.sep).some(seg => IRRELEVANT_SEG.includes(seg))) continue;
    if (/(^|[.\/])(test|spec)[.\/]|\.(test|spec)\.[a-z]+$|_test\.[a-z]+$/i.test(f)) continue;
    let text = '';
    try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
    if (RELEVANT_CODE.some(re => re.test(text))) hits.push(f);
  }
  return hits;
}

function stagedFiles() {
  try {
    // git prints paths relative to the repo root; resolve against it so this
    // works when run from a subdirectory, not just from the root.
    let root = process.cwd();
    try {
      root = execFileSync('git', ['rev-parse', '--show-toplevel'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || process.cwd();
    } catch { /* not a repo */ }
    return execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'],
      { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .split(/\r?\n/).filter(Boolean).map(f => path.resolve(root, f));
  } catch { return []; }
}

const QUESTIONS = {
  ownership: 'For each record fetched by an ID from the request, what scopes it to the caller?',
  authorization: 'For each new route, which guard denies an unauthenticated or under-privileged caller?',
  taint: 'Where does each request value land — query, file path, shell, outbound URL, template?',
  'failure-direction': 'If the auth or permission check throws, does the request end up denied?',
};

// Answers are tied to a commit: new work needs a new review.
function currentRef() {
  // Track the repo being worked on, not wherever gate.js happens to live —
  // the same answers must resolve identically whether it runs from the skill
  // directory or a global install.
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: process.cwd(), encoding: 'utf8', stdio: ['ignore','pipe','ignore'] }).trim().slice(0, 12);
  } catch {
    // A repo with no commits yet still has a working tree to review.
    try {
      execFileSync('git', ['rev-parse', '--git-dir'], { cwd: process.cwd(), stdio: 'ignore' });
      return 'pre-initial-commit';
    } catch { return 'no-git'; }
  }
}

function load() {
  if (!fs.existsSync(STATE)) return { ref: null, answers: {} };
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch { return { ref: null, answers: {} }; }
}

function save(data) {
  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  fs.writeFileSync(STATE, JSON.stringify(data, null, 2) + '\n');
}

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (!cmd || cmd === '--help' || cmd === '-h') {
    process.stdout.write(`Done Gate — the manual review patterns cannot do.

  node hooks/gate.js --answer <question> "<answer>"
  node hooks/gate.js --status
  node hooks/gate.js --check     exit 2 if any question is unanswered
  node hooks/gate.js --reset     clear answers (start a new review)

Questions:
${Object.entries(QUESTIONS).map(([k, v]) => `  ${k.padEnd(18)} ${v}`).join('\n')}

"N/A" is a valid answer when a question does not apply to this change.
An answer of "yes"/"ok"/"done" is rejected — name the actual check.
`);
    return;
  }

  const ref = currentRef();
  let data = load();
  // Answers from an earlier commit do not carry forward.
  if (data.ref && data.ref !== ref) data = { ref, answers: {} };
  data.ref = ref;

  if (cmd === '--reset') {
    save({ ref, answers: {} });
    process.stdout.write('gate: answers cleared\n');
    return;
  }

  if (cmd === '--answer') {
    const q = args[1];
    const a = args.slice(2).join(' ').trim();
    if (!QUESTIONS[q]) {
      process.stderr.write(`gate: unknown question '${q}'. One of: ${Object.keys(QUESTIONS).join(', ')}\n`);
      process.exit(64);
    }
    if (!a) {
      process.stderr.write('gate: an answer is required\n');
      process.exit(64);
    }
    // A non-answer is worse than no answer: it looks reviewed and is not.
    // A blocklist only catches the filler someone thought of, so require
    // substance instead: either a bare "N/A", or something that actually says
    // what enforces the control.
    const isNA = /^n\/?a\b/i.test(a) && a.replace(/^n\/?a\b[\s—:-]*/i, '').trim().length >= 8;
    if (/^n\/?a\b/i.test(a) && !isNA) {
      process.stderr.write('gate: "N/A" needs a reason — say why the question does not apply.\n');
      process.stderr.write('  e.g. "N/A — no data access added in this change"\n');
      process.exit(64);
    }
    const words = a.split(/\s+/).filter(w => /[a-z0-9]/i.test(w));
    if (!isNA) {
      const filler = /^(yes|no|ok|okay|done|checked|fine|good|true|none|nothing|handled|todo|tbd|n\/?a|x|-|\.|see above|as above|same)$/i;
      if (filler.test(a) || words.length < 2 || a.replace(/[^a-z0-9]/gi, '').length < 12) {
        process.stderr.write(`gate: "${a}" does not name a check.\n`);
        process.stderr.write('Say what enforces it (a guard, predicate, middleware, or test), or "N/A — <why it does not apply>".\n');
        process.exit(64);
      }
    }
    data.answers[q] = { answer: a, at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
    save(data);
    process.stdout.write(`gate: recorded ${q}\n`);
    return;
  }

  const missing = Object.keys(QUESTIONS).filter(q => !data.answers[q]);

  if (cmd === '--status') {
    process.stdout.write(`Done Gate @ ${ref}\n\n`);
    for (const [q, text] of Object.entries(QUESTIONS)) {
      const a = data.answers[q];
      process.stdout.write(a ? `  [x] ${q}\n      ${a.answer}\n` : `  [ ] ${q}\n      ${text}\n`);
    }
    process.stdout.write(`\n${missing.length === 0 ? 'complete' : `${missing.length} unanswered`}\n`);
    return;
  }

  if (cmd === '--check') {
    // Only ask when the staged code contains what the questions are about.
    // --all forces the review regardless, for a deliberate audit.
    if (!args.includes('--all')) {
      const staged = stagedFiles();
      // Nothing staged means nothing to review. Falling through here made the
      // gate block on an idle tree, which is the state it is most often run in.
      if (staged.length === 0) {
        process.stdout.write('gate: skipped — nothing staged to review\n');
        process.exit(0);
      }
      {
        const relevant = relevantFiles(staged);
        if (relevant.length === 0) {
          process.stdout.write(`gate: skipped — no staged file handles requests, data access, or authorization (${staged.length} file(s) checked)\n`);
          process.exit(0);
        }
        if (missing.length > 0) {
          process.stderr.write(`gate: review required — ${relevant.length} staged file(s) handle requests or access data:\n`);
          for (const f of relevant.slice(0, 5)) process.stderr.write(`  ${f}\n`);
          if (relevant.length > 5) process.stderr.write(`  ... and ${relevant.length - 5} more\n`);
        }
      }
    }
    if (missing.length === 0) {
      process.stdout.write(`gate: complete (${Object.keys(QUESTIONS).length}/${Object.keys(QUESTIONS).length} answered @ ${ref})\n`);
      process.exit(0);
    }
    process.stderr.write(`gate: ${missing.length} unanswered — ${missing.join(', ')}\n`);
    process.stderr.write('Run: node hooks/gate.js --status\n');
    process.exit(2);
  }

  process.stderr.write(`gate: unknown option '${cmd}'\n`);
  process.exit(64);
}

if (require.main === module) main();
module.exports = { QUESTIONS, main };
