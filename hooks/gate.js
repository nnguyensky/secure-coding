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
const STATE = process.env.SECURE_CODING_GATE || path.join(DIR, 'checks', 'gate.json');

const QUESTIONS = {
  ownership: 'For each record fetched by an ID from the request, what scopes it to the caller?',
  authorization: 'For each new route, which guard denies an unauthenticated or under-privileged caller?',
  taint: 'Where does each request value land — query, file path, shell, outbound URL, template?',
  'failure-direction': 'If the auth or permission check throws, does the request end up denied?',
};

// Answers are tied to a commit: new work needs a new review.
function currentRef() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: DIR, encoding: 'utf8' }).trim().slice(0, 12);
  } catch { return 'no-git'; }
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
    if (/^(yes|no|ok|okay|done|n\/?a\b.{0,3}$|checked|fine|good|true)$/i.test(a) && !/^n\/?a$/i.test(a)) {
      process.stderr.write(`gate: "${a}" does not name a check. Say what enforces it, or "N/A".\n`);
      process.exit(64);
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
