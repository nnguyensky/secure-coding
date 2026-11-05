#!/usr/bin/env node
// Secrets in git history. A key deleted from the code is still in every clone
// of the repository, and still has to be rotated. Scans the lines each commit
// ADDED (git log -p) with the secret rules and the entropy check only — code
// rules on old revisions would be noise.
//
// Usage: node hooks/scan.js --history [--since <rev>] [--all-refs] [--json]
//        node hooks/history.js ...same flags
'use strict';

const path = require('path');
const { execFileSync } = require('child_process');
const { helpRequested } = require('./config');

const USAGE = `Usage: node hooks/scan.js --history [--since <rev>] [--all-refs] [--json]

Looks for secrets in lines added by past commits.
  --since <rev>   only commits after <rev> (e.g. origin/main, v2.1.0)
  --all-refs      every branch and tag, not just the current one
  --json          machine-readable output
Exit codes: 0 nothing found, 2 secrets found.`;

const MAX_BUFFER = 1024 * 1024 * 1024; // git log -p of a large repository

function parseArgs(argv) {
  const out = { since: null, allRefs: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--since') out.since = argv[++i] || null;
    else if (argv[i] === '--all-refs') out.allRefs = true;
    else if (argv[i] === '--json') out.json = true;
  }
  return out;
}

// Yields { commit, date, author, file, added: [{ line, text }] } per file
// per commit, from `git log -p -U0` output.
function* commitsAdded(logText) {
  let meta = null;
  let file = null;
  let added = [];
  let lineNo = 0;
  const flush = function* () {
    if (meta && file && added.length) yield { ...meta, file, added };
    added = [];
  };
  for (const raw of logText.split('\n')) {
    if (raw.startsWith('\u0000')) {
      yield* flush();
      const [commit, date, ...author] = raw.slice(1).split('\u0001');
      meta = { commit, date, author: author.join(' ') };
      file = null;
      continue;
    }
    if (raw.startsWith('+++ ')) {
      yield* flush();
      const p = raw.slice(4);
      file = p === '/dev/null' ? null : p.replace(/^b\//, '');
      continue;
    }
    if (raw.startsWith('@@')) {
      const m = raw.match(/\+(\d+)/);
      lineNo = m ? Number(m[1]) : 0;
      continue;
    }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      added.push({ line: lineNo, text: raw.slice(1) });
      lineNo++;
    }
  }
  yield* flush();
}

function run(argv, patterns) {
  if (helpRequested(argv, USAGE)) return 0;
  const opts = parseArgs(argv);
  const scan = require('./scan');
  const secretRules = (patterns || scan.loadPatterns()).filter(p => /^secret(?:-|$)/.test(p.id))
    .map(p => ({ ...p, exts: '*' })); // a key is a key in any file type

  const args = ['log', '-p', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=AM',
    '--format=%x00%H%x01%ad%x01%an', '--date=short'];
  if (opts.allRefs) args.push('--all');
  if (opts.since) args.push(`${opts.since}..HEAD`);
  let log;
  try {
    log = execFileSync('git', args, { encoding: 'utf8', maxBuffer: MAX_BUFFER, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    process.stderr.write(`secure-coding: cannot read git history (${(e.stderr || e.message || '').toString().trim().split('\n')[0]})\n`);
    return 1;
  }

  // One finding per (file, rule, masked text): the commit that introduced it.
  // git log runs newest first, so the last one seen is the oldest.
  const found = new Map();
  for (const c of commitsAdded(log)) {
    const text = c.added.map(a => a.text).join('\n');
    const hits = scan.matchContent(text, c.file, secretRules);
    for (const h of hits) {
      const src = c.added[h.line - 1];
      const key = `${c.file}|${h.id}|${h.snippet}`;
      found.set(key, {
        id: h.id, severity: h.severity, file: c.file, line: src ? src.line : 0,
        commit: c.commit, date: c.date, author: c.author, snippet: h.snippet,
      });
    }
  }

  // Still in the current tree, or only in history?
  const results = [...found.values()];
  for (const r of results) {
    try {
      const now = execFileSync('git', ['show', `HEAD:${r.file}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: MAX_BUFFER });
      const hits = scan.matchContent(now, r.file, secretRules);
      r.stillPresent = hits.some(h => h.id === r.id && h.snippet === r.snippet);
    } catch { r.stillPresent = false; }
  }
  results.sort((a, b) => (a.date + a.file).localeCompare(b.date + b.file));

  if (opts.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
  } else if (results.length === 0) {
    process.stdout.write('secure-coding: no secrets found in history\n');
  } else {
    process.stdout.write(`Secrets found in git history (${results.length}):\n\n`);
    for (const r of results) {
      process.stdout.write(`  [${r.severity.toUpperCase()}] ${r.id}  ${r.file}:${r.line}  ${r.commit.slice(0, 10)} ${r.date} ${r.author}${r.stillPresent ? '  (still in HEAD)' : '  (removed, still in history)'}\n`);
      process.stdout.write(`    > ${r.snippet.slice(0, 100)}\n`);
    }
    process.stdout.write('\nRotate every one of these: deleting the line does not remove it from clones.\n'
      + 'Then purge history (git filter-repo) only if the repository has not been shared.\n');
  }
  return results.length ? 2 : 0;
}

if (require.main === module) process.exit(run(process.argv.slice(2)));

module.exports = { run, commitsAdded };
