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

const DIR = path.resolve(__dirname, '..');
const STATE = process.env.SECURE_CODING_STATE || path.join(DIR, 'checks', 'findings.jsonl');
const FIXES = path.join(DIR, 'checks', 'fixes.md');

const args = process.argv.slice(2);
const APPLY = args.includes('--apply') || args.includes('--print');
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

const AUTOFIX_RULES = {
  'weak-rng': [
    {
      regex: /Math\.random\s*\(\)/g,
      replace: "require('crypto').randomBytes(16).toString('hex')",
    },
  ],
  'set-hide-error': [
    {
      regex: /set\s+\+e/g,
      replace: 'set -euo pipefail',
    },
  ],
  'jwt-no-verify': [
    {
      regex: /verify\s*=\s*False/g,
      replace: 'verify=True',
    },
    {
      regex: /verifySignature\s*:\s*false/g,
      replace: 'verifySignature: true',
    },
  ],
  'llm-unbounded-tokens': [
    {
      regex: /(client|openai|anthropic)\.(chat|completions|messages)\.create\s*\(([^)]+)\)/g,
      replace: (match, p1, p2, p3) => {
        if (p3.includes('max_tokens') || p3.includes('maxOutputTokens')) return match;
        return `${p1}.${p2}.create(${p3.trim()}, max_tokens=1000)`;
      },
    },
  ],
  'sbd-legacy-tls': [
    {
      regex: /PROTOCOL_TLSv1(_[01])?/g,
      replace: 'PROTOCOL_TLS_CLIENT',
    },
    {
      regex: /min_version\s*=\s*ssl\.TLSVersion\.TLSv1(_[01])?/g,
      replace: 'min_version=ssl.TLSVersion.TLSv1_3',
    },
  ],
  'iot-debug-interface': [
    {
      regex: /(DEBUG_UART|ENABLE_JTAG|CONFIG_BOOT_SWD)\s*[:=]\s*(1|true|TRUE|enabled)/g,
      replace: '$1 = false',
    },
    {
      regex: /(#define\s+(?:DEBUG_UART|ENABLE_JTAG|CONFIG_BOOT_SWD)\s+)1/g,
      replace: '$1 0',
    },
  ],
  'sbd-missing-timeout': [
    {
      regex: /(requests\.(?:get|post|put|delete|patch)\s*\([^)]+)(\))/g,
      replace: (match, p1, p2) => {
        if (p1.includes('timeout')) return match;
        return `${p1}, timeout=10.0${p2}`;
      },
    },
  ],
};

function applyAutofix(file, ruleId, dryRun) {
  if (!fs.existsSync(file)) return false;
  const rules = AUTOFIX_RULES[ruleId];
  if (!rules) return false;

  let content = fs.readFileSync(file, 'utf8');
  let modified = content;

  for (const r of rules) {
    if (typeof r.replace === 'function') {
      modified = modified.replace(r.regex, r.replace);
    } else {
      modified = modified.replace(r.regex, r.replace);
    }
  }

  if (modified !== content) {
    if (!dryRun) {
      fs.writeFileSync(file, modified);
      console.log(`✅ [Autofix Applied] ${ruleId} -> ${path.relative(process.cwd(), file)}`);
    } else {
      console.log(`🔍 [Autofix Dry-Run] ${ruleId} -> ${path.relative(process.cwd(), file)}`);
    }
    return true;
  }
  return false;
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

  const isDryRun = args.includes('--dry-run');
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
