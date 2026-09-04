#!/usr/bin/env node
// The five security frontiers, as data. Shared by `gate.js --grill` and the
// MCP tool so the two can never drift from each other or from
// checks/secure-grilling.md.
'use strict';

// Each frontier names the Done Gate question it pre-answers, so a decision
// settled here is the same sentence checked at commit time.
const FRONTIERS = [
  {
    id: 'identity',
    title: 'Identity & Boundary',
    gate: 'authorization',
    domains: ['api', 'auth', 'llm'],
    questions: [
      {
        q: 'Who calls this?',
        options: ['Authenticated user (Recommended — assume auth until told otherwise)',
                  'Internal service or background job',
                  'Anonymous public'],
        why: 'Deny by default. A public endpoint should be a decision, not an omission.',
      },
      {
        q: 'How is that identity proven?',
        options: ['Session cookie + CSRF token, or a bearer JWT validated for signature, exp, aud and iss (Recommended)',
                  'mTLS or a signed API key for service-to-service',
                  'A caller-supplied user id'],
        why: 'A caller-supplied id is not identity; it is a request parameter.',
      },
    ],
  },
  {
    id: 'tenancy',
    title: 'Tenancy & Ownership',
    gate: 'ownership',
    domains: ['api', 'auth', 'storage'],
    questions: [
      {
        q: 'Can caller A reach caller B\'s row? Answer at the query level.',
        options: ['Scope in the query: WHERE id = $1 AND org_id = $2, or Row-Level Security (Recommended)',
                  'Fetch by id, then compare owner in application code',
                  'No scoping — every caller sees every row'],
        why: 'Fetch-then-compare is a TOCTOU window and leaks existence through timing and error codes.',
      },
    ],
  },
  {
    id: 'data',
    title: 'Data Classification & Storage',
    gate: 'taint',
    domains: ['storage', 'api', 'llm'],
    questions: [
      {
        q: 'Highest sensitivity this handles?',
        options: ['PII or credentials — encrypt at rest, envelope/KMS for the top tier (Recommended if unsure)',
                  'Internal only',
                  'Public'],
        why: 'Classifying too high costs encryption; too low costs a breach notification.',
      },
      {
        q: 'Where does each request value end up — query, file path, shell, outbound URL, template?',
        options: ['Parameterized query only, no file or shell sink (Recommended)',
                  'Reaches a file path or outbound URL — needs canonicalisation or an allowlist',
                  'Reaches a shell or template'],
        why: 'Name the sink now; the scanner only sees it when source and sink share a line.',
      },
    ],
  },
  {
    id: 'failure',
    title: 'Resilience & Failure Direction',
    gate: 'failure-direction',
    domains: ['api', 'auth', 'storage', 'llm'],
    questions: [
      {
        q: 'If the auth service, session store or database times out — deny or allow?',
        options: ['Deny: return 503 and refuse the request (Recommended)',
                  'Allow degraded access'],
        why: 'The exception path is the one an attacker aims for. It must be the safest path, not the weakest.',
      },
      {
        q: 'Rate limits or quotas at the perimeter?',
        options: ['Per-user and per-IP limits on auth and expensive routes (Recommended)',
                  'None yet — accepted risk'],
        why: 'Without a limit, credential stuffing and enumeration are free.',
      },
    ],
  },
  {
    id: 'agency',
    title: 'Action Irreversibility & Agency',
    gate: null,
    domains: ['llm', 'api'],
    questions: [
      {
        q: 'Is this action reversible?',
        options: ['Read-only (Recommended where it suffices)',
                  'State-changing but reversible',
                  'Irreversible — deletion, payment, email, external write'],
        why: 'Irreversible actions need confirmation, step-up auth, or an idempotency key.',
      },
      {
        q: 'If an LLM can call this, what is the blast radius when the model is prompt-injected into calling it with attacker-chosen arguments?',
        options: ['Bounded: read-only, or scoped to the caller\'s own data (Recommended)',
                  'Unbounded: can act on arbitrary records or reach the network'],
        why: 'Excessive agency is the LLM failure mode that turns a prompt into an action.',
      },
    ],
  },
];

const DOMAINS = ['api', 'auth', 'storage', 'llm'];

function forDomain(domain) {
  if (!domain || domain === 'all') return FRONTIERS;
  return FRONTIERS.filter(f => f.domains.includes(domain));
}

// Render as the round an agent should put to the user: numbered, with a
// recommended secure default on each.
function render(domain) {
  const picked = forDomain(domain);
  const lines = [];
  lines.push(`Security frontier${domain && domain !== 'all' ? ` — ${domain}` : ''}`);
  lines.push('');
  lines.push('Ask these in ONE round. Number them, recommend the secure default, then wait.');
  lines.push('Look facts up yourself — only unsettled decisions go to the user.');
  lines.push('');
  let n = 0;
  for (const f of picked) {
    lines.push(`## ${f.title}${f.gate ? `  → pre-answers gate: ${f.gate}` : ''}`);
    for (const item of f.questions) {
      n++;
      lines.push('');
      lines.push(`❓ **Q${n} — ${f.title}**: ${item.q}`);
      item.options.forEach((o, i) => lines.push(`   ${String.fromCharCode(65 + i)}. ${o}`));
      lines.push(`➡️ ${item.why}`);
    }
    lines.push('');
  }
  lines.push('When settled, record each decision so the Done Gate is pre-answered:');
  lines.push('  node hooks/gate.js --answer <question> "<what enforces it>"');
  return lines.join('\n');
}

module.exports = { FRONTIERS, DOMAINS, forDomain, render };

// The file has a shebang and is executable, so it has to work when run
// directly rather than exiting silently. `gate.js --grill` and the MCP tool
// both render the same data through render()/forDomain().
if (require.main === module) {
  const { helpRequested } = require('./config');
  const args = process.argv.slice(2);
  const USAGE = `Usage: node hooks/frontiers.js [domain] [--json]

Prints the security questions to settle before writing a route, auth change,
data model, upload, outbound call or LLM tool.
  [domain]  one of: ${DOMAINS.join(', ')} (default: all five)
  --json    machine-readable output`;
  if (helpRequested(args, USAGE)) process.exit(0);

  const domain = args.find(a => !a.startsWith('-'));
  if (domain && !DOMAINS.includes(domain)) {
    process.stderr.write(`frontiers.js: unknown domain '${domain}'\n\n${USAGE}\n`);
    process.exit(64); // EX_USAGE
  }
  // render() takes the domain label and resolves it itself; passing the
  // resolved array made the heading read "[object Object],[object Object]".
  if (args.includes('--json')) console.log(JSON.stringify(forDomain(domain), null, 2));
  else console.log(render(domain));
}
