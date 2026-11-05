#!/usr/bin/env node
// ==============================================================================
// 🛡️ secure-coding: Native Model Context Protocol (MCP) Stdio Server
// Exposes proactive secure coding, AI-SBOM, VEX, clean code, and dependency audit
// tools directly to Antigravity, Claude Desktop, Cursor, and MCP-enabled IDEs.
// Zero external dependencies (pure Node.js standard library).
// ==============================================================================
'use strict';

const readline = require('readline');
const path = require('path');
const { spawnSync } = require('child_process');
const fs = require('fs');

const ROOT_DIR = path.resolve(__dirname, '..');
const SCAN_SCRIPT = path.join(ROOT_DIR, 'hooks', 'scan.js');
const FIX_SCRIPT = path.join(ROOT_DIR, 'hooks', 'fix.js');
const AUDIT_SCRIPT = path.join(ROOT_DIR, 'hooks', 'audit.js');
const CLEAN_SCRIPT = path.join(ROOT_DIR, 'hooks', 'clean.js');
const GATE_SCRIPT = path.join(ROOT_DIR, 'hooks', 'gate.js');
const SBOM_SCRIPT = path.join(ROOT_DIR, 'hooks', 'sbom.js');
const SUMMARY_SCRIPT = path.join(ROOT_DIR, 'hooks', 'summary.js');
const DEPS_SCRIPT = path.join(ROOT_DIR, 'hooks', 'deps.js');
const HISTORY_SCRIPT = path.join(ROOT_DIR, 'hooks', 'history.js');
const SERVE_SCRIPT = path.join(ROOT_DIR, 'hooks', 'serve.js');
const FIXES_FILE = path.join(ROOT_DIR, 'checks', 'fixes.md');
const CHECKS_DIR = path.join(ROOT_DIR, 'checks');

const SERVER_NAME = 'secure-coding-mcp';
// Read from package.json rather than a second literal: a hardcoded copy
// silently reports a stale version to every client after a release bump.
const SERVER_VERSION = require(path.join(ROOT_DIR, 'package.json')).version;

// JSON-RPC 2.0 reserved error codes (spec section 5.1). Only the ones this
// server actually returns are declared.
const JSONRPC_PARSE_ERROR = -32700;
const JSONRPC_INVALID_REQUEST = -32600;
const JSONRPC_METHOD_NOT_FOUND = -32601;
const JSONRPC_INTERNAL_ERROR = -32603;
const JSONRPC_INVALID_PARAMS = -32602;
// Protocol versions this server can speak. initialize answers with the
// client's version when it is one of these, else the newest.
const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

// Every child process gets a deadline. Without one, a hung package manager in
// security_dependency_audit blocked the server — and every later request —
// forever. Audit runs one tool per ecosystem, so it gets longer.
const CHILD_TIMEOUT_MS = Number(process.env.SECURE_CODING_MCP_TIMEOUT_MS) || 120000;
const AUDIT_TIMEOUT_MS = Number(process.env.SECURE_CODING_MCP_AUDIT_TIMEOUT_MS) || 300000;

function run(script, args, opts = {}) {
  const res = spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8', timeout: CHILD_TIMEOUT_MS, maxBuffer: 32 * 1024 * 1024, ...opts,
  });
  if (res.error && res.error.code === 'ETIMEDOUT') {
    res.stderr = `${res.stderr || ''}\n${path.basename(script)} timed out after ${Math.round((opts.timeout || CHILD_TIMEOUT_MS) / 1000)}s`;
    res.timedOut = true;
  } else if (res.error) {
    res.stderr = `${res.stderr || ''}\n${path.basename(script)} could not run: ${res.error.message}`;
  }
  return res;
}

const TOOLS = [
  {
    name: 'secure_code_scan',
    description: 'Scans source code or files against 516 OWASP, Secure by Design, IoT, LLM, and Shannon entropy secret patterns. Returns precise line numbers, code snippets, and remediation guidance.',
    inputSchema: {
      type: 'object',
      properties: {
        code: {
          type: 'string',
          description: 'Source code content to scan directly.',
        },
        files: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of specific file paths to scan.',
        },
        staged: {
          type: 'boolean',
          description: 'Scan only Git staged files (runs in <20ms).',
        },
        diff: {
          type: 'boolean',
          description: 'Scan modified working tree files.',
        },
      },
    },
  },
  {
    name: 'secure_code_autofix',
    description: 'Retrieves remediation guidance or applies in-place automated refactoring for detected vulnerabilities (weak RNG, missing timeouts, legacy TLS, IoT debug interfaces).',
    inputSchema: {
      type: 'object',
      properties: {
        patternId: {
          type: 'string',
          description: 'Optional pattern ID to get specific Wrong vs Right code guidance.',
        },
        apply: {
          type: 'boolean',
          description: 'Apply deterministic code fixes in-place.',
        },
        dryRun: {
          type: 'boolean',
          description: 'Preview unified diff of proposed fixes without modifying files.',
        },
      },
    },
  },
  {
    name: 'security_dependency_audit',
    description: 'Audits third-party dependencies across 9 package ecosystems (npm, pnpm, yarn, pip, cargo, go, dotnet, composer, bundler) and flags known security advisories.',
    inputSchema: {
      type: 'object',
      properties: {
        targetDir: {
          type: 'string',
          description: 'Optional path to the project root containing lockfiles.',
        },
      },
    },
  },
  {
    name: 'clean_code_lint',
    description: 'Lints source code against 14 universal Clean Code standards (magic numbers, multi-responsibility functions, swallowed errors, boolean flag parameters).',
    inputSchema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          description: 'Path to a single source file to lint.',
        },
        files: {
          type: 'array',
          items: { type: 'string' },
          description: 'Several file paths to lint in one pass.',
        },
        all: {
          type: 'boolean',
          description: 'Lint every tracked file in the repository.',
        },
        listRules: {
          type: 'boolean',
          description: 'List all 14 clean code standards with explanations.',
        },
      },
    },
  },
  {
    name: 'generate_ai_sbom',
    description: 'Generates a Software Bill of Materials (SBOM) conforming to BSI 7 AI Clusters and ACSC/CISA VEX vulnerability exploitability states.',
    inputSchema: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          enum: ['cyclonedx', 'spdx'],
          default: 'cyclonedx',
          description: 'Output SBOM specification format.',
        },
        includeAi: {
          type: 'boolean',
          default: true,
          description: 'Include BSI 7 AI Information Clusters (model parameters, datasets, KPIs).',
        },
        includeVex: {
          type: 'boolean',
          default: true,
          description: 'Include ACSC/CISA VEX exploitability status assessments.',
        },
        outFile: {
          type: 'string',
          description: 'Optional file path to save the generated SBOM manifest.',
        },
      },
    },
  },
  {
    name: 'get_security_frontier',
    description: 'Returns the security questions to put to the user BEFORE writing a route, auth change, data model, upload, outbound call or LLM tool. Each frontier pre-answers a Done Gate question, so the decision settled here is the one verified at commit time. Ask the whole round at once with the recommended secure default for each.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: {
          type: 'string',
          enum: ['api', 'auth', 'storage', 'llm', 'all'],
          description: 'Which frontier subset applies. Omit for all five.',
        },
      },
    },
  },
  {
    name: 'record_security_decision',
    description: 'Records one Done Gate answer — what actually enforces a control. Use after settling a frontier question, so the decision is captured without shell access. Rejects filler like "yes" or "ok": name the guard, predicate or test, or answer "N/A — <why>".',
    inputSchema: {
      type: 'object',
      properties: {
        question: {
          type: 'string',
          enum: ['ownership', 'authorization', 'taint', 'failure-direction'],
          description: 'Which control this answers.',
        },
        answer: { type: 'string', description: 'What enforces it, in concrete terms.' },
      },
      required: ['question', 'answer'],
    },
  },
  {
    name: 'check_done_gate',
    description: 'Reports which Done Gate questions are answered and which remain, and whether the staged code needs a review at all. Use before declaring work complete.',
    inputSchema: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          enum: ['status', 'adr'],
          description: 'status (default) lists what remains; adr renders the settled answers as an Architecture Decision Record.',
        },
      },
    },
  },
  {
    name: 'security_summary',
    description: 'Returns a one-line status check of open versus resolved security findings in the workspace.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'explain_finding',
    description: 'Explains one finding id (e.g. sql-concat, taint-ssrf, dep-not-found): why it is dangerous, the wrong and right code, what to watch for, and its CWE / OWASP mapping.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'The finding or pattern id, as printed by a scan.' } },
      required: ['id'],
    },
  },
  {
    name: 'check_dependencies',
    description: 'Checks dependencies a change ADDS to package.json, requirements*.txt or pyproject.toml against npm/PyPI: packages that do not exist (hallucinated names), packages published in the last 30 days, and install scripts. Call it before installing anything an AI suggested.',
    inputSchema: {
      type: 'object',
      properties: {
        file: { type: 'string', description: 'One manifest to check against HEAD. Omit to check every changed manifest.' },
        staged: { type: 'boolean', description: 'Compare the git index with HEAD instead of the working tree.' },
      },
    },
  },
  {
    name: 'scan_git_history',
    description: 'Looks for secrets in lines added by past commits — keys that were deleted from the code but are still in every clone and must be rotated.',
    inputSchema: {
      type: 'object',
      properties: {
        since: { type: 'string', description: 'Only commits after this revision (e.g. origin/main).' },
        allRefs: { type: 'boolean', description: 'Every branch and tag, not just the current branch.' },
      },
    },
  },
  {
    name: 'open_dashboard',
    description: 'Starts the local security dashboard (React, 3D views of the findings, live rescan) and returns its URL. It listens on 127.0.0.1 only and the URL carries a one-time token; give the link to the user rather than fetching it.',
    inputSchema: {
      type: 'object',
      properties: { open: { type: 'boolean', description: 'Also open it in the default browser (default false).' } },
    },
  }
];

const { loadPatterns, matchContent, fixBlock } = require(SCAN_SCRIPT);

// --- resources: the guidance itself, readable by the agent on demand ---
// secure-coding://skill            SKILL.md
// secure-coding://checks/<name>    checks/<name>.md (threat model, LLM top 10, ...)
// secure-coding://fix/<id>         one fix block from checks/fixes.md
function fixIds() {
  try {
    return fs.readFileSync(FIXES_FILE, 'utf8').split(/^## /m).slice(1)
      .map(part => part.split('\n')[0].trim()).filter(id => id && !id.startsWith('#'));
  } catch { return []; }
}

function listResources() {
  const out = [{ uri: 'secure-coding://skill', name: 'SKILL.md', description: 'How the skill works: trigger groups, workflow, tools.', mimeType: 'text/markdown' }];
  try {
    for (const f of fs.readdirSync(CHECKS_DIR).filter(n => n.endsWith('.md')).sort()) {
      const name = f.replace(/\.md$/, '');
      if (name === 'fixes') continue;
      out.push({ uri: `secure-coding://checks/${name}`, name: `checks/${f}`, mimeType: 'text/markdown' });
    }
  } catch { /* no checks directory */ }
  for (const id of fixIds()) out.push({ uri: `secure-coding://fix/${id}`, name: `fix: ${id}`, mimeType: 'text/markdown' });
  return out;
}

function readResource(uri) {
  if (uri === 'secure-coding://skill') {
    try { return fs.readFileSync(path.join(ROOT_DIR, 'SKILL.md'), 'utf8'); } catch { return null; }
  }
  let m = uri.match(/^secure-coding:\/\/checks\/([a-z0-9-]+)$/);
  if (m) {
    try { return fs.readFileSync(path.join(CHECKS_DIR, `${m[1]}.md`), 'utf8'); } catch { return null; }
  }
  m = uri.match(/^secure-coding:\/\/fix\/([A-Za-z0-9_-]+)$/);
  if (m) return fixBlock(m[1]) || null;
  return null;
}

// --- prompts: reusable starting points a client can offer the user ---
const PROMPTS = [
  {
    name: 'secure_design_review',
    description: 'Before writing a feature: ask the five security frontiers (identity, tenancy, data classification, failure direction, irreversibility) with a recommended secure default for each.',
    arguments: [{ name: 'feature', description: 'What is about to be built.', required: true }],
    build: a => {
      const { render } = require(path.join(ROOT_DIR, 'hooks', 'frontiers.js'));
      return `I am about to build: ${a.feature || '(not described)'}\n\nBefore any code, ask me these in one round, each with your recommended secure default, then wait for my answers:\n\n${render('all')}`;
    },
  },
  {
    name: 'fix_finding',
    description: 'Fix one scanner finding properly, using its remediation block, then re-scan.',
    arguments: [
      { name: 'id', description: 'Finding id, e.g. sql-concat.', required: true },
      { name: 'file', description: 'File the finding is in.', required: false },
    ],
    build: a => `Fix the ${a.id} finding${a.file ? ` in ${a.file}` : ''}. Follow this guidance exactly — the Right form, not a suppression:\n\n${fixBlock(String(a.id || '')) || '(no fix block found for that id)'}\n\nThen re-run the scan on the file and confirm the finding is gone.`,
  },
];

function handleToolCall(name, args) {
  args = args || {};

  switch (name) {
    case 'record_security_decision': {
      // Shell out rather than reimplement: gate.js owns the filler rejection,
      // the N/A rule and the per-commit expiry. A second copy would drift.
      const res = run(GATE_SCRIPT, ['--answer', String(args.question || ''), String(args.answer || '')]);
      const text = (res.stdout || '') + (res.stderr || '');
      return { content: [{ type: 'text', text: text.trim() || 'No output.' }], isError: res.status !== 0 };
    }

    case 'check_done_gate': {
      const mode = args.format === 'adr' ? '--adr' : '--status';
      const res = run(GATE_SCRIPT, [mode]);
      const text = (res.stdout || '') + (res.stderr || '');
      return { content: [{ type: 'text', text: text.trim() || 'No output.' }] };
    }

    case 'get_security_frontier': {
      const { render, DOMAINS } = require(path.join(__dirname, '..', 'hooks', 'frontiers.js'));
      const domain = args.domain;
      if (domain && domain !== 'all' && !DOMAINS.includes(domain)) {
        return { content: [{ type: 'text', text: `Unknown domain '${domain}'. One of: ${DOMAINS.join(', ')}, all` }], isError: true };
      }
      return { content: [{ type: 'text', text: render(domain) }] };
    }

    case 'secure_code_scan': {
      if (args.code !== undefined && args.code !== null && args.code !== '') {
        const patterns = loadPatterns();
        const hits = matchContent(String(args.code), String(args.filename || 'sample.js'), patterns);
        if (hits.length === 0) {
          return { content: [{ type: 'text', text: '✅ Code is clean. Zero security findings.' }] };
        }
        const blocks = hits.map(h => {
          const loc = h.line ? ` (Line ${h.line})` : '';
          const snippet = h.snippet ? `\n> ${h.snippet.slice(0, 120)}` : '';
          const block = fixBlock(h.id);
          if (block) {
            const formatted = block.replace(`## ${h.id}`, `## ${h.id}${loc} [${(h.severity || 'medium').toUpperCase()}]`);
            return `${formatted}${snippet}`;
          }
          return `## ${h.id}${loc} [${(h.severity || 'medium').toUpperCase()}]\n${h.hint || 'Review and fix this security finding.'}${snippet}`;
        }).join('\n\n');

        return { content: [{ type: 'text', text: `Security patterns found (${hits.length}):\n\n${blocks}` }] };
      }

      const scanArgs = [];
      if (args.staged) scanArgs.push('--staged');
      else if (args.diff) scanArgs.push('--diff');
      else if (args.files && args.files.length) scanArgs.push('--files', '--', ...[].concat(args.files).map(String));

      const res = run(SCAN_SCRIPT, scanArgs, {
        env: { ...process.env, SECURE_CODING_REPORT: 'off' },
      });
      const output = res.stdout || res.stderr || (res.status === 0 ? '✅ Code is clean. Zero security findings.' : 'Scan completed.');
      return { content: [{ type: 'text', text: output }], isError: res.status !== 0 && !res.stdout };
    }

    case 'secure_code_autofix': {
      const fixArgs = [];
      if (args.patternId) fixArgs.push('--suggest', args.patternId);
      else if (args.dryRun) fixArgs.push('--dry-run');
      else if (args.apply) fixArgs.push('--apply');

      const res = run(FIX_SCRIPT, fixArgs);
      return { content: [{ type: 'text', text: res.stdout || res.stderr || 'No fixes required.' }] };
    }

    case 'security_dependency_audit': {
      const res = run(AUDIT_SCRIPT, [], {
        cwd: args.targetDir ? String(args.targetDir) : process.cwd(),
        timeout: AUDIT_TIMEOUT_MS,
      });
      return { content: [{ type: 'text', text: res.stdout || res.stderr || 'Audit completed.' }] };
    }

    case 'clean_code_lint': {
      if (args.listRules) {
        const res = run(CLEAN_SCRIPT, ['--list']);
        return { content: [{ type: 'text', text: res.stdout || res.stderr }] };
      }
      // Mirror the CLI: one file, several files, or the whole repository.
      // The tool previously accepted only `file`, so an agent had to call it
      // once per path to do what `--all` does in a single pass.
      const cleanArgs = [];
      if (args.all) cleanArgs.push('--all');
      else if (Array.isArray(args.files) && args.files.length > 0) cleanArgs.push(...args.files.map(String));
      else if (args.file) cleanArgs.push(String(args.file));
      else {
        return { content: [{ type: 'text', text: 'Error: clean_code_lint needs one of file, files or all' }], isError: true };
      }
      const res = run(CLEAN_SCRIPT, cleanArgs);
      return { content: [{ type: 'text', text: res.stdout || res.stderr || '✅ No clean code violations found.' }] };
    }

    case 'generate_ai_sbom': {
      const sbomArgs = ['--format', args.format || 'cyclonedx'];
      if (args.includeAi !== false) sbomArgs.push('--ai');
      if (args.includeVex !== false) sbomArgs.push('--vex');
      if (args.outFile) sbomArgs.push('--out', args.outFile);

      const res = run(SBOM_SCRIPT, sbomArgs);
      return { content: [{ type: 'text', text: res.stdout || res.stderr || 'SBOM generated successfully.' }] };
    }

    case 'security_summary': {
      const res = run(SUMMARY_SCRIPT, []);
      return { content: [{ type: 'text', text: (res.stdout || res.stderr || 'Status unknown.').trim() }] };
    }

    case 'explain_finding': {
      const id = String(args.id || '').trim();
      const block = id && fixBlock(id);
      if (!block) {
        return { content: [{ type: 'text', text: `No explanation for "${id}". Ids are the names a scan prints, e.g. sql-concat or taint-ssrf.` }], isError: true };
      }
      return { content: [{ type: 'text', text: block }] };
    }

    case 'check_dependencies': {
      const depArgs = args.file ? ['--file', String(args.file)] : args.staged ? ['--staged'] : [];
      const res = run(DEPS_SCRIPT, depArgs);
      return { content: [{ type: 'text', text: (res.stdout || res.stderr || 'No output.').trim() }], isError: res.status !== 0 && res.status !== 2 };
    }

    case 'scan_git_history': {
      const hArgs = [];
      if (args.since) hArgs.push('--since', String(args.since));
      if (args.allRefs) hArgs.push('--all-refs');
      const res = run(HISTORY_SCRIPT, hArgs, { timeout: AUDIT_TIMEOUT_MS });
      return { content: [{ type: 'text', text: (res.stdout || res.stderr || 'No output.').trim() }], isError: res.status !== 0 && res.status !== 2 };
    }

    case 'open_dashboard': {
      // serve.js --background starts a detached server (it stops itself after
      // an hour without requests) and prints its URL.
      const res = run(SERVE_SCRIPT, ['--background', ...(args.open ? [] : ['--no-open'])], { timeout: 20000 });
      const url = (res.stdout || '').trim();
      if (res.status !== 0 || !/^http:\/\/127\.0\.0\.1:\d+\//.test(url)) {
        return { content: [{ type: 'text', text: (res.stderr || 'The dashboard did not start.').trim() }], isError: true };
      }
      return { content: [{ type: 'text', text: `Dashboard: ${url}\nLocal only. The token in the link is the key to it — share it with the user, not elsewhere. It stops after an hour without use.` }] };
    }

    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  }
}

function processMessage(message) {
  if (!message || typeof message !== 'object') return null;

  const id = message.id;
  const method = message.method;
  const params = message.params || {};

  // Handle standard JSON-RPC 2.0 / MCP methods
  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: SUPPORTED_PROTOCOL_VERSIONS.includes(params.protocolVersion)
            ? params.protocolVersion : PROTOCOL_VERSION,
          capabilities: {
            tools: {},
            resources: {},
            prompts: {},
          },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION,
          },
        },
      };

    case 'notifications/initialized':
      return null; // Notifications don't receive responses

    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };

    case 'resources/list':
      return { jsonrpc: '2.0', id, result: { resources: listResources() } };

    case 'resources/read': {
      const text = readResource(String(params.uri || ''));
      if (text === null) {
        return { jsonrpc: '2.0', id, error: { code: JSONRPC_INVALID_PARAMS, message: `Unknown resource: ${params.uri}` } };
      }
      return { jsonrpc: '2.0', id, result: { contents: [{ uri: params.uri, mimeType: 'text/markdown', text }] } };
    }

    case 'prompts/list':
      return { jsonrpc: '2.0', id, result: { prompts: PROMPTS.map(({ build, ...p }) => p) } };

    case 'prompts/get': {
      const p = PROMPTS.find(x => x.name === params.name);
      if (!p) return { jsonrpc: '2.0', id, error: { code: JSONRPC_INVALID_PARAMS, message: `Unknown prompt: ${params.name}` } };
      return { jsonrpc: '2.0', id, result: { description: p.description, messages: [{ role: 'user', content: { type: 'text', text: p.build(params.arguments || {}) } }] } };
    }

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          tools: TOOLS,
        },
      };

    case 'tools/call': {
      const toolName = params.name;
      const toolArgs = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
      // A tool that throws is a tool error, reported in the result with the
      // request's id (MCP: isError). It used to escape to the line handler and
      // come back as "Parse error" with id null, so the client never got an
      // answer to its request and waited forever.
      let result;
      try {
        result = handleToolCall(toolName, toolArgs);
      } catch (e) {
        result = { content: [{ type: 'text', text: `${toolName} failed: ${e && e.message ? e.message : String(e)}` }], isError: true };
      }
      return {
        jsonrpc: '2.0',
        id,
        result,
      };
    }

    default:
      if (id !== undefined) {
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: JSONRPC_METHOD_NOT_FOUND,
            message: `Method not found: ${method}`,
          },
        };
      }
      return null;
  }
}

function startServer() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  const send = obj => process.stdout.write(JSON.stringify(obj) + '\n');
  rl.on('line', (line) => {
    line = line.trim();
    if (!line) return;

    let message;
    try {
      message = JSON.parse(line);
    } catch (e) {
      send({ jsonrpc: '2.0', id: null, error: { code: JSONRPC_PARSE_ERROR, message: 'Parse error: invalid JSON' } });
      return;
    }
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      send({ jsonrpc: '2.0', id: null, error: { code: JSONRPC_INVALID_REQUEST, message: 'Invalid request' } });
      return;
    }
    // Only a parse failure is a parse error. Anything else that goes wrong
    // still answers the request it belongs to.
    try {
      const response = processMessage(message);
      if (response) send(response);
    } catch (e) {
      if (message.id !== undefined) {
        send({ jsonrpc: '2.0', id: message.id, error: { code: JSONRPC_INTERNAL_ERROR, message: `Internal error: ${e && e.message ? e.message : String(e)}` } });
      }
    }
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { startServer, processMessage, handleToolCall, TOOLS };
