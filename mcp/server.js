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
const SBOM_SCRIPT = path.join(ROOT_DIR, 'hooks', 'sbom.js');
const SUMMARY_SCRIPT = path.join(ROOT_DIR, 'hooks', 'summary.js');

const SERVER_NAME = 'secure-coding-mcp';
const SERVER_VERSION = '2.1.0';
const PROTOCOL_VERSION = '2024-11-05';

const TOOLS = [
  {
    name: 'secure_code_scan',
    description: 'Scans source code or files against 356+ OWASP, Secure by Design, IoT, LLM, and Shannon entropy secret patterns. Returns precise line numbers, code snippets, and remediation guidance.',
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
    description: 'Lints source code against 22 universal Clean Code standards (magic numbers, multi-responsibility functions, swallowed errors, boolean flag parameters).',
    inputSchema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          description: 'Path to the source code file to lint.',
        },
        listRules: {
          type: 'boolean',
          description: 'List all 22 clean code standards with explanations.',
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
    name: 'security_summary',
    description: 'Returns a one-line status check of open versus resolved security findings in the workspace.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

const { loadPatterns, matchContent, fixBlock } = require(SCAN_SCRIPT);

function handleToolCall(name, args) {
  args = args || {};

  switch (name) {
    case 'secure_code_scan': {
      if (args.code) {
        const patterns = loadPatterns();
        const hits = matchContent(args.code, args.filename || 'sample.js', patterns);
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
      else if (args.files && args.files.length) scanArgs.push('--files', ...args.files);

      const res = spawnSync('node', [SCAN_SCRIPT, ...scanArgs], {
        encoding: 'utf8',
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

      const res = spawnSync('node', [FIX_SCRIPT, ...fixArgs], { encoding: 'utf8' });
      return { content: [{ type: 'text', text: res.stdout || res.stderr || 'No fixes required.' }] };
    }

    case 'security_dependency_audit': {
      const res = spawnSync('node', [AUDIT_SCRIPT], {
        cwd: args.targetDir || process.cwd(),
        encoding: 'utf8',
      });
      return { content: [{ type: 'text', text: res.stdout || res.stderr || 'Audit completed.' }] };
    }

    case 'clean_code_lint': {
      if (args.listRules) {
        const res = spawnSync('node', [CLEAN_SCRIPT, '--list'], { encoding: 'utf8' });
        return { content: [{ type: 'text', text: res.stdout || res.stderr }] };
      }
      if (!args.file) {
        return { content: [{ type: 'text', text: 'Error: file parameter is required for clean_code_lint' }], isError: true };
      }
      const res = spawnSync('node', [CLEAN_SCRIPT, '--file', args.file], { encoding: 'utf8' });
      return { content: [{ type: 'text', text: res.stdout || res.stderr || '✅ No clean code violations found.' }] };
    }

    case 'generate_ai_sbom': {
      const sbomArgs = ['--format', args.format || 'cyclonedx'];
      if (args.includeAi !== false) sbomArgs.push('--ai');
      if (args.includeVex !== false) sbomArgs.push('--vex');
      if (args.outFile) sbomArgs.push('--out', args.outFile);

      const res = spawnSync('node', [SBOM_SCRIPT, ...sbomArgs], { encoding: 'utf8' });
      return { content: [{ type: 'text', text: res.stdout || res.stderr || 'SBOM generated successfully.' }] };
    }

    case 'security_summary': {
      const res = spawnSync('node', [SUMMARY_SCRIPT], { encoding: 'utf8' });
      return { content: [{ type: 'text', text: (res.stdout || res.stderr || 'Status unknown.').trim() }] };
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
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {
            tools: {},
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
      const toolArgs = params.arguments || {};
      const result = handleToolCall(toolName, toolArgs);
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
            code: -32601,
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

  rl.on('line', (line) => {
    line = line.trim();
    if (!line) return;

    try {
      const message = JSON.parse(line);
      const response = processMessage(message);
      if (response) {
        process.stdout.write(JSON.stringify(response) + '\n');
      }
    } catch (e) {
      const errResponse = {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32700,
          message: 'Parse error: invalid JSON',
        },
      };
      process.stdout.write(JSON.stringify(errResponse) + '\n');
    }
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { startServer, processMessage, handleToolCall, TOOLS };
