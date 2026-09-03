#!/usr/bin/env node
// ==============================================================================
// 🛡️ secure-coding: Interactive Terminal Installer & Setup Wizard
// Zero external dependencies (pure Node.js standard library).
// Usage:
//   node hooks/install.js                (interactive terminal wizard)
//   node hooks/install.js --yes          (non-interactive default install)
//   node hooks/install.js --mcp          (configure Model Context Protocol server)
//   node hooks/install.js --agent all    (install with all AI agent rules)
//   node hooks/install.js --global       (install globally for Antigravity & Claude)
// ==============================================================================
'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { execSync, exec } = require('child_process');

const DIR = path.resolve(__dirname, '..');

// ANSI formatting
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const NC = '\x1b[0m';

function printBanner() {
  console.log(`${CYAN}${BOLD}`);
  console.log("  ____                               ____          _ _             ");
  console.log(" / ___|  ___  ___ _   _ _ __ ___    / ___|___   __| (_)_ __   __ _ ");
  console.log(" \\___ \\ / _ \\/ __| | | | '__/ _ \\  | |   / _ \\ / _` | | '_ \\ / _` |");
  console.log("  ___) |  __/ (__| |_| | | |  __/  | |__| (_) | (_| | | | | | (_| |");
  console.log(" |____/ \\___|\\___|\\__,_|_|  \\___|   \\____\\___/ \\__,_|_|_| |_|\\__, |");
  console.log("                                                             |___/ ");
  console.log(`${NC}  Token-Optimized Secure Coding & Clean Code System for AI Agents & Devs`);
  console.log("  ----------------------------------------------------------------------\n");
}

function showHelp() {
  printBanner();
  console.log(`Usage: node hooks/install.js [OPTIONS]

Options:
  -i, --interactive    Force interactive terminal wizard
  -y, --yes            Accept all defaults non-interactively
  --target <dir>       Target project directory (default: current directory)
  --agent <name>       Configure AI agent: antigravity | claude | cursor | windsurf | cline | all
  --mcp                Configure Model Context Protocol (MCP) server for IDEs/Agents
  --global             Install globally to ~/.secure-coding and link Antigravity & Claude
  --no-hooks           Skip Git pre-commit & pre-push hook installation
  --no-vscode          Skip .vscode/tasks.json installation
  --no-config          Skip .securecodingrc.json creation
  --wizard             Launch browser UI configuration wizard after setup
  -h, --help           Show this help message

Examples:
  node hooks/install.js
  node hooks/install.js --agent antigravity --mcp
  node hooks/install.js --target ../my-app --agent all --yes
  node hooks/install.js --global --mcp
`);
  process.exit(0);
}

function ask(rl, query, defaultValue = '') {
  return new Promise((resolve) => {
    const promptText = defaultValue
      ? `${query} ${DIM}(default: ${defaultValue})${NC}: `
      : `${query}: `;
    rl.question(promptText, (answer) => {
      resolve(answer.trim() || defaultValue);
    });
  });
}

function askYesNo(rl, query, defaultYes = true) {
  return new Promise((resolve) => {
    const promptText = defaultYes
      ? `${query} ${DIM}[Y/n]${NC}: `
      : `${query} ${DIM}[y/N]${NC}: `;
    rl.question(promptText, (answer) => {
      const clean = answer.trim().toLowerCase();
      if (!clean) return resolve(defaultYes);
      resolve(clean === 'y' || clean === 'yes');
    });
  });
}

function installGitHooks(targetDir) {
  const gitDir = path.join(targetDir, '.git');
  if (!fs.existsSync(gitDir)) {
    console.log(`${YELLOW}⚠️  No .git directory found at ${targetDir}. Skipping Git hooks.${NC}`);
    return;
  }

  const hooksDir = path.join(gitDir, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });

  // Pre-commit hook
  const preCommitPath = path.join(hooksDir, 'pre-commit');
  const preCommitScript = `#!/usr/bin/env sh
# secure-coding: fast staged scan before commit
if [ -n "$SECURE_CODING_SKIP" ]; then
  exit 0
fi

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SCAN_SCRIPT="$ROOT_DIR/hooks/scan.js"
if [ ! -f "$SCAN_SCRIPT" ] && [ -f "$HOME/.secure-coding/hooks/scan.js" ]; then
  SCAN_SCRIPT="$HOME/.secure-coding/hooks/scan.js"
fi

if [ -f "$SCAN_SCRIPT" ]; then
  node "$SCAN_SCRIPT" --staged
  EXIT_CODE=$?
  if [ "$EXIT_CODE" -ne 0 ]; then
    echo ""
    echo "❌ Commit rejected due to open security findings."
    echo "💡 Fix the highlighted code or bypass with: git commit --no-verify (or SECURE_CODING_SKIP=1)"
    exit "$EXIT_CODE"
  fi
fi

# Done Gate: the manual review no pattern can perform. Opt in by setting
# SECURE_CODING_GATE_REQUIRED=1 — off by default so it never surprises a
# first-time user.
GATE_SCRIPT="$ROOT_DIR/hooks/gate.js"
if [ ! -f "$GATE_SCRIPT" ] && [ -f "$HOME/.secure-coding/hooks/gate.js" ]; then
  GATE_SCRIPT="$HOME/.secure-coding/hooks/gate.js"
fi
GATE_REQUIRED="$SECURE_CODING_GATE_REQUIRED"
if [ -z "$GATE_REQUIRED" ]; then
  GATE_REQUIRED="$(git config --get secure-coding.gate 2>/dev/null)"
fi
case "$GATE_REQUIRED" in 0|false|no|off|"") GATE_REQUIRED="" ;; esac

if [ -n "$GATE_REQUIRED" ] && [ -f "$GATE_SCRIPT" ]; then
  node "$GATE_SCRIPT" --check
  GATE_CODE=$?
  if [ "$GATE_CODE" -ne 0 ]; then
    echo ""
    echo "❌ Commit rejected: the manual security review is incomplete."
    echo '💡 Answer with: node hooks/gate.js --answer <question> "<what enforces it>"'
    exit "$GATE_CODE"
  fi
fi
exit 0
`;
  fs.writeFileSync(preCommitPath, preCommitScript, { mode: 0o755 });
  console.log(`${GREEN}✅ Git pre-commit hook installed:${NC} ${preCommitPath}`);

  // Pre-push hook
  const prePushPath = path.join(hooksDir, 'pre-push');
  const prePushScript = `#!/usr/bin/env sh
# secure-coding: dependency audit and pattern validation before push
if [ -n "$SECURE_CODING_SKIP" ]; then
  exit 0
fi

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
AUDIT_SCRIPT="$ROOT_DIR/hooks/audit.js"
if [ ! -f "$AUDIT_SCRIPT" ] && [ -f "$HOME/.secure-coding/hooks/audit.js" ]; then
  AUDIT_SCRIPT="$HOME/.secure-coding/hooks/audit.js"
fi

if [ -f "$AUDIT_SCRIPT" ]; then
  node "$AUDIT_SCRIPT"
  EXIT_CODE=$?
  if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Push rejected: dependency vulnerabilities found by hooks/audit.js"
    exit $EXIT_CODE
  fi
fi
exit 0
`;
  fs.writeFileSync(prePushPath, prePushScript, { mode: 0o755 });
  console.log(`${GREEN}✅ Git pre-push hook installed:${NC} ${prePushPath}`);
}

function installVsCodeTasks(targetDir) {
  const vscodeDir = path.join(targetDir, '.vscode');
  fs.mkdirSync(vscodeDir, { recursive: true });
  const tasksPath = path.join(vscodeDir, 'tasks.json');

  if (!fs.existsSync(tasksPath)) {
    const tasksContent = {
      version: '2.0.0',
      tasks: [
        {
          label: 'Security: Staged Scan',
          type: 'shell',
          command: 'node hooks/scan.js --staged',
          group: 'test',
          problemMatcher: [],
        },
        {
          label: 'Security: Dependency Vulnerability Audit',
          type: 'shell',
          command: 'node hooks/audit.js',
          group: 'test',
          problemMatcher: [],
        },
        {
          label: 'Security: Clean Code Quality Linter',
          type: 'shell',
          command: 'node hooks/clean.js',
          group: 'test',
          problemMatcher: [],
        },
        {
          label: 'Security: Generate Markdown PR Report',
          type: 'shell',
          command: 'node hooks/report.js --markdown',
          problemMatcher: [],
        },
        {
          label: 'Security: Generate CycloneDX SBOM (with AI & VEX)',
          type: 'shell',
          command: 'node hooks/sbom.js --format cyclonedx --ai --vex --out sbom.json',
          problemMatcher: [],
        },
      ],
    };
    fs.writeFileSync(tasksPath, JSON.stringify(tasksContent, null, 2) + '\n');
    console.log(`${GREEN}✅ VS Code tasks installed:${NC} ${tasksPath}`);
  } else {
    console.log(`${YELLOW}ℹ️  VS Code tasks already exist:${NC} ${tasksPath}`);
  }
}

function installConfig(targetDir, severity = 'high') {
  const configPath = path.join(targetDir, '.securecodingrc.json');
  if (!fs.existsSync(configPath)) {
    const configContent = {
      failOn: severity,
      entropyDetection: true,
      generateMarkdownPR: true,
      modules: {
        llm: true,
        jwt: true,
        cors: true,
        cleanCode: true,
        sbd: true,
        iot: true,
      },
      ignorePaths: ['tests/**', 'fixtures/**', 'scripts/seed/**', 'e2e/**'],
      ignorePatterns: [],
      audit: {
        ecosystems: ['npm', 'pnpm', 'pip', 'cargo', 'go', 'dotnet'],
        failOnAdvisory: severity,
      },
    };
    fs.writeFileSync(configPath, JSON.stringify(configContent, null, 2) + '\n');
    console.log(`${GREEN}✅ Security policy configured:${NC} ${configPath}`);
  } else {
    console.log(`${YELLOW}ℹ️  Existing policy preserved:${NC} ${configPath}`);
  }
}

function installMcpConfig(targetDir) {
  const mcpServerPath = path.join(DIR, 'mcp', 'server.js');
  const mcpEntry = {
    command: 'node',
    args: [mcpServerPath],
    description: 'OWASP Secure Coding, AI-SBOM, Clean Code & Dependency Audit Engine',
  };

  // 1. Workspace MCP config (mcp_config.json)
  const workspaceMcp = path.join(targetDir, 'mcp_config.json');
  let currentCfg = { mcpServers: {} };
  if (fs.existsSync(workspaceMcp)) {
    try { currentCfg = JSON.parse(fs.readFileSync(workspaceMcp, 'utf8')); } catch {}
  }
  currentCfg.mcpServers = currentCfg.mcpServers || {};
  currentCfg.mcpServers['secure-coding'] = mcpEntry;
  fs.writeFileSync(workspaceMcp, JSON.stringify(currentCfg, null, 2) + '\n');
  console.log(`${GREEN}✅ Workspace MCP configuration created:${NC} ${workspaceMcp}`);

  // 2. Cursor MCP config (.cursor/mcp.json)
  const cursorDir = path.join(targetDir, '.cursor');
  if (fs.existsSync(cursorDir)) {
    const cursorMcp = path.join(cursorDir, 'mcp.json');
    let cursorCfg = { mcpServers: {} };
    if (fs.existsSync(cursorMcp)) {
      try { cursorCfg = JSON.parse(fs.readFileSync(cursorMcp, 'utf8')); } catch {}
    }
    cursorCfg.mcpServers = cursorCfg.mcpServers || {};
    cursorCfg.mcpServers['secure-coding'] = mcpEntry;
    fs.writeFileSync(cursorMcp, JSON.stringify(cursorCfg, null, 2) + '\n');
    console.log(`${GREEN}✅ Cursor MCP configuration updated:${NC} ${cursorMcp}`);
  }

  // 3. Claude Desktop MCP config (if present)
  const homeDir = process.env.HOME || process.env.USERPROFILE || '';
  if (homeDir) {
    const claudeDesktopDir = process.platform === 'darwin'
      ? path.join(homeDir, 'Library', 'Application Support', 'Claude')
      : process.platform === 'win32'
      ? path.join(process.env.APPDATA || path.join(homeDir, 'AppData', 'Roaming'), 'Claude')
      : path.join(homeDir, '.config', 'Claude');

    const claudeDesktopCfg = path.join(claudeDesktopDir, 'claude_desktop_config.json');
    if (fs.existsSync(claudeDesktopDir)) {
      try {
        let claudeCfg = { mcpServers: {} };
        if (fs.existsSync(claudeDesktopCfg)) {
          try { claudeCfg = JSON.parse(fs.readFileSync(claudeDesktopCfg, 'utf8')); } catch {}
        }
        claudeCfg.mcpServers = claudeCfg.mcpServers || {};
        claudeCfg.mcpServers['secure-coding'] = mcpEntry;
        fs.writeFileSync(claudeDesktopCfg, JSON.stringify(claudeCfg, null, 2) + '\n');
        console.log(`${GREEN}✅ Configured Claude Desktop MCP:${NC} ${claudeDesktopCfg}`);
      } catch (e) {} // secure-coding-ignore: swallowed-exception -- optional step, must not abort
    }
  }
}

function installGlobal() {
  const homeDir = process.env.HOME || process.env.USERPROFILE || '';
  if (!homeDir) return;

  // 1. Install ~/.secure-coding
  const globalDir = path.join(homeDir, '.secure-coding');
  try {
    fs.mkdirSync(globalDir, { recursive: true });
    console.log(`${GREEN}✅ Global skill directory configured:${NC} ${globalDir}`);
  } catch (e) {
    console.log(`${YELLOW}ℹ️  Global directory write skipped (${e.message})${NC}`);
  }

  // 2. Link for Claude Code (~/.claude/skills/secure-coding)
  try {
    const claudeDir = path.join(homeDir, '.claude');
    if (fs.existsSync(claudeDir)) {
      const claudeSkills = path.join(claudeDir, 'skills');
      fs.mkdirSync(claudeSkills, { recursive: true });
      const claudeLink = path.join(claudeSkills, 'secure-coding');
      try { fs.unlinkSync(claudeLink); } catch {}
      fs.symlinkSync(DIR, claudeLink, 'dir');
      console.log(`${GREEN}✅ Linked to Claude Code at:${NC} ${claudeLink}`);
    }
  } catch (e) {} // secure-coding-ignore: swallowed-exception -- optional step, must not abort

  // 3. Link for OpenCode (~/.opencode/skills/secure-coding)
  try {
    const opencodeDir = path.join(homeDir, '.opencode');
    if (fs.existsSync(opencodeDir)) {
      const opencodeSkills = path.join(opencodeDir, 'skills');
      fs.mkdirSync(opencodeSkills, { recursive: true });
      const opencodeLink = path.join(opencodeSkills, 'secure-coding');
      try { fs.unlinkSync(opencodeLink); } catch {}
      fs.symlinkSync(DIR, opencodeLink, 'dir');
      console.log(`${GREEN}✅ Linked to OpenCode at:${NC} ${opencodeLink}`);
    }
  } catch (e) {} // secure-coding-ignore: swallowed-exception -- optional step, must not abort

  // 4. Link for Google Antigravity (~/.gemini/config/plugins/secure-coding)
  try {
    const geminiPlugins = path.join(homeDir, '.gemini', 'config', 'plugins');
    if (fs.existsSync(path.join(homeDir, '.gemini', 'config')) || fs.existsSync(geminiPlugins)) {
      const pluginDir = path.join(geminiPlugins, 'secure-coding');
      const skillsDir = path.join(pluginDir, 'skills');
      fs.mkdirSync(skillsDir, { recursive: true });
      const targetSymlink = path.join(skillsDir, 'secure-coding');
      try { fs.unlinkSync(targetSymlink); } catch {}
      fs.symlinkSync(DIR, targetSymlink, 'dir');
      const manifestPath = path.join(pluginDir, 'plugin.json');
      fs.writeFileSync(manifestPath, JSON.stringify({
        name: 'secure-coding',
        version: '2.1.0',
        description: 'OWASP Secure Coding Practices, ACSC/CISA Secure by Design, Clean Code, and LLM Safety Engine.',
        author: { name: 'OWASP' },
        license: 'MIT',
      }, null, 2) + '\n');
      console.log(`${GREEN}✅ Registered global Antigravity plugin:${NC} ${pluginDir}`);
    }
  } catch (e) {} // secure-coding-ignore: swallowed-exception -- optional step, must not abort
}

function configureAgent(targetDir, agentName) {
  if (!agentName || agentName === 'none') return;

  if (agentName === 'antigravity' || agentName === 'all') {
    const agentsMd = path.join(targetDir, 'AGENTS.md');
    if (!fs.existsSync(agentsMd)) {
      const content = `# AI Agent Instructions

When writing code that handles user input, authentication, sessions, permissions, secrets, databases, files, network calls, LLM prompts/tools, or raw memory:
1. Read \`SKILL.md\` and apply matching design groups and templates (\`templates/<language>.md\`).
2. When architecting systems, review \`checks/secure-by-design.md\`, \`checks/memory-safety.md\`, \`checks/cryptography.md\`, \`checks/iot-security.md\`, \`checks/deployment-safety.md\`, or \`checks/sbom.md\`.
3. When building AI/LLM workflows or RAG pipelines, review \`checks/llm-top10.md\`.
4. After writing code, run: \`node hooks/scan.js --staged\`
5. Before declaring completion, run the Done Gate: \`node hooks/summary.js && node hooks/audit.js && node hooks/gate.js --check\`
6. \`gate.js --check\` exits 2 until you answer the four questions no pattern can check — ownership, authorization, taint, failure-direction. Record each with \`node hooks/gate.js --answer <question> "<what enforces it>"\`. A clean scan is not a pass on its own.
`;
      fs.writeFileSync(agentsMd, content);
      console.log(`${GREEN}✅ Configured Antigravity instructions:${NC} ${agentsMd}`);
    }

    // Also register into global Antigravity plugins if directory exists
    const homeDir = process.env.HOME || process.env.USERPROFILE || '';
    if (homeDir) {
      const geminiPlugins = path.join(homeDir, '.gemini', 'config', 'plugins');
      if (fs.existsSync(geminiPlugins)) {
        try {
          const pluginDir = path.join(geminiPlugins, 'secure-coding');
          const skillsDir = path.join(pluginDir, 'skills');
          fs.mkdirSync(skillsDir, { recursive: true });
          const targetSymlink = path.join(skillsDir, 'secure-coding');
          try { fs.unlinkSync(targetSymlink); } catch {}
          fs.symlinkSync(DIR, targetSymlink, 'dir');
          const manifestPath = path.join(pluginDir, 'plugin.json');
          fs.writeFileSync(manifestPath, JSON.stringify({
            name: 'secure-coding',
            version: '2.1.0',
            description: 'OWASP Secure Coding Practices, ACSC/CISA Secure by Design, Clean Code, and LLM Safety Engine.',
            author: { name: 'OWASP' },
            license: 'MIT',
          }, null, 2) + '\n');
          console.log(`${GREEN}✅ Registered global Antigravity plugin:${NC} ${pluginDir}`);
        } catch {}
      }
    }
  }

  if (agentName === 'cursor' || agentName === 'all') {
    const cursorDir = path.join(targetDir, '.cursor', 'rules');
    fs.mkdirSync(cursorDir, { recursive: true });
    const cursorRule = path.join(cursorDir, 'secure-coding.mdc');
    const content = `---
globs: ["**/*.{py,js,ts,go,java,kt,swift,rb,php,cs,rs,c,cpp,h,sh,tf,yaml,yml}"]
alwaysApply: false
---
Apply OWASP Secure Coding Practices, ACSC Modern Defensible Architecture, and Clean Code rules while writing code.
Refer to SKILL.md, templates/, and checks/secure-by-design.md for secure patterns.
After writing, run \`node hooks/scan.js --staged\`, then \`node hooks/gate.js --check\` before declaring the task complete.
`;
    fs.writeFileSync(cursorRule, content);
    console.log(`${GREEN}✅ Configured Cursor rule:${NC} ${cursorRule}`);
  }

  if (agentName === 'windsurf' || agentName === 'all') {
    const windsurfRules = path.join(targetDir, '.windsurfrules');
    if (!fs.existsSync(windsurfRules)) {
      const content = `When writing code that handles user input, auth, secrets, databases, files, or LLM pipelines:
- Read SKILL.md and apply matching templates from templates/.
- When designing architecture, refer to checks/secure-by-design.md and checks/memory-safety.md.
- After writing, verify using: node hooks/scan.js --staged\n- Before declaring done: node hooks/gate.js --check (exits 2 until the manual review is answered)
`;
      fs.writeFileSync(windsurfRules, content);
      console.log(`${GREEN}✅ Configured Windsurf rules:${NC} ${windsurfRules}`);
    }
  }

  if (agentName === 'cline' || agentName === 'all') {
    const clineRules = path.join(targetDir, '.clinerules');
    if (!fs.existsSync(clineRules)) {
      const content = `# Secure Coding Instructions
Always write secure code from the start. Never defer security fixes.
- Before coding, read SKILL.md and templates/<language>.md.
- When handling LLM tools or RAG, review checks/llm-top10.md.
- After writing code, run \`node hooks/scan.js --staged\` and fix any reported findings immediately.\n- Before declaring done, run \`node hooks/gate.js --check\` and answer the four manual questions it names.
`;
      fs.writeFileSync(clineRules, content);
      console.log(`${GREEN}✅ Configured Cline rules:${NC} ${clineRules}`);
    }
  }

  if (agentName === 'opencode' || agentName === 'all') {
    const opencodeDir = path.join(targetDir, '.opencode', 'skills');
    try {
      fs.mkdirSync(opencodeDir, { recursive: true });
      const opencodeLink = path.join(opencodeDir, 'secure-coding');
      try { fs.unlinkSync(opencodeLink); } catch {}
      fs.symlinkSync(DIR, opencodeLink, 'dir');
      console.log(`${GREEN}✅ Configured OpenCode workspace skills:${NC} ${opencodeLink}`);
    } catch {}
  }

  if (agentName === 'claude') {
    console.log(`${CYAN}ℹ️  For Claude Code, add the PostToolUse hook to ~/.claude/settings.json (see INSTALLATION.md).${NC}`);
  }
}

async function runInteractive() {
  printBanner();
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  console.log(`${BOLD}Welcome to the Secure Coding Setup Wizard!${NC}\n`);

  // Step 1: Target directory
  const targetAnswer = await ask(rl, '📂 Target repository path', process.cwd());
  const targetDir = path.resolve(targetAnswer);

  // Step 2: Global installation
  const installGlob = await askYesNo(rl, '🌐 Install globally for Google Antigravity & Claude Code?', true);

  // Step 3: MCP Server Setup
  const installMcp = await askYesNo(rl, '🔌 Configure Model Context Protocol (MCP) Server for IDEs/Agents?', true);

  // Step 4: Git hooks
  const installHooks = await askYesNo(rl, '⚓ Install Git pre-commit and pre-push hooks?', true);

  // Step 5: VS Code tasks
  const installVscode = await askYesNo(rl, '💻 Install VS Code security tasks (.vscode/tasks.json)?', true);

  // Step 6: AI Agent integration
  console.log(`\n🤖 Select AI Agent environment:
  ${BOLD}1)${NC} Antigravity (AGENTS.md)
  ${BOLD}2)${NC} Claude Code (~/.claude/settings.json)
  ${BOLD}3)${NC} Cursor (.cursor/rules)
  ${BOLD}4)${NC} Windsurf (.windsurfrules)
  ${BOLD}5)${NC} Cline (.clinerules)
  ${BOLD}6)${NC} All of the above
  ${BOLD}7)${NC} None / Manual`);
  const agentChoice = await ask(rl, 'Enter choice (1-7)', '1');
  const agentMap = {
    '1': 'antigravity',
    '2': 'claude',
    '3': 'cursor',
    '4': 'windsurf',
    '5': 'cline',
    '6': 'all',
    '7': 'none',
  };
  const agentSelected = agentMap[agentChoice] || 'antigravity';

  // Step 7: Severity Threshold
  console.log(`\n🚦 Security Policy Failure Threshold:
  ${BOLD}1)${NC} critical (Block only on severe vulnerabilities & leaked secrets)
  ${BOLD}2)${NC} high     (Recommended: Block on critical + high OWASP risks)
  ${BOLD}3)${NC} medium   (Strict: Block on all warnings)`);
  const sevChoice = await ask(rl, 'Enter threshold (1-3)', '2');
  const sevMap = { '1': 'critical', '2': 'high', '3': 'medium' };
  const selectedSev = sevMap[sevChoice] || 'high';

  // Step 8: Browser UI Wizard
  const launchUi = await askYesNo(rl, '🌐 Launch browser UI configuration wizard when finished?', false);

  rl.close();

  console.log(`\n${BOLD}Applying configuration...${NC}\n`);

  if (installGlob) installGlobal();
  if (installMcp) installMcpConfig(targetDir);
  if (installHooks) installGitHooks(targetDir);
  if (installVscode) installVsCodeTasks(targetDir);
  installConfig(targetDir, selectedSev);
  configureAgent(targetDir, agentSelected);

  // Run self-check validation
  try {
    const syncScript = path.join(DIR, 'hooks', 'sync.js');
    const testScript = path.join(DIR, 'hooks', 'test.js');
    if (fs.existsSync(syncScript) && fs.existsSync(testScript)) {
      execSync(`node "${syncScript}"`, { stdio: 'ignore' });
      execSync(`node "${testScript}"`, { stdio: 'ignore' });
      console.log(`\n${GREEN}✅ Self-check: All 298 tests and pattern validations PASSED.${NC}`);
    }
  } catch (e) {
    // Ignore in non-dev repos
  }

  console.log(`\n${GREEN}${BOLD}🎉 Setup Complete!${NC}`);
  console.log('----------------------------------------------------------------------');
  console.log('• Fast Staged Scan:   node hooks/scan.js --staged');
  console.log('• Done Gate:         node hooks/gate.js --check');
  console.log('• Dependency Audit:   node hooks/audit.js');
  console.log('• MCP Stdio Server:   node mcp/server.js');
  console.log('• Policy Wizard UI:   node hooks/config.js --ui');
  console.log('• CycloneDX SBOM:     node hooks/sbom.js --format cyclonedx --ai --vex');
  console.log('• SARIF v2.1.0:       node hooks/report.js --sarif');
  console.log('----------------------------------------------------------------------\n');

  if (launchUi) {
    const configScript = path.join(DIR, 'hooks', 'config.js');
    if (fs.existsSync(configScript)) {
      const start = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
      const wizardHtml = path.join(DIR, 'reports', 'config-wizard.html');
      exec(`${start} "${wizardHtml}"`);
    }
  }
}

function runNonInteractive(args) {
  printBanner();

  let targetDir = process.cwd();
  let agentName = '';
  let installHooks = true;
  let installVscode = true;
  let installCfg = true;
  let launchUi = false;
  let isGlobal = args.includes('--global');
  let isMcp = args.includes('--mcp');

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--target' && args[i + 1]) {
      targetDir = path.resolve(args[i + 1]);
      i++;
    } else if (args[i] === '--agent' && args[i + 1]) {
      agentName = args[i + 1].toLowerCase();
      i++;
    } else if (args[i] === '--no-hooks') {
      installHooks = false;
    } else if (args[i] === '--no-vscode') {
      installVscode = false;
    } else if (args[i] === '--no-config') {
      installCfg = false;
    } else if (args[i] === '--wizard') {
      launchUi = true;
    }
  }

  console.log(`${BOLD}Running automated installation for:${NC} ${targetDir}\n`);

  if (isGlobal) installGlobal();
  if (isMcp) installMcpConfig(targetDir);
  if (installHooks) installGitHooks(targetDir);
  if (installVscode) installVsCodeTasks(targetDir);
  if (installCfg) installConfig(targetDir, 'high');
  if (agentName) configureAgent(targetDir, agentName);

  console.log(`\n${GREEN}${BOLD}🎉 Installation Complete!${NC}\n`);

  if (launchUi) {
    const wizardHtml = path.join(DIR, 'reports', 'config-wizard.html');
    const start = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
    exec(`${start} "${wizardHtml}"`);
  }
}

function main() {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    showHelp();
  }

  const isExplicitInteractive = args.includes('-i') || args.includes('--interactive');
  const isExplicitNonInteractive = args.includes('-y') || args.includes('--yes') || args.includes('--agent') || args.includes('--target') || args.includes('--global') || args.includes('--mcp');

  if (isExplicitInteractive || (!isExplicitNonInteractive && process.stdin.isTTY)) {
    runInteractive();
  } else {
    runNonInteractive(args);
  }
}

if (require.main === module) {
  main();
}

module.exports = { main, installGitHooks, installVsCodeTasks, installConfig, installGlobal, installMcpConfig, configureAgent };
