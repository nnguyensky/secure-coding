#!/usr/bin/env sh
# ==============================================================================
# 🛡️ secure-coding: Complete Zero-Dependency Installer
# Installs git hooks, VS Code tasks, configuration, and AI agent integrations.
# Usage:
#   ./install.sh [options]
#   sh install.sh --target /path/to/project --agent all --wizard
# ==============================================================================

set -e

# ANSI Color Codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default settings
TARGET_DIR="$(pwd)"
INSTALL_GLOBAL=false
INSTALL_GIT_HOOKS=true
INSTALL_VSCODE=true
INSTALL_CONFIG=true
LAUNCH_WIZARD=false
AGENT_TYPE=""

# Script directory (location of secure-coding skill)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

print_banner() {
  printf "${CYAN}${BOLD}"
  echo "  ____                               ____          _ _             "
  echo " / ___|  ___  ___ _   _ _ __ ___    / ___|___   __| (_)_ __   __ _ "
  echo " \___ \ / _ \/ __| | | | '__/ _ \  | |   / _ \ / _\` | | '_ \ / _\` |"
  echo "  ___) |  __/ (__| |_| | | |  __/  | |__| (_) | (_| | | | | | (_| |"
  echo " |____/ \___|\___|\__,_|_|  \___|   \____\___/ \__,_|_|_| |_|\__, |"
  echo "                                                             |___/ "
  printf "${NC}"
  echo "  Token-Optimized Secure Coding & Clean Code System for AI Agents & Devs"
  echo "  ----------------------------------------------------------------------"
}

show_help() {
  print_banner
  echo ""
  echo "Usage: ./install.sh [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --target <dir>     Target repository directory (default: current working dir)"
  echo "  --agent <name>     Configure specific AI agent: antigravity | claude | cursor | windsurf | opencode | cline | aider | all"
  echo "  --mcp              Configure Model Context Protocol (MCP) server for IDEs/Agents"
  echo "  --global           Install skill globally to ~/.secure-coding"
  echo "  --no-hooks         Skip Git pre-commit and pre-push hook installation"
  echo "  --no-vscode        Skip .vscode/tasks.json installation"
  echo "  --no-config        Skip default .securecodingrc.json creation"
  echo "  --wizard           Launch interactive browser configuration wizard after install"
  echo "  --help, -h         Show this help message"
  echo ""
  echo "Examples:"
  echo "  ./install.sh"
  echo "  ./install.sh --agent claude"
  echo "  ./install.sh --target /path/to/my-app --agent all --wizard"
  echo "  ./install.sh --global"
  exit 0
}

# Parse CLI arguments
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      TARGET_DIR="$2"
      shift 2
      ;;
    --agent)
      AGENT_TYPE="$2"
      shift 2
      ;;
    --mcp)
      INSTALL_MCP=true
      shift
      ;;
    --global)
      INSTALL_GLOBAL=true
      shift
      ;;
    --no-hooks)
      INSTALL_GIT_HOOKS=false
      shift
      ;;
    --no-vscode)
      INSTALL_VSCODE=false
      shift
      ;;
    --no-config)
      INSTALL_CONFIG=false
      shift
      ;;
    --wizard)
      LAUNCH_WIZARD=true
      shift
      ;;
    --help|-h)
      show_help
      ;;
    *)
      printf "${RED}Unknown option: $1${NC}\n"
      echo "Run ./install.sh --help for available options."
      exit 1
      ;;
  esac
done

print_banner

# Step 1: Check Node.js prerequisite
printf "\n${BOLD}[1/5] Checking prerequisites...${NC}\n"
if ! command -v node >/dev/null 2>&1; then
  printf "${RED}❌ Error: Node.js is not installed or not in PATH.${NC}\n"
  echo "Please install Node.js (https://nodejs.org) to use secure-coding."
  exit 1
fi

NODE_VERSION=$(node -v)
printf "${GREEN}✅ Node.js detected:${NC} %s\n" "$NODE_VERSION"

# Step 2: Global installation (if requested)
if [ "$INSTALL_GLOBAL" = true ]; then
  GLOBAL_DIR="$HOME/.secure-coding"
  printf "\n${BOLD}[2/5] Installing globally to %s...${NC}\n" "$GLOBAL_DIR"
  mkdir -p "$GLOBAL_DIR"
  cp -R "$SCRIPT_DIR/"* "$GLOBAL_DIR/" 2>/dev/null || true
  printf "${GREEN}✅ Global secure-coding skill installed at %s${NC}\n" "$GLOBAL_DIR"
  
  # Also link for Claude Code if installed
  if [ -d "$HOME/.claude" ]; then
    mkdir -p "$HOME/.claude/skills"
    ln -sfn "$GLOBAL_DIR" "$HOME/.claude/skills/secure-coding"
    printf "${GREEN}✅ Linked to Claude Code at ~/.claude/skills/secure-coding${NC}\n"
  fi

  # Also link for Google Antigravity if installed
  if [ -d "$HOME/.gemini/config/plugins" ]; then
    mkdir -p "$HOME/.gemini/config/plugins/secure-coding/skills"
    ln -sfn "$GLOBAL_DIR" "$HOME/.gemini/config/plugins/secure-coding/skills/secure-coding"
    cat << 'PEOF' > "$HOME/.gemini/config/plugins/secure-coding/plugin.json"
{
  "name": "secure-coding",
  "version": "2.1.0",
  "description": "OWASP Secure Coding Practices, ACSC/CISA Secure by Design, Clean Code, and LLM Safety Engine.",
  "author": { "name": "Stephen N." },
  "license": "MIT"
}
PEOF
    printf "${GREEN}✅ Linked to Google Antigravity at ~/.gemini/config/plugins/secure-coding${NC}\n"
  fi
else
  printf "\n${BOLD}[2/5] Target repository:${NC} %s\n" "$TARGET_DIR"
fi

# Step 3: Git Hooks setup
if [ "$INSTALL_GIT_HOOKS" = true ]; then
  printf "\n${BOLD}[3/5] Configuring Git hooks...${NC}\n"
  if [ -d "$TARGET_DIR/.git" ]; then
      # Delegate to install.js rather than keeping a second copy of the hook
      # scripts here. The duplicate had already drifted: it overwrote existing
      # hooks with no backup and never ran the Done Gate.
      SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
      node "$SCRIPT_DIR/hooks/install.js" --target "$TARGET_DIR" --no-vscode --no-config --yes
  else
    printf "${YELLOW}⚠️  No .git directory found at %s. Skipping git hooks.${NC}\n" "$TARGET_DIR"
  fi
else
  printf "\n${BOLD}[3/5] Skipping Git hooks (--no-hooks)${NC}\n"
fi

# Step 4: IDE Tasks & Config setup
printf "\n${BOLD}[4/5] Configuring workspace tasks & policy...${NC}\n"

# VS Code tasks
if [ "$INSTALL_VSCODE" = true ]; then
  VSCODE_DIR="$TARGET_DIR/.vscode"
  mkdir -p "$VSCODE_DIR"
  TASKS_JSON="$VSCODE_DIR/tasks.json"
  if [ ! -f "$TASKS_JSON" ]; then
    cat << 'EOF' > "$TASKS_JSON"
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security: Staged Scan",
      "type": "shell",
      "command": "node hooks/scan.js --staged",
      "group": "test",
      "problemMatcher": []
    },
    {
      "label": "Security: Dependency Vulnerability Audit",
      "type": "shell",
      "command": "node hooks/audit.js",
      "group": "test",
      "problemMatcher": []
    },
    {
      "label": "Security: Clean Code Quality Linter",
      "type": "shell",
      "command": "node hooks/clean.js --all",
      "group": "test",
      "problemMatcher": []
    },
    {
      "label": "Security: Check Done Gate",
      "type": "shell",
      "command": "node hooks/gate.js --check",
      "group": "test",
      "problemMatcher": []
    },
    {
      "label": "Security: Generate Markdown PR Report",
      "type": "shell",
      "command": "node hooks/report.js --markdown",
      "problemMatcher": []
    },
    {
      "label": "Security: Generate CycloneDX SBOM",
      "type": "shell",
      "command": "node hooks/sbom.js --format cyclonedx --ai --vex --out sbom.json",
      "problemMatcher": []
    }
  ]
}
EOF
    printf "${GREEN}✅ VS Code tasks installed:${NC} %s\n" "$TASKS_JSON"
  else
    printf "${YELLOW}ℹ️  VS Code tasks already exist:${NC} %s\n" "$TASKS_JSON"
  fi
fi

# Configuration file
if [ "$INSTALL_CONFIG" = true ]; then
  CONFIG_JSON="$TARGET_DIR/.securecodingrc.json"
  if [ ! -f "$CONFIG_JSON" ]; then
    cat << 'EOF' > "$CONFIG_JSON"
{
  "failOn": "high",
  "entropyDetection": true,
  "taintTracking": true,
  "generateMarkdownPR": true,
  "modules": {
    "llm": true,
    "jwt": true,
    "cors": true,
    "cleanCode": true,
    "sbd": true,
    "iot": true
  },
  "ignorePaths": [
    "tests/**",
    "fixtures/**",
    "scripts/seed/**",
    "e2e/**",
    "reports/**"
  ],
  "ignorePatterns": [],
  "audit": {
    "ecosystems": ["npm", "pnpm", "pip", "cargo", "go", "dotnet"],
    "failOnAdvisory": "high"
  }
}
EOF
    printf "${GREEN}✅ Default policy initialized:${NC} %s\n" "$CONFIG_JSON"
  else
    printf "${YELLOW}ℹ️  Existing policy preserved:${NC} %s\n" "$CONFIG_JSON"
  fi
fi

# Model Context Protocol (MCP) Setup
if [ "$INSTALL_MCP" = true ]; then
  MCP_SERVER_PATH="$SCRIPT_DIR/mcp/server.js"
  MCP_JSON="$TARGET_DIR/mcp_config.json"
  cat << EOF > "$MCP_JSON"
{
  "mcpServers": {
    "secure-coding": {
      "command": "node",
      "args": ["$MCP_SERVER_PATH"],
      "description": "OWASP Secure Coding, AI-SBOM, Clean Code & Dependency Audit Engine"
    }
  }
}
EOF
  printf "${GREEN}✅ Workspace MCP configuration created:${NC} %s\n" "$MCP_JSON"

  if [ -d "$TARGET_DIR/.cursor" ]; then
    CURSOR_MCP="$TARGET_DIR/.cursor/mcp.json"
    cp "$MCP_JSON" "$CURSOR_MCP"
    printf "${GREEN}✅ Cursor MCP configuration updated:${NC} %s\n" "$CURSOR_MCP"
  fi
fi

# Step 5: AI Agent Integrations
printf "\n${BOLD}[5/5] Configuring AI Agent integrations...${NC}\n"

setup_agent_antigravity() {
  AGENTS_MD="$TARGET_DIR/AGENTS.md"
  if [ ! -f "$AGENTS_MD" ]; then
    cat << 'EOF' > "$AGENTS_MD"
# AI Agent Instructions

When writing code that handles user input, authentication, sessions, permissions, secrets, databases, files, network calls, LLM prompts/tools, or raw memory:
0. If the task creates or changes a route, auth, tenancy, a data model, an upload, an outbound call, or an LLM tool: ask the five security frontiers in `checks/secure-grilling.md` before writing — identity, tenancy, data classification, failure direction, irreversibility — each with your recommended secure default. Skip for bug fixes, refactors, docs and tests.
1. Read `SKILL.md` and apply matching design groups and templates (`templates/<language>.md`).
2. When architecting systems, review `checks/secure-by-design.md`, `checks/memory-safety.md`, `checks/cryptography.md`, `checks/iot-security.md`, `checks/deployment-safety.md`, or `checks/sbom.md`.
3. When building AI/LLM workflows or RAG pipelines, review `checks/llm-top10.md`.
4. After writing code, run: `node hooks/scan.js --staged`
5. Before declaring completion, run the Done Gate: `node hooks/summary.js && node hooks/audit.js && node hooks/gate.js --check`
6. `gate.js --check` exits 2 until you answer the four questions no pattern can check — ownership, authorization, taint, failure-direction. Record each with `node hooks/gate.js --answer <question> "<what enforces it>"`. A clean scan is not a pass on its own.
EOF
    printf "${GREEN}✅ Created Antigravity AGENTS.md instructions${NC}\n"
  else
    printf "${YELLOW}ℹ️  Existing AGENTS.md preserved${NC}\n"
  fi
}

setup_agent_cursor() {
  CURSOR_DIR="$TARGET_DIR/.cursor/rules"
  mkdir -p "$CURSOR_DIR"
  CURSOR_RULE="$CURSOR_DIR/secure-coding.mdc"
  cat << 'EOF' > "$CURSOR_RULE"
---
globs: ["**/*.{py,js,ts,go,java,kt,swift,rb,php,cs,rs,c,cpp,h,sh,tf,yaml,yml}"]
alwaysApply: false
---
Before writing a route, auth, data model, upload or LLM tool, ask the five security frontiers in checks/secure-grilling.md with recommended secure defaults.
Apply OWASP Secure Coding Practices, ACSC Modern Defensible Architecture, and Clean Code rules while writing code.
Refer to SKILL.md, templates/, and checks/secure-by-design.md for secure patterns.
After writing, run `node hooks/scan.js --staged`, then `node hooks/gate.js --check` before declaring the task complete.
EOF
  printf "${GREEN}✅ Created Cursor rule: %s${NC}\n" "$CURSOR_RULE"
}

setup_agent_windsurf() {
  WINDSURF_RULES="$TARGET_DIR/.windsurfrules"
  if [ ! -f "$WINDSURF_RULES" ]; then
    cat << 'EOF' > "$WINDSURF_RULES"
When writing code that handles user input, auth, secrets, databases, files, or LLM pipelines:
- Read SKILL.md and apply matching templates from templates/.
- Before writing a route, auth, data model, upload or LLM tool, ask the five security frontiers in checks/secure-grilling.md with recommended secure defaults.
- When designing architecture, refer to checks/secure-by-design.md and checks/memory-safety.md.
- After writing, verify using: node hooks/scan.js --staged
- Before declaring done: node hooks/gate.js --check (exits 2 until the manual review is answered)
EOF
    printf "${GREEN}✅ Created Windsurf rules: %s${NC}\n" "$WINDSURF_RULES"
  fi
}

setup_agent_cline() {
  CLINE_RULES="$TARGET_DIR/.clinerules"
  if [ ! -f "$CLINE_RULES" ]; then
    cat << 'EOF' > "$CLINE_RULES"
# Secure Coding Instructions
Always write secure code from the start. Never defer security fixes.
- Before coding, read SKILL.md and templates/<language>.md.
- Before writing a route, auth, data model, upload, outbound call or LLM tool, ask the five security frontiers in checks/secure-grilling.md with a recommended secure default for each.
- When handling LLM tools or RAG, review checks/llm-top10.md.
- After writing code, run `node hooks/scan.js --staged` and fix any reported findings immediately.
- Before declaring done, run `node hooks/gate.js --check` and answer the four manual questions it names.
EOF
    printf "${GREEN}✅ Created Cline rules: %s${NC}\n" "$CLINE_RULES"
  fi
}

case "$AGENT_TYPE" in
  antigravity)
    setup_agent_antigravity
    ;;
  cursor)
    setup_agent_cursor
    ;;
  windsurf)
    setup_agent_windsurf
    ;;
  cline)
    setup_agent_cline
    ;;
  all)
    setup_agent_antigravity
    setup_agent_cursor
    setup_agent_windsurf
    setup_agent_cline
    ;;
  "")
    printf "${CYAN}ℹ️  No --agent specified. (Use --agent antigravity|cursor|windsurf|cline|all if desired)${NC}\n"
    ;;
  *)
    printf "${YELLOW}ℹ️  Custom agent '%s' specified. Refer to INSTALLATION.md for details.${NC}\n" "$AGENT_TYPE"
    ;;
esac

# Verification check
printf "\n${BOLD}Verifying installation self-test...${NC}\n"
# The suite's installer-parity test runs this script; without this guard that
# recurses forever (install.sh -> test.js -> install.sh -> ...).
if [ -n "$SECURE_CODING_NO_SELFTEST" ]; then
  printf "${YELLOW}ℹ️  Self-check skipped (SECURE_CODING_NO_SELFTEST).${NC}\n"
elif [ -f "$SCRIPT_DIR/hooks/sync.js" ] && [ -f "$SCRIPT_DIR/hooks/test.js" ]; then
  node "$SCRIPT_DIR/hooks/sync.js" > /dev/null 2>&1
  TEST_OUT="$(node "$SCRIPT_DIR/hooks/test.js" 2>&1 | tail -1)"
  case "$TEST_OUT" in
    *"fail=0"*) printf "${GREEN}✅ Self-check: %s and synchronization validations PASSED.${NC}\n" "$TEST_OUT" ;;
    *)          printf "${YELLOW}⚠️  Self-check reported: %s${NC}\n" "$TEST_OUT" ;;
  esac
fi

# Optional browser wizard
if [ "$LAUNCH_WIZARD" = true ] && [ -f "$SCRIPT_DIR/hooks/config.js" ]; then
  printf "\n${BOLD}Launching interactive configuration wizard...${NC}\n"
  node "$SCRIPT_DIR/hooks/config.js" --ui
fi

printf "\n${GREEN}${BOLD}🎉 Installation Complete!${NC}\n"
echo "----------------------------------------------------------------------"
echo "• Fast Staged Scan:   node hooks/scan.js --staged"
echo "• Dependency Audit:   node hooks/audit.js"
echo "• Config Wizard UI:   node hooks/config.js --ui"
echo "• SBOM Generator:     node hooks/sbom.js --format cyclonedx"
echo "• SARIF Generator:    node hooks/report.js --sarif"
echo "----------------------------------------------------------------------"
exit 0
