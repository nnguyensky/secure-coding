<div align="center">

# 📦 Installation & Integration Guide

**Zero-Dependency Secure Coding, AI-SBOM, Clean Code & Model Context Protocol (MCP) Setup**

[![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A518.0.0-green?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)
[![MCP Protocol](https://img.shields.io/badge/MCP%202024--11--05-Compatible-purple?style=for-the-badge&logo=probot&logoColor=white)](mcp/server.js)
[![Tests](https://img.shields.io/badge/Tests-455%20Passing-brightgreen?style=for-the-badge&logo=checkmarx&logoColor=white)](hooks/test.js)

<p align="center">
  <a href="#-quickstart-options">⚡ Quickstart</a> •
  <a href="#-model-context-protocol-mcp-setup">🔌 MCP Server</a> •
  <a href="#-ai-agent-integrations">🤖 AI Agents</a> •
  <a href="#-cicd-pipeline-github-actions">🔄 CI/CD</a> •
  <a href="#-verification">🧪 Verification</a>
</p>

---

</div>

## ⚡ Quickstart Options

### Option 1: Direct NPX (No Global Clone Required)

Run the interactive terminal wizard directly via npm/npx:

```bash
# Launch interactive setup wizard
npx github:nnguyensky/secure-coding --global

# Or install with MCP server and Antigravity rules non-interactively
npx github:nnguyensky/secure-coding --global --agent antigravity --mcp --yes
```

---

### Option 2: Interactive Terminal Setup Wizard (Node.js)

```bash
# Launch interactive step-by-step wizard
node install.js
```

---

### Option 3: Universal Shell Installer

```bash
# Basic setup in current repository
./install.sh

# Install globally and link to Antigravity & Claude Code
./install.sh --global --agent all --mcp

# Install into a target project and launch the configuration wizard
./install.sh --target /path/to/my-project --agent all --mcp --wizard
```

---

### Option 4: Interactive Browser GUI Policy Wizard

```bash
# Open dark-mode glassmorphism configuration wizard
node hooks/config.js --ui
```

---

## 🔌 Model Context Protocol (MCP) Setup

`secure-coding` includes a native, zero-dependency JSON-RPC 2.0 MCP server ([`mcp/server.js`](mcp/server.js)) exposing 9 standard security tools directly to AI editors and agent runtimes:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NATIVE MCP SERVER (mcp/server.js)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  • secure_code_scan          • Scan code / staged files for 376 OWASP bugs  │
│  • secure_code_autofix       • Retrieve fix advice or refactor in-place     │
│  • security_dependency_audit • Audit lockfiles across 9 package ecosystems  │
│  • clean_code_lint           • Lint code against 14 Clean Code rules        │
│  • generate_ai_sbom          • Export BSI AI-SBOM & ACSC/CISA VEX manifests │
│  • get_security_frontier     • Pre-write architecture questions to ask      │
│  • record_security_decision  • Record one Done Gate answer                  │
│  • check_done_gate           • Gate status, or render it as an ADR          │
│  • security_summary          • Fast status check of open vs resolved bugs   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. Google Antigravity & VS Code
Add to your project root `mcp_config.json` (or `.vscode/mcp.json`):

```json
{
  "mcpServers": {
    "secure-coding": {
      "command": "node",
      "args": ["<path-to>/secure-coding/mcp/server.js"],
      "description": "OWASP Secure Coding, AI-SBOM, Clean Code & Dependency Audit Engine"
    }
  }
}
```

### 2. Claude Desktop
Add to your Claude Desktop configuration:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "secure-coding": {
      "command": "node",
      "args": ["/absolute/path/to/secure-coding/mcp/server.js"]
    }
  }
}
```

### 3. Cursor IDE
Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "secure-coding": {
      "command": "node",
      "args": ["/absolute/path/to/secure-coding/mcp/server.js"]
    }
  }
}
```

---

## 🤖 AI Agent Integrations

<details>
<summary><b>1. Google Antigravity</b> (Click to expand)</summary>

Add to project root `AGENTS.md` (or install globally with `node install.js --global`):

```markdown
# AI Agent Instructions

When writing code that handles user input, authentication, sessions, permissions, secrets, databases, files, network calls, LLM prompts/tools, or raw memory:
1. Read `SKILL.md` and apply matching design groups and templates (`templates/<language>.md`).
2. When architecting systems, review `checks/secure-by-design.md`, `checks/memory-safety.md`, `checks/cryptography.md`, `checks/iot-security.md`, `checks/deployment-safety.md`, or `checks/sbom.md`.
3. When building AI/LLM workflows or RAG pipelines, review `checks/llm-top10.md`.
4. After writing code, run: `node hooks/scan.js --staged`
5. Before declaring completion, verify zero open vulnerabilities with: `node hooks/summary.js && node hooks/audit.js`
```
</details>

<details>
<summary><b>2. Claude Code</b> (Click to expand)</summary>

Link globally:
```bash
node install.js --global
```

Add the auto-scan hook to `~/.claude/settings.json`:
```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "node $HOME/.claude/skills/secure-coding/hooks/scan.js"
          }
        ]
      }
    ]
  }
}
```
</details>

<details>
<summary><b>3. Cursor IDE</b> (Click to expand)</summary>

Add `.cursor/rules/secure-coding.mdc`:
```markdown
---
globs: ["**/*.{py,js,ts,go,java,kt,swift,rb,php,cs,rs,c,cpp,h,sh,tf,yaml,yml}"]
alwaysApply: false
---
Apply OWASP Secure Coding Practices, ACSC Modern Defensible Architecture, and Clean Code rules while writing code.
Refer to SKILL.md, templates/, and checks/secure-by-design.md for secure patterns.
```
</details>

<details>
<summary><b>4. Windsurf</b> (Click to expand)</summary>

Add to `.windsurfrules`:
```markdown
When writing code that handles user input, auth, secrets, databases, files, or LLM pipelines:
- Read SKILL.md and apply matching templates from templates/.
- When designing architecture, refer to checks/secure-by-design.md and checks/memory-safety.md.
- After writing, verify using: node hooks/scan.js --staged
```
</details>

<details>
<summary><b>5. Cline & OpenCode</b> (Click to expand)</summary>

Add to `.clinerules`:
```markdown
# Secure Coding Instructions
Always write secure code from the start. Never defer security fixes.
- Before coding, read SKILL.md and templates/<language>.md.
- When handling LLM tools or RAG, review checks/llm-top10.md.
- After writing code, run `node hooks/scan.js --staged` and fix any reported findings immediately.
```
</details>

---

## 🔄 CI/CD Pipeline (GitHub Actions)

Add `.github/workflows/security-scan.yml` to automate pull request gates and SARIF / AI-SBOM exports:

```yaml
name: Security Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]

jobs:
  security-audit:
    name: OWASP Secure Coding & SARIF Upload
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Validate Patterns & Consistency
        run: node hooks/sync.js

      - name: Run Test Suite
        run: node hooks/test.js

      - name: Dependency Vulnerability Audit
        run: node hooks/audit.js

      - name: Scan PR Changes
        if: github.event_name == 'pull_request'
        run: |
          git diff --name-only origin/${{ github.base_ref }}...HEAD > pr_files.txt
          node hooks/scan.js --files $(cat pr_files.txt)

      - name: Generate SARIF Security Report
        if: always()
        run: node hooks/report.js --sarif > results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
        continue-on-error: true

      - name: Generate CycloneDX AI-SBOM & VEX
        if: always()
        run: node hooks/sbom.js --format cyclonedx --ai --vex --out sbom.json

      - name: Upload CycloneDX SBOM Artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cyclonedx-ai-sbom
          path: sbom.json
```

---

## ⚓ Python `pre-commit` Framework Integration

If your project uses [pre-commit](https://pre-commit.com/), add to your repository `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/nnguyensky/secure-coding
    rev: main          # pin to a commit sha once you have one you trust
    hooks:
      - id: secure-coding-scan
      - id: secure-coding-clean
      - id: secure-coding-audit
```

---

## 🧪 Verification

Verify all 301 test fixtures, pattern compilations, secret masking, and MCP tool handlers:

```bash
node hooks/sync.js && node hooks/test.js && node hooks/summary.js && node hooks/audit.js
```
