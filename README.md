<div align="center">

# 🛡️ secure-coding

**Catches insecure code as it is written, then asks the questions a scanner cannot.**

[![OWASP Coverage](https://img.shields.io/badge/OWASP%20SCP-213%2F213%20Controls-blue?style=for-the-badge&logo=owasp&logoColor=white)](checks/review.md)
[![Secure by Design](https://img.shields.io/badge/ACSC%20%2F%20CISA-Secure%20by%20Design-orange?style=for-the-badge&logo=shield&logoColor=white)](checks/secure-by-design.md)
[![AI-SBOM & VEX](https://img.shields.io/badge/BSI%20%2F%20CISA-AI--SBOM%20%26%20VEX-darkblue?style=for-the-badge&logo=probot&logoColor=white)](checks/sbom.md)
[![IoT Standard](https://img.shields.io/badge/AS%20ETSI%20EN%20303%20645-13%20Principles-success?style=for-the-badge&logo=espressif&logoColor=white)](checks/iot-security.md)
[![OWASP Top 10](https://img.shields.io/badge/OWASP%20Top%2010-2025%20%2B%20CWE-critical?style=for-the-badge&logo=owasp&logoColor=white)](checks/owasp-top10-2025.md)
[![LLM Top 10](https://img.shields.io/badge/OWASP%20LLM%20Top%2010-2025%20Ready-green?style=for-the-badge&logo=openai&logoColor=white)](checks/llm-top10.md)
[![Tests](https://img.shields.io/badge/Tests-408%20Passing%20(100%25)-brightgreen?style=for-the-badge&logo=checkmarx&logoColor=white)](hooks/test.js)
[![Zero-Token Idle](https://img.shields.io/badge/Idle%20Cost-0%20Tokens-purple?style=for-the-badge&logo=speedtest&logoColor=white)](#-the-inverted-architecture)

<p align="center">
  <a href="#-quickstart--installation">⚡ Quickstart</a> •
  <a href="#-system-architecture">🏛️ Architecture</a> •
  <a href="#-how-each-layer-works">🔍 5-Layer Defense</a> •
  <a href="#-cli-reference-cookbook">🛠️ CLI Cookbook</a> •
  <a href="#-language-template-matrix">🌐 Templates</a> •
  <a href="#-ai-agent-integrations">🤖 AI Setup</a> •
  <a href="#-model-context-protocol-mcp-server">🔌 MCP Server</a>
</p>

---

</div>

A security skill for AI coding agents. It loads only the rules that match what is
being written, scans each file the moment it is saved, and blocks commits that
carry findings. What static analysis genuinely cannot see — a missing ownership
check, an absent guard, a fail-open `catch` — it asks as four written questions
before the change lands.

13 language templates · 376 patterns mapped to CWE and OWASP Top 10:2025 · 408
self-tests · zero dependencies.

## 💡 The Inverted Architecture

> [!IMPORTANT]
> **Traditional security checklists fail with AI agents.** Dumping 200+ rules into LLM context burns 30,000+ tokens, dilutes focus, and generates noisy post-write errors.

**The idea:** don't give the agent every rule. Give it the few that match what it
is writing right now, then check the result mechanically.

Security guidance is loaded on demand, not up front. A scan runs after the write
and costs nothing when the code is clean. What a scanner cannot judge — a missing
ownership check, an absent guard — is asked as a question at the end.

Five layers, from design to remediation:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│  LAYER 0: PLANNING & SECURE-BY-DESIGN ARCHITECTURE (Progressive Disclosure) │
│  • STRIDE/DREAD  • ACSC Modern Defensible  • Zero Trust  • AI-SBOM (BSI)    │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 1: PROACTIVE DESIGN SHAPING (Pre-Write Rule Trigger Groups)          │
│  • 9 Focused Trigger Groups  • 13 Drop-In Templates (25 Standards Each)     │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 2: MECHANICAL SCANNER & SHANNON ENTROPY (0 Tokens Clean, <20ms)      │
│  • 32 Pattern Files (376 Regexes)  • Shannon Entropy H ≥ 3.5 Bits/Byte      │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 3: VERIFICATION & MULTI-ECOSYSTEM AUDITING                           │
│  • 213 Verifiable Controls  • 9 Package Managers  • 14 Clean Code Standards │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 4: POLICY GOVERNANCE, SBOM & SARIF CI/CD                             │
│  • Browser GUI Wizard  • CycloneDX v1.5 / SPDX v2.3  • OASIS SARIF v2.1.0   │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 5: AUTOMATED IN-PLACE REMEDIATION                                    │
│  • Deterministic In-Place Code Refactoring (hooks/fix.js --apply)           │
└─────────────────────────────────────────────────────────────────────────────┘
```

- ⚡ **Zero-Token Idle Cost**: Local hooks execute in ~1ms for a typical file (~20ms for 2,000 lines). If code is clean, it consumes **0 LLM tokens**.
- 🎯 **Progressive Disclosure**: Specialized architecture guides load on-demand **only** when touching relevant systems.
- 🛠️ **Deterministic Fixes**: Violations return exact line snippets with copy-pasteable `When / Wrong / Right / Watch` blocks.

---

## 🏛️ System Architecture

How the pieces fit: guidance files the agent reads on demand, pattern files the
scanner matches against, and hooks that run at write, commit and CI time.

```mermaid
flowchart TD
    subgraph L0["Layer 0: Planning, Threat Modeling & Architecture"]
        TM["checks/threat-model.md<br/>• STRIDE Architecture &amp; DREAD Risk"]
        SBD["checks/secure-by-design.md<br/>• OWASP SbD 36-Control Checklist<br/>• ACSC Modern Defensible Architecture<br/>• Zero Trust &amp; CDS Ingress Normalization"]
        MEM["checks/memory-safety.md<br/>• Memory Safe Language (MSL) Selection<br/>• Safe C/C++ Intermediary Wrappers"]
        CRYPTO["checks/cryptography.md<br/>• FIPS 140-3 KMS Envelope Encryption<br/>• Post-Quantum Cryptography (ML-KEM, ML-DSA)"]
        IOT["checks/iot-security.md<br/>• AS ETSI EN 303 645 (13 IoT Principles)<br/>• Secure Boot, OTA Signing &amp; JTAG Lockout"]
        SBOM_GUIDE["checks/sbom.md<br/>• BSI 7 AI-SBOM Clusters<br/>• ACSC/CISA VEX Exploitability"]
        DEP["checks/deployment-safety.md<br/>• Pre-Mortem Failure Analysis<br/>• Canary Rollouts &amp; Automated Rollback"]
    end

    subgraph L1["Layer 1: Proactive Design (Progressive Disclosure)"]
        SKILL["SKILL.md (~3.6k tokens)<br/>• 9 Modular Trigger Groups"]
        TEMPLATES["templates/*.md (13 Languages)<br/>• 25 Secure Standards Each"]
        LLM["checks/llm-top10.md (~1.1k tokens)<br/>• OWASP Top 10 for LLMs (2025)"]
    end

    subgraph L2["Layer 2: Fast Mechanical Scanner (0 Tokens Clean)"]
        SCAN["hooks/scan.js (&lt;20ms)<br/>• Line Numbers &amp; Code Snippets"]
        ENTROPY["Shannon Entropy Engine<br/>• Un-prefixed Secret Detection ($H \\ge 3.5$)"]
        PATTERNS["patterns/*.txt (32 Files, 376 Regexes)<br/>• JWT, CORS, Deser, Cloud Keys, SbD, IoT"]
        SUPPRESS["Inline Comment Suppression<br/>• // secure-coding-ignore: id"]
    end

    subgraph L3["Layer 3: Verification & Auditing"]
        REVIEW["checks/review.md<br/>• 213 Verifiable Controls"]
        AUDIT["hooks/audit.js<br/>• 9 Ecosystems (npm, pnpm, yarn, pip, cargo, go...)"]
        CLEAN["hooks/clean.js<br/>• 14 Clean Code Quality Rules"]
    end

    subgraph L4["Layer 4: Policy, Governance & CI/CD"]
        WIZARD["reports/config-wizard.html<br/>• Interactive Browser UI Wizard"]
        CONFIG[".securecodingrc.json<br/>• Project Policy &amp; Severity Gates"]
        PR["hooks/report.js --markdown<br/>• GitHub/GitLab PR Comment Tables"]
        SARIF["hooks/report.js --sarif<br/>• OASIS SARIF v2.1.0 for Code Scanning"]
        SBOM["hooks/sbom.js<br/>• CycloneDX v1.5 &amp; SPDX v2.3 (AI &amp; VEX)"]
        GIT["install.sh / hooks/install.js<br/>• Git Pre-commit &amp; Pre-push Hooks"]
    end

    subgraph L5["Layer 5: Automated Remediation & MCP Server"]
        FIX["hooks/fix.js<br/>• --suggest &lt;id&gt; Guidance<br/>• --apply In-Place Refactoring<br/>• --dry-run Unified Diff Preview"]
        MCP["mcp/server.js<br/>• Native JSON-RPC 2.0 MCP Tools"]
    end

    L0 --> L1
    L1 --> L2
    L2 --> L3
    L3 --> L4
    L2 -. Violation Detected .-> L5
```

---

## ⏱️ What Runs, and When

Nothing here runs on a schedule or in the background. Each check is attached to
something you already do.

**The main check does not involve git.** The scanner runs the moment the agent
writes a file, so a problem is caught while the code is still being written. The
git hooks are a second net, for code the agent did not write and for the review
questions that only make sense once a change is complete.

| You do this | This runs | What happens |
|---|---|---|
| Ask an agent to write code touching input, auth, secrets, files, or network calls | The agent loads `SKILL.md` | It reads the rules for that topic before writing, not all 376 patterns |
| The agent finishes writing a file | `scan.js`, via the PostToolUse hook `install.js` sets up | ~1ms. Silent when clean, so it costs no tokens. Otherwise prints the finding and how to fix it, immediately — no commit needed |
| `git commit` | `scan.js --staged`, then `gate.js --check` | Blocks the commit if the staged code has findings, or if it handles requests and the review is unanswered |
| `git push` | `audit.js` | Blocks the push on a known-vulnerable dependency |
| Open a PR or push to `main` | GitHub Actions | Re-runs the checks, uploads SARIF so findings appear on the PR diff |
| Weekly, on GitHub | Dependabot | Opens a PR when a pinned GitHub Action has an update |

### When the Done Gate asks, and when it stays quiet

It only asks about code it has questions for. Everything else passes through:

| Change | Gate |
|---|---|
| README, docs, comments | **Skipped** |
| `package.json`, config, YAML | **Skipped** |
| CSS, images | **Skipped** |
| Tests and fixtures | **Skipped** |
| A utility function with no request handling | **Skipped** |
| A route or endpoint | **Asks** |
| Reading `req.query`, `req.body`, `$_GET`, form values | **Asks** |
| Fetching a record — `findById`, `findFirst`, a `SELECT` | **Asks** |
| An auth check, or returning 401/403 | **Asks** |

### Turning things off

| To do this | Run |
|---|---|
| Skip every check for one commit | `git commit --no-verify` |
| Skip every check for one commit (no git flag) | `SECURE_CODING_SKIP=1 git commit` |
| Turn the Done Gate off for a repository | `git config secure-coding.gate false` |
| Never scan a path | Add it to `ignorePaths` in `.securecodingrc.json` |
| Silence one finding on one line | `// secure-coding-ignore: <pattern-id>` |

---

## 🔄 End-to-End Developer Lifecycle Flow

One change, start to finish — what runs automatically and what asks for you.

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / AI Agent
    participant Plan as Layer 0: Threat Model & SbD
    participant Code as Layer 1: Code & Templates
    participant Scan as Layer 2: hooks/scan.js
    participant Fix as Layer 5: hooks/fix.js
    participant Git as Layer 4: Git Hooks
    participant CI as Layer 4: CI/CD & SARIF

    Dev->>Plan: Review STRIDE threat model & SbD Architecture during design
    Dev->>Code: Write feature using language templates
    Code->>Scan: PostToolUse Hook triggers (stdin payload)
    alt Security Smell / Secret Found
        Scan-->>Dev: [Exit 2] Line number, snippet & fix guidance
        Dev->>Fix: node hooks/fix.js --apply (or manual fix)
        Fix-->>Code: Applies in-place safe code refactor
    else Clean Code
        Scan-->>Dev: [Exit 0] Silent (0 tokens consumed)
    end

    Dev->>Dev: gate.js --check (manual review: ownership, authz, taint, failure)
    Note over Dev: Exits 2 until all four are answered — patterns cannot see these

    Dev->>Git: git commit (triggers pre-commit hook)
    Git->>Scan: scan.js --staged
    Git-->>Dev: Commit accepted

    Dev->>Git: git push (triggers pre-push hook)
    Git->>Git: audit.js (dependencies) & sync.js (consistency)
    Git-->>Dev: Push verified & sent to remote

    CI->>CI: GitHub Actions runs security-scan.yml
    CI->>CI: report.js --sarif > results.sarif
    CI-->>Dev: Annotates PR diff via GitHub Code Scanning
```

---

## 🔍 How Each Layer Works

Each layer answers a different question:

| Layer | Question it answers | When it runs |
|---|---|---|
| **0** Design | How should this be built? | Before any code exists |
| **1** Templates | What does the secure version look like? | While writing |
| **2** Scanner | Did anything unsafe get written? | After each write, in ~1ms |
| **3** Verification | Are the dependencies and the whole file clean? | Before commit |
| **4** Policy & CI | Is the result recorded and shareable? | On commit and in CI |
| **5** Remediation | How do I fix what was found? | When a finding appears |

### 🏛️ Layer 0: Planning, Architecture & Secure by Design

Read before writing code, when you are still deciding how a system fits together.
Each file is loaded only when its topic comes up:
- **STRIDE & DREAD Threat Modeling** ([`checks/threat-model.md`](checks/threat-model.md)): Structured threat categorization and quantitative risk scoring.
- **OWASP SbD 36-Control Review & ACSC Defensible Architecture** ([`checks/secure-by-design.md`](checks/secure-by-design.md)): Edge Gateway, mTLS service meshes, Postgres Row-Level Security (RLS), Fail-Closed authorization, and Cross-Domain Solutions (CDS) ingress normalization.
- **Memory Safety Roadmaps & C/C++ Hardening** ([`checks/memory-safety.md`](checks/memory-safety.md)): Memory-Safe Language decision matrix, Safe Intermediary Wrappers, and compiler hardening (`-fstack-protector-strong`, ASan/UBSan, PIE, CFI).
- **FIPS 140-3 Cryptographic Key Management & PQC** ([`checks/cryptography.md`](checks/cryptography.md)): Hardware Root of Trust, Envelope Encryption (DEK/KEK), OIDC Workload Identity, and Post-Quantum transition (**ML-KEM / FIPS 203**, **ML-DSA / FIPS 204**).
- **AS ETSI EN 303 645 Consumer IoT Security** ([`checks/iot-security.md`](checks/iot-security.md)): 13 IoT principles, Multi-stage Secure Boot, cryptographically signed OTA updates, JTAG/UART lockout, and MQTTS/CoAPS.
- **Supply Chain, AI-SBOM & VEX** ([`checks/sbom.md`](checks/sbom.md)): BSI 7 AI Information Clusters, ACSC/CISA VEX exploitability states, and Sigstore/Cosign signing.
- **Safe Software Deployment** ([`checks/deployment-safety.md`](checks/deployment-safety.md)): Pre-mortem failure analysis, canary rollout pipeline (1–5%), and automated rollback circuit breakers.
- **Choosing Secure & Verifiable Technologies** ([`checks/technology-selection.md`](checks/technology-selection.md)): ACSC procurement questions for adopting a dependency, SaaS, or vendor — Secure by Default, supply chain due diligence, data jurisdiction, and the accept/transfer/avoid/mitigate decision.

### 📐 Layer 1: Proactive Design Rules & Language Templates
- **Trigger-Based Loading**: [`SKILL.md`](SKILL.md) categorizes security into 9 functional trigger groups. The agent reads only the group matching its immediate task. Full per-group requirements live in [`checks/code-groups.md`](checks/code-groups.md), keeping the always-loaded `SKILL.md` at ~3,650 tokens.
- **13 Drop-In Secure Templates** ([`templates/`](templates/)): Battle-tested implementations for all 25 OWASP standards across *TypeScript, JavaScript, Python, Go, Rust, Java, Kotlin, Swift, C#, C, PHP, Ruby, Shell*.
- **Progressive Disclosure for AI/LLMs** ([`checks/llm-top10.md`](checks/llm-top10.md)): High-density guidance (~1.1k tokens) covering all 10 OWASP LLM 2025 risks.

### ⚡ Layer 2: Reactive Mechanical Scanner (`hooks/scan.js`)
- **Fast Execution**: Pure Node.js standard library, zero dependencies. ~1ms for a typical file; ~20ms for a 2,000-line one, since multi-line taint tracking adds a per-line pass.
- **Precise Extraction**: Pinpoints exact line numbers and code snippets (`Line 42: const key = ...`).
- **Multi-Line Taint Tracking**: Regex alone only matches when untrusted input sits *inside* the sink call. The scanner also follows `var = req.query.x` into a later file, HTTP, process, or query call — reported as `taint-*` — within one function and one hop through interpolation. Sanitizers (`basename`, `validate`, `parseInt`, allowlist checks, parameterized queries) clear the taint. Disable with `"taintTracking": false`.
- **Per-Occurrence Findings**: Three SQL injections in one file are three findings, tracked by `(file, id, line)`. Fixing one closes only that one, so a partial fix can never silently clear a live vulnerability.
- **Absence-of-Control Detection**: Some defects are the *lack* of something. `logging-disabled` catches `LOG_LEVEL=off` and `Level.OFF`; `auth-no-log` catches a 401/403 returned with no logging call nearby; `fail-open-catch` catches a `catch` block that returns success. What remains genuinely undetectable — a codebase that simply never logs, or an IDOR — routes to the Done Gate.
- **Shannon Entropy Secret Detection**:
  $$H(S) = -\sum_{i=1}^n p(x_i) \log_2 p(x_i)$$
  Calculates string randomness to distinguish true cryptographic keys ($H \ge 3.5\text{ bits/byte}$) from repetitive test strings (`"aaaaaaaaaaaaaaaa"`).
- **Inline Comment Suppression**: Allows fine-grained exclusions:
  ```typescript
  // secure-coding-ignore: eval
  const result = eval(sanitizedMathExpression);
  ```

### 🔬 Layer 3: Verification & Auditing
- **Semantic OWASP Checklist** ([`checks/review.md`](checks/review.md)): 213 verifiable controls.
- **Multi-Ecosystem Package Audit** ([`hooks/audit.js`](hooks/audit.js)): Scans lockfiles across 9 ecosystems (`npm`, `pnpm`, `yarn`, `pip`, `poetry`, `cargo`, `go`, `dotnet`, `composer`, `bundler`). Exits with code `2` on high/critical advisories.
- **Clean Code Linter** ([`hooks/clean.js`](hooks/clean.js)): Flags magic numbers, multi-responsibility functions, and unneeded context. Standards documented in [`checks/clean-code.md`](checks/clean-code.md).
- **OWASP Top 10:2025 → CWE Map** ([`checks/owasp-top10-2025.md`](checks/owasp-top10-2025.md)): Every category mapped to its key CWEs and the pattern ids that cover it — including the two new 2025 categories (**A03 Software Supply Chain Failures**, **A10 Mishandling of Exceptional Conditions**) and an explicit note on which categories patterns *cannot* cover.
- **NIST SSDF (SP 800-218) Coverage Map** ([`checks/ssdf-mapping.md`](checks/ssdf-mapping.md)): All 4 practice groups and 20 practices mapped to the skill's tooling, with the gaps stated plainly for attestation purposes.
- **Dynamic Testing & Fuzzing Plan** ([`checks/dynamic-testing.md`](checks/dynamic-testing.md)): The scanner never runs your code. This maps findings to fuzz targets (deserializers, XML parsers, ReDoS regexes, buffer functions), lists per-language tooling, and covers what fuzzing also misses — races, authorization matrices, load, and deployed configuration.

### 📜 Layer 4: Policy, Governance & CI/CD Integration
- **Interactive UI Configuration Wizard** ([`reports/config-wizard.html`](reports/config-wizard.html)): Modern browser wizard to customize failure thresholds, excluded paths, and monitored ecosystems into `.securecodingrc.json`.
- **SARIF v2.1.0 Export** (`hooks/report.js --sarif`): Emits OASIS standard SARIF for GitHub Code Scanning, tagged with `external/cwe/cwe-N`, `OWASP-Annn:2025`, and `security-severity` so alerts land correctly classified rather than untyped.
- **Software Bill of Materials (SBOM & AI-SBOM)** ([`hooks/sbom.js`](hooks/sbom.js)): Generates CycloneDX v1.5 and SPDX v2.3 manifests with BSI AI-SBOM 7 clusters and ACSC/CISA VEX data.
- **Git Pre-commit & Pre-push Hooks** (`install.sh` / `hooks/install.js`): Automates staged and repository-wide protection.
- **Done Gate** ([`hooks/gate.js`](hooks/gate.js)): see the section below.

### 🔧 Layer 5: Automated In-Place Remediation & MCP Server
- **Interactive Guidance**: `node hooks/fix.js --suggest <id>` prints the `When / Wrong / Right / Watch` block for a finding, sourced from [`checks/fixes.md`](checks/fixes.md) — 135 blocks, every one tagged with its CWE and OWASP 2025 category.
- **Autofix Engine**: `node hooks/fix.js --apply` safely refactors deterministic vulnerabilities in-place.
- **Native MCP Server** ([`mcp/server.js`](mcp/server.js)): Exposes tools directly over JSON-RPC 2.0 stdio for IDEs and AI agents.

---

## ⚡ Quick Start

Five steps: install, verify, configure a project, wire it into your workflow,
confirm the agent is using it.

**Requirements:** Node.js 18+ and nothing else. No dependencies are installed — every tool uses the Node standard library only.

### 1. Install

The fastest way — no clone, no npm publish needed:

```bash
npx github:nnguyensky/secure-coding --global --agent all --mcp
```

`--global` matters. It copies the skill to `~/.secure-coding`, which is where
the git hooks look for the scanner. Without it the hooks are installed but do
nothing, because npx deletes its cache the moment the command exits.

To work on the skill itself, clone it instead:

```bash
git clone https://github.com/nnguyensky/secure-coding.git
cd secure-coding
node install.js --agent all --mcp
```

### 2. Verify it works

```bash
node hooks/test.js     # expect: pass=408 fail=0
node hooks/sync.js     # expect: 0 errors, 0 warnings
```

The first checks every pattern still catches what it should and ignores safe
code. The second checks the patterns, templates and remediation blocks still
agree with each other.

### 3. Configure a specific project

```bash
node install.js --target ../my-app --agent all --mcp
```

Run without arguments for an interactive wizard. Useful flags:

| Flag | Effect |
|---|---|
| `--target <dir>` | Project to configure (default: current directory) |
| `--agent <name>` | `antigravity` \| `claude` \| `cursor` \| `windsurf` \| `cline` \| `all` |
| `--mcp` | Register the MCP server for IDEs and agents |
| `--global` | Install to `~/.secure-coding` and link Antigravity + Claude Code |
| `--yes` | Non-interactive; accept defaults |
| `--no-hooks` / `--no-vscode` / `--no-config` | Skip that step |
| `--wizard` | Open the browser policy UI when finished |

`node install.js --help` lists them all.

> **Heads up:** `--mcp` writes outside `--target` — it registers the server in
> your Claude Desktop config (`~/Library/Application Support/Claude/`) and links
> a global Antigravity plugin under `~/.gemini/`. Omit `--mcp` to keep every
> change inside the project directory.

### 4. Wire it into your workflow

**Git hooks** are installed by step 1 unless you pass `--no-hooks`. To use the
[pre-commit](https://pre-commit.com) framework instead:

```yaml
repos:
  - repo: https://github.com/nnguyensky/secure-coding
    rev: main          # pin to a commit sha once you have one you trust
    hooks:
      - id: secure-coding-scan     # staged files, on commit
      - id: secure-coding-gate     # the manual review, on commit
      - id: secure-coding-audit    # dependencies, on push
      - id: secure-coding-clean    # clean-code lint, optional
```

**CI**: copy [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml). It runs `sync.js`, `test.js`, `audit.js`, scans changed files, and uploads SARIF to GitHub code scanning with CWE tags. Actions are pinned to commit SHAs and tracked by [`.github/dependabot.yml`](.github/dependabot.yml).

**npm scripts** are shortcuts for the same commands:

```bash
npm test              # sync.js + test.js
npm run staged        # scan staged files
npm run audit         # dependency advisories
npm run sbom          # CycloneDX AI-SBOM + VEX
npm run wizard        # browser policy UI
npm run mcp           # start the MCP server on stdio
```

### 5. Confirm the agent picked it up

Ask your agent to read `SKILL.md`, then have it write something insecure — a query built by string concatenation is the quickest check. It should refuse and produce a parameterized version. If nothing happens, confirm the rules file for your agent exists (`.cursor/rules/`, `.clinerules`, `.windsurfrules`, `AGENTS.md`) and that `node hooks/scan.js --staged` runs from the project root.

---

## 🛠️ CLI Reference Cookbook

Every command is plain Node with no dependencies. Exit codes are consistent:
**0** means clean, **2** means findings were reported, **64** means the command
was used wrongly.

**Most of these are manual.** Only six run on their own, and each is attached to
a git or CI event — the ⚡ column below marks them. Everything unmarked runs only
when you type it.

| ⚡ | Command | Runs automatically when |
|---|---|---|
| ⚡ | `scan.js --staged` | `git commit` — blocks on findings |
| ⚡ | `gate.js --check` | `git commit`, after the scan — blocks if the staged code needs review |
| ⚡ | `audit.js` | `git push` — blocks on a vulnerable dependency |
| ⚡ | `report.js` | Any scan that finds something, writing `reports/security-<date>.html`. Set `SECURE_CODING_REPORT=off` to stop it |
| ⚡ | `sync.js`, `test.js`, `audit.js`, `scan.js --files`, `report.js --sarif`, `sbom.js` | A push or PR to `main`/`master`/`develop`, via GitHub Actions |
| ⚡ | `scan.js` (stdin) | **An agent finishes writing a file.** `install.js --agent claude` configures this, so scanning happens at write time and never waits for a commit |

`clean.js` runs automatically only if you enable the `secure-coding-clean`
pre-commit id. Everything else — `fix.js`, `config.js`, `stats.js`, `detect.js`,
`coverage.js`, `reset.js`, `sbom.js` locally, and the MCP server — is manual.

| Category | Command | Description |
|---|---|---|
| **🔍 Scanning** | `node hooks/scan.js` | Scans post-write payload on stdin. |
| | `node hooks/scan.js --staged` | Scans only Git staged files (~1ms each). |
| | `node hooks/scan.js --diff` | Scans modified working tree files. |
| | `node hooks/scan.js --files <paths...>` | Scans an explicit list of files. |
| | `node hooks/scan.js --file <f> --json` | Outputs findings as structured JSON. |
| **📦 Audit & SBOM** | `node hooks/audit.js` | Audits dependencies across 9 ecosystems. |
| | `node hooks/sbom.js --format cyclonedx` | Generates CycloneDX v1.5 JSON SBOM (9 ecosystems). |
| | `node hooks/sbom.js --format spdx` | Generates SPDX v2.3 JSON SBOM. |
| | `node hooks/sbom.js --ai` | Generates BSI AI-SBOM with 7 ML clusters. |
| | `node hooks/sbom.js --vex` | Generates ACSC/CISA VEX exploitability report. |
| | `node hooks/sbom.js --ai --vex --out sbom.json` | Full AI-SBOM & VEX manifest export. |
| **📊 Reporting** | `node hooks/report.js` | Generates interactive HTML dashboard. |
| | `node hooks/report.js --markdown` | Prints PR comment table for GitHub/GitLab. |
| | `node hooks/report.js --sarif` | Generates OASIS SARIF v2.1.0 for GitHub Code Scanning. |
| **⚙️ Policy & Wizard**| `node hooks/config.js --ui` | Launches browser configuration wizard. |
| | `node hooks/config.js --init` | Initializes default `.securecodingrc.json`. |
| | `node hooks/config.js --get <key>` | Reads configuration parameter. |
| **🔧 Autofix** | `node hooks/fix.js` | Lists open findings with fix blocks. |
| | `node hooks/fix.js --suggest <id>` | Shows Wrong vs Right guide for any pattern ID. |
| | `node hooks/fix.js --apply` | Applies in-place automated code refactoring. |
| | `node hooks/fix.js --dry-run` | Previews autofix diff without writing files. |
| **🧹 Quality** | `node hooks/clean.js` | Lints against 14 clean code standards. |
| | `node hooks/summary.js` | One-line status check (`3 open, 5 fixed`). |
| | `node hooks/stats.js` | Displays pattern metrics and false-positive rates. |
| **🔌 MCP Server** | `node mcp/server.js` | Launches native Model Context Protocol stdio server. |
| **✅ Done Gate** | `node hooks/gate.js --check` | Exits `2` if the staged code needs review and it is unanswered. |
| | `node hooks/gate.js --answer <q> "<a>"` | Records one answer: `ownership`, `authorization`, `taint`, `failure-direction`. |
| | `node hooks/gate.js --status` | Shows which questions remain. |
| | `node hooks/gate.js --check --all` | Force a full review even for a docs-only change. |
| | `git config secure-coding.gate false` | Turn commit blocking off for this repository. |
| **🧪 Testing** | `node hooks/sync.js` | Validates pattern regexes and template coverage. |
| | `node hooks/coverage.js` | Verifies all 213 OWASP SCP items are accounted for. |
| | `node hooks/detect.js` | Reports which languages a project uses. |
| | `node hooks/reset.js` | Clears findings state for a new session. |
| | `node hooks/test.js` | Executes the full 408-test self-check suite. |

---

## ✅ The Done Gate

**The problem:** the most common API breach is IDOR — fetching a record by an ID
from the request without checking the caller owns it. A scanner cannot see it.
`db.findById(req.params.id)` is correct code in one app and a data breach in
another; the difference is a check that *isn't there*. The same is true of a
route with no guard, and a `catch` block that lets the request through.

**The answer:** ask. Before a commit lands, four questions have to be answered in
writing:

| Question | What it asks |
|---|---|
| `ownership` | For each record fetched by an ID from the request, what scopes it to the caller? |
| `authorization` | For each new route, which guard denies an unauthenticated caller? |
| `taint` | Where does each request value end up — query, file path, shell, URL, template? |
| `failure-direction` | If the auth check throws, does the request end up denied? |

```bash
node hooks/gate.js --answer ownership "scoped by db.order.findFirst({where:{id, userId}})"
node hooks/gate.js --status     # what is still unanswered
node hooks/gate.js --check      # exits 2 until all four are answered
```

**It only asks when it matters.** A gate that fires on every commit teaches people
to reach for `--no-verify`, which would disable the scanner too — they share a
hook. So it inspects the staged files first, and stays silent unless one of them
handles a request, accesses data, or makes an authorization decision:

```
$ git commit -m "fix typo in README"
gate: skipped — no staged file handles requests, data access, or authorization

$ git commit -m "add order endpoint"
gate: review required — 1 staged file(s) handle requests or access data:
  routes/orders.js
```

**Answers have to say something.** `"yes"`, `"ok"`, `"x"` and a bare `"N/A"` are
rejected. Name the guard, the predicate, or the test — or write `N/A — <why it
does not apply>`. Answers are tied to the current commit, so the next change
needs its own review.

**On by default.** Disable per repository with `git config secure-coding.gate false`,
bypass one commit with `git commit --no-verify`, or force a full review of any
change with `node hooks/gate.js --check --all`.

---

## 🌐 Language Template Matrix

Each template shows the *correct* implementation of 25 controls in one language —
the version to copy when you are about to write that code. `N/A` marks a control
that does not apply to the language: shell scripts have no cookies, C has no CORS.

| # | Security Control | TS | JS | Py | Go | Rs | Java | Kt | Swift | C# | C | PHP | Rb | Sh |
|:--|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | Parameterized Query | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 2 | Password Hashing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 3 | Authenticated Encryption | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 4 | Secure Random | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 5 | Constant-Time Comparison | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 6 | Secure Temp Files | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 7 | Secure Cookie Flags | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| 8 | Safe Shell Execution | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 9 | Strict Input Validation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 10 | Output Encoding | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| 11 | TLS Configuration | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| 12 | Secrets via Env/Vault | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 13 | Safe Error Handling | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 14 | Secure Logging | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 15 | File Upload / Traversal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| 16 | Open Redirect Validation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| 17 | Cache-Control Headers | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| 18 | Session Regeneration | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| 19 | Password Complexity | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 20 | File Permissions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 21 | Envelope Encryption | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 22 | Cryptographic Integrity | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 23 | SSRF Prevention | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | ✅ |
| 24 | CORS Allowlist | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| 25 | Log Injection Sanitization | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 🤖 AI Agent Integrations

Each agent reads a different file to learn how to behave. `node install.js`
writes them all. They say the same thing: read `SKILL.md` before writing, scan
after, and answer the Done Gate before declaring the work done.

<details>
<summary><b>1. Google Antigravity</b> (Click to expand)</summary>

Add to `AGENTS.md` (or install globally via `node install.js --global`):
```markdown
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

## 🔌 How to Use Model Context Protocol (MCP) Properly

MCP lets an IDE or agent call the scanner directly instead of shelling out to
the CLI. Same engine, same results — it returns findings as structured data the
agent can act on.

`secure-coding` includes a native, zero-dependency JSON-RPC 2.0 MCP server ([`mcp/server.js`](mcp/server.js)). It gives AI agents direct access to 6 security tools without running subshells or polluting chat context.

### 🛠️ Available MCP Tools

| MCP Tool | Purpose | Example AI Prompt |
|---|---|---|
| `secure_code_scan` | Scans in-memory code snippets or staged files for 376 OWASP & SbD patterns. | *"Scan this authentication function for vulnerabilities."* |
| `secure_code_autofix` | Returns exact remediation diffs or refactors code in-place. | *"Fix the weak random number generator in auth.ts."* |
| `security_dependency_audit` | Scans lockfiles across 9 package ecosystems for CVEs. | *"Check package.json and requirements.txt for vulnerabilities."* |
| `clean_code_lint` | Lints source code against 14 universal Clean Code quality standards. | *"Lint my recent changes for clean code issues."* |
| `generate_ai_sbom` | Exports CycloneDX v1.5 / SPDX v2.3 SBOM with BSI 7 AI clusters & VEX data. | *"Generate a CycloneDX AI-SBOM with VEX exploitability."* |
| `security_summary` | Returns a one-line status of open vs resolved security findings. | *"Give me a security status summary of the workspace."* |

---

### ⚙️ Step-by-Step Configuration

#### 1. Google Antigravity
Create or add to `mcp_config.json` in your workspace project root:
```json
{
  "mcpServers": {
    "secure-coding": {
      "command": "node",
      "args": ["/absolute/path/to/secure-coding/mcp/server.js"],
      "description": "OWASP Secure Coding, AI-SBOM & Dependency Audit Engine"
    }
  }
}
```

#### 2. Claude Desktop
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

#### 3. Cursor IDE
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

#### 4. VS Code (Cline / Roo Code / Continue)
Add to your VS Code MCP settings:
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

### 🧪 Verify MCP Server Locally

Test that the MCP server responds correctly over stdio:

```bash
# List available tools over JSON-RPC 2.0:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | node mcp/server.js

# Test scanning a code snippet:
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secure_code_scan","arguments":{"code":"const key = \"AKIA1111111111111111\";"}}}' | node mcp/server.js
```

---

## 🧪 Validation & Test Suite

The skill checks itself. Three commands, all of which should pass before you
trust a change:

| Command | What it proves |
|---|---|
| `node hooks/test.js` | Every pattern still catches what it should, and still ignores safe code. |
| `node hooks/sync.js` | Patterns, templates and remediation blocks agree with each other. |
| `node hooks/coverage.js` | All 213 OWASP SCP items are accounted for. |

Verify all 408 test assertions, pattern compilation, secret masking, and MCP tools:

```bash
node hooks/sync.js && node hooks/test.js && node hooks/summary.js && node hooks/audit.js
```

---

<div align="center">

### 📄 License

MIT License • Built for engineers, security architects, and autonomous AI agents.

</div>

