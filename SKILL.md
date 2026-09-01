---
name: secure-coding
description: Use when writing or changing code that handles user input, authentication, sessions, permissions, secrets, databases, files, network calls, AI/LLMs, or raw memory. Applies OWASP, Secure by Design, and Clean Code standards on first write.
---

# Secure Coding

**Rule 1: Never write insecure code to fix later.**
Apply security standards while writing the code. The first version of any function, route, or module must be secure. The scanner is a safety net, not the primary plan.

**Rule 2: Fix every finding before shipping.**
No finding is marked as accepted, deferred, or ignored without an explicit reviewed reason. Fix it immediately or remove the insecure code.

---

## 🚀 3-Step Workflow

### Step 1: Before Writing — Pick Rules & Architecture

1. **Check if your task touches a specialized domain:**
   - **System Architecture & Zero Trust** → [`checks/secure-by-design.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/secure-by-design.md) (OWASP 40-item checklist, ACSC Modern Defensible Architecture, Ingress Normalization)
   - **Memory Safety & C/C++ Hardening** → [`checks/memory-safety.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/memory-safety.md) (Language selection matrix, Safe Intermediary Wrappers, compiler flags)
   - **Keys & Cryptography** → [`checks/cryptography.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/cryptography.md) (FIPS 140-3 KMS, Envelope Encryption, Post-Quantum ML-KEM/ML-DSA)
   - **IoT & Embedded Systems** → [`checks/iot-security.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/iot-security.md) (AS ETSI EN 303 645 13 principles, Secure Boot, JTAG lockout)
   - **Release & Deployment Safety** → [`checks/deployment-safety.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/deployment-safety.md) (Pre-mortem failure analysis, canary rollout pipeline)
   - **Supply Chain, AI-SBOM & VEX** → [`checks/sbom.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/sbom.md) (BSI 7 AI clusters, ACSC/CISA VEX exploitability states)
   - **AI/LLMs & Prompts** → [`checks/llm-top10.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/llm-top10.md) (Prompt injection, output handling, excessive agency, token caps)
   - **Threat Modeling** → [`checks/threat-model.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/threat-model.md) (STRIDE & DREAD analysis)

2. **Identify which of the 9 code groups apply:**
   - (1) Data in/out • (2) Identity & Auth • (3) Secrets & Crypto • (4) Errors & Logs • (5) Storage & Transport • (6) Files & System • (7) Deployment & Config • (8) API Security • (9) Containers & Cloud

3. **Need a copy-paste secure pattern?** Load `templates/<language>.md` (12 languages supported).

---

### Step 2: While Writing — Build Securely & Cleanly

Write code that is secure by default from line one:

```python
# ❌ WRONG: String formatting in queries
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ RIGHT: Parameterized from the start
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

#### First-Write Security Checklist:
- **Input:** Validate server-side against an allowlist; check types and lengths.
- **Output:** Context-escape for HTML, SQL, shell, URL, or JSON.
- **Auth:** Deny by default, verify ownership on every request, fail closed.
- **Secrets:** Read from environment or secret manager; never hardcode or log.
- **Crypto:** Use high-level standard libraries (AES-GCM, Argon2id); never hand-assemble.
- **Errors:** Hide stack traces and internal details from end-users; log safely.

#### Clean Code Standards (`checks/clean-code.md`):
- **N3 (Constants):** Replace magic numbers with named constants.
- **F1 (Focus):** Functions do one thing. If a name has "And" (`saveAndEmail`), split it.
- **F2 (Parameters):** Max 2-3 parameters. Bundle larger sets into an options object.
- **F5 (Flags):** Avoid boolean flags in function arguments; split into separate functions.
- **T1 (Purity):** Return new values instead of mutating input arguments.
- **C1/C2 (Hygiene):** Delete dead code and commented-out blocks.

---

### Step 3: After Writing — Scan, Verify & Fix

Run verification to confirm zero open issues:

1. **Auto-Scan:** `node hooks/scan.js --staged` (runs in $<20\text{ms}$).
2. **Review Guidance:** Fix any flagged patterns using the provided `When / Wrong / Right / Watch` blocks.
3. **Autofix:** Run `node hooks/fix.js --apply` to automatically refactor common deterministic issues.
4. **Audit Dependencies:** `node hooks/audit.js` (scans package lockfiles).
5. **Quality Check:** `node hooks/clean.js --file <path>`.
6. **Done Gate:** Run `node hooks/summary.js && node hooks/audit.js`.

#### Done Gate Criteria:
- [ ] `summary.js` reports `0 open` findings.
- [ ] `audit.js` reports `0 critical/high` vulnerabilities.
- [ ] Every finding is fixed in code (never marked as accepted or deferred).
- [ ] Tests pass cleanly (`node hooks/test.js`).

---

## 🛡️ The 9 Security Code Groups

### 1. Data In / Data Out
*When handling user input, queries, templates, or external data:*
- **Input Validation:** Validate on the server side using strict allowlists and bounds. Never rely on client-side checks alone.
- **SQL / NoSQL Queries:** Always use parameterized queries or ORM bindings. Never concatenate input into query strings.
- **Deserialization:** Avoid unsafe formats (`pickle`, `yaml.load`, `unserialize`). Use JSON with schema validation.
- **Templates (SSTI):** Use static templates with bound context variables. Never render user strings as templates.
- **Object Assignment:** Disallow `__proto__` and `constructor` to prevent prototype pollution.
- **XML Parsing:** Disable external DTDs and entity expansion (`defusedxml` in Python).
- **Regular Expressions:** Escape user strings to prevent ReDoS, or use simple string methods.

### 2. Identity & Access Control
*When handling login, sessions, roles, and permissions:*
- **Route Authorization:** Deny by default. Verify permissions and tenant ownership on every request.
- **Object Access (BOLA/IDOR):** Scope database queries to the authenticated user ID (`db.find({ id, userId })`).
- **Session IDs:** Generate a new cryptographically secure session ID upon login. Invalidate on logout.
- **CSRF Protection:** Require anti-CSRF tokens or `SameSite=Strict/Lax` cookies for state-changing endpoints.
- **Password Storage:** Use `Argon2id` (preferred), `scrypt`, or `bcrypt` (cost 12+). Never use MD5 or SHA-256 for passwords.
- **OAuth2 / OpenID:** Validate random `state` on callback and enforce an exact redirect URI allowlist.
- **JWT Tokens:** Validate signature, algorithm, expiration (`exp`), audience (`aud`), and issuer (`iss`).

### 3. Secrets & Cryptography
*When encrypting, generating random values, or managing keys:*
- **Secret Storage:** Read secrets from environment variables or a KMS. Never commit secrets to source control.
- **Random Numbers:** Use cryptographically secure RNG (`crypto.randomBytes()`, `secrets`). Never use `Math.random()`.
- **String Comparison:** Use constant-time comparison (`timingSafeEqual`) for tokens, hashes, and signatures.
- **Ciphers:** Use authenticated encryption (AES-256-GCM or ChaCha20-Poly1305). Never use ECB mode, DES, or RC4.
- **Key Rotation:** Use envelope encryption (DEK/KEK) and maintain an automated rotation policy.

### 4. Failure & Visibility
*When handling errors, logging, and diagnostics:*
- **Fail Closed:** Ensure catch blocks deny access if an exception occurs during an auth or permission check.
- **User Error Messages:** Return generic messages to users. Never expose stack traces, database errors, or file paths.
- **Log Sanitization:** Redact passwords, API keys, session tokens, and PII before logging.
- **Log Injection:** Strip CR/LF characters (`\r`, `\n`) from user input before writing to text logs.

### 5. Storage & Transport
*When saving data, configuring TLS, or setting headers:*
- **Transport Security:** Enforce TLS 1.3 (or TLS 1.2 minimum) and set the `Strict-Transport-Security` (HSTS) header.
- **Sensitive Responses:** Add `Cache-Control: no-store` to prevent caching of private data.
- **Database Access:** Connect using least-privilege credentials; avoid superuser/admin roles.
- **WebSocket Handshake:** Validate the `Origin` header against an allowlist and authenticate in the connection handler.

### 6. Files & System Execution
*When working with paths, file uploads, archives, or subprocesses:*
- **Path Traversal:** Canonicalize paths and verify they reside within the intended directory boundary.
- **File Uploads:** Validate file contents by MIME type/magic bytes, generate unique filenames, and store outside the web root.
- **Archive Extraction (Zip Slip):** Verify target paths remain inside the target directory before extracting files.
- **Command Execution:** Pass arguments as an array/list. Never pass unescaped user input to `shell=True` or `exec`.
- **C/C++ Buffers:** Use bounded operations (`strncpy`, `snprintf`); avoid `strcpy`, `strcat`, and `gets`.

### 7. Deployment & Configuration
*When setting up environments, Dockerfiles, or CI/CD pipelines:*
- **Debug Flags:** Ensure `DEBUG=False` and development seams are disabled in production builds.
- **Default Accounts:** Remove or randomize default passwords and admin accounts.
- **Container Privilege:** Run containers as non-root users (`USER 10001`) with read-only root filesystems.
- **Dependency Pinning:** Pin dependencies in lockfiles (`package-lock.json`, `Cargo.lock`, `go.sum`, `poetry.lock`).
- **CI/CD Security:** Pin third-party GitHub Actions to full commit SHAs.

### 8. API Security
*When building REST, GraphQL, or gRPC APIs:*
- **SSRF Prevention:** Validate outgoing request URLs against an allowlist; block internal IP ranges (`10.0.0.0/8`, `127.0.0.1`).
- **Rate Limiting:** Enforce rate limits per user/IP, especially on authentication and password-reset routes.
- **Mass Assignment:** Use strict input allowlists / DTOs rather than binding request bodies directly to database models.
- **Pagination:** Set strict default and maximum page limits on collection endpoints.
- **Request Size:** Enforce a maximum request body size limit to prevent memory exhaustion.

### 9. Containers & Cloud
*When writing Dockerfiles, Kubernetes manifests, or IaC:*
- **Non-Root Execution:** Set `runAsNonRoot: true` and specify non-zero UIDs in security contexts.
- **Privileged Containers:** Remove `privileged: true` and drop all unnecessary Linux capabilities (`drop: ["ALL"]`).
- **Network Isolation:** Apply Kubernetes `NetworkPolicy` to restrict traffic between namespaces and pods.
- **Host Sharing:** Disable host namespace sharing (`hostNetwork`, `hostPID`, `hostIPC`).

---

## 🔍 Security Smells & Baseline Review

Even when no automated pattern flags, check for these design smells:

1. **Hidden Trust Boundary:** Untrusted data moves into trusted layers without visible validation.
   *Fix:* Validate at the edge, sanitize, and pass typed domain objects.
2. **Mixed Privilege in One Function:** A function handles both admin and normal user branches.
   *Fix:* Split into two distinct functions with separate permission guards.
3. **Over-Scoped Secrets:** A secret is passed through multiple layers that don't need it.
   *Fix:* Pass only the derived token or perform the operation within a specialized service.
4. **Implicit Allow:** An auth check allows access when an unknown condition or empty list occurs.
   *Fix:* Invert the logic to deny access by default.
5. **Time-of-Check to Time-of-Use (TOCTOU):** A resource state is checked and then modified without a lock.
   *Fix:* Use atomic operations or acquire a database/file lock.

---

## 🧰 Tool & Script Quick Reference

| Tool | Purpose | Primary Command |
|---|---|---|
| **`scan.js`** | Fast mechanical scan with line snippets & entropy engine | `node hooks/scan.js --staged` |
| **`install.js`** | Interactive setup wizard (Git hooks, tasks, agent rules) | `node install.js` |
| **`summary.js`** | One-line status check & automated done gate | `node hooks/summary.js` |
| **`audit.js`** | Dependency vulnerability scan across 9 ecosystems | `node hooks/audit.js` |
| **`fix.js`** | View remediation guidance or apply automated refactors | `node hooks/fix.js --apply` |
| **`sbom.js`** | CycloneDX v1.5 & SPDX v2.3 SBOM with AI-SBOM & VEX | `node hooks/sbom.js --ai --vex` |
| **`clean.js`** | Universal clean code linter (22 rules) | `node hooks/clean.js --file <f>` |
| **`report.js`** | Export HTML report, PR Markdown, or SARIF v2.1.0 | `node hooks/report.js --sarif` |
| **`config.js`** | Manage policy or launch visual browser UI | `node hooks/config.js --ui` |
| **`mcp/server.js`** | Native Model Context Protocol (MCP) stdio server | `node mcp/server.js` |

---

### One Finding Per Occurrence

Three SQL injections in one file are **three findings**, tracked separately by
`(file, id, line)`. Fixing one closes only that one — the siblings stay open,
so a partial fix can never silently clear a live vulnerability.

- Scan output, `stats.js`, and SARIF all report every occurrence with its line.
- `fix.js --apply` still runs **once per file per id**: an autofix rewrites the
  whole file, so applying it per occurrence would be redundant.
- Occurrences per id per file are capped at **20** (override with
  `SECURE_CODING_MAX_OCCURRENCES`) so a generated or minified file cannot flood
  the report. The finding is still reported; only the line list is truncated.

---

### One Defect, One Finding

Patterns are layered: a broad catch-all rule and a language-specific rule often
match the same code. The scanner reports each defect **once**:

- **Same id, same file** — deduplicated automatically (first match wins).
- **Different ids, same line** — the more specific finding supersedes the
  generic one via `SUPERSEDES` in `hooks/scan.js` (e.g. `secret-aws-key` absorbs
  `secret`; `jwt-none-alg` absorbs `jwt`).
- **Two genuinely different defects on one line** — both are reported. Disabled
  cert verification and a missing timeout are separate bugs and must both show.

**Adding a pattern?** If it overlaps an existing rule, either reuse that rule's
id (preferred — keeps one id per defect across languages) or add a `SUPERSEDES`
entry. Never leave two ids describing the same defect with the same fix; run
`node hooks/test.js` to confirm nothing double-reports and nothing is lost.

---

### Suppressing Reviewed Exceptions

For intentional, reviewed exceptions, suppress a finding on a single line with an inline comment:

```ts
// secure-coding-ignore: eval
const result = eval(sanitizedMathExpression);
```

```python
# nosec: insecure-deserialization
data = pickle.loads(trusted_internal_blob)
```

To exclude test directories or mock files, add paths to `.securecodingrc.json`:
```json
{
  "ignorePaths": ["tests/**", "fixtures/**", "scripts/seed/**"]
}
```
