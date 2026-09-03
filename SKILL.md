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

## 🚀 4-Step Workflow

### Step 0: Before Deciding — Ask, Don't Guess

If the task creates or changes a **route, auth, tenancy, a data model, an
upload, an outbound call, or an LLM tool**, the security-relevant decisions are
not yours to assume. Run the interview in
[`checks/secure-grilling.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/secure-grilling.md):
ask the whole frontier in one round, recommend the secure default for each, and
wait for the answer.

Five frontiers, each pre-answering a Done Gate question: **identity & boundary**,
**tenancy & ownership**, **data classification**, **failure direction**, and
**action irreversibility**.

Skip this for a bug fix inside an existing boundary, a pure refactor, docs, or
tests. Look facts up yourself — only unsettled *decisions* go to the user.

### Step 1: Before Writing — Pick Rules & Architecture

1. **Check if your task touches a specialized domain:**
   - **System Architecture & Zero Trust** → [`checks/secure-by-design.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/secure-by-design.md) (OWASP SbD 36-control checklist, ACSC Modern Defensible Architecture, Ingress Normalization)
   - **Memory Safety & C/C++ Hardening** → [`checks/memory-safety.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/memory-safety.md) (Memory safe roadmap, language selection matrix, Safe Intermediary Wrappers, compiler flags)
   - **Keys & Cryptography** → [`checks/cryptography.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/cryptography.md) (FIPS 140-3 KMS, envelope encryption, chain of trust & revocation, positions of trust, PQC)
   - **IoT & Embedded Systems** → [`checks/iot-security.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/iot-security.md) (AS ETSI EN 303 645 13 principles, Secure Boot, JTAG lockout)
   - **Release & Deployment Safety** → [`checks/deployment-safety.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/deployment-safety.md) (Pre-mortem failure analysis, canary rollout pipeline)
   - **Supply Chain, AI-SBOM & VEX** → [`checks/sbom.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/sbom.md) (BSI 7 AI clusters, ACSC/CISA VEX exploitability states)
   - **Adopting a Dependency, Vendor or SaaS** → [`checks/technology-selection.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/technology-selection.md) (ACSC procurement questions, Secure by Default, supply chain & jurisdiction)
   - **AI/LLMs & Prompts** → [`checks/llm-top10.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/llm-top10.md) (Prompt injection, output handling, excessive agency, token caps)
   - **Settling Architecture Before Coding** → [`checks/secure-grilling.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/secure-grilling.md) (5 security frontiers, frontier rounds with secure defaults, pre-answers the Done Gate)
   - **Threat Modeling** → [`checks/threat-model.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/threat-model.md) (STRIDE & DREAD analysis)
   - **SSDF Attestation & Coverage** → [`checks/ssdf-mapping.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/ssdf-mapping.md) (NIST SP 800-218 PO/PS/PW/RV map, and the gaps this skill does not cover)
   - **Dynamic Testing & Fuzzing** → [`checks/dynamic-testing.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/dynamic-testing.md) (what to fuzz based on findings, tooling per language, races and authz matrices)
   - **OWASP Top 10 (2025) & CWE ids** → [`checks/owasp-top10-2025.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/owasp-top10-2025.md) (category → CWE → pattern map, and which categories patterns cannot cover)

2. **Identify which of the 9 code groups apply:**
   - (1) Data in/out • (2) Identity & Auth • (3) Secrets & Crypto • (4) Errors & Logs • (5) Storage & Transport • (6) Files & System • (7) Deployment & Config • (8) API Security • (9) Containers & Cloud

3. **Need a copy-paste secure pattern?** Load `templates/<language>.md` (13 languages supported).

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

1. **Auto-Scan:** `node hooks/scan.js --staged` (~1ms for a typical file,
   ~20ms for a 2000-line one). This includes
   multi-line taint tracking: request data assigned to a variable and later
   used in a file, HTTP, process, or query call is reported as `taint-*`.
   Disable with `"taintTracking": false` in `.securecodingrc.json`.
2. **Review Guidance:** Fix any flagged patterns using the provided `When / Wrong / Right / Watch` blocks.
3. **Autofix:** Run `node hooks/fix.js --apply` to automatically refactor common deterministic issues.
4. **Audit Dependencies:** `node hooks/audit.js` (scans package lockfiles).
5. **Quality Check:** `node hooks/clean.js --file <path>`.
6. **Done Gate:** Run `node hooks/summary.js && node hooks/audit.js && node hooks/gate.js --check`.

#### Done Gate Criteria:

**Tool checks — necessary, not sufficient:**
- [ ] `summary.js` reports `0 open` findings.
- [ ] `audit.js` reports `0 critical/high` vulnerabilities.
- [ ] Every finding is fixed in code (never marked as accepted or deferred).
- [ ] Tests pass cleanly (`node hooks/test.js`).
- [ ] `gate.js --check` reports complete.

**Manual review — enforced by `node hooks/gate.js --check`, which exits 2 until
every question is answered.** A green scan is not a pass on its own. Record each
answer as you go:

```bash
node hooks/gate.js --answer ownership "scoped by db.order.findFirst({where:{id, userId}})"
node hooks/gate.js --answer authorization "requireAdmin middleware on the router"
node hooks/gate.js --answer taint "N/A — no new request values"
node hooks/gate.js --answer failure-direction "catch returns 403; covered by test"
```

Enable commit-time blocking with `git config secure-coding.gate true` once the
git hooks are installed. "N/A" is valid when a question does not apply. `"yes"`, `"ok"` and `"done"` are
rejected — name the check. Answers are tied to the current commit, so new work
needs a new review. For every route, handler, or data access you added or
changed:

- [ ] **Ownership:** For each record fetched by an ID from the request, what
      scopes it to the caller? Name the check. `findById(req.params.id)` with
      no owner predicate is BOLA/IDOR — the single most common API breach, and
      no pattern can see it. (Smell 1, 4)
- [ ] **Authorization:** For each new route, which guard denies an
      unauthenticated or under-privileged caller? Deny-by-default, or a named
      middleware. An admin route with no guard scans clean. (Smell 2, 4)
- [ ] **Untrusted input reaching a sink:** Trace each request value to where
      it lands — query, file path, shell, outbound URL, template. Taint
      tracking catches the direct cases (`taint-*` findings), but only within
      one function and one hop; anything through a helper, an object field, or
      another module is yours to trace. (Smell 1)
- [ ] **Failure direction:** If the auth or permission check throws, does the
      request end up denied? (Smell 4)

If you cannot name the check, it does not exist — go add it.

---

## 🛡️ The 9 Security Code Groups

Identify which apply, then write to them. Full per-group requirements: [`checks/code-groups.md`](file:///Users/nhan/Personal/My%20AI%20Workspace/My%20Skills/secure-coding/checks/code-groups.md).

1. **Data In/Out** — validate server-side against an allowlist; parameterize every query; no unsafe deserialization; escape per output context.
2. **Identity & Access** — deny by default; verify ownership on every request; rotate session id on login; CSRF tokens; Argon2id.
3. **Secrets & Crypto** — env or KMS, never source; CSPRNG; constant-time compare; AES-GCM or ChaCha20-Poly1305.
4. **Failure & Visibility** — fail closed; generic errors to users; redact secrets and PII from logs; strip CR/LF.
5. **Storage & Transport** — TLS 1.3, HSTS, `Cache-Control: no-store`; least-privilege DB credentials.
6. **Files & System** — canonicalize and bound paths; validate uploads by content; argument arrays, never shell strings.
7. **Deployment & Config** — `DEBUG=False`; no default accounts; non-root containers; pinned lockfiles and Actions.
8. **API Security** — SSRF allowlists; rate limits; DTOs over mass assignment; max page size and body size.
9. **Containers & Cloud** — `runAsNonRoot`, drop ALL capabilities, NetworkPolicy, no host namespace sharing.


## ⚠️ What the Scanner Cannot See

The scanner matches regexes line by line. That makes it fast and precise on
what it covers, and structurally blind to everything below. **A clean scan
means "no known bad patterns matched" — never "this code is secure."**

| Blind spot | Why | Who catches it |
|---|---|---|
| **Missing checks** (IDOR/BOLA, absent authz, no rate limit) | A regex sees what is *present*. There is no pattern for a guard that was never written. | Done Gate manual review |
| **Taint beyond one hop** | The taint pass follows `var = <request data>` into a sink, plus one hop through interpolation, within a single function. Longer chains, helper calls, and object fields are not followed. | Done Gate manual review |
| **Cross-file / cross-function flow** | Each file is matched in isolation, with no call graph. | Design review, threat model |
| **Logic and business rules** | Price manipulation, workflow bypass, race conditions in app logic. | `checks/threat-model.md` |
| **Runtime and config state** | What is actually deployed, which env vars are set, real TLS termination. | Deployment review |
| **Novel or obfuscated code** | Only known shapes match; renamed or dynamically built calls slip past. | Human review |

Corollary: **never treat a finding count of zero as evidence of security.**
It is evidence that the mechanical layer found nothing — which is exactly
why Rule 1 puts the security in the first draft rather than the scan.

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
| **`clean.js`** | Universal clean code linter (14 rules) | `node hooks/clean.js --file <f>` |
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
