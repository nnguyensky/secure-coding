---
name: secure-coding
description: Use when writing or changing code that handles user input, authentication, sessions, permissions, secrets, databases, files, network calls, AI/LLM prompts or tools, or raw memory. Write it secure the first time, then scan and answer the review questions before calling it done.
---

# Secure Coding

Two rules:

1. **Write it secure the first time.** Don't plan to fix it later. The scanner is a safety net, not the plan.
2. **Fix every finding.** Don't defer or ignore one. If a finding is genuinely wrong, suppress that one line with a reason (see below).

## Step 0 — Ask before deciding

If the task creates or changes a **route, login or permissions, tenancy, a data
model, a file upload, an outbound call, or an LLM tool**, some decisions are the
user's, not yours. Ask them in one message, each with the safe default you
recommend, then wait. The questions are in
[`checks/secure-grilling.md`](checks/secure-grilling.md):

- **Identity** — who can call this, and how do we know who they are?
- **Tenancy** — whose data is this, and what stops one user reading another's?
- **Data** — how sensitive is it: public, internal, personal, secret?
- **Failure** — if a check errors, do we deny or allow?
- **Irreversibility** — can the action be undone? Does it need confirmation?

Look up facts yourself; only ask about decisions. Skip this step for bug fixes
inside existing code, refactors, docs and tests.

## Step 1 — Before writing

Read only what the task needs:

| Task | Read |
|---|---|
| Any code in a known language | `templates/<language>.md` — copy-ready secure versions of 25 controls |
| Architecture, trust boundaries | [`checks/secure-by-design.md`](checks/secure-by-design.md) |
| Threats in a new feature | [`checks/threat-model.md`](checks/threat-model.md) |
| Keys, encryption, signing | [`checks/cryptography.md`](checks/cryptography.md) |
| LLM prompts, tools, RAG | [`checks/llm-top10.md`](checks/llm-top10.md) |
| C, C++, `unsafe` Rust | [`checks/memory-safety.md`](checks/memory-safety.md) |
| IoT and firmware | [`checks/iot-security.md`](checks/iot-security.md) |
| Choosing a library, vendor or SaaS | [`checks/technology-selection.md`](checks/technology-selection.md) |
| Releases and rollouts | [`checks/deployment-safety.md`](checks/deployment-safety.md) |
| SBOM, AI-SBOM, VEX | [`checks/sbom.md`](checks/sbom.md) |
| What to fuzz or test dynamically | [`checks/dynamic-testing.md`](checks/dynamic-testing.md) |
| Mapping to OWASP Top 10, CWE or NIST SSDF | [`checks/owasp-top10-2025.md`](checks/owasp-top10-2025.md), [`checks/ssdf-mapping.md`](checks/ssdf-mapping.md) |

The nine areas to check in every change are in [`checks/code-groups.md`](checks/code-groups.md):
data in/out, identity and access, secrets and crypto, errors and logs, storage
and transport, files and system, config, API limits, containers and cloud.

## Step 2 — While writing

```python
# Wrong: user input inside the SQL text
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Right: a parameter
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

- **Input** — validate on the server against an allowlist: type, length, format.
- **Output** — escape for where it goes: HTML, SQL, shell, URL, JSON.
- **Access** — deny by default. Check the caller owns every record they ask for.
- **Secrets** — from the environment or a secret manager. Never in code or logs.
- **Crypto** — use the standard library's high-level API (AES-GCM, Argon2id). Never build your own.
- **Errors** — fail closed. Show users a generic message; log the detail without secrets.
- **Packages** — never guess a package name. Look it up. A made-up name can be registered by an attacker.

Keep it readable too ([`checks/clean-code.md`](checks/clean-code.md)): named
constants instead of magic numbers, one job per function, few parameters, no
dead code.

## Step 3 — After writing

```bash
node hooks/scan.js --staged     # findings in what you changed
node hooks/deps.js              # packages you added: do they exist? are they new?
node hooks/fix.js --dry-run     # automatic fixes, if any; --apply to write them
node hooks/audit.js             # known advisories in lock files
```

Fix what they report, using the guidance printed with each finding (wrong code,
right code, what to watch for).

## Step 4 — Before saying "done"

```bash
node hooks/summary.js && node hooks/audit.js && node hooks/gate.js --check
```

`summary.js` must show `0 open`. `gate.js --check` fails until you answer four
questions that no scanner can check. For every route, handler or data access you
added or changed:

- **ownership** — for each record fetched by an ID from the request, what limits it to the caller? `findById(req.params.id)` with no owner check is the most common API breach.
- **authorization** — which guard stops an unauthenticated or under-privileged caller on each new route?
- **taint** — where does each request value end up: query, file path, shell, URL, template, prompt? The scanner follows one function and one hop; the rest is yours to trace.
- **failure-direction** — if the permission check throws, is the request denied?

```bash
node hooks/gate.js --answer ownership "scoped by findFirst({ where: { id, userId } })"
node hooks/gate.js --answer taint "N/A — no new request values"
```

Name the actual check. "N/A — reason" is fine; "yes" or "ok" is rejected. If you
cannot name the check, it does not exist yet: add it.

## What a clean scan does not prove

The scanner matches known bad patterns. It cannot see a check that is missing,
data flowing through helpers or other files, business-logic flaws, or what is
deployed. Zero findings means nothing known was matched, not that the code is
safe. That is why Step 0 and Step 4 exist.

Also watch for:

- untrusted data entering a trusted layer with no validation in between;
- one function serving both admins and normal users — split it;
- a secret passed through layers that do not need it;
- a permission check that allows on an empty list or unknown value;
- a value checked, then used later without a lock (time-of-check to time-of-use).

## Suppressing a finding

Only when the finding is genuinely wrong. Name the rule and give the reason, on the same line:

```ts
const r = eval(expr); // secure-coding-ignore: eval -- input is a fixed math grammar
```

```python
data = pickle.loads(blob)  # nosec: insecure-deserialization -- blob is HMAC-verified first
```

`all` is not accepted. Suppressions appear in the report and in SARIF, so
reviewers see them. Test and fixture folders can be excluded in
`.securecodingrc.json` with `"ignorePaths": ["tests/**"]`.

## Tools

| Command | Use |
|---|---|
| `node hooks/scan.js --staged` | Scan staged files (`--all`, `--files <paths>`) |
| `node hooks/deps.js` | Check packages you added |
| `node hooks/fix.js --suggest <id>` | Fix guidance for one rule |
| `node hooks/gate.js --grill` | The Step 0 questions for a domain (`api`, `auth`, `storage`, `llm`) |
| `node hooks/scan.js --history` | Secrets in past commits |
| `node hooks/scan.js --baseline` | Existing repo: record current findings so only new ones block |
| `node hooks/serve.js` | Dashboard for the user — give them the printed link |
| `node hooks/report.js --sarif` | SARIF for code scanning (`--markdown` for a PR comment) |
