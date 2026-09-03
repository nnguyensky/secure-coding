# 🔥 Secure Grilling — Settle the Architecture Before Writing

The worst vulnerabilities an agent introduces are not typos. They are
**assumptions made in silence**: a record fetched by id with no owner check, a
token in `localStorage`, an auth failure that falls open. The scanner cannot see
any of these, because nothing wrong is *present* — something necessary is
*absent*.

Ask first. A question costs a sentence; the same decision costs a refactor once
it is load-bearing.

## When to run this

Any task that creates or changes:
- a route, endpoint, or handler
- authentication, sessions, permissions, or tenancy
- a data model, migration, or anything storing user data
- an outbound call, upload, or third-party/LLM integration

**Skip it** for a bug fix inside an existing boundary, a refactor with no
behaviour change, docs, or tests. Grilling a typo fix is noise, and noise gets
the whole protocol ignored.

## How to ask

Work the decisions as a **tree**. The **frontier** is every decision whose
prerequisites are already settled — what you can ask now without guessing at an
answer you have not heard yet.

Ask the whole frontier in **one round**. Number each question, give options, and
**recommend the secure-by-default one**. Then wait.

```
❓ **Q1 — <title>**: <the question, with options>

  A (Recommended): <the secure default>
  B: <the common alternative>
  C: <the thing to avoid, named so it can be rejected explicitly>

➡️ **Recommended: A** — <one line on why, in terms of what it prevents>
```

Two rules that make this work:

- **Facts are your job, decisions are the user's.** If a question needs a fact
  from the codebase — which ORM, is there already a tenant column, what does the
  existing middleware do — go and look. Never ask the user something you can
  read. Only unsettled *decisions* go to them.
- **A question that depends on another open question belongs to a later round.**
  Do not ask "how do we scope by tenant" before "is this multi-tenant at all".

Stop when the frontier is empty. One or two rounds is normal; if you are on
round five, you are asking about things that are not decisions.

---

## Getting the questions

The questions are also available as data, so you do not have to retype them:

```bash
node hooks/gate.js --grill          # all five frontiers
node hooks/gate.js --grill api      # api | auth | storage | llm
```

Agents over MCP can call `get_security_frontier({ domain })` for the same text.
Both read `hooks/frontiers.js`, so the CLI, the MCP tool and this document
cannot drift apart.

## The 5 Security Frontiers

Each maps to a Done Gate question, so settling it here pre-answers the gate at
commit time.

### 1. Identity & Boundary → *gate: authorization*
- Who calls this? Anonymous public, authenticated user, internal service,
  background job, or an LLM tool call?
- How is that identity proven? Session cookie + CSRF token, bearer JWT, mTLS,
  signed API key?
- Which guard denies an unauthenticated caller, and is it deny-by-default?

### 2. Tenancy & Ownership → *gate: ownership*
- Is data segregated per user, per team, or per tenant?
- **Can caller A reach caller B's row?** Answer at the query level, not in prose.
- Recommended: scope in the query (`WHERE id = $1 AND org_id = $2`) or enforce
  with Row-Level Security. Fetch-then-compare in application code is a TOCTOU
  window and leaks existence through timing and error codes.

### 3. Data Classification & Storage → *gate: taint*
- Highest sensitivity handled: public, internal, PII, or secret/credential?
- Where does it live at rest, and is it encrypted — envelope/KMS for the top tier?
- What gets logged? Never the credential, never the full PII record.
- Where does each request value *end up*: query, file path, shell, outbound URL,
  template?

### 4. Resilience & Failure Direction → *gate: failure-direction*
- If the auth service, session store, or database times out — deny or allow?
  **The answer is deny.** Say it out loud so the code is written that way.
- Rate limits and quotas at the perimeter, or none?
- What does the caller see on failure: a generic message, never a stack trace.

### 5. Action Irreversibility & Agency
*Especially for LLM tools and anything an agent can call on its own.*
- Read-only, or state-changing?
- Irreversible — deletion, payment, email, external API write?
- Does it need confirmation, step-up auth, or an idempotency key?
- For an LLM tool: what is the blast radius if the model is prompt-injected into
  calling it with attacker-chosen arguments?

---

## Recording the outcome

Write the settled decisions down before you write code. Use the ADR template in
[`secure-by-design.md`](secure-by-design.md), or the plan file you are already
working from.

Then pre-answer the Done Gate, so the decision and the check are the same
sentence:

```bash
node hooks/gate.js --answer ownership "scoped in query: WHERE id = $1 AND org_id = $2"
node hooks/gate.js --answer authorization "requireAuth + requireOrgMember on the router"
node hooks/gate.js --answer taint "id from params -> parameterized query only; no file or shell sink"
node hooks/gate.js --answer failure-direction "auth store timeout returns 503, denies"
```

If an answer changes while you implement, update it. The gate records what the
code actually does, not what you intended at the start.
