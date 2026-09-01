# STRIDE Threat Modeling Guide

Use during the architectural planning and design phase of any new feature, API route, or service.

---

## The STRIDE Framework

| Threat | Security Property | Core Question | Primary Mitigations |
|---|---|---|---|
| **S**poofing | Authenticity | Can an attacker pretend to be someone else? | Strong auth, MFA, signed JWTs/sessions, API key verification, mutual TLS. |
| **T**ampering | Integrity | Can an attacker modify data in transit or at rest? | Parameterized queries, message signatures (HMAC), immutable logs, schema validation. |
| **R**epudiation | Non-repudiation | Can a user deny performing an action? | Secure append-only audit logs, timestamped signing, transaction records. |
| **I**nformation Disclosure | Confidentiality | Can an attacker read private data or secrets? | TLS encryption, envelope encryption at rest, least-privilege DB access, PII masking. |
| **D**enial of Service | Availability | Can an attacker make the system unavailable? | Rate limiting, request size limits, query pagination, connection pools, circuit breakers. |
| **E**levation of Privilege | Authorization | Can an unprivileged user gain admin capabilities? | RBAC/ABAC checks on every handler, default-deny access control, tenant boundary checks. |

---

## 4-Step Feature Threat Modeling Process

### 1. Identify Assets & Trust Boundaries
- **Assets:** User passwords, billing data, private messages, internal API keys, database records.
- **Boundaries:** Public Internet &rarr; API Gateway &rarr; Backend Services &rarr; Database / External APIs.

### 2. Trace Data Flows
- Where does user input enter?
- What validation / sanitization occurs before reaching business logic or databases?
- Are cross-service internal calls authenticated?

### 3. Apply STRIDE Questions
- **Auth (S):** Is caller identity validated server-side on every request?
- **Data (T/I):** Are database queries parameterized? Are sensitive response fields filtered out?
- **Access Control (E):** If a user passes `orderId=123`, does the code verify that `order.tenantId == currentTenant`?
- **Resilience (D):** What happens if a client sends a 100MB payload or requests 1,000,000 records?

### 4. Record Decisions
Document any residual risks or mitigations directly in the feature's design plan or PR description.
