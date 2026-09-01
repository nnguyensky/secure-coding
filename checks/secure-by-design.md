# 🏛️ Secure by Design & Architecture Reference

*References: [Shifting the balance of cybersecurity risk](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/shifting-the-balance-of-cybersecurity-risk) | [ACSC Modern Defensible Architecture](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/modern-defensible-architecture) | [ACSC Cross Domain Solutions](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/cross-domain-solutions) | [OWASP SbD Framework](https://owasp.org/www-project-secure-by-design-framework/)*

---

## 1. The 3 Core SbD Pillars
1. **Take Ownership of Customer Security Outcomes**: Secure-by-Default (zero default passwords, MFA out of the box, no SSO tax, free UTC SIEM audit logging).
2. **Radical Transparency**: Maintain full SBOMs (CycloneDX/SPDX), publish accurate CVEs with CWE root causes, publish Memory Safe Roadmaps.
3. **Top-Down Organizational Leadership**: Treat security as a core dimension of product quality and reliability.

---

## 2. Modern Defensible Architecture & Zero Trust Invariants
- **Identity as the Perimeter**: Network topology and IP addresses no longer confer trust. Every request evaluates caller identity (OIDC/mTLS), device health, and contextual risk on every call.
- **"Assume Breach" (Micro-segmentation)**: Partition services into isolated blast-radius zones. The compromise of a public worker must not allow lateral movement to databases or admin planes.
- **Cross Domain Solutions (CDS)**:
  - Stratify domains: $\text{Untrusted Public} \rightarrow \text{Edge DMZ} \rightarrow \text{Core Tier} \rightarrow \text{Data Vault}$.
  - **Assured Ingress Pipeline**: Ingress data crossing a trust boundary must never pass as raw payloads. Parse, validate schemas, and transform into strongly typed domain objects before delegating to internal services.
  - **Anti-Backchannel**: Enforce unidirectional or verified flows to prevent high-trust data leakage.

---

## 3. OWASP SbD 40-Item Review Checklist (Architectural Categories)

| Domain | Key Architectural Invariants & Requirements |
|---|---|
| **Edge Gateway** | Single ingress point, SSL termination (TLS $\ge 1.3$), JWT token validation, IP/token rate limiting, request payload size limits. |
| **Inter-Service** | Mutual TLS (mTLS) with short-lived SPIFFE/x509 certs, token forwarding, circuit breakers with retry budgets, bulkheads, explicit request timeouts. |
| **Data Layer** | Database Row-Level Security (RLS) for multi-tenancy, parameterized queries, field-level encryption, KMS envelope encryption (DEK/KEK). |
| **Identity & Auth** | Centralized IdP (OIDC/SAML), phishing-resistant MFA (WebAuthn), least-privilege RBAC/ABAC, access tokens $\le 15\text{ mins}$, refresh token rotation. |
| **Resilience & Faults** | **Fail-Closed Authorization**: Unexpected errors or unreachable auth services must deny access, never permit. Graceful degradation. |
| **Audit & Telemetry** | ISO 8601 UTC timestamps, structured JSON logging, strict redaction of PII/credentials, tamper-evident write-only SIEM pipelines. |

---

## 4. Architecture Decision Record (ADR) Template (Agent Inline Format)
When designing new services or auth boundaries, document decisions in planning:
```markdown
### ADR-[Number]: [Title]
- **Status**: [Proposed | Accepted | Superseded]
- **Context & Trust Boundary**: [Describe caller, data flow, and trust tier transition]
- **Decision**: [Chosen architecture pattern, e.g., Edge API Gateway + Postgres RLS + OIDC]
- **Failure Mode & Fail-Closed Behavior**: [What happens on auth failure, network timeout, or downstream error]
- **Consequences**: [Trade-offs, performance impact, operational considerations]
```
