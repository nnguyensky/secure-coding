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

## 3. OWASP SbD Review Checklist — 36 Controls in 5 Domains

*Control ids are the framework's own (AS/DM/RR/AC/MT), so a review can cite them directly.*

| Domain (control ids) | Key Architectural Invariants & Requirements |
|---|---|
| **A. Architecture & Service Design** (AS-01…08) | Trust zones enforced, cross-zone traffic only via a governed gateway/bus. Clear service boundaries, no circular dependencies, each service owns its data. Avoid long synchronous chains. Versioned API/event contracts with consumer notice before breaking changes. Durable messaging with a DLQ strategy. Startup resilience for missing dependencies. Legacy behind an anti-corruption layer. |
| **B. Data Management & Protection** (DM-01…06) | Data classified with named owners, controls proportional to classification. Encryption in transit (TLS/mTLS) and at rest with managed keys and rotation. Idempotent handlers with duplicate suppression. Sagas/compensations over 2PC. Retention/deletion policy per data class, with minimisation. Documented consistency model. Row-Level Security for multi-tenancy; parameterized queries. |
| **C. Reliability & Resilience** (RR-01…08) | Retries with exponential backoff + jitter. Circuit breakers and bulkheads; degraded modes for non-critical features. Defined async semantics (ordering, delivery guarantees, ack timeouts, monitored DLQs). HA shared integration layers that contain errors. Idempotency-Key on every mutating endpoint. Timeouts on all calls, health probes, multi-AZ failover. Quotas, autoscaling, edge rate limits. Caching and back-pressure. |
| **D. Access Control & Secure Comms** (AC-01…07) | TLS/mTLS everywhere with verified service identity (mesh-issued certs). Central IdP (OIDC/OAuth2), MFA on privileged paths, short-lived tokens. RBAC/ABAC over APIs *and* messaging publish/consume. Authorization centralized at gateway/mesh as policy-as-code. Secrets in a secret manager, keys/certs auto-rotating, never in code or logs. Regulatory controls identified with evidence. Least privilege extended to CI/CD, VCS apps, and third-party tooling. |
| **E. Monitoring, Testing & Incident Readiness** (MT-01…07) | Structured centralized logs with correlation/trace ids; admin access logged. Metrics/SLOs with actionable alerts. ASVS-aligned and negative tests drawn from threat modeling. SbD controls verifiable in test — isolation, mTLS, authZ denials, rate-limit behaviour. Published OpenAPI/AsyncAPI, current ADRs and runbooks. Rehearsed incident response plan. Audit retention $\ge 12$ months, tamper-evident, searchable hot window. |
| **Fail-Closed** (cross-cutting) | Unexpected errors or an unreachable auth service must deny access, never permit. Graceful degradation without privilege escalation. |

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
