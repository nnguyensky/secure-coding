# 🧾 Choosing Secure & Verifiable Technologies

*References: [Choosing secure and verifiable technologies](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/choosing-secure-and-verifiable-technologies) | [Executive guidance](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/choosing-secure-and-verifiable-technologies-executive-guidance)*

Use when **adopting** something rather than writing it: a new dependency, library, SaaS, model provider, or vendor product. Every procurement enlarges your attack surface, and the risk is not only the supplier's — it is their whole upstream supply chain.

You will not get answers to all of these. The goal is enough information to make an informed decision, and to record what you could not learn as accepted risk.

---

## 1. Transparency & Track Record
- [ ] Published **vulnerability disclosure policy** and program?
- [ ] Accurate, complete **CVEs** published for known issues (with CWE root causes)?
- [ ] Published **threat models** for the product?
- [ ] Published a **memory safe roadmap** (see `memory-safety.md`)?
- [ ] Does the manufacturer's reputation and incident history sit inside your risk tolerance?

## 2. Secure by Default
- [ ] Are security features in the **base product**, or behind a paywall (an "SSO tax")?
- [ ] Do default configurations ship at the **highest security setting**?
- [ ] **No default passwords** — confirmed by the manufacturer?
- [ ] **MFA or SSO** included, not an upsell?
- [ ] Are all configuration and setting changes **audited** by the product?
- [ ] Is there a guide describing the risk of changing each setting, and compensating controls?

## 3. Supply Chain & SBOM
- [ ] Is there a **Supply Chain Risk Management plan**, reviewed periodically?
- [ ] Has the manufacturer done **due diligence on its own suppliers**' Secure by Design practices?
- [ ] Any **single-supplier reliance** identified upstream, and mitigated?
- [ ] Does the **SBOM include inherited/transitive components**, in a spec that supports automated monitoring (CycloneDX/SPDX — see `sbom.md`)?
- [ ] Can the supplier **produce an SBOM at all**? Inability to is itself a risk signal.
- [ ] Are security advisories published in a machine-readable format (**CSAF**), with **VEX** exploitability status?
- [ ] Are releases **signed**, with anti-tampering verification available to you?

## 4. Open Source Posture
- [ ] Is there a documented **OSS management** policy (approval, rejection, training)?
- [ ] **Continuous monitoring** of all OSS components used?
- [ ] Have the **component repositories** been risk assessed, including how contributors are vetted?
- [ ] Has the manufacturer committed to **supporting modified OSS components** it ships, and the upstream communities it depends on?

## 5. Development Assurance
- [ ] Built following a **Secure by Design** methodology, in a secure development environment?
- [ ] **Attestation** against a standard (SSDF, ISM, CSA/ANSI T200:22)?
- [ ] Evidence of the **testing regimen** — penetration testing, unit/integration coverage, field testing?
- [ ] Was any third-party assessment a **desktop review or a real controls verification**? Against which maturity model, which product version, and how often is it repeated?

## 6. Data & Jurisdiction
- [ ] Is the manufacturer **collecting data** during your use? For what purpose?
- [ ] Is the **geographic location** of all data *and logs* specified in the contract — and verified?
- [ ] Are **backups** held in the contracted region — and verified?

## 7. Geopolitical & Continuity
- [ ] Does the manufacturer or its supply chain operate in **high-risk regions**?
- [ ] Mitigations for **geopolitical tension** or conflict affecting supply?
- [ ] **Trade restrictions or tariffs** affecting cost, availability, or security?
- [ ] What happens at **end of life** — support horizon, migration path, data export?

---

## Decision
Record the outcome explicitly. If the product exceeds your risk tolerance, name the treatment: **accept, transfer, avoid, or mitigate** — and if you accept, say who accepted it and when. Procurement risk is managed both **pre-purchase and post-purchase**; re-assess on renewal and after any supplier security incident.
