# Software Bill of Materials (SBOM), AI-SBOM & VEX Guide

> **Authoritative References:**
> - BSI & G7 Cybersecurity Working Group: *SBOM for AI - Minimum Elements* (May 2026)
> - ACSC, CISA, BSI, NCSC-UK, NSA, FBI: *Joint Guidance: A Shared Vision of Software Bill of Materials (SBOM) for Cybersecurity*
> - OWASP CycloneDX v1.5 / SPDX v2.3 Specifications

---

## 1. ACSC & CISA Joint SBOM Architecture Invariants

An enterprise-ready SBOM provides machine-readable inventory of software components, dependencies, and supply chain provenance:

1. **Standard Package URL (pURL)**:
   Every component must use unambiguous pURL format:
   `pkg:<type>/<namespace>/<name>@<version>?qualifiers#subpath`
   - Examples: `pkg:npm/%40angular/core@18.0.0`, `pkg:pypi/cryptography@42.0.5`, `pkg:cargo/tokio@1.38.0`.

2. **Cryptographic Hashes**:
   Every component should include SHA-256 / SHA-512 hashes of package artifacts or lockfile entries for tamper detection.

3. **Dependency Graph Relationships**:
   Differentiate direct vs. transitive dependencies (`dependsOn`, `contains`, `patches`, `derivedFrom`).

---

## 2. Generating & Using SBOMs (Joint Guidance)

**Where the SBOM comes from**, best first:
1. **Build-time tooling** — generated as part of the build, so it reflects what was actually shipped. Preferred.
2. **Source repository** analysis, when build integration is not available.
3. **Binary analysis**, for software that already exists — heuristic, so treat completeness as best-effort.

**An SBOM is only useful if it is machine-processable.** Emit a widely used format (CycloneDX/SPDX) with enough component detail to correlate against vulnerability databases automatically. A PDF or a wiki page is not an SBOM. Automate generation, management, *and* consumption — a file nobody ingests provides no security value.

**Three roles, three different uses** — an organisation is usually more than one:

| Role | What the SBOM is for |
|---|---|
| **Producer** | Track upstream components, respond to vulnerability disclosures, manage licence obligations, reduce code bloat, spot support/quality risk early. |
| **Chooser** | Make risk-informed acquisition decisions. *Whether a supplier can produce an SBOM at all is itself a procurement signal* (see `technology-selection.md`). |
| **Operator** | Understand exposure when a new CVE lands; triage which systems and missions are affected; apply compensating controls or isolation when no patch exists. |

**Lifecycle obligations**
- **Version and retain** SBOMs — you need the SBOM for the release that is actually deployed, not just the latest.
- **Request SBOMs from suppliers** and **provide them downstream**. Transparency only compounds if it propagates.
- **Continuously monitor** — an SBOM is a snapshot; new vulnerabilities appear in unchanged components. Log4Shell is the canonical case: the value was in answering "do we run this?" in minutes rather than weeks.
- Pair SBOM data with machine-readable advisories — **CSAF** for security advisories, **VEX** for exploitability status (§4).
- **Licence tracking** is a first-class use, not a side effect. A licence violation can force a recall or sale suspension.

> SBOM is how the Secure by Design principle of **radical transparency and accountability** is made concrete: build one per product, ask suppliers for theirs, and publish yours to customers.

---

## 3. BSI & G7 "SBOM for AI" — The 7 Information Clusters

AI and Machine Learning systems require specialized tracking across 7 distinct clusters:

*Cluster order and element names follow the BSI/G7 document. These are **additional** to the general SBOM minimum elements in §1 — an AI-SBOM does not replace them.*

| Cluster | BSI Minimum Elements | Machine-Readable Field (CycloneDX / JSON) |
|---|---|---|
| **1. Metadata** | SBOM author (the entity running the tool — distinct from the component's *producer*), SBOM version, data format name + version, **author signature**, tool name + version, **generation context**, timestamp, dependency relationship | `metadata.tools`, `metadata.timestamp`, `metadata.authors`, `signature` |
| **2. System-Level Properties (SLP)** | System name, components, producer, version, timestamp, **data flow**, **data usage**, input/output properties, intended application area | `component.properties["ai:system:*"]` |
| **3. Models** | Model name, identifier, version, timestamp, producer, description, **hash value + hash algorithm**, properties, input-output properties, **training properties**, license, external references | `component[type="machine-learning-model"]`, `modelCard.modelParameters` |
| **4. Datasets Properties (DP)** | Dataset name, description, content, identifier, hash, **provenance**, **statistical properties**, **sensitivity**, dependency relationship, license | `data.provenance`, `data.properties["ai:dataset:*"]` |
| **5. Infrastructure** | Infrastructure software (firmware, package managers, third-party libraries, frameworks, runtime environments, tools) and hardware | `component.dependencies`, `properties["ai:runtime"]` |
| **6. Security Properties (SP)** | Security controls (encryption, data minimization, differential privacy, access controls, API authentication, I/O anomaly detection, adversarial robustness, prompt-injection controls, input/output filters), **security compliance**, cybersecurity policy information, **vulnerability referencing** | `component.properties["ai:security:*"]` |
| **7. Key Performance Indicators (KPI)** | Security metrics, operational performance KPIs | `modelCard.quantitativeAnalysis.performanceMetrics` |

Elements in **bold** are the ones most often missing from a hand-rolled AI-SBOM.

> `node hooks/sbom.js --ai` emits a **complete scaffold**: every element listed above appears as a
> `bsi:cluster:<cluster>:<element>` property across all 7 clusters. Values that cannot be derived
> automatically carry the literal `TODO`, so nothing is silently missing and no placeholder can be
> mistaken for real data. The command reports how many remain — e.g.
> `AI-SBOM scaffold — 42/49 BSI elements still marked TODO` — on stderr, so piped JSON stays clean.
> Fill each one in or mark it not-applicable before publishing.

---

## 4. ACSC & CISA VEX (Vulnerability Exploitability eXchange)

VEX communicates the **actionable status** of a vulnerability in a component within the specific application context, eliminating vulnerability scanner noise:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345" },
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "Vulnerable parser method is not invoked by application ingestion pipeline."
      },
      "affects": [{ "ref": "pkg:npm/example-lib@1.2.0" }]
    }
  ]
}
```

### Standard VEX Exploitability States:
- `not_affected`: Component is present but cannot be exploited (requires `justification`).
- `affected`: Vulnerability is reachable and exploitable (requires recommended `action`).
- `fixed`: Patch or update has already been applied.
- `in_triage`: Vulnerability is under active investigation.

### VEX Justification Codes:
- `code_not_reachable`: The vulnerable function/code path is never called.
- `inline_mitigations_exist`: Upstream input validation/firewall prevents exploit payload.
- `requires_configuration`: Vulnerability only exists under non-default, unused configuration.
- `vulnerable_code_cannot_be_controlled_by_adversary`: Adversary cannot reach input interface.

---

## 5. Supply Chain Attestation & Signing

1. **In-Toto / Sigstore Signing**:
   ```bash
   # Generate CycloneDX SBOM
   node hooks/sbom.js --format cyclonedx --ai --vex --out sbom.cdx.json

   # Cryptographically sign SBOM using Sigstore Cosign
   cosign sign-blob --bundle sbom.bundle.json sbom.cdx.json
   ```
2. **Verification in CI/CD**:
   ```bash
   cosign verify-blob --bundle sbom.bundle.json --certificate-identity "https://github.com/org/repo" sbom.cdx.json
   ```
