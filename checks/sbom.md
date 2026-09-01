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

## 2. BSI & G7 "SBOM for AI" — The 7 Information Clusters

AI and Machine Learning systems require specialized tracking across 7 distinct clusters:

| Cluster | Key Elements | Machine-Readable Field (CycloneDX / JSON) |
|---|---|---|
| **1. Metadata** | Author, tool, timestamp, format spec, serial URN | `metadata.tools`, `metadata.timestamp` |
| **2. System-Level Properties (SLP)** | AI System name, primary intended use, deployment target (edge/cloud), input/output modalities | `component.properties["ai:system:use_case"]` |
| **3. Models** | Foundation model name, model architecture (Transformer/CNN), weight provenance, quantization (FP16/INT8/GGUF), license, hashes | `component[type="machine-learning-model"]`, `modelCard.modelParameters` |
| **4. Dataset Properties (DP)** | Dataset identifier, purpose (training/eval/fine-tuning/RAG), token count, cutoff date, provenance | `data.provenance`, `data.properties["ai:dataset:tokens"]` |
| **5. Key Performance Indicators (KPI)** | Benchmark scores (MMLU, GSM8k, BLEU, latency, perplexity), evaluation dates | `modelCard.quantitativeAnalysis.performanceMetrics` |
| **6. Security Properties (SP)** | Model guardrails, prompt injection sanitizers, weight encryption at rest, secure enclave / TEE | `component.properties["ai:security:guardrails"]` |
| **7. Infrastructure** | PyTorch / vLLM / ONNX versions, CUDA / ROCm version, GPU/TPU hardware requirements | `component.dependencies`, `properties["ai:runtime"]` |

---

## 3. ACSC & CISA VEX (Vulnerability Exploitability eXchange)

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

## 4. Supply Chain Attestation & Signing

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
