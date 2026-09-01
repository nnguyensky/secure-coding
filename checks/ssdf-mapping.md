# 🗂️ NIST SSDF (SP 800-218) Coverage Map

*Reference: [NIST SP 800-218, Secure Software Development Framework v1.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf)*

The SSDF is 4 practice groups / 20 practices / 48 tasks. It is **outcome-oriented**: it says what to achieve, not how. This maps the skill's tooling onto it, so you can answer "which SSDF tasks does this cover, and what still needs a human or a process?"

Use it when asked for an **SSDF attestation** (`technology-selection.md` asks vendors for exactly this), or to see where the skill stops.

---

## PO — Prepare the Organization
*Mostly organisational. The skill supports these; it cannot satisfy them alone.*

| Task | Covered by | Gap |
|---|---|---|
| PO.1.1–1.3 Define security requirements | `SKILL.md` 9 code groups, `checks/review.md` (147 checks covering all 213 OWASP SCP items) | Requirements must be adopted as policy and maintained over time. |
| PO.2.1–2.3 Roles & responsibilities | `cryptography.md` §5 positions of trust | Role assignment, training, and management commitment are yours. |
| PO.3.1–3.3 Supporting toolchains | `hooks/scan.js`, `audit.js`, `clean.js`, `sbom.js`, `report.js --sarif`; `.pre-commit-hooks.yaml`; CI workflow | **Toolchain must be deployed and its output acted on.** A configured tool nobody reads satisfies nothing. |
| PO.4.1–4.2 Criteria for security checks | Done Gate in `SKILL.md`; `summary.js` exit 2; `.securecodingrc.json` `failOn` | Define the release-blocking threshold for your risk appetite. |
| PO.5.1–5.2 Secure build environments | `secure-by-design.md` (segmentation, least privilege), `technology-selection.md` §5 | **Build-environment separation and hardening are infrastructure work, not code.** |

## PS — Protect the Software

| Task | Covered by | Gap |
|---|---|---|
| PS.1.1 Protect code from tampering | `sbom.md` §5 attestation & signing; secrets patterns | Repository access control and branch protection. |
| PS.2.1 Verify release integrity | `sbom.md` §5 (signing, provenance) | Publish the verification mechanism to consumers. |
| PS.3.1–3.2 Archive & protect releases, collect provenance | `sbom.js` (CycloneDX/SPDX, per-release SBOM retention) | Archival storage and retention policy. |

## PW — Produce Well-Secured Software
*The skill's core. Strongest coverage here.*

| Task | Covered by |
|---|---|
| PW.1.1 Design to meet security requirements | `secure-by-design.md` (OWASP SbD 36 controls), `threat-model.md` (STRIDE/DREAD) |
| PW.1.2 Threat modeling | `threat-model.md`; Done Gate manual review |
| PW.1.3 Reuse standard security services | `templates/<language>.md` (13 languages), `cryptography.md` |
| PW.2.1 Verify design meets requirements | Done Gate manual review; `secure-by-design.md` ADR template |
| PW.3.1–3.2 Verify third-party software | `audit.js` (9 ecosystems), `sbom.md`, `technology-selection.md` |
| PW.4.1–4.5 Reuse well-secured software | `templates/`, `memory-safety.md` §3 MSL matrix |
| PW.5.1–5.2 Secure coding practices | **`patterns/` (359 rules, 122 ids), taint tracking, `fixes.md` remediation** |
| PW.6.1–6.2 Harden build & compiler settings | `memory-safety.md` §5 compiler flags; `patterns/27-dockerfile.txt`, `30-terraform.txt` |
| PW.7.1–7.2 Code review / static analysis | `scan.js`, `clean.js` (14 rules), `review.md`, `report.js --sarif` for code scanning |
| PW.8.1–8.2 Test executable code | `test.js`; **dynamic/fuzz testing is a gap — see below** |
| PW.9.1–9.2 Secure settings by default | `patterns/` config rules (debug flags, default creds), `secure-by-design.md` |

## RV — Respond to Vulnerabilities

| Task | Covered by | Gap |
|---|---|---|
| RV.1.1–1.3 Identify vulnerabilities ongoing | `audit.js`; Dependabot (`.github/dependabot.yml`); `sbom.md` §2 continuous monitoring | Monitor advisories for components the audit tools do not reach. |
| RV.2.1–2.2 Assess, prioritise, remediate | `summary.js` severity gating, `fix.js`, VEX exploitability (`sbom.md` §4) | — |
| RV.3.1–3.2 Root cause analysis | `diagnose`-style investigation; `fixes.md` "Watch" notes | Recording RCA outcomes is a process. |
| **RV.3.3 Eradicate the vulnerability *class*** | **Add a `patterns/` rule + a regression test.** This is the skill's central mechanism: fix the class once, and every future scan enforces it. | — |
| RV.3.4 Update the SDLC to prevent recurrence | Amend `SKILL.md` / Done Gate; add a `sync.js` or `test.js` guard | Process change is yours. |

---

## Known gaps — do not claim these
- **Dynamic testing.** SSDF PW.8 expects executable testing; the joint memory-safety guidance specifically calls for **fuzzing**. This skill is static-analysis only. Pair it with fuzzing and DAST.
- **Runtime and deployment state.** PO.5 build-environment hardening and live configuration are outside a source scanner.
- **Anything organisational** — roles, training, policy, management commitment, retention. The skill produces evidence for these; it does not satisfy them.

> An SSDF attestation covering PW and RV is defensible with this tooling in place. PO and PS need process and infrastructure evidence alongside it.
