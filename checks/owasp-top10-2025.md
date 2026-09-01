# 🔟 OWASP Top 10 (2025) → CWE → Pattern Map

*Reference: [OWASP Top 10:2025](https://owasp.org/Top10/2025/)*

Use this to translate a scanner finding into the language auditors, SARIF consumers, and CVE reports expect: **pattern id → OWASP category → CWE**. Also use it to check whether a category has *any* mechanical coverage before claiming the scan was clean.

**What changed in 2025**: two new categories — **A03 Software Supply Chain Failures** (broader than 2021's "Vulnerable and Outdated Components") and **A10 Mishandling of Exceptional Conditions** (new). Injection dropped #3→#5; Cryptographic Failures #2→#4; Misconfiguration rose #5→#2.

---

| # | Category | Key CWEs | Skill coverage (pattern ids) |
|---|---|---|---|
| **A01** | Broken Access Control | 22, 23, 35, 59, 200, 276, 284, 285, 352, 425, 441, 497, 538, 552, 566, 601, 639, 862, 863, 913, 1275 | `path-traversal` `zip-slip` `csrf-exempt` `samesite` `cookie` `open-redirect` `oauth2-*` `sbd-unauthenticated-route` `dir-listing` `http-methods` `k8s-np` — **IDOR/BOLA and missing authz have no pattern** (Done Gate manual review) |
| **A02** | Security Misconfiguration | 2, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174 | `debug-on` `default-cred` `default-db-account` `dir-listing` `server-banner` `cors-*` `xxe` `container-*` `k8s-*` `docker*` `tf-password` `hostpath` `autocomplete-on` |
| **A03** | **Software Supply Chain Failures** *(new)* | 447, 477, 1035, 1104, 1329, 1357, 1395 | `npm-audit` `unpinned-action` `docker-digest` `dockerfile-latest` `dockerfile-curl-bash` `provisioner-*`; `audit.js` (9 ecosystems), `sbom.js`, Dependabot |
| **A04** | Cryptographic Failures | 261, 296, 319, 321, 326, 327, 328, 329, 330, 331, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916 | `weak-hash` `weak-crypto` `weak-rng` `pw-fast-hash` `pw-slow-hash` `tls-off` `sbd-legacy-tls` `secret-*` `jwt-*` `iot-unencrypted-*` `iot-hardcoded-flash-key` |
| **A05** | Injection | 20, 74, 77, 78, 79, 88, 89, 90, 91, 93, 94, 95, 97, 116, 117, 470, 471, 564, 643, 917, 943, 1236 | `sql-concat` `nosql-inject` `shell` `exec-py` `eval` `eval-input` `xss-sink` `ssti` `xxe` `log-inject` `prototype-pollution` `dynamic-include` `redos-input` + **taint-\*** (multi-line) |
| **A06** | Insecure Design | 73, 256, 269, 311, 312, 362, 434, 501, 522, 602, 653, 656, 799, 807, 840, 841, 1021, 1173 | `file-upload` `upload-exec` `temp-race` `mktemp` `API-*` `llm-excessive-agency`; **primarily `threat-model.md` + `secure-by-design.md`, not patterns** |
| **A07** | Authentication Failures | 258, 259, 287, 288, 290, 294, 295, 297, 304, 306, 307, 308, 384, 521, 613, 620, 640, 798, 940, 1216 | `default-cred` `jwt-*` `session-fixation` `oauth2-state` `oauth2-redirect` `pw-*-hash` `secret-*` `API-2` `ws-auth` `sbd-unauthenticated-route` |
| **A08** | Software or Data Integrity Failures | 345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926 | `insecure-deserialization` `unpinned-action` `docker-digest` `dockerfile-curl-bash` `rsc-unvalidated-action` `prototype-pollution`; signing/attestation in `sbom.md` §5 |
| **A09** | Security Logging & Alerting Failures | 117, 221, 223, 532, 778 | `log-inject` `log-leak` `set-hide-error` — **thin. Absence of logging cannot be pattern-matched**; see Done Gate and `secure-by-design.md` MT-01…07 |
| **A10** | **Mishandling of Exceptional Conditions** *(new)* | 209, 215, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 544, 584, 600, 636, 703, 754, 755 | `set-hide-error` `cc-swallowed-error` `cc-empty-throw` (via `clean.js`) — **weak coverage.** Fail-open on exception is a design smell: see Done Gate "failure direction" and `secure-by-design.md` Fail-Closed |

---

## Where the skill is weakest
Three categories cannot be substantially pattern-matched, because they are about what is **missing or wrongly structured**, not what is present:

- **A01** — missing ownership/authorization checks (IDOR/BOLA).
- **A09** — absent or unmonitored logging.
- **A10** — swallowed exceptions and fail-open error paths.

All three are covered by the **Done Gate manual review** in `SKILL.md`. A clean scan is not evidence for any of them — see *What the Scanner Cannot See*.

## Citing a finding
When reporting or writing a `fixes.md` entry, give the CWE alongside the pattern id: SARIF consumers, GitHub code scanning, and CVE records are all keyed on CWE. Example: `sql-concat` → **A05:2025 Injection** → **CWE-89**.
