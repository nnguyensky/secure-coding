# Scope notes

Every OWASP SCP item is now checked somewhere. This file records *where*,
for the items that cannot be verified by reading application source.

## Checked in config, not code

Group 7 of `checks/review.md` covers System Configuration [151-166],
default accounts [54,175,178], and the Access Control Policy [100].

The scanner checks these against the files you actually write:

| Check | Fires on |
|---|---|
| `debug-on` | settings, `.env`, `app.run(debug=True)` |
| `dir-listing` | nginx/apache config |
| `server-banner` | `server_tokens`, `expose_php` |
| `http-methods` | WebDAV, TRACE |
| `default-cred` | config, compose, `.env` |
| `container-root` | Dockerfile `USER root` |
| `container-priv` | `privileged: true` |
| `test-code` | `BYPASS_AUTH`, `SKIP_AUTH` flags |
| `default-db-account` | `GRANT ALL` |
| `docker-copy-secrets` | `COPY . .`, secrets in Dockerfile |
| `dockerfile-latest` | Unpinned `:latest` base image |
| `dockerfile-upgrade` | `apt-get upgrade` in Dockerfile |
| `dockerfile-env-secrets` | Secrets in `ENV` |
| `unpinned-action` | GitHub Actions pinned to tag |
| `lockfile-missing` | No lockfile committed |

## Verified by process, not by file

Six items have no artifact in a repo to grep. They stay as review
questions in group 7 and are answered by the team, not the scanner:

- [151,152] Current patched versions — belongs to a dependency scanner
  (Dependabot, `npm audit`, `pip-audit`) in CI
- [163] Configuration exportable for audit
- [164] Asset management system
- [165] Development environments isolated from production
- [166] Change control system
- [100] A written Access Control Policy

These are real requirements. They are organizational controls, so the
check is "does this exist", answered once, not per commit.

---

## OWASP Cheat Sheets — out of scope for code-level skill

The following OWASP cheat sheets cover organizational, design, process,
or infrastructure-level controls that cannot be verified by reading
application source code. They are documented here for completeness.

### Business Logic & Secure Design

| Cheat Sheet | Why out of scope |
|---|---|
| Business Logic Security | Flow control bypass, abuse cases — requires business context |
| Secure Product Design | Threat modeling, attack surface analysis — design-phase activity |
| Threat Modeling | STRIDE/DREAD analysis — requires architecture knowledge |
| Abuse Case | Identifying abuse scenarios — requires domain expertise |
| Attack Surface Analysis | Mapping entry points — requires full system view |

### Mobile & Client-Side

| Cheat Sheet | Why out of scope |
|---|---|
| Mobile Application Security (MASVS) | Mobile-specific threats, keychain, biometrics |
| Browser Extension Vulnerabilities | Extension-specific attack surface |
| HTML5 Security | HTML5 API-specific issues (Web Workers, etc.) |
| DOM Clobbering Prevention | DOM-based attacks requiring browser context |
| Third Party Javascript Management | Third-party script auditing |
| XS Leaks | Browser-side information leaks |
| AJAX Security | AJAX-specific patterns |

### AI, LLM & Agent Security

| Cheat Sheet | Why out of scope |
|---|---|
| AI Agent Security | Agent-specific threats, tool use, autonomy |
| LLM Prompt Injection Prevention | Prompt injection attacks on LLMs |
| RAG Security | Retrieval-augmented generation threats |
| Secure AI Model Ops | Model deployment, inference security |
| Secure Coding with AI | AI-assisted development risks |
| MCP Security | Model Context Protocol threats |

### Infrastructure & Cloud

| Cheat Sheet | Why out of scope |
|---|---|
| Secure Cloud Architecture | Cloud provider-specific controls |
| Zero Trust Architecture | Network-level zero trust design |
| Network Segmentation | Network architecture, VLANs, firewalls |
| Subdomain Takeover Prevention | DNS-level controls |
| Multi Tenant Security | Tenant isolation architecture |
| Drone Security | Embedded/IoT-specific threats |
| Automotive Security | Automotive-specific protocols |
| Legacy Application Management | Legacy system migration |

### CI/CD & Supply Chain

| Cheat Sheet | Why out of scope |
|---|---|
| CI/CD Security | Pipeline hardening (partially covered by `unpinned-action`) |
| Dependency Graph SBOM | Software bill of materials generation |
| Vulnerable Dependency Management | Dependency scanning process |

### Language & Framework-Specific

| Cheat Sheet | Why out of scope |
|---|---|
| Java Security | Java-specific crypto, deserialization, JAAS |
| .NET Security | .NET-specific GAC, CAS, Code Access Security |
| Laravel | Laravel-specific CSRF, Blade, Eloquent |
| Django Security | Django-specific middleware, CSRF, SQL escaping |
| Django REST Framework | DRF-specific serializers, viewsets |
| Ruby on Rails | Rails-specific strong parameters, CSRF |
| Symfony | Symfony-specific security component |
| PHP Configuration | `php.ini` security settings |
| Node.js Security | Node.js-specific prototype pollution, eval |
| Node.js Docker | Node.js Dockerfile best practices |
| Bean Validation | Java Bean Validation API |
| JAAS | Java Authentication and Authorization Service |

### Authentication & Session (broader patterns)

| Cheat Sheet | Why out of scope |
|---|---|
| Authentication | Full auth architecture (passwordless, MFA, OAuth flows) |
| Authorization | Full authorization design (ABAC, RBAC, ReBAC) |
| Multifactor Authentication | MFA enrollment, TOTP, WebAuthn |
| Choosing Security Questions | Security question design |
| Credential Stuffing Prevention | Rate limiting, bot detection at scale |
| Forgot Password | Password reset flow design |
| Session Management | Full session lifecycle (regeneration, timeout, fixation) |
| OAuth2 | Full OAuth2/OIDC flow design |
| SAML Security | SAML assertion validation, XML signing |
| Transaction Authorization | Step-up auth for high-value transactions |

### Input & Injection (broader patterns)

| Cheat Sheet | Why out of scope |
|---|---|
| Injection Prevention | Comprehensive injection guide (SQL, NoSQL, OS, LDAP) |
| Injection Prevention in Java | Java-specific injection (SpEL, OGNL) |
| LDAP Injection Prevention | LDAP-specific escaping |
| XML External Entity Prevention | XXE prevention (partially covered by `insecure-deserialization`) |
| XML Security | XML signature, encryption |
| DOM based XSS Prevention | DOM-specific sinks and sources |
| XSS Filter Evasion | WAF bypass techniques |
| Prototype Pollution Prevention | JavaScript prototype pollution |
| Deserialization | Full deserialization guide (broader than `insecure-deserialization` pattern) |

### Cryptography (broader patterns)

| Cheat Sheet | Why out of scope |
|---|---|
| Cryptographic Storage | Full key rotation, envelope encryption |
| Key Management | Key lifecycle, HSM, rotation policies |
| TLS Cipher String | Cipher suite selection |
| Transport Layer Security | Full TLS configuration |
| Transport Layer Protection | TLS deployment guide |
| Pinning | Certificate/public key pinning |

### Web Security (broader patterns)

| Cheat Sheet | Why out of scope |
|---|---|
| Content Security Policy | CSP header design, nonce/directive selection |
| HTTP Headers | Full security header suite |
| HTTP Strict Transport Security | HSTS preload, max-age tuning |
| Clickjacking Defense | X-Frame-Options, CSP frame-ancestors |
| Cookie Theft Mitigation | Full cookie security (flags, rotation) |
| Unvalidated Redirects and Forwards | Redirect validation (partially covered by `open-redirect`) |
| CORS | Full CORS preflight design |
| WebSocket Security | Full WS security lifecycle |
| gRPC Security | gRPC-specific auth, TLS |
| GraphQL | GraphQL-specific introspection, batching |
| REST Security | Full REST API security design |
| REST Assessment | REST API security testing |
| Web Service Security | SOAP, WS-Security |

### Logging & Monitoring

| Cheat Sheet | Why out of scope |
|---|---|
| Logging | Full logging architecture (SIEM, retention, alerting) |
| Logging Vocabulary | Event classification standards |

### DevOps & Deployment

| Cheat Sheet | Why out of scope |
|---|---|
| Serverless FaaS Security | Lambda/Cloud Functions isolation |
| Infrastructure as Code Security | Terraform/CloudFormation scanning |
| Docker Security | Full Docker daemon configuration |
| Kubernetes Security | Full K8s security architecture |

### Database

| Cheat Sheet | Why out of scope |
|---|---|
| Database Security | Full DB hardening (users, grants, encryption at rest) |
| NoSQL Security | Full NoSQL security guide |
| Query Parameterization | Parameterized query guide (partially covered by `sql-concat`) |

### Other

| Cheat Sheet | Why out of scope |
|---|---|
| Denial of Service | DoS mitigation at infrastructure level |
| Email Validation and Verification | Email verification flow design |
| Pinning | Certificate pinning implementation |
| Software Supply Chain Security | Full supply chain security program |
| Virtual Patching | WAF rules, virtual patches |
| Vulnerability Disclosure | Disclosure policy and process |
| Legacy Application Management | Legacy system migration security |
| Network Segmentation | Network architecture design |
| Securing CSS | CSS injection prevention |
