# Secure Coding Review

Load this only when reviewing finished code. It is the full OWASP SCP
checklist, organized by the same nine groups as `SKILL.md`.

How to use it: read the code, identify which groups it touches, and check
only those. Each item is a check — if the answer is no, fix it before
declaring the code done. The mechanical mistakes are already caught by
`hooks/scan.js`; this catches what grep cannot: absence, indirection, and
context.

Tags: **[HARD]** = non-negotiable, always a violation. **[JUDGEMENT]**
= depends on context, policy, or organizational decisions.

Word budget: keep the review under 400 words. Quote the specific code
that violates a rule. One line per finding. Skip anything the scanner
already catches.

---

## 1. Data in / Data out

**When:** code accepts input from outside the process, or writes output a
user or another system will interpret.

- [ ] Is all validation on the server, not the client? **[HARD]** [1,2,3,24,31,59,101,113]
- [ ] Is validation allowlist-based (what is valid), not blocklist-based? **[JUDGEMENT]** [14,15]
- [ ] Do validation failures reject the input, not clean it up and continue? **[HARD]** [6,168]
- [ ] Are data type, range, and length validated? **[HARD]** [11,12,13,169]
- [ ] Is input canonicalized (single encoding) before validating? **[HARD]** [4,5,7,149]
- [ ] Are null bytes, newlines, and `../` path characters rejected? **[HARD]** [16,8,9,10]
- [ ] Is SQL parameterized, never built by joining strings? **[HARD]** [167,21]
- [ ] Are shell commands passed as argument lists, never a shell string? **[HARD]** [22,203]
- [ ] Are LDAP, XML, and XPath queries parameterized or escaped? **[HARD]** [21]
- [ ] Is output escaped for its exact context (HTML body, attribute, JS, URL, SQL)? **[HARD]** [17,18,19,20]
- [ ] Is untrusted data never deserialized into objects (`pickle`, `yaml.load`, `unserialize`)? **[HARD]** [194]
- [ ] Are file paths built from input resolved and confirmed inside the intended directory? **[HARD]** [190,191]
- [ ] Are URLs from user input validated against an allowlist before making server-side requests (SSRF prevention)? **[HARD]** [API-1]
- [ ] Is user input validated by type and value before use in NoSQL queries (MongoDB operator injection prevention)? **[HARD]** [NoSQL]
- [ ] Are all input data sources identified and classified as trusted or untrusted? **[JUDGEMENT]** [2]

## 2. Identity

**When:** code authenticates a user, manages a session, or checks permission.

- [ ] Is every handler that touches a record scoped to the caller, or does it check ownership? **[HARD]** [77,86,88,89]
- [ ] Does every protected route deny by default, on the server, on every request? **[HARD]** [23,78,79,80,81,84,85,87,90,91,95]
- [ ] Is privileged logic segregated from ordinary application code? **[JUDGEMENT]** [82]
- [ ] Is access restricted to files and resources outside the application's direct control? **[HARD]** [83]
- [ ] Is client-stored state encrypted and integrity-checked server-side to catch tampering? **[HARD]** [92]
- [ ] Do enforced logic flows follow the business rules, not just individual permission checks? **[JUDGEMENT]** [93]
- [ ] Can accounts be disabled and their sessions terminated when authorization ceases? **[JUDGEMENT]** [97,98]
- [ ] Is a new session id created at login and at privilege change? **[HARD]** [66,67,71,72]
- [ ] Is a caller-supplied session id never accepted? **[HARD]** [58,59,60]
- [ ] Are session cookies `HttpOnly`, `Secure`, `SameSite`, with idle and absolute timeouts? **[HARD]** [61,64,65,75,76]
- [ ] Does logout destroy the server-side session, not just the cookie? **[HARD]** [62,63,70]
- [ ] Are session identifiers regenerated periodically, not just at login or privilege change? **[JUDGEMENT]** [60]
- [ ] Is the referer header used only as a supplemental authorization check, never as the sole check? **[HARD]** [93]
- [ ] Do permission checks fail closed (error = deny)? **[HARD]** [28,79,103,112]
- [ ] Do state-changing requests carry a per-session or per-request CSRF token? **[HARD]** [73,74]
- [ ] Are login attempts rate-limited or locked out after N failures? **[HARD]** [41,53,94]
- [ ] Do "no such user" and "wrong password" return identical message and timing? **[HARD]** [33,32]
- [ ] Are critical operations re-authenticated? **[JUDGEMENT]** [55,96]
- [ ] Is MFA used for highly sensitive accounts? **[JUDGEMENT]** [56]
- [ ] Are password reset flows as strongly controlled as login (pre-registered address, short-lived single-use token, forced change, user notified)? **[JUDGEMENT]** [42,43,44,45,46,47]
- [ ] Are credentials sent only by POST over an encrypted connection, never in a URL or GET? **[HARD]** [36,37]
- [ ] Is password entry obscured, with autocomplete and "remember me" disabled on password fields? **[HARD]** [40,51]
- [ ] Are password re-use and minimum-age rules enforced where policy requires? **[JUDGEMENT]** [48,49,50]
- [ ] Is authentication used for connections to external systems handling sensitive data? **[HARD]** [34]
- [ ] Are authentication controls centralized and segregated from the resource being requested? **[JUDGEMENT]** [26,27,29]
- [ ] Is the last login (success or failure) reported to the user, and are concurrent logins handled per policy? **[JUDGEMENT]** [52,68]
- [ ] Is the session ID regenerated after successful login (session fixation prevention)? **[HARD]** [66,67]
- [ ] Does the OAuth2 flow use a cryptographically random `state` parameter validated server-side? **[HARD]** [OAuth2]
- [ ] Is the OAuth2 `redirect_uri` validated against pre-registered URIs, never accepted from user input? **[HARD]** [OAuth2]
- [ ] Are OAuth2 access tokens verified for signature, expiration, and audience before use? **[HARD]** [OAuth2]
- [ ] Are WebSocket connections authenticated after upgrade, not just trusted from the HTTP handshake? **[HARD]** [WebSocket]
- [ ] Are WebSocket connections validated against a trusted Origin header to prevent cross-site hijacking? **[HARD]** [WebSocket]
- [ ] Are passwords hashed with `argon2id` (or `scrypt`/`bcrypt` 12+), never a fast hash? **[HARD]** [30,38,39]
- [ ] Are passwords never stored in plaintext or with reversible encryption? **[HARD]** [30,31]
- [ ] Are password hashes salted with a unique, random salt per user? **[HARD]** [31]
- [ ] Is the credential store writable only by the application? **[HARD]** [35,70]

## 3. Secrets & Crypto

**When:** code stores, hashes, encrypts, or generates anything secret or random.

- [ ] Are secrets read from the environment or a secret manager, never source/config/log/URL? **[HARD]** [35,102,135,172]
- [ ] Are passwords hashed with a slow, salted algorithm (`argon2id`)? **[HARD]** [30,31]
- [ ] Are tokens, ids, salts, and resets generated with the crypto RNG, not `random()`? **[HARD]** [60,104]
- [ ] Are secrets compared in constant time? **[HARD]** [32]
- [ ] Are only authenticated ciphers used (AES-GCM, ChaCha20-Poly1305), never ECB/DES/RC4? **[HARD]** [133,105]
- [ ] Is the library's high-level crypto API used, never a hand-assembled cipher? **[HARD]** [25,101,105]
- [ ] Is there a key-management policy (rotation, storage, access)? **[JUDGEMENT]** [106,102]
- [ ] Do cryptographic modules fail securely rather than exposing sensitive data on error? **[HARD]** [105]

## 4. Failure & Visibility

**When:** code handles an error, or logs an event.

- [ ] Do security controls fail closed on error? **[HARD]** [28,79,103,110,112,155]
- [ ] Do user-facing errors avoid stack traces, SQL, file paths, and library versions? **[HARD]** [107,108]
- [ ] Are generic error messages and custom error pages used? **[HARD]** [109]
- [ ] Are security events logged: login success/failure, permission denials, validation failures, admin actions? **[JUDGEMENT]** [114,115,121,122,123,124,125,126,127,128,129]
- [ ] Are passwords, tokens, keys, card numbers, and session ids never logged? **[HARD]** [119,69]
- [ ] Is untrusted data in logs sanitized so it cannot execute in the log viewer? **[HARD]** [116]
- [ ] Is user input stripped of CR/LF and delimiter characters before logging (log injection prevention)? **[HARD]** [116,117]
- [ ] Are passwords, tokens, API keys, secrets, and PII never written to log output? **[HARD]** [119,69]
- [ ] Is log access restricted to authorized individuals? **[JUDGEMENT]** [117,130]
- [ ] Is there a mechanism to analyze logs? **[JUDGEMENT]** [118,120]
- [ ] Are log files stored with appropriate retention and disposal policies? **[JUDGEMENT]** [118,130]

## 5. Storage & Transport

**When:** code stores data, or sends it over a connection.

- [ ] Is sensitive data never in GET parameters? **[HARD]** [138,150,69]
- [ ] Are sensitive forms `Cache-Control: no-store` and `autocomplete=off`? **[HARD]** [139,140]
- [ ] Are temp/cached copies of sensitive data purged when no longer needed? **[JUDGEMENT]** [132,141,142]
- [ ] Is server-side source code not downloadable, with revealing comments and docs stripped from production? **[JUDGEMENT]** [134,136,137]
- [ ] Is TLS used everywhere, with verification on, never disabled? **[HARD]** [143,144,146,147,148]
- [ ] Do failed TLS connections fail, not fall back to insecure? **[HARD]** [145]
- [ ] Is the `Strict-Transport-Security` (HSTS) header set with a long max-age to prevent SSL stripping? **[HARD]** [HSTS]
- [ ] Are WebSocket connections authenticated and authorized after the upgrade handshake? **[HARD]** [WebSocket]
- [ ] Are WebSocket Origin headers validated against a trusted allowlist? **[HARD]** [WebSocket]
- [ ] Is the database account least-privilege, never admin? **[HARD]** [170,131,154]
- [ ] Is a separate credential used per trust level? **[JUDGEMENT]** [179,171,99]
- [ ] Are connection strings stored on a trusted system, not hard-coded? **[HARD]** [172]
- [ ] Are connections closed as soon as possible? **[JUDGEMENT]** [174,199]
- [ ] Are stored procedures used to abstract data access where they remove base-table permissions? **[JUDGEMENT]** [173]
- [ ] Are default database accounts and passwords changed or disabled, and unused features turned off? **[HARD]** [175,176,177,178]

## 6. Files & System

**When:** code reads or writes files, runs commands, or manages resources.

- [ ] Are uploads validated by file header, not extension? **[HARD]** [183,182]
- [ ] Is file upload MIME type validated server-side (not just Content-Type header)? **[HARD]** [183]
- [ ] Are upload file sizes enforced with a maximum limit? **[HARD]** [183]
- [ ] Are uploads saved where the server cannot execute them? **[HARD]** [184,185,186,187]
- [ ] Are uploaded file names and types allowlisted? **[HARD]** [188,193]
- [ ] Is authentication required before an upload is accepted? **[HARD]** [181]
- [ ] Are application files and resources read-only where possible? **[JUDGEMENT]** [192]
- [ ] Are user-supplied paths resolved and confirmed inside the intended directory? **[HARD]** [180,190]
- [ ] Are redirect targets allowlisted, never a user-supplied URL? **[HARD]** [189]
- [ ] Is the absolute file path never sent to the client? **[HARD]** [191]
- [ ] Is `eval`/`exec`/`shell=True`/`os.system` never used on input-touched data? **[HARD]** [210,211]
- [ ] Is shared state synchronized against race conditions? **[HARD]** [205,206]
- [ ] Are privileges raised late and dropped early? **[JUDGEMENT]** [208]
- [ ] Is third-party code reviewed for necessity and safety? **[JUDGEMENT]** [57,212,213,204]
- [ ] Are variables explicitly initialized before first use? **[JUDGEMENT]** [203]
- [ ] Are checksums or hashes used to verify the integrity of interpreted code, libraries, and configuration files? **[JUDGEMENT]** [210]
- [ ] Are C/C++ copies bounded, allocations checked, and memory freed once? **[HARD]** [195,196,197,198,201,202,111,200,207,209]
- [ ] Are resources (connections, file handles) closed explicitly, not left to GC? **[JUDGEMENT]** [199]

## 7. Deployment & Configuration

**When:** code touches config files, containers, CI, web-server rules, or
database grants. These are checked in the files you write, not at runtime.

- [ ] Is debug mode off, with no development env leaking into a deployable config? **[HARD]** [157,162]
- [ ] Are directory listings turned off and the directory structure not disclosed? **[HARD]** [153,158]
- [ ] Are server, framework, and language version banners stripped from responses? **[HARD]** [162]
- [ ] Are only the HTTP methods the app uses enabled, with WebDAV and TRACE off? **[HARD]** [159,160,161]
- [ ] Are all vendor default accounts and passwords changed or disabled? **[HARD]** [54,175,178]
- [ ] Do containers run as a non-root user, unprivileged, with capabilities dropped? **[HARD]** [154]
- [ ] Is test code, and every auth-bypass flag, absent from anything deployable? **[HARD]** [156,157]
- [ ] Are unnecessary features, sample content, and default schemas removed? **[JUDGEMENT]** [156,176,177]
- [ ] Are servers, frameworks, and dependencies on a current patched version? **[JUDGEMENT]** [151,152]
- [ ] Is the security configuration exportable in human-readable form for audit? **[JUDGEMENT]** [163]
- [ ] Are components registered in an asset management system? **[JUDGEMENT]** [164]
- [ ] Are development environments isolated from the production network? **[JUDGEMENT]** [165]
- [ ] Is there a change control system recording code changes? **[JUDGEMENT]** [166]
- [ ] Is there a written Access Control Policy documenting rules and criteria? **[JUDGEMENT]** [100]
- [ ] Does the Dockerfile use COPY instead of ADD, and copy only needed files (not `COPY . .`)? **[HARD]** [Docker]
- [ ] Are base images pinned to specific versions (not `:latest`)? **[HARD]** [Docker]
- [ ] Are secrets excluded from Docker build context (no `ENV PASSWORD=...`, no `COPY .env .`)? **[HARD]** [Docker]
- [ ] Are GitHub Actions pinned to full commit SHAs, not mutable tags? **[HARD]** [SupplyChain]
- [ ] Is a lockfile committed (package-lock.json, yarn.lock, Cargo.lock, go.sum)? **[HARD]** [SupplyChain]
- [ ] Are container base images pinned to digests for immutable builds? **[JUDGEMENT]** [SupplyChain]

## 8. API Security (OWASP API Top 10 2023)

**When:** code exposes or consumes REST, GraphQL, gRPC, or any HTTP-based API.
These checks use `API-*` IDs, distinct from the OWASP SCP items (1-213).

- [ ] Is every data-access endpoint scoped to the authenticated user's objects (no IDOR/BOLA)? **[HARD]** [API-1]
- [ ] Are API endpoints rate-limited, especially authentication and password-reset? **[HARD]** [API-2]
- [ ] Does user input never bind directly to data models without field allowlisting (no mass assignment)? **[HARD]** [API-3]
- [ ] Do list endpoints enforce pagination with a maximum page size? **[HARD]** [API-4]
- [ ] Are state-changing endpoints (PUT, POST, DELETE) authorization-checked for the caller's role (no BFLA)? **[HARD]** [API-5]
- [ ] Are request body size limits enforced to prevent resource exhaustion? **[HARD]** [API-6]
- [ ] Are pagination limits bounded (no `limit=-1` or unbounded queries)? **[HARD]** [API-7]
- [ ] Do API error responses return generic messages, never stack traces or internal details? **[HARD]** [API-8]
- [ ] Are deprecated API versions removed or return 410 Gone, not silently served? **[JUDGEMENT]** [API-9]
- [ ] Are responses from third-party APIs validated against a schema before use? **[HARD]** [API-10]

## 9. Container & Orchestration Security

**When:** code touches Dockerfiles, docker-compose, Kubernetes manifests, or Helm charts.
These checks use `C-*` IDs, distinct from the OWASP SCP items (1-213).

- [ ] Do containers run as a non-root user (USER directive, runAsNonRoot)? **[HARD]** [C-1]
- [ ] Are containers unprivileged (no `privileged: true`)? **[HARD]** [C-2]
- [ ] Do containers use their own network/pid/ipc namespaces (no hostNetwork/hostPID/hostIPC)? **[HARD]** [C-3]
- [ ] Is the container root filesystem read-only where possible? **[JUDGEMENT]** [C-4]
- [ ] Are Linux capabilities restricted (drop ALL, add only needed)? **[HARD]** [C-5]
- [ ] Is the Docker socket never mounted into a container? **[HARD]** [C-6]
- [ ] Do containers and pods have healthchecks (liveness/readiness probes)? **[HARD]** [C-7]
- [ ] Do pods set `runAsNonRoot: true` with a non-zero UID? **[HARD]** [C-8]
- [ ] Are service account tokens auto-mounted only when necessary? **[JUDGEMENT]** [C-9]
- [ ] Are CPU and memory limits set on every container? **[HARD]** [C-10]
- [ ] Are `hostPath` volumes avoided in favor of PersistentVolumeClaims or emptyDir? **[HARD]** [K8s]
- [ ] Are NetworkPolicies defined to restrict pod-to-pod traffic? **[JUDGEMENT]** [K8s]
- [ ] Is a pod security standard enforced (baseline or restricted, not privileged)? **[HARD]** [K8s]
- [ ] Is a seccomp profile applied to pods (RuntimeDefault or custom)? **[JUDGEMENT]** [K8s]
