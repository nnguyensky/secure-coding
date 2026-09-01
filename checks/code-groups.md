# 🛡️ The 9 Security Code Groups

*Detailed per-group requirements. `patterns/` enforces most of these mechanically — load this when you need the full rationale for a group, or are working in an area the scanner does not cover.*

### 1. Data In / Data Out
*When handling user input, queries, templates, or external data:*
- **Input Validation:** Validate on the server side using strict allowlists and bounds. Never rely on client-side checks alone.
- **SQL / NoSQL Queries:** Always use parameterized queries or ORM bindings. Never concatenate input into query strings.
- **Deserialization:** Avoid unsafe formats (`pickle`, `yaml.load`, `unserialize`). Use JSON with schema validation.
- **Templates (SSTI):** Use static templates with bound context variables. Never render user strings as templates.
- **Object Assignment:** Disallow `__proto__` and `constructor` to prevent prototype pollution.
- **XML Parsing:** Disable external DTDs and entity expansion (`defusedxml` in Python).
- **Regular Expressions:** Escape user strings to prevent ReDoS, or use simple string methods.

### 2. Identity & Access Control
*When handling login, sessions, roles, and permissions:*
- **Route Authorization:** Deny by default. Verify permissions and tenant ownership on every request.
- **Object Access (BOLA/IDOR):** Scope database queries to the authenticated user ID (`db.find({ id, userId })`).
- **Session IDs:** Generate a new cryptographically secure session ID upon login. Invalidate on logout.
- **CSRF Protection:** Require anti-CSRF tokens or `SameSite=Strict/Lax` cookies for state-changing endpoints.
- **Password Storage:** Use `Argon2id` (preferred), `scrypt`, or `bcrypt` (cost 12+). Never use MD5 or SHA-256 for passwords.
- **OAuth2 / OpenID:** Validate random `state` on callback and enforce an exact redirect URI allowlist.
- **JWT Tokens:** Validate signature, algorithm, expiration (`exp`), audience (`aud`), and issuer (`iss`).

### 3. Secrets & Cryptography
*When encrypting, generating random values, or managing keys:*
- **Secret Storage:** Read secrets from environment variables or a KMS. Never commit secrets to source control.
- **Random Numbers:** Use cryptographically secure RNG (`crypto.randomBytes()`, `secrets`). Never use `Math.random()`.
- **String Comparison:** Use constant-time comparison (`timingSafeEqual`) for tokens, hashes, and signatures.
- **Ciphers:** Use authenticated encryption (AES-256-GCM or ChaCha20-Poly1305). Never use ECB mode, DES, or RC4.
- **Key Rotation:** Use envelope encryption (DEK/KEK) and maintain an automated rotation policy.

### 4. Failure & Visibility
*When handling errors, logging, and diagnostics:*
- **Fail Closed:** Ensure catch blocks deny access if an exception occurs during an auth or permission check.
- **User Error Messages:** Return generic messages to users. Never expose stack traces, database errors, or file paths.
- **Log Sanitization:** Redact passwords, API keys, session tokens, and PII before logging.
- **Log Injection:** Strip CR/LF characters (`\r`, `\n`) from user input before writing to text logs.

### 5. Storage & Transport
*When saving data, configuring TLS, or setting headers:*
- **Transport Security:** Enforce TLS 1.3 (or TLS 1.2 minimum) and set the `Strict-Transport-Security` (HSTS) header.
- **Sensitive Responses:** Add `Cache-Control: no-store` to prevent caching of private data.
- **Database Access:** Connect using least-privilege credentials; avoid superuser/admin roles.
- **WebSocket Handshake:** Validate the `Origin` header against an allowlist and authenticate in the connection handler.

### 6. Files & System Execution
*When working with paths, file uploads, archives, or subprocesses:*
- **Path Traversal:** Canonicalize paths and verify they reside within the intended directory boundary.
- **File Uploads:** Validate file contents by MIME type/magic bytes, generate unique filenames, and store outside the web root.
- **Archive Extraction (Zip Slip):** Verify target paths remain inside the target directory before extracting files.
- **Command Execution:** Pass arguments as an array/list. Never pass unescaped user input to `shell=True` or `exec`.
- **C/C++ Buffers:** Use bounded operations (`strncpy`, `snprintf`); avoid `strcpy`, `strcat`, and `gets`.

### 7. Deployment & Configuration
*When setting up environments, Dockerfiles, or CI/CD pipelines:*
- **Debug Flags:** Ensure `DEBUG=False` and development seams are disabled in production builds.
- **Default Accounts:** Remove or randomize default passwords and admin accounts.
- **Container Privilege:** Run containers as non-root users (`USER 10001`) with read-only root filesystems.
- **Dependency Pinning:** Pin dependencies in lockfiles (`package-lock.json`, `Cargo.lock`, `go.sum`, `poetry.lock`).
- **CI/CD Security:** Pin third-party GitHub Actions to full commit SHAs.

### 8. API Security
*When building REST, GraphQL, or gRPC APIs:*
- **SSRF Prevention:** Validate outgoing request URLs against an allowlist; block internal IP ranges (`10.0.0.0/8`, `127.0.0.1`).
- **Rate Limiting:** Enforce rate limits per user/IP, especially on authentication and password-reset routes.
- **Mass Assignment:** Use strict input allowlists / DTOs rather than binding request bodies directly to database models.
- **Pagination:** Set strict default and maximum page limits on collection endpoints.
- **Request Size:** Enforce a maximum request body size limit to prevent memory exhaustion.

### 9. Containers & Cloud
*When writing Dockerfiles, Kubernetes manifests, or IaC:*
- **Non-Root Execution:** Set `runAsNonRoot: true` and specify non-zero UIDs in security contexts.
- **Privileged Containers:** Remove `privileged: true` and drop all unnecessary Linux capabilities (`drop: ["ALL"]`).
- **Network Isolation:** Apply Kubernetes `NetworkPolicy` to restrict traffic between namespaces and pods.
- **Host Sharing:** Disable host namespace sharing (`hostNetwork`, `hostPID`, `hostIPC`).

---
