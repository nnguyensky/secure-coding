# Fixes
# One block per check id. scan.js prints only the blocks it matched.

## weak-hash
OWASP: 30,105 | CWE-328 | A04:2025
MD5 and SHA-1 are broken. Do not use them for anything security-related.
Wrong: md5(x), sha1(x)
Right: sha256 for checksums and signatures. argon2id for passwords.
Watch: fine only for a non-security checksum (cache key, dedupe) — say so in a comment if that is the case.

## pw-fast-hash
OWASP: 30,31 | CWE-916 | A04:2025
A password needs a slow hash. Fast hashes are guessed in bulk.
Wrong: sha256(password), md5(password), any single-pass hash
Right: argon2id with default params. Else scrypt, or bcrypt at cost 12+.
Watch: never log the hash, never return it, compare in constant time.


## tls-off
OWASP: 143,144,145,146 | CWE-319 | A04:2025
Turning off certificate checks makes TLS decorative. Anyone on the path can read and change traffic.
Wrong: verify=False, rejectUnauthorized:false, InsecureSkipVerify:true
Right: leave verification on. For a self-signed dev cert, add that CA to the trust store.
Watch: this must not differ between dev and prod — it always ships.

## xss-sink
OWASP: 19,20 | CWE-79 | A05:2025
Putting user data into HTML as markup runs it as script.
Wrong: innerHTML =, dangerouslySetInnerHTML, document.write, v-html, |safe
Right: textContent, or the framework's normal binding, which escapes.
Watch: must render user HTML? Sanitize with a maintained library (DOMPurify), never a regex.

## eval
OWASP: 210,203 | CWE-95 | A05:2025
eval on anything touched by input is code execution.
Wrong: eval(x), new Function(x), setTimeout("string"), exec(f"...")
Right: a lookup table, JSON.parse, or a real parser.
Watch: string-as-code in setTimeout/setInterval is eval wearing a hat.

## sql-concat
OWASP: 167,21 | CWE-89 | A05:2025
SQL built by joining strings is SQL injection. Escaping by hand does not fix it.
Wrong: execute(f"SELECT ... {id}"), "SELECT ..." + x, ${x} in a query
Right: parameterized queries — execute(sql, [id]). Or the ORM's normal query API.
Watch: table and column names cannot be parameterized — allowlist them instead.

## shell
OWASP: 22,203 | CWE-78 | A05:2025
Passing a built string to a shell lets input add its own commands.
Wrong: shell=True, os.system(x), popen(x), child_process.exec(x)
Right: pass an argument list, no shell — subprocess.run([cmd, arg]), execFile.
Watch: quoting the input is not a fix; the shell has too many ways in.

## weak-rng
OWASP: 60,104 | CWE-338 | A04:2025
Regular random is predictable. An attacker can compute the next value.
Wrong: Math.random(), random.randint(), new Random() for tokens, keys, salts, OTPs, resets
Right: crypto RNG — secrets.token_urlsafe, crypto.randomBytes, SecureRandom.
Watch: fine for tests, shuffles, jitter. Not for anything anyone could guess to gain access.

## secret
OWASP: 35,102,135,172 | CWE-798 | A04:2025
A secret in source is public. It stays in git history after you delete it.
Wrong: hard-coded key, token, password, or private key
Right: read from the environment or a secret manager. Commit an example file with blanks.
Watch: if it was ever committed, rotate it — removing the line is not enough.

## weak-crypto
OWASP: 133,105 | CWE-327 | A04:2025
Broken ciphers and modes. ECB leaks the shape of your data.
Wrong: DES, RC4, Blowfish, AES-ECB
Right: AES-GCM or ChaCha20-Poly1305 — authenticated encryption.
Watch: use the library's high-level API. Never assemble a cipher yourself.

## cookie
OWASP: 75,76 | CWE-1004 | A02:2025
A cookie without flags can be stolen by script or read off the wire.
Wrong: httpOnly:false, secure:false on a session or auth cookie
Right: httpOnly, secure, sameSite together.
Watch: httpOnly:false only if JS genuinely must read it — a session id never must.

## jwt
OWASP: 28,79 | CWE-347 | A07:2025
Skipping signature checks means anyone can write their own token.
Wrong: alg "none", verify:false, verify_signature:False
Right: verify the signature, pin the expected algorithm, check exp and aud.
Watch: never let the token's own header pick the algorithm.

## mem
OWASP: 195,196,197,201 | CWE-787 | A06:2025
Unbounded copies overflow the buffer.
Wrong: strcpy, strcat, sprintf, gets, alloca
Right: strncpy/snprintf with a real size, or the platform's safe variants.
Watch: check every allocation for NULL. Never trust a length that came from input.

## cors
OWASP: 81,95 | CWE-942 | A02:2025
A wildcard origin with credentials lets any site call your API as the user.
Wrong: Allow-Origin "*" with credentials, or origin:true with credentials:true
Right: an explicit allowlist of origins.
Watch: never reflect the request's Origin header back unchecked.

## csrf-exempt
OWASP: 73,74 | CWE-352 | A01:2025
Disabling CSRF protection leaves state-changing requests open to forgery.
Wrong: @csrf_exempt, csrf: false, csrf_exempt()
Right: keep CSRF protection on; send a per-session or per-request token with every state change.
Watch: only disable with a compensating control, and never on a state-changing endpoint.

## samesite
OWASP: 75,76 | CWE-1275 | A01:2025
SameSite=None without Secure is rejected by modern browsers and is a cookie flag mistake.
Wrong: SameSite=None alone
Right: SameSite=None with Secure, or SameSite=Lax/Strict for session cookies.
Watch: SameSite=None requires Secure to work at all.

## world-writable
OWASP: 142,192 | CWE-732 | A02:2025
World-writable permissions let any local user read or change the file.
Wrong: chmod 777, 0777, 0o777
Right: the narrowest permission the file needs; 600 for secrets, 644 for read-only public files.
Watch: never 777 on config, keys, or anything security-relevant.

## mktemp
OWASP: 132,141 | CWE-377 | A06:2025
mktemp/tmpnam create predictable temp files — a race lets an attacker pre-create them.
Wrong: mktemp(), tmpnam()
Right: the platform's secure temp API (tempfile, mkstemp, tmpfile).
Watch: always use the secure variant; never guess a temp name.

## exec-py
OWASP: 210,203 | CWE-78 | A05:2025
exec() runs a string as code. On anything touched by input, that is code execution.
Wrong: exec(x), exec(compile(x, ...))
Right: a lookup table, JSON.parse, or a real parser.
Watch: exec is eval wearing a hat — same risk, same fix.

## debug-on
OWASP: 157,162,109 | CWE-489 | A02:2025
Debug mode leaks stack traces, config, and sometimes a live console.
Wrong: DEBUG=True, FLASK_ENV=development, app.run(debug=True) in anything deployable
Right: debug off by default; enable only from a local-only env file.
Watch: this is the single most common way internals reach production.

## dir-listing
OWASP: 153,158 | CWE-548 | A02:2025
Directory listing hands an attacker your file layout.
Wrong: autoindex on, Options +Indexes, directory_listing: true
Right: turn it off; serve an explicit index or 404.
Watch: check the static-file and upload locations specifically.

## server-banner
OWASP: 162 | CWE-200 | A02:2025
Version banners tell an attacker which exploits to try.
Wrong: server_tokens on, expose_php = On
Right: server_tokens off; strip version headers at the proxy.
Watch: also remove X-Powered-By and framework debug headers.

## http-methods
OWASP: 159,160 | CWE-650 | A02:2025
Extra HTTP methods widen the attack surface.
Wrong: WebDAV/PROPFIND/MKCOL enabled, TRACE or TRACK allowed
Right: allow only the methods the app uses, usually GET and POST.
Watch: TRACE enables cross-site tracing; disable it explicitly.

## default-cred
OWASP: 54,175,178 | CWE-1392 | A07:2025
Default accounts and passwords are the first thing tried.
Wrong: root/admin/sa/postgres with admin, password, changeme, 123456
Right: unique credentials from a secret manager; disable unused default accounts.
Watch: applies to the database, the message broker, and the admin UI.

## container-root
OWASP: 154,208 | CWE-250 | A02:2025
A container running as root turns an app bug into host access.
Wrong: USER root, or no USER line at all
Right: create an unprivileged user and USER it before CMD.
Watch: drop capabilities too; the default set is broader than needed.

## container-priv
OWASP: 154 | CWE-250 | A02:2025
A privileged container has effectively no isolation.
Wrong: privileged: true
Right: leave it off; grant only the specific capability required.
Watch: also check hostNetwork, hostPID, and mounted docker sockets.

## test-code
OWASP: 157 | CWE-489 | A02:2025
Test hooks left in production are a working auth bypass.
Wrong: if TESTING / BYPASS_AUTH / SKIP_AUTH / DISABLE_AUTH branches
Right: remove before deploy; keep test seams in test builds only.
Watch: a flag that disables a security control must not exist in a shipped binary.

## default-db-account
OWASP: 170,175,179 | CWE-1392 | A07:2025
An app connecting with full rights turns SQL injection into total compromise.
Wrong: GRANT ALL, WITH GRANT OPTION, CREATE USER ... IDENTIFIED BY 'password'
Right: least privilege per trust level; separate credentials for read and write.
Watch: the app account should not be able to DROP or GRANT.

## dynamic-include
OWASP: 180,190 | CWE-98 | A05:2025
A user-controlled include path executes a file the attacker chooses.
Wrong: include($_GET['page']), require($_REQUEST[...])
Right: map an index value to a fixed allowlist of paths.
Watch: never pass a path through; pass a key that selects one.

## open-redirect
OWASP: 189 | CWE-601 | A01:2025
An open redirect lends your domain to a phishing page.
Wrong: redirect(req.query.next) straight through
Right: allowlist targets, or accept only validated relative paths.
Watch: check the whole URL - //evil.com and \/\/evil.com both escape a naive check.

## upload-exec
OWASP: 185,186 | CWE-434 | A06:2025
An upload directory the server executes is a shell.
Wrong: a location block mapping uploads to php/cgi/fastcgi
Right: serve uploads from a separate non-executing location or a content server.
Watch: turn off execute permission on the directory as well.

## path-traversal
OWASP: 180,190,191 | CWE-22 | A01:2025
A user-supplied path lets an attacker read or write files outside the intended directory.
Wrong: File.read(params[:file]), os.Open(r.URL.Query().Get("path")), new File(req.getParameter("p"))
Right: resolve the path, then confirm it stays inside the allowed directory before opening.
Watch: never pass a path through; pass a key that selects one from an allowlist.

## autocomplete-on
OWASP: 40,51 | CWE-200 | A02:2025
Password fields with autocomplete="on" let the browser save credentials. On shared or public machines, the next user inherits the session.
Wrong: autocomplete="on" on password fields, or missing autocomplete attribute
Right: autocomplete="new-password" on password fields (or "off"). Sensitive text fields: autocomplete="off".
Watch: some browsers ignore autocomplete="off" — use "new-password" or "one-time-code" instead.

## API-1
OWASP API: API1:2023 | CWE-918 | A06:2025
Server-Side Request Forgery (SSRF): user-supplied URL is passed to an HTTP client, letting the attacker reach internal services.
Wrong: requests.get(user_url), http.Get(userURL), fetch(userInput)
Right: validate the URL against an allowlist of permitted hosts/schemes. Reject internal IPs (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, ::1).
Watch: DNS rebinding can bypass IP checks — resolve first, then check the resolved address.

## API-2
OWASP API: API2:2023 | CWE-307 | A07:2025
Broken Authentication: endpoints lack rate limiting, allowing brute-force or credential stuffing.
Wrong: no rate limit on /login, /reset-password, /verify
Right: rate-limit authentication endpoints (e.g., 5 attempts per minute per IP). Return identical responses for valid/invalid users.
Watch: apply rate limiting at the infrastructure level (reverse proxy, gateway) to avoid bypass.

## API-3
OWASP API: API3:2023 | CWE-915 | A01:2025
Mass Assignment: user input binds directly to a data model, letting the attacker set fields like role, is_admin, or balance.
Wrong: User(**request.json), Object.assign(user, req.body), model.update(**request.form)
Right: allowlist accepted fields. Never spread user input directly into a model.
Watch: frameworks with auto-binding (Rails, Spring, Django REST) are especially prone.

## API-4
OWASP API: API4:2023 | CWE-770 | A06:2025
Overfetching: endpoints return the full model when the client needs only a few fields, leaking sensitive data.
Wrong: res.json(user), return User.objects.all(), SELECT * FROM users
Right: select only the fields the client needs. Use field filtering or a DTO.
Watch: GraphQL mitigates this by design; REST endpoints need explicit field selection.

## API-5
OWASP API: API5:2023 | CWE-285 | A01:2025
Broken Function Level Authorization (BFLA): state-changing endpoints lack role checks, letting regular users perform admin actions.
Wrong: router.delete('/users/:id') without role check, @app.route('/admin/...') without @admin_required
Right: check the caller's role/permission before every state-changing operation. Deny by default.
Watch: horizontal privilege escalation (user A edits user B's data) is the most common form.

## API-6
OWASP API: API6:2023 | CWE-770 | A06:2025
Unrestricted Resource Consumption: no request size limit allows an attacker to exhaust memory or CPU.
Wrong: app.use(express.json()) without limit, no max_content_length
Right: set body size limits (e.g., 1MB for JSON). Add rate limiting per client.
Watch: file upload endpoints need separate size limits from JSON body limits.

## API-7
OWASP API: API7:2023 | CWE-918 | A06:2025
Unbounded Pagination: no maximum page size lets the attacker request millions of records in one call.
Wrong: limit=-1, no default limit, per_page from user input unchecked
Right: enforce a default page size (e.g., 20) and a maximum (e.g., 100). Ignore user-supplied limit if it exceeds the max.
Watch: cursor-based pagination avoids this issue entirely for large datasets.

## API-8
OWASP API: API8:2023 | CWE-16 | A02:2025
Security Misconfiguration — verbose errors: exception details leak to the API response, exposing internals.
Wrong: except Exception as e: return str(e), catch(err) { res.send(err) }
Right: return a generic error message (e.g., "Internal server error"). Log the details server-side.
Watch: HTTP 500 with a stack trace is a reconnaissance gift.

## API-9
OWASP API: API9:2023 | CWE-1059 | A02:2025
Improper Inventory Management: deprecated API versions remain accessible, exposing unpatched vulnerabilities.
Wrong: /api/v1/ still serves requests, old endpoints not removed
Right: remove deprecated versions or return 410 Gone. Maintain an API inventory.
Watch: clients may depend on old versions — deprecate with a sunset header before removal.

## API-10
OWASP API: API10:2023 | CWE-20 | A05:2025
Unsafe Consumption of APIs: third-party API responses are used without validation, letting a compromised upstream inject malicious data.
Wrong: data = requests.get(external_api).json(), data = res.data
Right: validate the response schema before use. Check status codes. Set timeouts.
Watch: a compromised CDN or API can return valid-looking but malicious data.

## C-1
Container Security | CWE-250 | A02:2025
Container runs as root, turning an app vulnerability into host access.
Wrong: USER root, or no USER line in Dockerfile; runAsUser: 0 in K8s
Right: create a non-root user in Dockerfile and USER it. Set runAsNonRoot: true and runAsUser > 0 in securityContext.
Watch: some base images default to root — always add an explicit USER.

## C-2
Container Security | CWE-250 | A02:2025
Privileged container has effectively no isolation from the host.
Wrong: privileged: true in securityContext
Right: remove privileged flag. Grant only the specific capability needed via capabilities.add.
Watch: even with capabilities dropped, privileged containers can escape.

## C-3
Container Security | CWE-732 | A02:2025
Container shares host network/pid/ipc namespace, breaking isolation.
Wrong: hostNetwork: true, hostPID: true, hostIPC: true
Right: remove host namespace sharing. Use container-scoped namespaces and Services for networking.
Watch: hostNetwork bypasses Kubernetes network policies entirely.

## C-4
Container Security | CWE-923 | A02:2025
Writable root filesystem lets an attacker modify binaries or configs inside the container.
Wrong: readOnlyRootFilesystem: false, read_only: false
Right: set readOnlyRootFilesystem: true. Use emptyDir volumes for directories that need writes.
Watch: some apps need /tmp or /var/run writable — mount only those as emptyDir.

## C-5
Container Security | CWE-653 | A02:2025
Excessive Linux capabilities give the container host-level privileges.
Wrong: capabilities.add: ["ALL"], add: ["SYS_ADMIN", "NET_ADMIN"]
Right: capabilities.drop: ["ALL"], then add only the specific capabilities needed.
Watch: CAP_SYS_ADMIN alone allows mounting filesystems and many privilege escalations.

## C-6
Container Security | CWE-538 | A02:2025
Docker socket mount lets the container control the Docker daemon — full host compromise.
Wrong: volumes: /var/run/docker.sock:/var/run/docker.sock
Right: remove the socket mount. Use a Docker client with a restricted API proxy if Docker access is needed.
Watch: mounting the socket also exposes the daemon's TLS certs if using remote Docker.

## C-7
Container Security | CWE-1104 | A03:2025
No healthcheck means the orchestrator cannot detect a broken container.
Wrong: HEALTHCHECK NONE in Dockerfile; no livenessProbe/readinessProbe in K8s
Right: add a HEALTHCHECK in Dockerfile or liveness/readiness probes in the pod spec.
Watch: readinessProbe controls traffic routing — without it, broken pods still receive requests.

## C-8
Container Security | CWE-16 | A02:2025
Pod runs as UID 0 (root) despite other restrictions.
Wrong: runAsUser: 0, securityContext without runAsNonRoot: true
Right: set runAsNonRoot: true and runAsUser to a non-zero UID (e.g., 1000).
Watch: the container's USER directive and the pod's securityContext must both be non-root.

## C-9
Container Security | CWE-250 | A02:2025
Service account token auto-mounted into pods that don't need Kubernetes API access.
Wrong: automountServiceAccountToken: true (or omitted — defaults to true)
Right: set automountServiceAccountToken: false on pods that don't call the K8s API.
Watch: a leaked token in a compromised pod can enumerate the entire cluster.

## C-10
Container Security | CWE-532 | A09:2025
No CPU/memory limits allows a single container to starve the node.
Wrong: resources: {}, no limits section, limits: null
Right: set requests and limits for both CPU and memory on every container.
Watch: start with requests equal to limits, then tune based on actual usage.

## log-inject
OWASP: Logging CS, CWE-117
User input in log messages can inject CR/LF characters, forging log entries or exploiting log viewers.
Wrong: console.log(`User ${req.body.name} logged in`), logger.info("Input: " + userInput)
Right: Use structured logging with parameterized fields. Sanitize input by stripping control characters.
Watch: log injection can lead to log forging, log rotation attacks, or XSS in log viewers.

## log-leak
OWASP: Logging CS, OWASP SCP [119] | CWE-532 | A09:2025
Logging passwords, tokens, secrets, or PII exposes sensitive data in log files and monitoring systems.
Wrong: console.log("Password:", password), logger.info("Token: " + token)
Right: Remove or mask sensitive fields before logging. Use redaction middleware for sensitive data.
Watch: logs often persist longer than expected and may be accessed by operations teams or attackers.

## pw-slow-hash
OWASP: Password Storage CS, OWASP SCP [30,31] | CWE-916 | A04:2025
Plaintext password storage or weak hashing means a database breach exposes all credentials.
Wrong: storing password in plaintext, using MD5/SHA1/SHA256 for passwords
Right: hash with argon2id (preferred), scrypt, or bcrypt at cost 12+. Always use a unique random salt.
Watch: never log the hash, never return it to the client, compare in constant time.

## ssrf
OWASP: SSRF Prevention CS, OWASP API Top 10 API-1 | CWE-918 | A06:2025
User-supplied URLs passed to server-side HTTP clients let attackers reach internal services.
Wrong: requests.get(user_url), fetch(req.query.url), http.Get(req.URL.Query().Get("url"))
Right: validate URL against an allowlist of permitted hosts/schemes. Block internal IPs (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, ::1).
Watch: DNS rebinding can bypass IP checks — resolve first, then check the resolved address.

## file-upload
OWASP: File Upload CS, OWASP SCP [183] | CWE-434 | A06:2025
Unvalidated file uploads allow malicious files, executable code, or resource exhaustion.
Wrong: saving upload directly to disk without type or size check
Right: validate MIME type server-side (not just Content-Type header), check magic bytes, enforce max file size, store outside web root.
Watch: client-provided Content-Type headers are trivially forged — always verify server-side.

## nosql-inject
OWASP: NoSQL Security CS | CWE-943 | A05:2025
User input injected into NoSQL queries can manipulate query operators, bypassing authentication or extracting data.
Wrong: db.collection.find({username: req.body.username, password: req.body.password})
Right: validate input type and value before use in queries. Reject objects/arrays where primitives are expected. Use schema validation.
Watch: MongoDB operators like $gt, $ne, $where can bypass authentication if user input is not type-checked.

## oauth2-state
OWASP: OAuth2 CS | CWE-352 | A07:2025
Missing or predictable state parameter in OAuth2 flow enables CSRF attacks that link attacker accounts to victim sessions.
Wrong: no state parameter, state from client input, static/predictable state value
Right: generate cryptographically random state, store server-side, validate on callback. Reject if missing or mismatched.
Watch: state must be bound to the user's session — an attacker cannot forge or predict it.

## oauth2-token
OWASP: OAuth2 CS | CWE-522 | A07:2025
Skipping token verification lets attackers use expired, forged, or replayed tokens.
Wrong: verify:false, skipIntrospection:true, no exp/aud/iss check
Right: verify signature, check expiration (exp), validate audience (aud) and issuer (iss). Use library defaults.
Watch: token introspection adds a network call but catches revoked tokens in real time.

## oauth2-redirect
OWASP: OAuth2 CS | CWE-601 | A01:2025
Accepting redirect_uri from user input lets attackers steal authorization codes via open redirect.
Wrong: redirect_uri = request.args.get("redirect_uri"), using client-supplied URI
Right: validate redirect_uri against pre-registered URIs. Reject if not in allowlist.
Watch: even partial matching (startsWith) can be bypassed — use exact match.

## session-fixation
OWASP: Session Management CS [66,67] | CWE-384 | A07:2025
Not regenerating the session ID after login lets an attacker pre-set a session ID and hijack the authenticated session.
Wrong: using the same session ID before and after login, accepting session ID from client
Right: call session.regenerate() (Express), request.session.regenerate() (Kotlin), session.regenerate! (Rails) after successful authentication.
Watch: regenerate must happen before any response is sent to the client.

## hsts
OWASP: HSTS CS, HTTP Headers CS | CWE-319 | A04:2025
Missing HSTS header means the first visit (or any HTTP redirect) is vulnerable to SSL stripping attacks.
Wrong: no Strict-Transport-Security header, max-age too short (< 6 months)
Right: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Watch: HSTS is only effective over HTTPS — ensure HTTP redirects to HTTPS first.

## ws-origin
OWASP: WebSocket Security CS | CWE-346 | A01:2025
Missing Origin validation on WebSocket upgrades allows cross-site WebSocket hijacking from any malicious page.
Wrong: accepting WebSocket connections without checking Origin, CheckOrigin: func(r) { return true }
Right: validate Origin header against a trusted allowlist. Reject connections from unknown origins.
Watch: the Origin header is sent by the browser — server-side WS libraries may not check it by default.

## ws-auth
OWASP: WebSocket Security CS | CWE-306 | A07:2025
Trusting the HTTP upgrade handshake alone is insufficient — WebSocket connections bypass HTTP auth middleware.
Wrong: no authentication after WS upgrade, relying solely on cookie from upgrade request
Right: authenticate in the connection handler (onOpen/connect). Validate session/token. Reject unauthenticated sockets.
Watch: WebSocket connections persist — a logged-out user's open socket may still receive data.

## docker-copy-secrets
OWASP: Docker Security CS | CWE-538 | A02:2025
COPY . or ADD . copies everything into the image — including .env, .git, keys, and secrets.
Wrong: COPY . ., ADD . /app, COPY *.env .
Right: create a .dockerignore file excluding secrets, .git, node_modules, *.env. Copy only needed files.
Watch: Docker build context is sent to the daemon — secrets in context can leak via image layers.

## dockerfile-latest
OWASP: Docker Security CS | CWE-1104 | A03:2025
Using :latest tag means builds are non-reproducible — the base image changes without notice.
Wrong: FROM node:latest, FROM python:latest
Right: pin to specific version: FROM node:20-slim, FROM python:3.12-alpine
Watch: even pinning to a minor version (3.12) can drift — pin to patch for maximum reproducibility.

## dockerfile-upgrade
OWASP: Docker Security CS | CWE-1104 | A03:2025
apt-get upgrade in Dockerfile upgrades packages unpredictably — non-reproducible builds.
Wrong: RUN apt-get update && apt-get upgrade -y && apt-get install -y package
Right: pin base image version, install specific package versions, combine into single RUN with cleanup.
Watch: apt-get upgrade can pull in breaking changes — pin the base image instead.

## dockerfile-env-secrets
OWASP: Docker Security CS | CWE-538 | A02:2025
Secrets in ENV are baked into image layers and visible in docker inspect.
Wrong: ENV DB_PASSWORD=secret123, ENV API_KEY=sk_live_xxx
Right: use build secrets (DOCKER_BUILDKIT=1, --mount=type=secret) or runtime environment variables.
Watch: even with multi-stage builds, ENV in any stage persists in the final image.

## unpinned-action
OWASP: Software Supply Chain CS | CWE-1357 | A03:2025
GitHub Actions pinned to mutable tags (v1, main) can be silently modified by the action author.
Wrong: uses: actions/checkout@v4, uses: actions/setup-node@main
Right: pin to full commit SHA: uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
Watch: use a tool like Pinact or Dependabot to automate SHA pinning and updates.

## lockfile-missing
OWASP: Software Supply Chain CS | CWE-1357 | A03:2025
Missing lockfile means npm install resolves versions at deploy time — non-reproducible and vulnerable to dependency confusion.
Wrong: no package-lock.json, no yarn.lock, no Cargo.lock, no go.sum
Right: run npm install / yarn / cargo generate-lockfile. Commit the lockfile. Use npm ci / yarn --frozen-lockfile in CI.
Watch: CI should always use lockfile-only install (npm ci, not npm install) to prevent lockfile modification.

## docker-digest
OWASP: Docker Security CS | CWE-1104 | A03:2025
Base image pinned to tag only (node:20-slim) — tags can be moved, builds are not immutable.
Wrong: FROM node:20-slim, FROM python:3.12-alpine
Right: pin to digest: FROM node@sha256:abc123... for immutable builds.
Watch: digest pinning means manual updates — use Dependabot or Renovate to automate.

## dockerfile-add
OWASP: Docker Security CS | CWE-494 | A08:2025
ADD extracts archives automatically and supports URLs — COPY is safer and more explicit.
Wrong: ADD app.tar.gz /app, ADD https://example.com/file /app
Right: use COPY for local files. Extract archives in a separate RUN step if needed.
Watch: ADD with a URL downloads at build time with no checksum verification.

## dockerfile-curl-bash
OWASP: Docker Security CS | CWE-494 | A08:2025
Piping curl to bash executes arbitrary code from the internet at build time.
Wrong: RUN curl -sSL https://example.com/install.sh | bash
Right: download to a file, verify checksum, then execute. Or install from the package manager.
Watch: the script can change between builds — pin the URL or use a package manager.

## eval-input
OWASP: Shell Injection CS | CWE-95 | A05:2025
eval on user-controlled variables executes arbitrary code via shell expansion.
Wrong: eval $user_input, eval "$config"
Right: use a case statement, a lookup table, or safe parsing without eval.
Watch: even eval "$fixed_string" is dangerous if any part came from input.

## hostpath
OWASP: Kubernetes Security CS | CWE-552 | A02:2025
hostPath mounts the node's filesystem into the pod — breaks isolation.
Wrong: hostPath: { path: /var/log }
Right: use PersistentVolumeClaim, emptyDir, or a mounted ConfigMap/Secret.
Watch: hostPath can expose sensitive node files (SSH keys, Docker socket).

## k8s-np
OWASP: Kubernetes Security CS | CWE-923 | A02:2025
No NetworkPolicy means all pods can talk to each other — no network segmentation.
Wrong: no NetworkPolicy resource defined
Right: define NetworkPolicy to restrict pod-to-pod traffic to only what's needed.
Watch: start with a default-deny policy, then allow specific flows.

## k8s-psa
OWASP: Kubernetes Security CS | CWE-250 | A02:2025
No pod security standard enforced — pods can run as root, use privileged mode, or mount host paths.
Wrong: no PSA labels, pod-security.kubernetes.io/enforce: privileged
Right: set pod-security.kubernetes.io/enforce: baseline (or restricted) on namespaces.
Watch: restricted profile breaks some workloads — test before applying.

## k8s-readonly
OWASP: Kubernetes Security CS | CWE-732 | A02:2025
Writable root filesystem lets an attacker modify binaries or configs inside the container.
Wrong: readOnlyRootFilesystem: false (or omitted)
Right: set readOnlyRootFilesystem: true. Use emptyDir for directories that need writes.
Watch: some apps need /tmp or /var/run writable — mount only those as emptyDir.

## k8s-seccomp
OWASP: Kubernetes Security CS | CWE-250 | A02:2025
No seccomp profile means the container can use any syscall — wider attack surface.
Wrong: no seccompProfile in securityContext
Right: set seccompProfile.type: RuntimeDefault or a custom profile.
Watch: RuntimeDefault is the safe starting point — custom profiles need testing.

## npm-audit
OWASP: Software Supply Chain CS | CWE-1395 | A03:2025
Dependencies with known vulnerabilities are shipped to production.
Wrong: no audit step in CI, ignoring npm audit / pip-audit / cargo audit output
Right: run audit in CI, fail on critical/high. Use Dependabot or Renovate for automated fixes.
Watch: some vulnerabilities have no fix yet — document and monitor.

## provisioner-local
OWASP: Infrastructure as Code CS | CWE-78 | A05:2025
provisioner "local-exec" runs arbitrary commands on the machine running Terraform.
Wrong: provisioner "local-exec" { command = "..." }
Right: use null_resource with a controlled script, or use cloud-init / Ansible.
Watch: local-exec runs with the Terraform user's permissions — often root or CI token.

## provisioner-remote
OWASP: Infrastructure as Code CS | CWE-78 | A05:2025
provisioner "remote-exec" opens an SSH connection and runs commands on the target.
Wrong: provisioner "remote-exec" { inline = ["..."] }
Right: use Ansible, cloud-init, or a configuration management tool.
Watch: remote-exec runs as root by default and leaves no audit trail.

## tf-password
OWASP: Infrastructure as Code CS | CWE-798 | A04:2025
Hardcoded password in a connection block leaks credentials in state file and plan output.
Wrong: connection { password = var.db_password }
Right: use SSH key authentication. If password is required, reference a secret manager.
Watch: Terraform state stores connection attributes in plaintext — even var references are resolved.

## temp-race
OWASP: Temporary File CS | CWE-367 | A06:2025
tmpnam creates predictable temp file names — an attacker can pre-create the file (symlink attack).
Wrong: tmpnam(), tempnam()
Right: use mktemp (creates and opens atomically) or Python's tempfile.mkdtemp.
Watch: always use the secure variant; never guess a temp name.

## set-hide-error
OWASP: Error Handling CS | CWE-209 | A10:2025
set +e hides command failures — security controls that fail silently may go unnoticed.
Wrong: set +e before a security-relevant command
Right: let errexit propagate; handle errors with explicit if/trap.
Watch: set +e is sometimes needed for conditional logic — document why.

## unquoted-test
OWASP: Shell Injection CS | CWE-78 | A05:2025
Unquoted variables in test expressions undergo word splitting and glob expansion.
Wrong: [ $var == "yes" ], test $var -eq 0
Right: quote variables: [ "$var" == "yes" ], test "$var" -eq 0.
Watch: even quoted variables can be dangerous if they start with - (test interprets flags).

## unquoted-var
OWASP: Shell Injection CS | CWE-78 | A05:2025
Unquoted variables in command arguments undergo word splitting and glob expansion.
Wrong: rm $file, cp $src $dst, chmod 777 $dir
Right: quote variables: rm "$file", cp "$src" "$dst".
Watch: glob expansion on unquoted * can delete unexpected files.

## ssti
OWASP: Injection CS | CWE-1336 | A05:2025
Server-Side Template Injection evaluates untrusted user input within a template engine, leading to remote code execution.
Wrong: render_template_string(user_input), jinja2.Template(user_input), ejs.render(user_input)
Right: render static template files and pass user input as contextual data variables.
Watch: never concatenate user input into template source strings.

## prototype-pollution
OWASP: JavaScript Security CS | CWE-1321 | A05:2025
Recursive assignment or merge of untrusted objects can overwrite Object.prototype, affecting all application objects.
Wrong: Object.assign({}, req.body), lodash.merge(target, req.body)
Right: validate keys, disallow __proto__ and constructor, or use Map / Object.create(null).
Watch: JSON.parse does not prevent prototype pollution if recursive merge follows.

## redos-input
OWASP: Denial of Service CS | CWE-1333 | A05:2025
Passing unescaped user input directly into regular expression constructors allows ReDoS attacks.
Wrong: new RegExp(req.query.search), re.compile(request.args.get("q"))
Right: escape regex special characters or use plain string search methods (indexOf, includes).
Watch: validate regex input length and enforce timeouts.

## xxe
OWASP: XML Security CS | CWE-611 | A02:2025
XML External Entity (XXE) injection allows attackers to read server files or trigger SSRF via custom DOCTYPE entities.
Wrong: standard XML parsing with external entity resolution enabled.
Right: disable DTDs/external entities (FEATURE_SECURE_PROCESSING, defusedxml) or use JSON.
Watch: SOAP and SAML parsers often have external entity resolution enabled by default.

## zip-slip
OWASP: File Management CS | CWE-22 | A01:2025
Archive extraction without destination boundary checks allows writing files outside the target directory via path traversal.
Wrong: tarfile.extractall(), zipfile.extractall(), unzipper.Extract()
Right: verify resolved destination path starts with the extraction directory before writing.
Watch: check both zip/tar entry names and symbolic link targets.

## jwt-none-alg
OWASP: Authentication CS | CWE-347 | A07:2025
Accepting the 'none' algorithm in JWT tokens allows attackers to forge tokens with empty signatures and arbitrary claims.
Wrong: jwt.verify(token, key, { algorithms: ['none'] }), pyjwt.decode(token, options={"verify_signature": False})
Right: restrict accepted algorithms to explicit strong algorithms (e.g. ['RS256', 'ES256', 'HS256']).
Watch: never trust alg header from unverified token payload.

## jwt-hardcoded-secret
OWASP: Cryptographic Practices CS | CWE-798 | A07:2025
Hardcoded symmetric secrets in JWT signing or verification can be extracted from source code or compiled binaries.
Wrong: jwt.sign(payload, "secret123"), Jwts.builder().setSigningKey("default")
Right: load symmetric or asymmetric keys from environment variables or a secret manager.
Watch: ensure secret has sufficient entropy (at least 256 bits for HMAC-SHA256).

## jwt-no-verify
OWASP: Authentication CS | CWE-347 | A07:2025
Decoding JWT tokens without cryptographic signature verification allows authentication bypass.
Wrong: jwt.decode(token, verify=False), jwt.decode(token, { verifySignature: false })
Right: verify signature with public key or shared secret, and validate exp, aud, and iss claims.
Watch: decode() should only be used for debugging, never in request authentication flows.

## cors-wildcard-credentials
OWASP: Communication Security CS | CWE-942 | A02:2025
Combining Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is insecure and rejected by modern browsers.
Wrong: cors({ origin: '*', credentials: true })
Right: specify an exact trusted origin allowlist when credentials (cookies/auth headers) are permitted.
Watch: wildcard origin with credentials exposes authenticated endpoints to cross-origin abuse.

## cors-origin-reflection
OWASP: Communication Security CS | CWE-346 | A02:2025
Reflecting the incoming Origin header into Access-Control-Allow-Origin without allowlist validation bypasses same-origin protections.
Wrong: res.setHeader("Access-Control-Allow-Origin", req.headers.origin)
Right: validate the request Origin against a strict allowlist array before echoing it.
Watch: check exact hostname matches, not weak substrings (e.g. attacker-site.com containing target.com).

## insecure-deserialization
OWASP: 194,210 | CWE-502 | A08:2025
Deserializing untrusted data runs code. This is remote code execution.
Wrong: pickle.loads, yaml.load, unserialize, readObject on anything from outside
Right: JSON to plain values. yaml.safe_load. Validate the shape after parsing.
Watch: "it's our own service" is not trust — the transport can be tampered with.

## taint-path-traversal
OWASP: 180,190,191 | CWE-22 | A01:2025
Request data reaches a filesystem call after passing through a variable. Same bug as path-traversal; the pattern scanner misses it because the source and the sink are on different lines.
Wrong: const p = req.params.name; fs.readFileSync(`/data/${p}`)
Right: resolve the path, then confirm it stays inside the allowed directory. Or pass a key that selects a file from an allowlist.
Watch: basename() alone still allows picking any file in that directory.

## taint-ssrf
OWASP: 137,138 | CWE-918 | A06:2025
Request data reaches an outbound HTTP call after passing through a variable. The server will fetch whatever the caller names, including internal addresses.
Wrong: const t = req.query.url; await fetch(t)
Right: allowlist the destination host, and block private ranges (10.0.0.0/8, 127.0.0.1, 169.254.169.254).
Watch: check the URL after resolution — redirects and DNS rebinding move the target.

## taint-command
OWASP: 22,203 | CWE-78 | A05:2025
Request data reaches a process call after passing through a variable. Anything the caller sends can add its own command.
Wrong: const c = req.body.cmd; exec(c)
Right: pass an argument array with no shell — execFile(bin, [arg]), subprocess.run([bin, arg]).
Watch: quoting the input is not a fix; the shell has too many ways in.

## taint-sql
OWASP: 167,21 | CWE-89 | A05:2025
Request data reaches a query call after passing through a variable, so escaping was never applied.
Wrong: const id = req.params.id; db.query("SELECT * FROM u WHERE id = " + id)
Right: parameterized queries — db.query(sql, [id]). Or the ORM's normal query API.
Watch: table and column names cannot be parameterized — allowlist them instead.

## llm-prompt-injection
OWASP: LLM Applications Security | CWE-1427 | A05:2025
Concatenating unescaped user input directly into LLM prompt strings enables direct prompt injection attacks.
Wrong: client.chat.completions.create(messages=[{"role": "user", "content": f"Translate this: {user_input}"}])
Right: separate system instructions from user inputs using structured message roles and delimiter tags (e.g. <user_query>).
Watch: treat all LLM outputs and inputs crossing trust boundaries as untrusted.

## llm-unsafe-exec
OWASP: LLM Applications Security | CWE-94 | A05:2025
Executing code or system commands directly generated by an LLM allows remote code execution.
Wrong: eval(completion.choices[0].message.content), exec(response.text)
Right: execute generated code inside an isolated container/sandbox, or require explicit human confirmation.
Watch: LLM outputs are probabilistic and vulnerable to prompt injection hijacking.

## rsc-unvalidated-action
OWASP: API Security CS | CWE-20 | A05:2025
Next.js Server Actions without argument validation expose internal mutation handlers to arbitrary client payloads.
Wrong: "use server"; export async function updateProfile(data) { await db.user.update(data); }
Right: validate action arguments using a schema validator (such as Zod) before executing mutations.
Watch: Server Actions are callable via HTTP POST endpoints independent of client UI components.

## secret-aws-key
OWASP: Sensitive Data Exposure CS | CWE-798 | A04:2025
Hardcoded AWS access keys in source code risk immediate credential leakage when pushed to version control.
Wrong: AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
Right: load credentials from AWS IAM roles, environment variables, or AWS Secrets Manager.
Watch: rotate any AWS keys that have ever been committed to a repository.

## secret-github-token
OWASP: Sensitive Data Exposure CS | CWE-798 | A04:2025
GitHub Personal Access Tokens in source code allow full access to repositories and organization resources.
Wrong: const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
Right: use GitHub Actions secrets, fine-grained access tokens stored in environment variables.
Watch: revoked tokens should be immediately regenerated and checked with GitHub secret scanning.

## secret-stripe-key
OWASP: Sensitive Data Exposure CS | CWE-798 | A04:2025
Stripe live secret keys allow unauthorized payment charges and financial data access.
Wrong: const stripe = new Stripe("sk_live_1234567890abcdefghijklmn");
Right: load Stripe secret keys from secure environment variables on the backend only.
Watch: never expose sk_live or rk_live keys in client-side bundles.

## secret-google-key
OWASP: Sensitive Data Exposure CS | CWE-798 | A04:2025
Unrestricted Google / Firebase API keys can be abused to rack up cloud billing or access sensitive APIs.
Wrong: const apiKey = "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
Right: apply application restrictions (HTTP referrers / package names) and API restrictions in Google Cloud Console.
Watch: even public Firebase API keys should have granular security rules and Firestore constraints.

## secret-private-key
OWASP: Cryptographic Practices CS | CWE-798 | A04:2025
Private RSA/EC/SSH keys committed to source code compromise the entire Public Key Infrastructure (PKI).
Wrong: -----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----
Right: store private keys in KMS, Hardware Security Modules (HSM), or secure environment secrets.
Watch: rotate compromised certificates and revoke associated public keys.

## secret-slack-webhook
OWASP: Sensitive Data Exposure CS | CWE-798 | A04:2025
Hardcoded Slack Webhook URLs allow unauthorized parties to post arbitrary messages or spam workspace channels.
Wrong: url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
Right: read webhook URLs from environment variables or vault storage.
Watch: Slack invalidates publicly committed webhooks automatically.

## secret-db-url
OWASP: Sensitive Data Exposure CS | CWE-798 | A04:2025
Database connection strings with plaintext passwords in code expose database clusters to takeover.
Wrong: const uri = "postgres://admin:pass123@db.internal:5432/prod";
Right: compose connection parameters from separate environment variables or secret managers.
Watch: logs that print error objects often inadvertently dump the full connection URI.

## llm-output-html
OWASP: LLM Applications Security | CWE-79 | A05:2025
Directly inserting LLM-generated output into DOM without sanitization leads to Cross-Site Scripting (XSS).
Wrong: document.getElementById("chat").innerHTML = llmResponse.text
Right: use textContent, or sanitize with DOMPurify before rendering markdown/HTML.
Watch: indirect prompt injection can force the model to output malicious `<script>` tags.

## llm-rag-no-filter
OWASP: LLM Applications Security | CWE-285 | A01:2025
Querying vector databases without tenant or user authorization filters enables cross-tenant data leakage.
Wrong: vectorStore.similaritySearch(userQuery, k=5)
Right: enforce tenant/user metadata filtering: vectorStore.similaritySearch(userQuery, { filter: { tenantId } })
Watch: always verify document authorization at query time, not just during indexing.

## llm-excessive-agency
OWASP: LLM Applications Security | CWE-269 | A06:2025
Allowing LLM agents to execute destructive or state-changing tools without human approval creates excessive agency risks.
Wrong: execute_tool(tool_name, params, auto_approve=True)
Right: require explicit human authorization gates for state changes (purchases, data deletions, external emails).
Watch: validate tool inputs against strict schemas before execution.

## llm-unbounded-tokens
OWASP: LLM Applications Security | CWE-770 | A06:2025
Invoking LLM APIs without specifying max_tokens can lead to token denial-of-service and runaway cloud bills.
Wrong: openai.chat.completions.create(model="gpt-4o", messages=messages)
Right: explicitly set max_tokens / max_completion_tokens based on expected response length.
Watch: enforce client-level rate limits and cost budgets.

## secret-entropy
OWASP: Sensitive Data Exposure CS | CWE-798 | A04:2025
Un-prefixed high-entropy string assigned to a secret/credential variable indicates hardcoded API keys or private tokens.
Wrong: const api_secret = "8f9a2b1c4e7d0f3a6b5c4d3e2f1a0b9c";
Right: read credentials and keys from environment variables or a secure key management vault.
Watch: rotate any exposed keys and never commit high-entropy secret blobs to source repositories.

## sbd-missing-timeout
OWASP: Secure by Design Architecture | CWE-1088 | A10:2025
Issuing HTTP client requests without explicit timeouts causes thread starvation and cascading failures during network degradation.
Wrong: response = requests.get("https://api.internal/data")
Right: specify explicit connect and read timeouts: requests.get("https://api.internal/data", timeout=(3.05, 10))
Watch: external API hangs will exhaust worker pools if timeouts are omitted.

## sbd-legacy-tls
OWASP: Secure Communication & Cryptography | CWE-327 | A04:2025
Using deprecated TLS versions (TLS 1.0, TLS 1.1, SSLv3) exposes traffic to known cryptographic attacks (BEAST, POODLE).
Wrong: context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_0)
Right: enforce modern TLS protocol versions: context = ssl.create_default_context() or mandate ssl.PROTOCOL_TLSv1_3
Watch: ensure client and server cipher suites disable obsolete ciphers (RC4, 3DES).

## sbd-dynamic-eval-reflection
OWASP: Injection & Safe Code Execution | CWE-470 | A05:2025
Dynamically evaluating code or constructing runtime execution objects from untrusted user requests causes Remote Code Execution (RCE).
Wrong: eval(req.body.code)
Right: use static data structures or safe declarative parsers without dynamic code interpretation.
Watch: dynamic reflection should only match against a strict compile-time allowlist of known safe types.

## sbd-unauthenticated-route
OWASP: Access Control & Authorization | CWE-306 | A01:2025
Administrative or privileged route handlers exposed without explicit authentication middleware allow unauthorized access.
Wrong: app.get("/admin/users", handleAdminUsers)
Right: attach authentication and RBAC middleware: app.get("/admin/users", authenticate, requireRole("admin"), handleAdminUsers)
Watch: apply authorization guards globally or at router level rather than relying on per-handler checks.

## iot-unencrypted-mqtt
OWASP: IoT & Embedded Security (AS ETSI EN 303 645) | CWE-319 | A04:2025
Connecting to MQTT message brokers without TLS transmits telemetry, sensor data, and control commands in cleartext.
Wrong: client.connect("mqtt://broker.hivemq.com:1883")
Right: connect over secure TLS port 8883 with mutual certificates: client.connect("mqtts://broker.hivemq.com:8883", { cert, key, ca })
Watch: verify the broker certificate and enforce client certificate authentication (mTLS).

## iot-unencrypted-coap
OWASP: IoT & Embedded Security (AS ETSI EN 303 645) | CWE-319 | A04:2025
Transmitting sensor metrics or actuations over unencrypted CoAP allows eavesdropping and packet injection on constrained networks.
Wrong: coap://sensor.local/telemetry
Right: use CoAPS over DTLS 1.3: coaps://sensor.local/telemetry with pre-shared keys (PSK) or X.509 certs.
Watch: DTLS handshake replay protection should be enabled on constrained edge nodes.

## iot-debug-interface
OWASP: IoT & Embedded Security (AS ETSI EN 303 645) | CWE-1263 | A02:2025
Enabling hardware debug interfaces (JTAG, UART, SWD) in production firmware allows physical extraction of firmware and keys.
Wrong: #define DEBUG_UART 1
Right: disable all debug logs, JTAG, and SWD interfaces in production builds (#define DEBUG_UART 0 or blow debug eFuses).
Watch: verify that production build configurations strip debug symbols and disable console serial output.

## iot-ota-no-verify
OWASP: IoT & Embedded Security (AS ETSI EN 303 645) | CWE-494 | A08:2025
Flashing OTA firmware updates without cryptographic signature verification allows malicious firmware overwrites.
Wrong: flash_write(OTA_PARTITION, image_buffer, image_len)
Right: verify the digital signature against a trusted public key baked into the hardware bootloader before flashing.
Watch: implement anti-rollback version counters to prevent downgrade attacks to vulnerable older firmware.

## iot-hardcoded-flash-key
OWASP: IoT & Embedded Security (AS ETSI EN 303 645) | CWE-798 | A04:2025
Hardcoding encryption keys or master secrets into firmware sources allows attackers to extract identical keys across all devices.
Wrong: #define DEVICE_KEY "a1b2c3d4e5f60718293a4b5c6d7e8f90"
Right: use unique per-device keys provisioned in a Hardware Root of Trust (Secure Element / TPM / ARM TrustZone).
Watch: never share symmetric master keys across a fleet of physical IoT devices.
