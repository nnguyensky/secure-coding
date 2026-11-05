# JavaScript / Node — secure snippets

Load only when writing JS/Node. Copy the right shape; adapt names.

## Parameterized query (node-postgres / mysql2)
```js
await db.query("SELECT * FROM users WHERE email = $1", [email]);
// never: db.query(`SELECT ... WHERE email = ${email}`)
```

## Password hashing (bcrypt / argon2)
```js
const hash = await bcrypt.hash(password, 12);
// verify: await bcrypt.compare(password, hash)
// never: crypto.createHash("sha256").update(password).digest()
```

## Authenticated encryption (Node crypto AES-256-GCM)
```js
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();
// never: createCipheriv("des-ecb", ...), "rc4"
```

## Secure random token
```js
const token = crypto.randomBytes(32).toString("base64url");
// never: Math.random().toString(36) for tokens/keys/salts
```

## Constant-time compare
```js
const crypto = require("crypto");
const bufA = Buffer.from(String(a));
const bufB = Buffer.from(String(b));
if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
  // deny
}
```

## Safe temp file
```js
const f = await fs.mkdtemp(path.join(os.tmpdir(), "prefix-"));
// never: a guessed name in /tmp
```

## Secure cookie
```js
res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });
```

## Shell — argument list, never a shell string
```js
const { execFile } = require("child_process");
execFile("ls", ["-l", dir], cb);
// never: child_process.exec("ls -l " + dir), execFile with a shell string
```

## Safe output / deserialization
```js
el.textContent = userInput;      // never: el.innerHTML = userInput
const data = JSON.parse(text);   // never: eval(text), new Function(text)
```

## Input validation — allowlist, not blocklist
```js
// allowlist what is valid; reject everything else
if (!/^[A-Za-z0-9_]{1,32}$/.test(username)) throw new Error("invalid");
// validate type, range, length
if (typeof age !== "number" || age < 0 || age > 150) throw new Error("invalid");
// never: a blocklist of "bad" characters — it always misses one
```

## Output encoding — escape for the exact context
```js
// HTML: use textContent, or a real escape fn — never innerHTML with input
// URL: encodeURIComponent(userInput)
// JSON: JSON.stringify(userInput)  (never build JSON by string concat)
// SQL: use parameters (see above), never escape-by-hand
```

## CSRF token — per-session, validated on state changes
```js
const csrf = crypto.randomBytes(32).toString("base64url");
// on every state-changing request, compare the submitted token
const bufSub = Buffer.from(String(submitted));
const bufCsrf = Buffer.from(String(sessionCsrf));
if (bufSub.length !== bufCsrf.length || !crypto.timingSafeEqual(bufSub, bufCsrf)) {
  throw new Error("CSRF check failed");
}
// never: accepting state changes without a CSRF token
```

## TLS — verification on, never disabled
```js
// Node https: verification is on by default
const res = await fetch("https://api.example.com", { agent: new https.Agent() });
// never: rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0
```

## Secrets — from env or a secret manager, never in code
```js
const dbPassword = process.env.DB_PASSWORD;   // or a secret manager
// never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```js
try { await doThing(); }
catch (e) {
  console.error("operation failed", e);       // full detail to logs only
  res.status(500).send("Something went wrong"); // generic to the user
}
// never: sending e.message, a stack trace, SQL, or file paths to the client
```

## Secure logging — log events, never secrets
```js
console.info("login ok user=%s", user);       // log the event
// never: logging passwords, tokens, keys, session ids, card numbers
// sanitize untrusted data so it cannot execute in a log viewer
```

## File upload — validate content, store out of web root
```js
// check the file's magic bytes / MIME, not just the extension
if (!ALLOWED_MIME.has(file.mimetype)) throw new Error("bad type");
// store under a random name outside the web root, never the client's name
// never: trusting the extension or client-supplied filename
```

## Safe redirect — allowlist targets only
```js
const ALLOWED = new Set(["/dashboard", "/profile"]);
const target = ALLOWED.has(req.query.next) ? req.query.next : "/";
// never: redirecting to a user-supplied URL (open redirect)
```

## Cache-Control — no-store for sensitive responses
```js
res.set("Cache-Control", "no-store");
res.set("Pragma", "no-cache");
// never: letting sensitive pages be cached
```

## Session — regenerate id at login and privilege change
```js
// after login / privilege escalation:
req.session.regenerate(() => { /* new session id, old one invalidated */ });
// never: accepting a caller-supplied session id, or reusing the pre-login id
```

## Password complexity — enforce policy on input
```js
function validatePassword(pw) {
  if (pw.length < 12) throw new Error("password too short");
  if (!/[A-Z]/.test(pw) || !/[0-9]/.test(pw) || !/[^A-Za-z0-9]/.test(pw))
    throw new Error("password must include upper, digit, and symbol");
}
// never: accepting any password without policy checks
```

## File permissions — least privilege
```js
const fs = require("fs");
fs.writeFileSync(path, data, { mode: 0o600 });
// never: 0o666 or 0o777
```

## Encryption at rest — encrypt sensitive stored data
```js
const crypto = require("crypto");
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
// store iv + ct + tag; decrypt with createDecipheriv
// never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```js
const crypto = require("crypto");
const hash = crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex");
// compare against a known-good value stored separately
// never: deploying without verifying integrity of interpreted code, libraries, or config
```

## SSRF prevention — validate URLs before server-side requests
```js
const net = require("net");
const dns = require("dns").promises;

const ALLOWED_HOSTS = new Set(["api.example.com", "cdn.example.com"]);

// Is this address private, loopback, link-local or otherwise internal?
function isInternalIp(ip) {
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") ||
           v.startsWith("fe80") || v.startsWith("::ffff:");
  }
  const [a, b] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
         (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
         (a === 100 && b >= 64 && b <= 127);
}

// Returns a URL object you can trust, or throws. The host must be on the
// allowlist AND every address it resolves to must be public.
async function validateOutboundUrl(urlStr) {
  const url = new URL(urlStr);
  if (url.protocol !== "https:") throw new Error("https only");
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error("host not allowed");
  const addrs = await dns.lookup(url.hostname, { all: true });
  if (addrs.some(a => isInternalIp(a.address))) throw new Error("internal address");
  return url;
}

const target = await validateOutboundUrl(req.query.url);
// redirect: "error" stops an allowed host from bouncing you to an internal one
const resp = await fetch(target, { redirect: "error", signal: AbortSignal.timeout(5000) });
// Residual risk: DNS can change between this check and the request. For
// high-risk fetches, connect to the checked IP (custom agent/lookup) or
// route all outbound calls through an egress proxy that blocks internal ranges.
// never: fetch(req.query.url) without validation
```

## CORS — explicit origin allowlist, never wildcard
```js
const ALLOWED_ORIGINS = new Set(["https://app.example.com", "https://admin.example.com"]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});
// never: Access-Control-Allow-Origin: * with credentials
```

## Log injection prevention — sanitize user input before logging
```js
function sanitizeLog(value) {
  return String(value).replace(/[\x00-\x1f\x7f]/g, "").replace(/\n/g, "\\n").replace(/\r/g, "\\r");
}

console.info("user_action user=%s input=%s", user, sanitizeLog(userInput));
// never: logging unsanitized user input — CR/LF can forge log entries
```

## XML parsing — no external entities (XXE)
```js
const { XMLParser } = require("fast-xml-parser");   // never resolves external entities
const doc = new XMLParser({ processEntities: false }).parse(xml);
// libxmljs: parseXml(xml, { noent: false, nonet: true }) — never noent: true
```

## Deserialization — plain data formats only
```js
const body = JSON.parse(raw);           // then validate with a schema (zod, ajv)
const cfg = yaml.load(text, { schema: yaml.JSON_SCHEMA });   // data only: no custom tags
// never: node-serialize unserialize(), eval(), vm.run*() on input
```

## JWT verification — fixed algorithm, issuer and audience
```js
const jwt = require("jsonwebtoken");
const claims = jwt.verify(token, publicKey, {
  algorithms: ["RS256"], issuer: "https://id.example.com", audience: "orders-api",
});
// never: jwt.decode(token) to authorize — it does not check the signature
```
