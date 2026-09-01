# Java / Kotlin — secure snippets

Load only when writing Java or Kotlin. Copy the right shape; adapt names.

## Parameterized query (JDBC)
```java
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE email = ?");
ps.setString(1, email);
ResultSet rs = ps.executeQuery();
// never: Statement + string concatenation
```

## Password hashing (org.springframework.security.crypto / argon2)
```java
// Spring: BCryptPasswordEncoder().encode(password)
// or argon2: Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
// never: MessageDigest sha256/md5 on a password
```

## Authenticated encryption (AES-GCM)
```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
byte[] ct = c.doFinal(plaintext);
// never: AES/ECB, DES, RC4
```

## Secure random token
```java
byte[] b = new byte[32];
SecureRandom sr = new SecureRandom();
sr.nextBytes(b);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
// never: new Random(), Math.random() for tokens/keys/salts
```

## Constant-time compare
```java
import java.security.MessageDigest;
if (!MessageDigest.isEqual(a, b)) { /* deny */ }
```

## Safe temp file
```java
Path p = Files.createTempFile("prefix", ".tmp");
// never: File.createTempFile with a guessed name is ok, but never a fixed name
```

## Secure cookie
```java
Cookie c = new Cookie("sid", token);
c.setHttpOnly(true);
c.setSecure(true);
c.setAttribute("SameSite", "Lax");
response.addCookie(c);
```

## Shell — argument list, never a shell string
```java
ProcessBuilder pb = new ProcessBuilder("ls", "-l", dir);
Process p = pb.start();
// never: Runtime.getRuntime().exec("ls -l " + dir)
```

## Input validation — allowlist, not blocklist
```java
// allowlist what is valid; reject everything else
if (!username.matches("[A-Za-z0-9_]{1,32}")) { /* reject */ }
// validate type, range, length
if (age < 0 || age > 150) { /* reject */ }
// never: a blocklist of "bad" characters — it always misses one
```

## Output encoding — escape for the exact context
```java
// HTML: use a real encoder (e.g. HtmlUtils.htmlEscape / OWASP ESAPI)
// URL: URLEncoder.encode(input, StandardCharsets.UTF_8)
// JSON: use a JSON library, never string concat
// SQL: use parameters (see above), never escape-by-hand
// never: injecting raw input into HTML/JS/URL/SQL
```

## CSRF token — per-session, validated on state changes
```java
// generate once per session, store server-side
String csrf = UUID.randomUUID().toString();
// on every state-changing request, compare the submitted token
if (!MessageDigest.isEqual(a, b)) { /* deny */ }
// never: accepting state changes without a CSRF token
```

## TLS — verification on, never disabled
```java
// default SSLContext verifies certs; never disable
SSLContext ctx = SSLContext.getDefault();
// never: TrustManager that accepts everything, verify=false
```

## Secrets — from env or a secret manager, never in code
```java
String dbPassword = System.getenv("DB_PASSWORD");   // or a secret manager
// never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```java
try { doThing(); }
catch (Exception e) {
    log.error("operation failed", e);        // full detail to logs only
    return ResponseEntity.status(500).body("Something went wrong");
}
// never: returning e.getMessage(), a stack trace, SQL, or file paths
```

## Secure logging — log events, never secrets
```java
log.info("login ok user={}", user);          // log the event
// never: logging passwords, tokens, keys, session ids, card numbers
// sanitize untrusted data so it cannot execute in a log viewer
```

## File upload — validate content, store out of web root
```java
// check the file's magic bytes / MIME, not just the extension
String mime = Files.probeContentType(path);
if (!Set.of("image/png", "image/jpeg").contains(mime)) { /* reject */ }
// store under a random name outside the web root, never the client's name
// never: trusting the extension or client-supplied filename
```

## Safe redirect — allowlist targets only
```java
Set<String> allowed = Set.of("/dashboard", "/profile");
String target = allowed.contains(next) ? next : "/";
// never: redirecting to a user-supplied URL (open redirect)
```

## Cache-Control — no-store for sensitive responses
```java
response.setHeader("Cache-Control", "no-store");
response.setHeader("Pragma", "no-cache");
// never: letting sensitive pages be cached
```

## Session — regenerate id at login and privilege change
```java
// after login / privilege escalation:
request.changeSessionId();   // new session id, old one invalidated
// never: accepting a caller-supplied session id, or reusing the pre-login id
```

## Password complexity — enforce policy on input
```java
public static void validatePassword(String pw) {
    if (pw.length() < 12) throw new IllegalArgumentException("password too short");
    if (!pw.matches(".*[A-Z].*") || !pw.matches(".*[0-9].*") || !pw.matches(".*[^A-Za-z0-9].*"))
        throw new IllegalArgumentException("password must include upper, digit, and symbol");
}
// never: accepting any password without policy checks
```

## File permissions — least privilege
```java
import java.nio.file.*;
Path p = Files.writeString(Path.of(path), data, StandardOpenOption.CREATE,
    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
// set owner-only via FileAttribute: PosixFilePermissions.asFileAttribute(Set.of(OWNER_READ, OWNER_WRITE))
// never: world-readable/writable permissions
```

## Encryption at rest — encrypt sensitive stored data
```java
// use AES-GCM (see Authenticated encryption above) for stored data
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
byte[] ct = c.doFinal(plaintext);
// store ct; decrypt with Cipher DECRYPT_MODE
// never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```java
import java.security.MessageDigest;
MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] hash = md.digest(Files.readAllBytes(Path.of(path)));
// compare against a known-good hash stored separately
// never: deploying without verifying integrity of interpreted code, libraries, or config
```

## SSRF prevention — validate URLs before server-side requests
```java
import java.net.URI;
import java.net.InetAddress;

Set<String> allowedHosts = Set.of("api.example.com", "cdn.example.com");

boolean isSafeUrl(String urlStr) {
    URI uri = URI.create(urlStr);
    if (!"https".equals(uri.getScheme())) return false;
    if (!allowedHosts.contains(uri.getHost())) return false;
    try {
        InetAddress addr = InetAddress.getByName(uri.getHost());
        if (addr.isLoopbackAddress() || addr.isAnyLocalAddress()) return false;
    } catch (Exception e) { return false; }
    return true;
}

if (!isSafeUrl(userUrl)) throw new IllegalArgumentException("URL not allowed");
// never: new URL(request.getParameter("url")) without validation
```

## CORS — explicit origin allowlist, never wildcard
```java
Set<String> allowedOrigins = Set.of("https://app.example.com");

// In your filter or handler:
String origin = request.getHeader("Origin");
if (allowedOrigins.contains(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Credentials", "true");
}
// never: Access-Control-Allow-Origin: * with credentials
```

## Log injection prevention — sanitize user input before logging
```java
String sanitizeLog(String value) {
    // Escape first: stripping control chars first would delete the CR/LF
    // before the replace() calls could ever see them, silently merging tokens.
    return value.replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replaceAll("[\\x00-\\x1f\\x7f]", "");
}

logger.info("user_action user={} input={}", user, sanitizeLog(userInput));
// never: logging unsanitized user input — CR/LF can forge log entries
```
