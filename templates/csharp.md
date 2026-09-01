# C# — secure snippets

Load only when writing C#. Copy the right shape; adapt names.

## Parameterized query (ADO.NET)
```csharp
using var cmd = new SqlCommand(
    "SELECT * FROM users WHERE email = @email", conn);
cmd.Parameters.AddWithValue("@email", email);
// never: "SELECT ... WHERE email = " + email, string.Format in SQL
```

## Password hashing (ASP.NET Core Identity / PBKDF2)
```csharp
// Use ASP.NET Core Identity's PasswordHasher<TUser>.
// never: SHA256.Create().ComputeHash(password), MD5.Create()
```

## Authenticated encryption (AES-GCM, .NET 6+)
```csharp
using var aes = new AesGcm(key, 16);   // key: 32 bytes
var nonce = RandomNumberGenerator.GetBytes(aes.NonceSize);
var ct = new byte[plaintext.Length];
var tag = new byte[aes.TagSize];
aes.Encrypt(nonce, plaintext, ct, tag);
// never: DES.Create(), RC2.Create(), TripleDES
```

## Secure random token
```csharp
var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
// never: new Random().Next(), Random.Shared for tokens/keys/salts
```

## Constant-time compare
```csharp
using System.Security.Cryptography;
if (!CryptographicOperations.FixedTimeEquals(a, b)) { /* deny */ }
```

## Safe temp file
```csharp
var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
// never: a guessed name in /tmp
```

## Secure cookie
```csharp
Response.Cookies.Append("sid", token, new CookieOptions {
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Lax,
});
```

## Shell — argument list, never a shell string
```csharp
var psi = new ProcessStartInfo("ls") { ArgumentList = { "-l", dir } };
var p = Process.Start(psi);
// never: Process.Start("ls -l " + dir), or UseShellExecute with a string
```

## Input validation — allowlist, not blocklist
```csharp
// allowlist what is valid; reject everything else
if (!Regex.IsMatch(username, @"^[A-Za-z0-9_]{1,32}$")) { /* reject */ }
// validate type, range, length
if (age < 0 || age > 150) { /* reject */ }
// never: a blocklist of "bad" characters — it always misses one
```

## Output encoding — escape for the exact context
```csharp
// HTML: WebUtility.HtmlEncode(input)
// URL: Uri.EscapeDataString(input)
// JSON: use System.Text.Json, never string concat
// SQL: use parameters (see above), never escape-by-hand
// never: injecting raw input into HTML/JS/URL/SQL
```

## CSRF token — per-session, validated on state changes
```csharp
// ASP.NET Core: [ValidateAntiForgeryToken] + @Html.AntiForgeryToken()
// never: accepting state changes without a CSRF token
```

## TLS — verification on, never disabled
```csharp
// HttpClient verifies certs by default; never disable
using var client = new HttpClient();
// never: HttpClientHandler { ServerCertificateCustomValidationCallback = (..) => true }
```

## Secrets — from env or a secret manager, never in code
```csharp
var dbPassword = Environment.GetEnvironmentVariable("DB_PASSWORD");
// or: IConfiguration + a secret manager (Azure Key Vault, etc.)
// never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```csharp
try { DoThing(); }
catch (Exception e) {
    _logger.LogError(e, "operation failed");   // full detail to logs only
    return StatusCode(500, "Something went wrong");
}
// never: returning e.Message, a stack trace, SQL, or file paths
```

## Secure logging — log events, never secrets
```csharp
_logger.LogInformation("login ok user={User}", user);   // log the event
// never: logging passwords, tokens, keys, session ids, card numbers
// sanitize untrusted data so it cannot execute in a log viewer
```

## File upload — validate content, store out of web root
```csharp
// check the file's magic bytes / MIME, not just the extension
if (!allowedMime.Contains(file.ContentType)) { /* reject */ }
// store under a random name outside the web root, never the client's name
// never: trusting the extension or client-supplied filename
```

## Safe redirect — allowlist targets only
```csharp
var allowed = new HashSet<string> { "/dashboard", "/profile" };
var target = allowed.Contains(next) ? next : "/";
// never: redirecting to a user-supplied URL (open redirect)
```

## Cache-Control — no-store for sensitive responses
```csharp
Response.Headers.CacheControl = "no-store";
Response.Headers.Pragma = "no-cache";
// never: letting sensitive pages be cached
```

## Session — regenerate id at login and privilege change
```csharp
// after login / privilege escalation:
await HttpContext.SignInAsync(...);   // issues a new session id
// never: accepting a caller-supplied session id, or reusing the pre-login id
```

## Password complexity — enforce policy on input
```csharp
public static void ValidatePassword(string pw) {
    if (pw.Length < 12) throw new ArgumentException("password too short");
    if (!pw.Any(char.IsUpper) || !pw.Any(char.IsDigit) || !pw.Any(c => !char.IsLetterOrDigit(c)))
        throw new ArgumentException("password must include upper, digit, and symbol");
}
// never: accepting any password without policy checks
```

## File permissions — least privilege
```csharp
var fi = new FileInfo(path);
fi.Create().Dispose();   // create first
File.SetAttributes(path, FileAttributes.Normal);
// then write; control ACLs via System.Security.AccessControl
// never: world-readable/writable permissions
```

## Encryption at rest — encrypt sensitive stored data
```csharp
// use AesGcm (see Authenticated encryption above) for stored data
using var aes = new AesGcm(key, 16);
var nonce = RandomNumberGenerator.GetBytes(aes.NonceSize);
var ct = new byte[plaintext.Length];
var tag = new byte[aes.TagSize];
aes.Encrypt(nonce, plaintext, ct, tag);
// store ct + tag; decrypt with aes.Decrypt
// never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```csharp
using System.Security.Cryptography;
var hash = SHA256.HashData(File.ReadAllBytes(path));
// compare against a known-good hash stored separately
// never: deploying without verifying integrity of interpreted code, libraries, or config
```

## SSRF prevention — validate URLs before server-side requests
```csharp
using System.Net;

var allowedHosts = new HashSet<string> { "api.example.com", "cdn.example.com" };

bool IsSafeUrl(string urlStr) {
    if (!Uri.TryCreate(urlStr, UriKind.Absolute, out var uri)) return false;
    if (uri.Scheme != "https") return false;
    if (!allowedHosts.Contains(uri.Host)) return false;
    try {
        var ip = Dns.GetHostEntry(uri.Host).AddressList[0];
        if (ip.IsLoopback || ip.ToString().StartsWith("10.") ||
            ip.ToString().StartsWith("192.168.") || ip.ToString().StartsWith("169.254."))
            return false;
    } catch { return false; }
    return true;
}

if (!IsSafeUrl(userUrl)) throw new ArgumentException("URL not allowed");
// never: new HttpClient().GetAsync(Request.Query["url"]) without validation
```

## CORS — explicit origin allowlist, never wildcard
```csharp
var allowedOrigins = new HashSet<string> { "https://app.example.com" };

// In your middleware:
var origin = Request.Headers["Origin"].FirstOrDefault();
if (allowedOrigins.Contains(origin)) {
    Response.Headers["Access-Control-Allow-Origin"] = origin;
    Response.Headers["Access-Control-Allow-Credentials"] = "true";
}
// never: Access-Control-Allow-Origin: * with credentials
```

## Log injection prevention — sanitize user input before logging
```csharp
string SanitizeLog(string value) {
    return Regex.Replace(value, @"[\x00-\x1f\x7f]", "")
               .Replace("\n", "\\n").Replace("\r", "\\r");
}

Logger.LogInformation("user_action user={User} input={Input}", user, SanitizeLog(userInput));
// never: logging unsanitized user input — CR/LF can forge log entries
```
