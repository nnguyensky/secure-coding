# Go — secure snippets

Load only when writing Go. Copy the right shape; adapt names.

## Parameterized query (database/sql)
```go
rows, err := db.Query("SELECT * FROM users WHERE email = ?", email)
// never: db.Query("SELECT * FROM users WHERE email = " + email)
```

## Password hashing (golang.org/x/crypto/argon2)
```go
salt := make([]byte, 16)
if _, err := rand.Read(salt); err != nil { /* fail closed */ }
hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
// store salt + hash; verify with argon2.IDKey + subtle.ConstantTimeCompare
```

## Authenticated encryption (AES-GCM)
```go
block, _ := aes.NewCipher(key)          // key: 32 bytes from crypto/rand
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
if _, err := rand.Read(nonce); err != nil { /* fail closed */ }
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
// decrypt: gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
```

## Secure random token
```go
b := make([]byte, 32)
if _, err := rand.Read(b); err != nil { /* fail closed */ }
token := base64.RawURLEncoding.EncodeToString(b)
// never: math/rand for tokens, keys, salts, resets
```

## Constant-time compare
```go
import "crypto/subtle"
if subtle.ConstantTimeCompare(a, b) != 1 { /* deny */ }
```

## Safe temp file
```go
f, err := os.CreateTemp("", "prefix-*")
// never: os.Create with a guessed name, mktemp
```

## Secure cookie
```go
http.SetCookie(w, &http.Cookie{
    Name: "sid", Value: token,
    HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
})
```

## Shell — argument list, never a shell string
```go
out, err := exec.Command("ls", "-l", dir).Output()
// never: exec.Command("sh", "-c", "ls " + dir)
```

## Input validation — allowlist, not blocklist
```go
import "regexp"
var userRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
if !userRe.MatchString(username) { /* reject */ }
// validate type, range, length
if age < 0 || age > 150 { /* reject */ }
// never: a blocklist of "bad" characters — it always misses one
```

## Output encoding — escape for the exact context
```go
import "html"   // html.EscapeString for HTML body / attribute
import "net/url" // url.QueryEscape for URL / query
// JSON: use encoding/json, never string concat
// SQL: use parameters (see above), never escape-by-hand
// never: injecting raw input into HTML/JS/URL/SQL
```

## TLS — verification on, never disabled
```go
// http.Client verifies certs by default; never disable
client := &http.Client{}
// never: &tls.Config{InsecureSkipVerify: true}
```

## Secrets — from env or a secret manager, never in code
```go
dbPassword := os.Getenv("DB_PASSWORD")   // or a secret manager
// never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```go
if err := doThing(); err != nil {
    log.Printf("operation failed: %v", err)   // full detail to logs only
    http.Error(w, "Something went wrong", http.StatusInternalServerError)
}
// never: returning err.Error(), a stack trace, SQL, or file paths
```

## Secure logging — log events, never secrets
```go
log.Printf("login ok user=%s", user)   // log the event
// never: logging passwords, tokens, keys, session ids, card numbers
// sanitize untrusted data so it cannot execute in a log viewer
```

## File permissions — least privilege
```go
// create files with 0600, never 0666/0777
f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
// never: os.Create (0666), os.WriteFile with 0777
```

## Race conditions — synchronize shared state
```go
var mu sync.Mutex
mu.Lock()
defer mu.Unlock()
// ... shared state ...
// never: reading/writing shared state without a lock
```

## Password complexity — enforce policy on input
```go
func validatePassword(pw string) error {
	if len(pw) < 12 {
		return fmt.Errorf("password too short")
	}
	hasUpper, hasDigit, hasSymbol := false, false, false
	for _, c := range pw {
		switch {
		case c >= 'A' && c <= 'Z': hasUpper = true
		case c >= '0' && c <= '9': hasDigit = true
		case c >= 33 && c <= 126:  hasSymbol = true
		}
	}
	if !hasUpper || !hasDigit || !hasSymbol {
		return fmt.Errorf("password must include upper, digit, and symbol")
	}
	return nil
}
// never: accepting any password without policy checks
```

## Encryption at rest — encrypt sensitive stored data
```go
// use AES-GCM (see Authenticated encryption above) for stored data
block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
if _, err := rand.Read(nonce); err != nil { /* fail closed */ }
ct := gcm.Seal(nonce, nonce, plaintext, nil)
// store ct; decrypt with gcm.Open
// never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```go
import "crypto/sha256"
data, _ := os.ReadFile(path)
h := sha256.Sum256(data)
// compare h[:] against a known-good hash stored separately
// never: deploying without verifying integrity of interpreted code, libraries, or config
```

## Cache-Control — no-store for sensitive responses
```go
w.Header().Set("Cache-Control", "no-store")
w.Header().Set("Pragma", "no-cache")
// never: letting sensitive pages be cached
```

## Session — regenerate id at login and privilege change
```go
// after login / privilege escalation:
// generate a new session id, invalidate the old one
session.ID = generateSessionID()
// never: accepting a caller-supplied session id, or reusing the pre-login id
```

## SSRF prevention — validate URLs before server-side requests
```go
import "net/url"

var allowedHosts = map[string]bool{"api.example.com": true, "cdn.example.com": true}

func isSafeURL(rawURL string) bool {
    u, err := url.Parse(rawURL)
    if err != nil || u.Scheme != "https" {
        return false
    }
    if !allowedHosts[u.Hostname()] {
        return false
    }
    // block internal IPs
    ips, err := net.LookupIP(u.Hostname())
    if err != nil {
        return false
    }
    for _, ip := range ips {
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return false
        }
    }
    return true
}

if !isSafeURL(userURL) {
    return errors.New("URL not allowed")
}
// never: http.Get(r.URL.Query().Get("url")) without validation
```

## CORS — explicit origin allowlist, never wildcard
```go
var allowedOrigins = map[string]bool{"https://app.example.com": true}

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        if allowedOrigins[origin] {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Credentials", "true")
        }
        next.ServeHTTP(w, r)
    })
}
// never: Access-Control-Allow-Origin: * with credentials
```

## Log injection prevention — sanitize user input before logging
```go
import "strings"

func sanitizeLog(s string) string {
    s = strings.ReplaceAll(s, "\n", "\\n")
    s = strings.ReplaceAll(s, "\r", "\\r")
    return s
}

log.Printf("user_action user=%s input=%s", user, sanitizeLog(userInput))
// never: logging unsanitized user input — CR/LF can forge log entries
```
