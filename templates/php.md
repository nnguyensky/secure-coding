# PHP — secure snippets

Load only when writing PHP. Copy the right shape; adapt names.

## Parameterized query (PDO)
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);
// never: mysqli_query($c, "SELECT ... WHERE email = " . $email)
```

## Password hashing (password_hash)
```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
// verify: password_verify($password, $hash)
// never: md5($password), sha1($password), hash("sha256", $password)
```

## Authenticated encryption (openssl AES-256-GCM)
```php
$iv = random_bytes(12);
$ct = openssl_encrypt($plaintext, "aes-256-gcm", $key, OPENSSL_RAW_DATA, $iv, $tag);
// never: openssl_encrypt($d, "des-ecb", $k), mcrypt_*
```

## Secure random token
```php
$token = bin2hex(random_bytes(32));
// never: rand(), mt_rand() for tokens/keys/salts
```

## Constant-time compare
```php
if (!hash_equals($a, $b)) { /* deny */ }
```

## Safe temp file
```php
$f = tmpfile();
// or: tempnam(sys_get_temp_dir(), "prefix")
// never: a guessed name in /tmp
```

## Secure cookie
```php
setcookie("sid", $token, [
    "httponly" => true,
    "secure" => true,
    "samesite" => "Lax",
]);
```

## Shell — argument list, never a shell string
```php
// PHP has no safe arg-list exec; avoid shell entirely.
// never: shell_exec("ls " . $dir), system(), passthru(), exec() on input
```

## Path safety
```php
$base = realpath(__DIR__ . "/uploads");
$path = realpath($base . "/" . $name);
if ($path === false || strpos($path, $base) !== 0) { /* deny */ }
// never: file_get_contents($_GET["file"])
```

## Input validation — allowlist, not blocklist
```php
// allowlist what is valid; reject everything else
if (!preg_match('/^[A-Za-z0-9_]{1,32}$/', $username)) { /* reject */ }
// validate type, range, length
if (!is_int($age) || $age < 0 || $age > 150) { /* reject */ }
// never: a blocklist of "bad" characters — it always misses one
```

## Output encoding — escape for the exact context
```php
htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');  // HTML body / attribute
rawurlencode($user_input);                            // URL / query
json_encode($user_input);                             // JSON (never concat)
// SQL: use parameters (see above), never escape-by-hand
// never: injecting raw input into HTML/JS/URL/SQL
```

## CSRF token — per-session, validated on state changes
```php
$csrf = bin2hex(random_bytes(32));   // store in $_SESSION
// on every state-changing request:
if (!hash_equals($_SESSION['csrf'], $_POST['csrf'])) { /* deny */ }
// never: accepting state changes without a CSRF token
```

## TLS — verification on, never disabled
```php
$ctx = stream_context_create(['ssl' => ['verify_peer' => true,
                                        'verify_peer_name' => true]]);
// never: verify_peer => false, verify_peer_name => false
```

## Secrets — from env or a secret manager, never in code
```php
$dbPassword = getenv('DB_PASSWORD');   // or a secret manager
// never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```php
try { doThing(); }
catch (Throwable $e) {
    error_log($e);                       // full detail to logs only
    http_response_code(500);
    echo "Something went wrong";         // generic to the user
}
// never: echoing $e->getMessage(), a stack trace, SQL, or file paths
```

## Secure logging — log events, never secrets
```php
error_log("login ok user=$user");        // log the event
// never: logging passwords, tokens, keys, session ids, card numbers
// sanitize untrusted data so it cannot execute in a log viewer
```

## File upload — validate content, store out of web root
```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['f']['tmp_name']);
if (!in_array($mime, ['image/png', 'image/jpeg'], true)) { /* reject */ }
// store under a random name outside the web root, never the client's name
// never: trusting the extension or client-supplied filename
```

## Safe redirect — allowlist targets only
```php
$allowed = ['/dashboard', '/profile'];
$target = in_array($_GET['next'], $allowed, true) ? $_GET['next'] : '/';
header("Location: $target");
// never: redirecting to a user-supplied URL (open redirect)
```

## Cache-Control — no-store for sensitive responses
```php
header('Cache-Control: no-store');
header('Pragma: no-cache');
// never: letting sensitive pages be cached
```

## Session — regenerate id at login and privilege change
```php
// after login / privilege escalation:
session_regenerate_id(true);   // new session id, old one invalidated
// never: accepting a caller-supplied session id, or reusing the pre-login id
```

## Password complexity — enforce policy on input
```php
function validatePassword(string $pw): void {
    if (strlen($pw) < 12) throw new InvalidArgumentException("password too short");
    if (!preg_match('/[A-Z]/', $pw) || !preg_match('/[0-9]/', $pw) || !preg_match('/[^A-Za-z0-9]/', $pw))
        throw new InvalidArgumentException("password must include upper, digit, and symbol");
}
// never: accepting any password without policy checks
```

## File permissions — least privilege
```php
$fd = fopen($path, 'w');
chmod($path, 0600);
// never: 0666 or 0777
```

## Encryption at rest — encrypt sensitive stored data
```php
// use openssl AES-256-GCM (see Authenticated encryption above) for stored data
$iv = random_bytes(12);
$ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
// store iv + ct + tag; decrypt with openssl_decrypt
// never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```php
$hash = hash_file('sha256', $path);
// compare against a known-good hash stored separately
// never: deploying without verifying integrity of interpreted code, libraries, or config
```

## SSRF prevention — validate URLs before server-side requests
```php
$allowedHosts = ['api.example.com', 'cdn.example.com'];

function isSafeUrl(string $url): bool {
    $parsed = parse_url($url);
    if (!$parsed || ($parsed['scheme'] ?? '') !== 'https') return false;
    if (!in_array($parsed['host'] ?? '', $GLOBALS['allowedHosts'], true)) return false;
    $ip = gethostbyname($parsed['host']);
    if (str_starts_with($ip, '127.') || str_starts_with($ip, '10.') ||
        str_starts_with($ip, '192.168.') || str_starts_with($ip, '169.254.')) return false;
    return true;
}

if (!isSafeUrl($userUrl)) throw new InvalidArgumentException("URL not allowed");
// never: file_get_contents($_GET['url']) without validation
```

## CORS — explicit origin allowlist, never wildcard
```php
$allowedOrigins = ['https://app.example.com'];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins, true)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
}
// never: header("Access-Control-Allow-Origin: *") with credentials
```

## Log injection prevention — sanitize user input before logging
```php
function sanitizeLog(string $value): string {
    return preg_replace('/[\x00-\x1f\x7f]/', '', str_replace(["\n", "\r"], ["\\n", "\\r"], $value));
}

error_log("user_action user=$user input=" . sanitizeLog($userInput));
// never: logging unsanitized user input — CR/LF can forge log entries
```
