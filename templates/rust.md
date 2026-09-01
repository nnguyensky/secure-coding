# Rust — secure snippets

Load only when writing Rust. Copy the right shape; adapt names.

## Parameterized query (sqlx / rusqlite)
```rust
// sqlx:
let row = sqlx::query("SELECT * FROM users WHERE email = $1")
    .bind(email).fetch_one(&pool).await?;
// rusqlite:
stmt.query_row("SELECT * FROM users WHERE email = ?1", [&email], |r| ...)?;
// never: format!("SELECT ... WHERE email = {}", email)
```

## Password hashing (argon2 crate)
```rust
use argon2::{Argon2, PasswordHasher, password_hash::{SaltString, rand_core::OsRng}};
let salt = SaltString::generate(&mut OsRng);
let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?.to_string();
// never: Sha256::digest(password)
```

## Authenticated encryption (aes-gcm crate)
```rust
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, AeadCore, OsRng}};
let cipher = Aes256Gcm::new_from_slice(&key)?;   // key: 32 bytes
let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // fresh random 96-bit nonce
let ct = cipher.encrypt(&nonce, plaintext.as_ref())?;
// never: static/reused nonce, des::, rc4::, blowfish::
```

## Secure random token
```rust
use rand::RngCore;
use base64::prelude::*;
let mut b = [0u8; 32];
rand::rngs::OsRng.fill_bytes(&mut b);
let token = BASE64_URL_SAFE_NO_PAD.encode(b);
// never: rand::thread_rng() for tokens/keys/salts
```

## Constant-time compare
```rust
use subtle::ConstantTimeEq;
if !a.ct_eq(b).into() { /* deny */ }
```

## Safe temp file
```rust
let f = tempfile::NamedTempFile::new()?;
// never: a guessed name in /tmp
```

## Shell — argument list, never a shell string
```rust
let out = std::process::Command::new("ls").arg("-l").arg(dir).output()?;
// never: Command::new("sh").arg("-c").arg(cmd)
```

## Input validation — allowlist, not blocklist
```rust
// allowlist what is valid; reject everything else
if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    || username.len() > 32 {
    return Err("invalid username");
}
// validate type, range, length
if !(0..=150).contains(&age) { return Err("invalid age"); }
// never: a blocklist of "bad" characters — it always misses one
```

## Output encoding — escape for the exact context
```rust
// HTML: use a real encoder (e.g. askama/tera auto-escape)
// URL: urlencoding::encode(input)
// JSON: use serde_json, never string concat
// SQL: use parameters (see above), never escape-by-hand
// never: injecting raw input into HTML/JS/URL/SQL
```

## TLS — verification on, never disabled
```rust
// reqwest verifies certs by default; never disable
let client = reqwest::Client::new();
// never: danger_accept_invalid_certs(true)
```

## Secrets — from env or a secret manager, never in code
```rust
let db_password = std::env::var("DB_PASSWORD")?;   // or a secret manager
// never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```rust
match do_thing() {
    Ok(_) => {}
    Err(e) => {
        eprintln!("operation failed: {e}");   // full detail to logs only
        // return a generic message to the user
    }
}
// never: returning the raw error, a stack trace, SQL, or file paths
```

## Secure logging — log events, never secrets
```rust
info!("login ok user={user}");   // log the event
// never: logging passwords, tokens, keys, session ids, card numbers
// sanitize untrusted data so it cannot execute in a log viewer
```

## File permissions — least privilege
```rust
use std::os::unix::fs::OpenOptionsExt;
let f = OpenOptions::new().write(true).create(true).mode(0o600).open(path)?;
// never: 0o666/0o777, or a guessed temp name
```

## Race conditions — synchronize shared state
```rust
use std::sync::{Arc, Mutex};
let state = Arc::new(Mutex::new(shared));
let mut g = state.lock().unwrap();
// ... shared state ...
// never: reading/writing shared state without a lock
```

## Password complexity — enforce policy on input
```rust
fn validate_password(pw: &str) -> Result<(), &'static str> {
    if pw.len() < 12 { return Err("password too short"); }
    let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw.chars().any(|c| !c.is_ascii_alphanumeric());
    if !has_upper || !has_digit || !has_symbol { return Err("password must include upper, digit, and symbol"); }
    Ok(())
}
// never: accepting any password without policy checks
```

## Encryption at rest — encrypt sensitive stored data
```rust
// use aes-gcm crate (see Authenticated encryption above) for stored data
let ct = cipher.encrypt(nonce, plaintext.as_ref())?;
// store ct; decrypt with cipher.decrypt
// never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```rust
use sha2::{Sha256, Digest};
let hash = Sha256::digest(std::fs::read(path)?);
// compare against a known-good hash stored separately
// never: deploying without verifying integrity of interpreted code, libraries, or config
```

## Secure cookie — HttpOnly, Secure, SameSite
```rust
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build(("session", token))
        .http_only(true)                 // unreachable from JavaScript
        .secure(true)                    // HTTPS only
        .same_site(SameSite::Strict)     // not sent on cross-site requests
        .path("/")
        .max_age(Duration::hours(8))
        .build()
}
```

## File upload — validate content, never trust the name
```rust
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MAX_UPLOAD: usize = 10 * 1024 * 1024;

fn handle_upload(data: &[u8], upload_dir: &Path) -> Result<PathBuf, Error> {
    if data.len() > MAX_UPLOAD {
        return Err(Error::TooLarge);
    }
    // Sniff the real type from the bytes; the supplied filename is untrusted.
    let ext = match infer::get(data).map(|t| t.mime_type()) {
        Some("image/jpeg") => "jpg",
        Some("image/png") => "png",
        Some("application/pdf") => "pdf",
        _ => return Err(Error::InvalidType),
    };
    let dest = upload_dir.join(format!("{}.{ext}", Uuid::new_v4()));

    // Confirm the path is still inside upload_dir before writing.
    let root = upload_dir.canonicalize()?;
    if !dest.parent().map_or(false, |p| p.canonicalize().map_or(false, |c| c.starts_with(&root))) {
        return Err(Error::PathEscape);
    }
    std::fs::write(&dest, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(dest)
}
```

## Safe redirect — allowlist the destination
```rust
use url::Url;

const ALLOWED_HOSTS: &[&str] = &["app.example.com", "www.example.com"];

fn safe_redirect(target: &str) -> String {
    // A relative path with no host is safe; anything else must be allowlisted.
    match Url::parse(target) {
        Ok(u) => {
            let host_ok = u.host_str().map_or(false, |h| ALLOWED_HOSTS.contains(&h));
            if u.scheme() == "https" && host_ok { u.to_string() } else { "/".to_string() }
        }
        // Parse failure means it is relative — accept only a rooted path.
        Err(_) if target.starts_with('/') && !target.starts_with("//") => target.to_string(),
        Err(_) => "/".to_string(), // fail closed
    }
}
```

## Cache-Control — no-store for sensitive responses
```rust
// axum / actix-web:
response.headers_mut().insert("Cache-Control", "no-store".parse().unwrap());
response.headers_mut().insert("Pragma", "no-cache".parse().unwrap());
// never: letting sensitive pages be cached
```

## Session — regenerate id at login and privilege change
```rust
// after login / privilege escalation:
// generate a new session id, invalidate the old one
session.id = generate_session_id();
// never: accepting a caller-supplied session id, or reusing the pre-login id
```

## SSRF prevention — validate URLs before server-side requests
```rust
use url::Url;
use std::net::IpAddr;

const ALLOWED_HOSTS: &[&str] = &["api.example.com", "cdn.example.com"];

fn is_safe_url(url_str: &str) -> bool {
    let url = match Url::parse(url_str) {
        Ok(u) => u, Err(_) => return false,
    };
    if url.scheme() != "https" { return false; }
    let host = match url.host_str() { Some(h) => h, None => return false };
    if !ALLOWED_HOSTS.contains(&host) { return false; }
    // block internal IPs
    if let Ok(ips) = dns_lookup::lookup_host(host) {
        for ip in ips {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                if addr.is_loopback() || addr.is_private() || addr.is_link_local() {
                    return false;
                }
            }
        }
    }
    true
}

if !is_safe_url(&user_url) { return Err("URL not allowed".into()); }
// never: reqwest::get(&user_url) without validation
```

## CORS — explicit origin allowlist, never wildcard
```rust
const ALLOWED_ORIGINS: &[&str] = &["https://app.example.com"];

// In your handler/middleware:
if let Some(origin) = headers.get("origin") {
    if ALLOWED_ORIGINS.contains(&origin.to_str().unwrap_or("")) {
        response.headers_mut().insert("access-control-allow-origin", origin.clone());
        response.headers_mut().insert("access-control-allow-credentials", "true".parse().unwrap());
    }
}
// never: Access-Control-Allow-Origin: * with credentials
```

## Log injection prevention — sanitize user input before logging
```rust
fn sanitize_log(value: &str) -> String {
    value.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r')
        .collect::<String>()
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

info!("user_action user={} input={}", user, sanitize_log(&user_input));
// never: logging unsanitized user input — CR/LF can forge log entries
```
