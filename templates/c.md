# C / C++ — secure snippets

Load only when writing C or C++. Copy the right shape; adapt names.

## Bounded string copy
```c
// never: strcpy(dst, src), strcat, sprintf, gets
snprintf(dst, sizeof dst, "%s", src);
// or: strncpy(dst, src, sizeof dst - 1); dst[sizeof dst - 1] = '\0';
```

## Check every allocation
```c
char *p = malloc(n);
if (p == NULL) { /* fail closed, do not continue */ }
```

## Free once, null after
```c
free(p);
p = NULL;   // prevents double-free and use-after-free
```

## No variable-length stack allocation from input
```c
// never: alloca(input_len)
// use: malloc + bounds check, or a fixed-size buffer
```

## Bounded input
```c
// never: gets(buf)
fgets(buf, sizeof buf, stdin);
```

## Password hashing (libsodium)
```c
// argon2id via libsodium:
char hash[crypto_pwhash_STRBYTES];
crypto_pwhash_str(hash, password, strlen(password),
                  crypto_pwhash_OPSLIMIT_INTERACTIVE,
                  crypto_pwhash_MEMLIMIT_INTERACTIVE);
// verify: crypto_pwhash_str_verify(hash, password, strlen(password))
```

## Authenticated encryption (libsodium)
```c
// secretbox (XSalsa20-Poly1305):
unsigned char ct[crypto_secretbox_MACBYTES + mlen];
crypto_secretbox_easy(ct, msg, mlen, nonce, key);
// never: DES, RC4, Blowfish, ECB
```

## Secure random
```c
unsigned char b[32];
randombytes_buf(b, sizeof b);   // libsodium
// never: rand(), random() for tokens/keys/salts
```

## Constant-time compare
```c
// libsodium:
if (sodium_memcmp(a, b, n) != 0) { /* deny */ }
```

## Safe temp file
```c
// never: mktemp(), tmpnam()
int fd = mkstemp(template);   // template ends in XXXXXX
```

## Input validation — allowlist, not blocklist
```c
// allowlist what is valid; reject everything else
// e.g. only [A-Za-z0-9_], bounded length
if (!is_valid_username(input)) { /* reject */ }
// validate type, range, length before use
// never: a blocklist of "bad" characters — it always misses one
```

## Secrets — from env or a secret manager, never in code
```c
const char *db_password = getenv("DB_PASSWORD");   // or a secret manager
// never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```c
if (do_thing() != 0) {
    log_error("operation failed");   // full detail to logs only
    return generic_error();          // generic to the user
}
// never: returning errno, a stack trace, SQL, or file paths to the client
```

## Secure logging — log events, never secrets
```c
log_info("login ok user=%s", user);   // log the event
// never: logging passwords, tokens, keys, session ids, card numbers
// sanitize untrusted data so it cannot execute in a log viewer
```

## File permissions — least privilege
```c
// create files with 0600, never 0666/0777
int fd = open(path, O_CREAT | O_WRONLY, 0600);
// never: open(path, O_CREAT, 0666), fopen with default perms
```

## Race conditions — synchronize shared state
```c
pthread_mutex_lock(&mu);
// ... shared state ...
pthread_mutex_unlock(&mu);
// never: reading/writing shared state without a lock
```

## Password complexity — enforce policy on input
```c
int validate_password(const char *pw) {
    int len = strlen(pw);
    if (len < 12) return 0;
    int has_upper = 0, has_digit = 0, has_symbol = 0;
    for (const char *p = pw; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') has_upper = 1;
        else if (*p >= '0' && *p <= '9') has_digit = 1;
        else if (*p >= 33 && *p <= 126) has_symbol = 1;
    }
    return has_upper && has_digit && has_symbol;
}
// never: accepting any password without policy checks
```

## Encryption at rest — encrypt sensitive stored data
```c
// use libsodium secretbox (see Authenticated encryption above) for stored data
unsigned char ct[crypto_secretbox_MACBYTES + len];
crypto_secretbox_easy(ct, msg, len, nonce, key);
// store ct; decrypt with crypto_secretbox_open_easy
// never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```c
// libsodium:
unsigned char hash[crypto_hash_sha256_BYTES];
crypto_hash_sha256(hash, data, data_len);
// compare against a known-good hash stored separately
// never: deploying without verifying integrity of interpreted code, libraries, or config
```
