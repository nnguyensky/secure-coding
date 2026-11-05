# C++ — secure snippets

Load only when writing C++. For C use `templates/c.md`. Copy the right shape; adapt names.

## Parameterized query (libpqxx / SQLite)
```cpp
pqxx::work tx{conn};
auto rows = tx.exec_params("SELECT id FROM users WHERE email = $1", email);
// SQLite: sqlite3_prepare_v2 + sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT)
// never: "SELECT ... WHERE email = '" + email + "'"
```

## Password hashing (libsodium argon2id)
```cpp
char hash[crypto_pwhash_STRBYTES];
if (crypto_pwhash_str(hash, pw.data(), pw.size(),
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) throw std::bad_alloc{};
bool ok = crypto_pwhash_str_verify(hash, pw.data(), pw.size()) == 0;
```

## Authenticated encryption (libsodium XChaCha20-Poly1305)
```cpp
std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;
randombytes_buf(nonce.data(), nonce.size());
std::vector<unsigned char> ct(msg.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
unsigned long long ct_len;
crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &ct_len, msg.data(), msg.size(),
    nullptr, 0, nullptr, nonce.data(), key.data());
```

## Secure random
```cpp
std::array<unsigned char, 32> token;
randombytes_buf(token.data(), token.size());
// never: std::rand(), std::mt19937 for tokens, keys or salts
```

## Constant-time comparison
```cpp
bool same = a.size() == b.size() && sodium_memcmp(a.data(), b.data(), a.size()) == 0;
// never: a == b or memcmp for MACs and tokens
```

## Temp files
```cpp
std::string path = (std::filesystem::temp_directory_path() / "app-XXXXXX").string();
int fd = mkstemp(path.data());          // created 0600, unique
// never: tmpnam, mktemp, or a predictable name
```

## Secure cookie — N/A
Not part of the language. In a C++ web framework (Drogon, Crow), set HttpOnly, Secure and SameSite on every session cookie.

## Shell — argument vector, never a shell string
```cpp
std::vector<char*> argv{const_cast<char*>("/usr/bin/convert"), in.data(), out.data(), nullptr};
pid_t pid; posix_spawn(&pid, argv[0], nullptr, nullptr, argv.data(), environ);
// never: std::system(cmd), popen(cmd) with any outside data
```

## Input validation — allowlist and bounds
```cpp
static const std::regex kId{R"(^[a-z0-9_-]{1,32}$)"};
if (!std::regex_match(id, kId)) throw std::invalid_argument("bad id");
int n{}; auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
if (ec != std::errc{} || n < 1 || n > 100) throw std::invalid_argument("bad n");
```

## Output encoding — N/A
No standard HTML layer. Escape for the target (HTML, SQL, shell) in the library that renders it.

## TLS (OpenSSL)
```cpp
SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
SSL_CTX_set_default_verify_paths(ctx);
SSL_set1_host(ssl, host.c_str());      // check the name, not just the chain
```

## Secrets — from the environment or a secret manager
```cpp
const char* key = std::getenv("API_KEY");
if (!key) throw std::runtime_error("API_KEY not set");
// never: a key or password in a string literal
```

## Error handling — no internals to the caller
```cpp
try { process(req); }
catch (const std::exception& e) { log_error(e.what()); respond(500, "internal error"); }
```

## Secure logging — events, never secrets
```cpp
spdlog::info("login user={} ok={}", user_id, ok);
// never: log passwords, tokens, keys or full request bodies
```

## File upload / path traversal
```cpp
namespace fs = std::filesystem;
fs::path full = fs::weakly_canonical(base / name);
auto [b, f] = std::mismatch(base.begin(), base.end(), full.begin());
if (b != base.end()) throw std::invalid_argument("outside base");
```

## Safe redirect — N/A
No standard web layer; in a framework, redirect only to allowlisted local paths.

## Cache-Control — N/A
Set `Cache-Control: no-store` on sensitive responses in the framework you use.

## Session — N/A
Use the framework's session store; rotate the id on login.

## Password complexity
```cpp
bool ok = pw.size() >= 12 && pw.size() <= 128 && !in_breached_list(pw);
```

## File permissions
```cpp
int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
```

## Encryption at rest — envelope encryption
```cpp
// Data key from KMS encrypts the data; only the wrapped key is stored with it.
auto [plain_key, wrapped_key] = kms.generate_data_key("alias/app");
encrypt_aead(plain_key, data);  sodium_memzero(plain_key.data(), plain_key.size());
```

## Integrity verification
```cpp
unsigned char out[crypto_hash_sha256_BYTES];
crypto_hash_sha256(out, data.data(), data.size());
bool ok = sodium_memcmp(out, expected.data(), sizeof out) == 0;
```

## SSRF prevention
```cpp
auto url = parse_url(input);
if (url.scheme != "https" || !allowed_hosts.contains(url.host)) throw std::invalid_argument("host");
// resolve once, reject private ranges, then connect to that address (no re-resolve)
```

## CORS — N/A
Configure in the web framework with an explicit origin allowlist.

## Log injection prevention
```cpp
std::string safe; for (char c : s) safe += (c == '\n' || c == '\r') ? ' ' : c;
```

## Memory safety — RAII, bounds, no raw ownership
```cpp
auto buf = std::make_unique<std::byte[]>(n);
std::vector<int> v(n);  int x = v.at(i);          // .at() checks bounds
std::span<const std::byte> view{data, len};        // pass size with the pointer
// never: new/delete pairs by hand, memcpy without a size check, strcpy
```

## Integer overflow — check before you multiply
```cpp
if (count != 0 && size > SIZE_MAX / count) throw std::length_error("too big");
```

## Format strings
```cpp
std::string s = std::format("user {} logged in", name);   // checked at compile time
// never: printf(user_text)
```

## XML parsing — no external entities (XXE)
```cpp
xmlDocPtr doc = xmlReadMemory(buf, len, nullptr, nullptr, XML_PARSE_NONET);
// never: XML_PARSE_NOENT or XML_PARSE_DTDLOAD on untrusted input
```
