# Python — secure snippets

Load only when writing Python. Copy the right shape; adapt names.

## Parameterized query (psycopg / sqlite3)
```python
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
# never: cur.execute(f"SELECT ... WHERE email = {email}")
```

## Password hashing (argon2-cffi)
```python
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
# verify: ph.verify(hash, password)
# never: hashlib.sha256(password), md5(password)
```

## Authenticated encryption (cryptography AES-GCM)
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ct = AESGCM(key).encrypt(nonce, plaintext, None)   # key: 32 bytes, nonce: 12 bytes
# never: AES.new(k, AES.MODE_ECB), DES, RC4
```

## Secure random token
```python
import secrets
token = secrets.token_urlsafe(32)
# never: random.random(), random.randint() for tokens/keys/salts
```

## Constant-time compare
```python
import hmac

def token_matches(provided: str, expected: str) -> bool:
    # == leaks the position of the first difference through timing.
    return hmac.compare_digest(provided.encode(), expected.encode())

if not token_matches(provided, expected):
    raise PermissionError("invalid token")
```

## Safe temp file
```python
import tempfile
with tempfile.NamedTemporaryFile() as f: ...
# never: mktemp(), tmpnam()
```

## Secure cookie
```python
response.set_cookie("sid", token, httponly=True, secure=True, samesite="Lax")
```

## Shell — argument list, never a shell string
```python
subprocess.run(["ls", "-l", dir])
# never: subprocess.run("ls -l " + dir, shell=True), os.system(x)
```

## Safe deserialization
```python
import json
data = json.loads(text)          # plain values
# or: yaml.safe_load(text)
# never: pickle.loads(x), yaml.load(x)
```

## Input validation — allowlist, not blocklist
```python
import re
# allowlist what is valid; reject everything else
if not re.fullmatch(r"[A-Za-z0-9_]{1,32}", username):
    raise ValueError("invalid username")
# validate type, range, length
if not isinstance(age, int) or not (0 <= age <= 150):
    raise ValueError("invalid age")
# never: a blocklist of "bad" characters — it always misses one
```

## Output encoding — escape for the exact context
```python
import html, urllib.parse
html.escape(user_input)                    # HTML body / attribute
urllib.parse.quote(user_input, safe="")    # URL / query
# JSON: json.dumps(user_input)  (never build JSON by string concat)
# SQL: use parameters (see above), never escape-by-hand
# never: injecting raw input into HTML/JS/URL/SQL
```

## CSRF token — per-session, validated on state changes
```python
import secrets
# generate once per session, store server-side
csrf = secrets.token_urlsafe(32)
# on every state-changing request, compare the submitted token
if not hmac.compare_digest(submitted, session_csrf):
    raise PermissionError("CSRF check failed")
# never: accepting state changes without a CSRF token
```

## TLS — verification on, never disabled
```python
import ssl, urllib.request
ctx = ssl.create_default_context()          # verifies certs by default
# never: ssl._create_unverified_context(), CERT_NONE, verify=False
```

## Secrets — from env or a secret manager, never in code
```python
import os
db_password = os.environ["DB_PASSWORD"]     # or a secret manager
# never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```python
try:
    do_thing()
except Exception as e:
    log.exception("operation failed")       # full detail to logs only
    return "Something went wrong", 500      # generic to the user
# never: returning str(e), a stack trace, SQL, or file paths to the client
```

## Secure logging — log events, never secrets
```python
import logging
logging.info("login ok user=%s", user)      # log the event
# never: logging passwords, tokens, keys, session ids, card numbers
# sanitize untrusted data so it cannot execute in a log viewer
```

## File upload — validate content, store out of web root
```python
import magic
if magic.from_buffer(data, mime=True) not in {"image/png", "image/jpeg"}:
    raise ValueError("bad file type")
# store under a random name outside the web root, never the client's name
# never: trusting the extension or client-supplied filename
```

## Safe redirect — allowlist targets only
```python
ALLOWED = {"/dashboard", "/profile"}
if target not in ALLOWED:
    target = "/"
# never: redirecting to a user-supplied URL (open redirect)
```

## Cache-Control — no-store for sensitive responses
```python
response.headers["Cache-Control"] = "no-store"
response.headers["Pragma"] = "no-cache"
# never: letting sensitive pages be cached
```

## Session — regenerate id at login and privilege change
```python
# after login / privilege escalation:
request.session.cycle_key()   # new session id, old one invalidated
# never: accepting a caller-supplied session id, or reusing the pre-login id
```

## Password complexity — enforce policy on input
```python
import re
def validate_password(pw: str) -> None:
    if len(pw) < 12:
        raise ValueError("password too short")
    if not re.search(r"[A-Z]", pw) or not re.search(r"[0-9]", pw) or not re.search(r"[^A-Za-z0-9]", pw):
        raise ValueError("password must include upper, digit, and symbol")
# never: accepting any password without policy checks
```

## File permissions — least privilege
```python
import os, tempfile
fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
# never: 0o666 or 0o777
```

## Encryption at rest — encrypt sensitive stored data
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aes = AESGCM(key)                      # key from secret manager
ct = aes.encrypt(nonce, plaintext, None)
# store ct; decrypt with aes.decrypt(nonce, ct, None)
# never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```python
import hashlib
expected = hashlib.sha256(open(path, "rb").read()).hexdigest()
# compare against a known-good value stored separately
# never: deploying without verifying integrity of interpreted code, libraries, or config
```

## SSRF prevention — validate URLs before server-side requests
```python
from urllib.parse import urlparse
import ipaddress, socket

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        return False
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    # block internal IPs
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except socket.gaierror:
        return False
    return True

if not is_safe_url(user_url):
    raise ValueError("URL not allowed")
resp = requests.get(user_url, timeout=5)
# never: requests.get(request.args.get("url")) without validation
```

## CORS — explicit origin allowlist, never wildcard
```python
from flask import Flask
app = Flask(__name__)

ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}

@app.after_request
def set_cors(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
# never: Access-Control-Allow-Origin: * with credentials
```

## Log injection prevention — sanitize user input before logging
```python
import re, logging

def sanitize_log(value: str) -> str:
    # Escape first: stripping control chars first would delete the CR/LF
    # before .replace() could see them, silently merging tokens.
    escaped = value.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r')
    return re.sub(r'[\x00-\x1f\x7f]', '', escaped)

logging.info("user_action user=%s input=%s", user, sanitize_log(user_input))
# never: logging unsanitized user input — CR/LF can forge log entries
```
