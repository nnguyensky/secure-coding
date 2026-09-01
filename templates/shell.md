# Shell — secure patterns

Bash/POSIX sh. Every snippet is copy-pasteable. Web-tier controls (cookies, CORS,
output encoding, TLS termination, sessions, uploads, redirects) do not apply to
shell and are omitted.

Start every script with:
```bash
#!/usr/bin/env bash
set -euo pipefail   # exit on error, on unset variable, and on any pipeline failure
IFS=$'\n\t'         # do not word-split on spaces
```
`set +e` hides failures — the scanner flags it (`set-hide-error`).

## Parameterized query — bind values, never interpolate
```bash
# psql: pass values as parameters, not inside the SQL string.
psql "$DB_URL" -v ON_ERROR_STOP=1 \
  -c "PREPARE q(text) AS SELECT id FROM users WHERE email = \$1" \
  -c "EXECUTE q('$(printf '%s' "$email" | sed "s/'/''/g")')"

# Better: hand the work to a real client rather than building SQL in shell.
python3 -c 'import sys,psycopg;    \
  psycopg.connect(sys.argv[1]).execute("SELECT id FROM users WHERE email=%s",(sys.argv[2],))' \
  "$DB_URL" "$email"
```

## Password hashing — never roll your own
```bash
# Argon2id via the argon2 CLI. Never md5sum/sha256sum a password.
hash=$(printf '%s' "$password" | argon2 "$(openssl rand -hex 16)" -id -t 3 -m 16 -p 4 -e)
```

## Authenticated encryption (AES-256-GCM)
```bash
# -pbkdf2 derives the key properly; GCM gives integrity as well as secrecy.
openssl enc -aes-256-gcm -pbkdf2 -iter 600000 -salt \
  -in secrets.txt -out secrets.enc -pass env:ENC_PASSPHRASE
```

## Secure random
```bash
token=$(openssl rand -base64 32)        # or: head -c 32 /dev/urandom | base64
# Never use $RANDOM: it is a predictable 15-bit PRNG.
```

## Constant-time compare
```bash
# String == leaks position of first difference through timing.
if printf '%s' "$provided" | openssl dgst -sha256 -binary \
   | cmp -s - <(printf '%s' "$expected" | openssl dgst -sha256 -binary); then
  echo "match"
fi
```

## Safe temp file
```bash
tmp=$(mktemp) || exit 1          # the -u flag only reserves a name — do not use it
trap 'rm -f "$tmp"' EXIT         # clean up on every exit path
chmod 600 "$tmp"
```

## Shell — argument list, never a built string
```bash
# eval on anything containing input is code execution.
find "$dir" -name "$pattern" -exec rm -- {} +   # -- ends option parsing
# Never pass input to eval: it is code execution, not string substitution.
```

## Input validation — allowlist, not blocklist
```bash
case "$env" in
  dev|staging|prod) ;;                       # known-good set
  *) echo "invalid environment" >&2; exit 1 ;;
esac
[[ "$id" =~ ^[0-9]{1,10}$ ]] || { echo "invalid id" >&2; exit 1; }
```

## Quoting — always quote expansions
```bash
rm -- "$file"                 # unquoted $file word-splits and globs
[ "$count" -gt 0 ] || exit 1  # unquoted test operands break on empty/spaces
cp -- "$src" "$dst"
```

## Secrets — from env or a secret manager, never in code
```bash
: "${API_TOKEN:?API_TOKEN is required}"   # fail fast if unset
# Never: API_TOKEN="sk_live_..." in the script, and never pass secrets as argv
# (visible in ps). Prefer env vars or a file with 0600.
curl -sS -H "Authorization: Bearer $API_TOKEN" "$URL"
```

## Safe error handling — no internals to the caller
```bash
if ! out=$(deploy 2>&1); then
  printf '%s\n' "$out" >> /var/log/deploy.err   # detail to the log
  echo "Deployment failed (ref: $(date +%s))" >&2  # generic to the user
  exit 1
fi
```

## Secure logging — log events, never secrets
```bash
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$LOG"; }
log "deploy started user=$USER"     # never log $API_TOKEN or $password
```

## Log injection prevention — strip CR/LF
```bash
# Newlines in input let an attacker forge whole log lines.
safe=$(printf '%s' "$untrusted" | tr -d '\r\n' | tr -c '[:print:]' '_')
log "login user=$safe"
```

## File permissions — least privilege
```bash
umask 077                      # new files default to 0600
install -m 600 config.tmp /etc/app/config
chmod 600 "$keyfile"           # never 0777
```

## Password complexity — enforce policy on input
```bash
if (( ${#password} < 12 )); then
  echo "password must be at least 12 characters" >&2
  exit 1
fi
```

## Encryption at rest
```bash
openssl enc -aes-256-gcm -pbkdf2 -iter 600000 -salt \
  -in backup.tar -out backup.tar.enc -pass env:BACKUP_KEY
shred -u backup.tar 2>/dev/null || rm -f backup.tar
```

## Integrity verification — checksums for code and config
```bash
sha256sum -c release.sha256 || { echo "integrity check failed" >&2; exit 1; }
gpg --verify release.tar.gz.sig release.tar.gz    # verify before extracting
```

## SSRF prevention — validate URLs before fetching
```bash
host=$(printf '%s' "$url" | awk -F/ '{print $3}')
case "$host" in
  api.example.com|cdn.example.com) ;;                 # allowlist
  *) echo "host not permitted" >&2; exit 1 ;;
esac
curl -sS --proto '=https' --max-time 10 -- "$url"     # https only, bounded
```

## Race conditions — no check-then-use on paths
```bash
# Do not test -e then write; create atomically instead.
if ( set -o noclobber; : > "$lockfile" ) 2>/dev/null; then
  trap 'rm -f "$lockfile"' EXIT
else
  echo "already running" >&2; exit 1
fi
```
