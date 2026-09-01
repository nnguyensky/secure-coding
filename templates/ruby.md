# Ruby — secure snippets

Load only when writing Ruby. Copy the right shape; adapt names.

## Parameterized query (ActiveRecord / raw)
```ruby
User.where(email: email)
# or raw:
conn.exec_params("SELECT * FROM users WHERE email = $1", [email])
# never: "SELECT * FROM users WHERE email = " + email, or #{} interpolation
```

## Password hashing (bcrypt)
```ruby
require "bcrypt"
hash = BCrypt::Password.create(password)
# verify: BCrypt::Password.new(stored) == password
# never: Digest::SHA256.hexdigest(password)
```

## Authenticated encryption (AES-256-GCM)
```ruby
require "openssl"
cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
cipher.key = key
iv = cipher.random_iv
ct = cipher.update(plaintext) + cipher.final
# never: OpenSSL::Cipher.new("des"), "rc4", "blowfish"
```

## Secure random token
```ruby
require "securerandom"
token = SecureRandom.urlsafe_base64(32)
# never: rand(10**6), Random.new for tokens/keys/salts
```

## Constant-time compare
```ruby
require "openssl"

def token_matches?(provided, expected)
  # == returns early on the first differing byte, which leaks length and content.
  OpenSSL.secure_compare(provided, expected)
end

raise "invalid token" unless token_matches?(provided, expected)
```

## Safe temp file
```ruby
require "tempfile"
f = Tempfile.new("prefix")
# never: a guessed temp name in /tmp
```

## Secure cookie
```ruby
cookies[:sid] = { value: token, httponly: true, secure: true, same_site: :lax }
```

## Shell — argument list, never a shell string
```ruby
system("ls", "-l", dir)
# never: system("ls -l " + dir), backticks with interpolation, Open3 with a string
```

## Input validation — allowlist, not blocklist
```ruby
# allowlist what is valid; reject everything else
unless username =~ /\A[A-Za-z0-9_]{1,32}\z/
  raise ArgumentError, "invalid username"
end
# validate type, range, length
unless age.is_a?(Integer) && age.between?(0, 150)
  raise ArgumentError, "invalid age"
end
# never: a blocklist of "bad" characters — it always misses one
```

## Output encoding — escape for the exact context
```ruby
require "cgi"
CGI.escapeHTML(user_input)      # HTML body / attribute
CGI.escape(user_input)          # URL / query
# JSON: user_input.to_json  (never build JSON by string concat)
# SQL: use parameters (see above), never escape-by-hand
# never: injecting raw input into HTML/JS/URL/SQL
```

## CSRF token — per-session, validated on state changes
```ruby
require "securerandom"
csrf = SecureRandom.urlsafe_base64(32)   # store in session
# on every state-changing request:
unless ActiveSupport::SecurityUtils.secure_compare(submitted, session_csrf)
  raise "CSRF check failed"
end
# never: accepting state changes without a CSRF token
```

## TLS — verification on, never disabled
```ruby
require "net/http"
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_PEER   # default; never disable
# never: verify_mode = VERIFY_NONE
```

## Secrets — from env or a secret manager, never in code
```ruby
db_password = ENV["DB_PASSWORD"]   # or a secret manager
# never: hard-coding a password/token/key in source, config, or logs
```

## Safe error handling — no internals to the user
```ruby
begin
  do_thing
rescue => e
  Rails.logger.error("operation failed: #{e}")   # full detail to logs only
  render plain: "Something went wrong", status: :internal_server_error
end
# never: rendering e.message, a stack trace, SQL, or file paths to the client
```

## Secure logging — log events, never secrets
```ruby
Rails.logger.info("login ok user=#{user}")   # log the event
# never: logging passwords, tokens, keys, session ids, card numbers
# sanitize untrusted data so it cannot execute in a log viewer
```

## File upload — validate content, store out of web root
```ruby
# check the file's magic bytes / MIME, not just the extension
unless %w[image/png image/jpeg].include?(file.content_type)
  raise "bad file type"
end
# store under a random name outside the web root, never the client's name
# never: trusting the extension or client-supplied filename
```

## Safe redirect — allowlist targets only
```ruby
ALLOWED = %w[/dashboard /profile]
target = ALLOWED.include?(params[:next]) ? params[:next] : "/"
redirect_to target
# never: redirecting to a user-supplied URL (open redirect)
```

## Cache-Control — no-store for sensitive responses
```ruby
response.headers["Cache-Control"] = "no-store"
response.headers["Pragma"] = "no-cache"
# never: letting sensitive pages be cached
```

## Session — regenerate id at login and privilege change
```ruby
# after login / privilege escalation:
reset_session   # new session id, old one invalidated
# never: accepting a caller-supplied session id, or reusing the pre-login id
```

## Password complexity — enforce policy on input
```ruby
def validate_password(pw)
  raise ArgumentError, "password too short" if pw.length < 12
  unless pw.match?(/[A-Z]/) && pw.match?(/[0-9]/) && pw.match?(/[^A-Za-z0-9]/)
    raise ArgumentError, "password must include upper, digit, and symbol"
  end
end
# never: accepting any password without policy checks
```

## File permissions — least privilege
```ruby
File.open(path, File::WRONLY | File::CREAT, 0600) { |f| f.write(data) }
# never: 0666 or 0777
```

## Encryption at rest — encrypt sensitive stored data
```ruby
require "openssl"
cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
cipher.key = key
iv = cipher.random_iv
ct = cipher.update(plaintext) + cipher.final
tag = cipher.auth_tag
# store iv + ct + tag; decrypt with cipher.auth_tag + cipher.decrypt
# never: storing plaintext passwords, tokens, PII on disk
```

## Integrity verification — checksums for code and config
```ruby
require "digest"
hash = Digest::SHA256.file(path).hexdigest
# compare against a known-good hash stored separately
# never: deploying without verifying integrity of interpreted code, libraries, or config
```

## SSRF prevention — validate URLs before server-side requests
```ruby
require "uri"
require "resolv"

ALLOWED_HOSTS = %w[api.example.com cdn.example.com].freeze

def safe_url?(url_str)
  uri = URI.parse(url_str)
  return false unless uri.scheme == "https"
  return false unless ALLOWED_HOSTS.include?(uri.hostname)
  # block internal IPs
  ips = Resolv.getaddresses(uri.hostname)
  ips.any? { |ip| ip.start_with?("127.", "10.", "192.168.", "169.254.") } ? false : true
rescue URI::InvalidURIError
  false
end

raise "URL not allowed" unless safe_url?(user_url)
# never: HTTParty.get(params[:url]) without validation
```

## CORS — explicit origin allowlist, never wildcard
```ruby
ALLOWED_ORIGINS = %w[https://app.example.com].freeze

# In your middleware or before_action:
origin = request.headers["Origin"]
if ALLOWED_ORIGINS.include?(origin)
  response.headers["Access-Control-Allow-Origin"] = origin
  response.headers["Access-Control-Allow-Credentials"] = "true"
end
# never: Access-Control-Allow-Origin: * with credentials
```

## Log injection prevention — sanitize user input before logging
```ruby
def sanitize_log(value)
  # Escape first: stripping control chars first would delete the CR/LF
  # before the gsub calls could see them, silently merging tokens.
  value.gsub("\\", "\\\\").gsub("\n", "\\n").gsub("\r", "\\r")
       .gsub(/[\x00-\x1f\x7f]/, "")
end

Rails.logger.info("user_action user=#{user} input=#{sanitize_log(user_input)}")
# never: logging unsanitized user input — CR/LF can forge log entries
```
