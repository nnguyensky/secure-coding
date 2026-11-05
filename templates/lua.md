# Lua / OpenResty — secure snippets

Load only when writing Lua (including OpenResty / nginx and game scripting). Copy the right shape; adapt names.

## Parameterized query (OpenResty)
```lua
local q = "SELECT id FROM users WHERE email = " .. ngx.quote_sql_str(email)   -- lua-resty-mysql
-- pgmoon: db:query("SELECT id FROM users WHERE email = $1", email)
-- never: "... WHERE email = '" .. email .. "'"
```

## Password hashing
```lua
local argon2 = require "argon2"      -- lua-argon2
local hash = assert(argon2.hash_encoded(password, salt, { variant = argon2.variants.argon2_id }))
local ok = argon2.verify(hash, password)
```

## Authenticated encryption
```lua
local aes = require "resty.openssl.cipher"
local c = assert(aes.new("aes-256-gcm"))
local ct = assert(c:encrypt(key, iv, plain, false, aad))
local tag = assert(c:get_aead_tag())
```

## Secure random
```lua
local rand = require "resty.random"
local token = require("resty.string").to_hex(rand.bytes(32, true))   -- strong = true
-- never: math.random() for tokens, keys or salts
```

## Constant-time comparison
```lua
local function same(a, b)
  if #a ~= #b then return false end
  local d = 0
  for i = 1, #a do d = d | (a:byte(i) ~ b:byte(i)) end   -- Lua 5.3+ bitwise ops
  return d == 0
end
```

## Temp files
```lua
local path = os.tmpname()     -- then open it immediately; prefer a private directory you own
```

## Secure cookie (OpenResty)
```lua
ngx.header["Set-Cookie"] = "sid=" .. token .. "; Path=/; Secure; HttpOnly; SameSite=Lax"
```

## Shell — avoid it
```lua
-- there is no argument-vector exec in standard Lua; avoid os.execute / io.popen with any outside data.
-- if unavoidable: allowlist the value first, then quote it
if not name:match("^[%w_-]+$") then error("bad name") end
-- never: os.execute("convert " .. file), io.popen("ping " .. host)
```

## Input validation
```lua
if not name:match("^[%a%d_-]+$") or #name > 32 then return ngx.exit(400) end
local n = tonumber(s); if not n or n < 1 or n > 100 then return ngx.exit(400) end
```

## Output encoding
```lua
local function html(s) return (s:gsub("[&<>\"']", { ["&"]="&amp;", ["<"]="&lt;", [">"]="&gt;", ['"']="&quot;", ["'"]="&#39;" })) end
```

## TLS
```lua
local httpc = require("resty.http").new()
local res, err = httpc:request_uri(url, { ssl_verify = true })   -- and set lua_ssl_trusted_certificate
-- never: ssl_verify = false
```

## Secrets
```lua
local key = os.getenv("API_KEY") or error("API_KEY not set")   -- nginx: env API_KEY; in nginx.conf
```

## Error handling
```lua
local ok, err = pcall(process)
if not ok then ngx.log(ngx.ERR, "process failed: ", err); return ngx.exit(500) end
```

## Secure logging
```lua
ngx.log(ngx.INFO, "login user=", user_id, " ok=", ok)   -- never tokens or passwords
```

## File upload / path traversal
```lua
if name:find("..", 1, true) or name:find("/", 1, true) then return ngx.exit(400) end
local path = base .. "/" .. name
```

## Safe redirect
```lua
local next = ngx.var.arg_next or "/"
if not next:match("^/[^/]") then next = "/" end
return ngx.redirect(next)
```

## Cache-Control
```lua
ngx.header["Cache-Control"] = "no-store"
```

## Session — rotate on login
```lua
local session = require("resty.session").start(); session:regenerate()
```

## Password complexity
```lua
local ok = #pw >= 12 and #pw <= 128
```

## File permissions
```lua
-- set in the deployment (umask 077, chmod 600); standard Lua cannot set modes
```

## Encryption at rest
```lua
-- envelope encryption: data key from a KMS, AES-GCM with resty.openssl, store the wrapped key only
```

## Integrity verification
```lua
local digest = require("resty.openssl.digest").new("sha256"):final(data)
```

## SSRF prevention
```lua
local host = url:match("^https://([^/:]+)")
if not host or not allowed_hosts[host] then return ngx.exit(400) end
```

## CORS
```lua
local origin = ngx.var.http_origin
if allowed_origins[origin] then ngx.header["Access-Control-Allow-Origin"] = origin end
```

## Log injection prevention
```lua
local safe = s:gsub("[\r\n]", " ")
```

## Dynamic code — never from input
```lua
-- never: load(input), loadstring(input), dofile(path_from_input)
```
