# Elixir / Phoenix — secure snippets

Load only when writing Elixir. Copy the right shape; adapt names.

## Parameterized query (Ecto)
```elixir
from(u in User, where: u.email == ^email) |> Repo.one()
Ecto.Adapters.SQL.query!(Repo, "SELECT id FROM users WHERE email = $1", [email])
# never: fragment("email = '#{email}'") or query!(Repo, "... #{email}")
```

## Password hashing
```elixir
hash = Argon2.hash_pwd_salt(password)          # argon2_elixir
Argon2.verify_pass(password, hash)
```

## Authenticated encryption
```elixir
iv = :crypto.strong_rand_bytes(12)
{ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plain, aad, true)
```

## Secure random
```elixir
token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
# never: :rand.uniform for tokens, keys or salts
```

## Constant-time comparison
```elixir
Plug.Crypto.secure_compare(a, b)
```

## Temp files
```elixir
{:ok, path} = Plug.Upload.random_file("app")    # unique file in a private tmp dir
```

## Secure cookie
```elixir
plug Plug.Session, store: :cookie, key: "_app", signing_salt: "...", secure: true, http_only: true, same_site: "Lax"
```

## Shell — argument list
```elixir
{out, 0} = System.cmd("convert", [in_path, out_path])
# never: System.cmd("sh", ["-c", cmd]), :os.cmd(~c"convert #{path}")
```

## Input validation (Ecto changeset)
```elixir
changeset |> validate_required([:name]) |> validate_format(:name, ~r/^[a-z0-9_-]{1,32}$/)
```

## Output encoding
```elixir
# HEEx escapes {@value} by default; never raw(@user_text) or Phoenix.HTML.raw on user data
```

## TLS
```elixir
Req.get!(url)       # Req / Finch verify certificates by default
# never: ssl: [verify: :verify_none]
```

## Secrets
```elixir
config :app, api_key: System.fetch_env!("API_KEY")    # config/runtime.exs
```

## Error handling
```elixir
# Phoenix renders a generic error page in prod; keep debug_errors: false outside dev
```

## Secure logging
```elixir
config :phoenix, :filter_parameters, ["password", "token", "secret"]
Logger.info("login user=#{user_id} ok=#{ok}")
```

## File upload / path traversal
```elixir
name = Path.basename(upload.filename)
full = Path.expand(name, base)
if not String.starts_with?(full, base <> "/"), do: raise(ArgumentError, "outside base")
```

## Safe redirect
```elixir
redirect(conn, to: ~p"/dashboard")       # `to:` only accepts local paths
# never: redirect(conn, external: params["next"])
```

## Cache-Control
```elixir
put_resp_header(conn, "cache-control", "no-store")
```

## Session — rotate on login
```elixir
conn |> configure_session(renew: true) |> put_session(:user_id, user.id)
```

## Password complexity
```elixir
validate_length(changeset, :password, min: 12, max: 128)
```

## File permissions
```elixir
File.chmod!(path, 0o600)
```

## Encryption at rest
```elixir
# Cloak.Ecto encrypted fields with keys from runtime config / KMS
```

## Integrity verification
```elixir
digest = :crypto.hash(:sha256, data)
Plug.Crypto.secure_compare(digest, expected)
# never: :crypto.hash(:md5, ...) for integrity
```

## SSRF prevention
```elixir
%URI{scheme: "https", host: host} = URI.parse(url)
if host not in @allowed_hosts, do: raise(ArgumentError, "host")
```

## CORS
```elixir
plug CORSPlug, origin: ["https://app.example.com"]
```

## Log injection prevention
```elixir
safe = String.replace(s, ~r/[\r\n]/, " ")
```

## Atoms from input — never
```elixir
role = String.to_existing_atom(params["role"])   # raises on unknown atoms
# never: String.to_atom(input) — atoms are never garbage-collected; enough of them crash the VM
```

## Deserialization
```elixir
term = :erlang.binary_to_term(bin, [:safe])       # and only from trusted peers
data = Jason.decode!(body)
```
