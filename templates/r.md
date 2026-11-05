# R — secure snippets

Load only when writing R (scripts, Shiny apps, Plumber APIs). Copy the right shape; adapt names.

## Parameterized query (DBI)
```r
DBI::dbGetQuery(con, "SELECT id FROM users WHERE email = ?", params = list(email))
sql <- glue::glue_sql("SELECT id FROM users WHERE email = {email}", .con = con)   # quoted for you
# never: dbGetQuery(con, paste0("SELECT ... WHERE email = '", email, "'"))
```

## Password hashing
```r
hash <- sodium::password_store(password)
ok <- sodium::password_verify(hash, password)
```

## Authenticated encryption
```r
nonce <- sodium::random(24)
ct <- sodium::data_encrypt(serialize(x, NULL), key, nonce)   # XSalsa20-Poly1305
```

## Secure random
```r
token <- sodium::bin2hex(sodium::random(32))
# never: sample() or runif() for tokens, keys or salts
```

## Constant-time comparison
```r
same <- length(a) == length(b) && sum(as.integer(xor(a, b))) == 0   # a, b: raw vectors
```

## Temp files
```r
path <- tempfile(fileext = ".csv")    # per-session private temp dir
on.exit(unlink(path), add = TRUE)
```

## Secure cookie (Plumber)
```r
res$setCookie("sid", token, secure = TRUE, http = TRUE, sameSite = "Lax")
```

## Shell — argument vector
```r
processx::run("convert", c(in_path, out_path))          # no shell
system2("convert", args = shQuote(c(in_path, out_path)))
# never: system(paste("convert", in_path, out_path))
```

## Input validation
```r
stopifnot(grepl("^[a-z0-9_-]{1,32}$", name))
n <- suppressWarnings(as.integer(s)); stopifnot(!is.na(n), n >= 1, n <= 100)
```

## Output encoding
```r
htmltools::htmlEscape(user_text)
# Shiny renderText escapes; never HTML(user_text) or renderUI with raw input
```

## TLS
```r
httr2::request(url) |> httr2::req_perform()    # verifies certificates
# never: httr::config(ssl_verifypeer = FALSE)
```

## Secrets
```r
key <- Sys.getenv("API_KEY", unset = NA); stopifnot(!is.na(key))
# or keyring::key_get("api"); never a key in a script or .Rhistory
```

## Error handling
```r
tryCatch(process(), error = function(e) { log_error(conditionMessage(e)); stop("request failed", call. = FALSE) })
```

## Secure logging
```r
logger::log_info("export user={user_id} rows={n}")   # never tokens or personal data
```

## File upload / path traversal
```r
full <- normalizePath(file.path(base, basename(name)), mustWork = FALSE)
stopifnot(startsWith(full, paste0(normalizePath(base), "/")))
```

## Safe redirect (Plumber)
```r
nxt <- req$args$`next`
if (is.null(nxt) || !grepl("^/[^/]", nxt)) nxt <- "/"
res$status <- 302; res$setHeader("Location", nxt)
```

## Cache-Control
```r
res$setHeader("Cache-Control", "no-store")
```

## Session — N/A
Shiny sessions are server-side; authenticate in a proxy (e.g. Posit Connect, oauth2-proxy).

## Password complexity
```r
ok <- nchar(pw) >= 12 && nchar(pw) <= 128
```

## File permissions
```r
Sys.chmod(path, mode = "0600")
```

## Encryption at rest
```r
# envelope encryption: data key from a KMS (paws), encrypt with sodium, store the wrapped key only
```

## Integrity verification
```r
digest::digest(file = path, algo = "sha256") == expected
# never: algo = "md5" for integrity of code or data you will run
```

## SSRF prevention
```r
u <- httr2::url_parse(url)
stopifnot(u$scheme == "https", u$hostname %in% allowed_hosts)
```

## CORS (Plumber)
```r
#* @filter cors
function(req, res) { if (req$HTTP_ORIGIN %in% allowed) res$setHeader("Access-Control-Allow-Origin", req$HTTP_ORIGIN); forward() }
```

## Log injection prevention
```r
safe <- gsub("[\r\n]", " ", s)
```

## Dynamic code and deserialization
```r
# never: eval(parse(text = input)); never readRDS() / load() on files from users or URLs
data <- jsonlite::fromJSON(body)
```
