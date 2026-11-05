# Scala — secure snippets

Load only when writing Scala. The JVM rules in `templates/java.md` also apply. Copy the right shape; adapt names.

## Parameterized query (Doobie / Slick / JDBC)
```scala
sql"SELECT id FROM users WHERE email = $email".query[Long].option        // Doobie: $x is a bind
sql"SELECT id FROM users WHERE email = $email".as[Long]                 // Slick plain SQL: $x is a bind
// never: #$x in Slick or Doobie (raw splice), s"... $email" passed to a JDBC execute
```

## Password hashing (argon2-jvm)
```scala
val argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id)
val hash = argon2.hash(3, 65536, 1, password.toCharArray)
val ok = argon2.verify(hash, password.toCharArray)
```

## Authenticated encryption (AES-GCM)
```scala
val iv = new Array[Byte](12); new SecureRandom().nextBytes(iv)
val c = Cipher.getInstance("AES/GCM/NoPadding")
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv))
val ct = c.doFinal(plain)
// never: Cipher.getInstance("AES") — that is ECB
```

## Secure random
```scala
val bytes = new Array[Byte](32); new SecureRandom().nextBytes(bytes)
// never: scala.util.Random for tokens, keys or salts
```

## Constant-time comparison
```scala
java.security.MessageDigest.isEqual(a, b)
```

## Temp files
```scala
val p = Files.createTempFile("app-", ".tmp", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
```

## Secure cookie (Play)
```scala
Ok(body).withCookies(Cookie("sid", token, secure = true, httpOnly = true, sameSite = Some(Cookie.SameSite.Lax)))
```

## Shell — argument list
```scala
import scala.sys.process._
val out = Seq("convert", inPath, outPath).!!
// never: s"convert $inPath $outPath".!! or Seq("sh", "-c", cmd)
```

## Input validation (Play forms)
```scala
val form = Form(single("name" -> nonEmptyText(maxLength = 32).verifying(pattern("^[a-z0-9_-]+$".r))))
```

## Output encoding
```scala
// Twirl templates escape @value by default; never @Html(userInput)
val safe = play.twirl.api.HtmlFormat.escape(userText)
```

## TLS
```scala
// the default SSLContext validates; never install a trust-all TrustManager or HostnameVerifier
val client = java.net.http.HttpClient.newHttpClient()
```

## Secrets
```scala
val key = sys.env.getOrElse("API_KEY", throw new IllegalStateException("API_KEY not set"))
```

## Error handling — no internals to the caller
```scala
override def onServerError(req: RequestHeader, e: Throwable) =
  Future.successful { logger.error("request failed", e); InternalServerError("internal error") }
```

## Secure logging
```scala
logger.info(s"login user=$userId ok=$ok")   // never passwords, tokens or full bodies
```

## File upload / path traversal
```scala
val full = base.resolve(name).normalize()
if (!full.startsWith(base)) throw new IllegalArgumentException("outside base")
```

## Safe redirect
```scala
val target = request.getQueryString("next").filter(n => n.startsWith("/") && !n.startsWith("//")).getOrElse("/")
Redirect(target)
```

## Cache-Control
```scala
Ok(body).withHeaders(CACHE_CONTROL -> "no-store")
```

## Session — rotate on login
```scala
Redirect("/").withNewSession.withSession("uid" -> user.id.toString)
```

## Password complexity
```scala
val ok = pw.length >= 12 && pw.length <= 128 && !breached(pw)
```

## File permissions
```scala
Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"))
```

## Encryption at rest — envelope encryption
```scala
val dk = kms.generateDataKey(GenerateDataKeyRequest.builder().keyId("alias/app").keySpec(DataKeySpec.AES_256).build())
// encrypt with dk.plaintext() (AES-GCM), store dk.ciphertextBlob() beside the data, then wipe the plaintext key
```

## Integrity verification
```scala
val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
MessageDigest.isEqual(digest, expected)
```

## SSRF prevention
```scala
val uri = new URI(url)
require(uri.getScheme == "https" && allowedHosts(uri.getHost), "host not allowed")
```

## CORS (Play)
```scala
// application.conf: play.filters.cors.allowedOrigins = ["https://app.example.com"]
```

## Log injection prevention
```scala
val safe = s.replaceAll("[\r\n]", " ")
```

## Deserialization
```scala
val order = Json.parse(body).validate[Order]   // Play JSON into a case class
// never: ObjectInputStream on untrusted bytes
```
