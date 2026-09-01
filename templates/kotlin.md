# Secure Coding Templates — Kotlin

Drop-in patterns for Kotlin applications (Ktor, Spring Boot, Android).

## Parameterized query
```kotlin
// Exposed ORM
val user = Users.selectAll().where { Users.id eq userId }.singleOrNull()

// Spring Data JPA
@Query("SELECT u FROM User u WHERE u.email = :email AND u.active = true")
fun findActiveByEmail(@Param("email") email: String): User?

// Raw JDBC PreparedStatement
connection.prepareStatement("SELECT * FROM users WHERE id = ?").use { stmt ->
    stmt.setString(1, userId)
    val rs = stmt.executeQuery()
}
// never: "SELECT * FROM users WHERE id = $userId"
```

## Password hashing
```kotlin
import de.mkammerer.argon2.Argon2Factory

val argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id)
val hash: String = argon2.hash(3, 65536, 4, password.toCharArray())
val isValid: Boolean = argon2.verify(hash, password.toCharArray())
// never: MessageDigest.getInstance("MD5") or SHA-256 for passwords
```

## Authenticated encryption
```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.SecretKey
import java.security.SecureRandom

fun encrypt(plaintext: ByteArray, key: SecretKey): Pair<ByteArray, ByteArray> {
    val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val ciphertext = cipher.doFinal(plaintext)
    return Pair(iv, ciphertext)
}
```

## Secure random
```kotlin
import java.security.SecureRandom
import java.util.Base64

val randomBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
val token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes)
// never: kotlin.random.Random or java.util.Random for tokens
```

## Constant-time
```kotlin
import java.security.MessageDigest

fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    return MessageDigest.isEqual(a, b)
}
// never: a.contentEquals(b) or a == b for secret verification
```

## Temp file
```kotlin
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

val tempDir = Files.createTempDirectory("app-secure-", 
    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
// never: File("/tmp/tempfile.txt")
```

## Secure cookie
```kotlin
import io.ktor.server.response.*
import io.ktor.http.*

response.cookies.append(
    Cookie(
        name = "session_id",
        value = sessionToken,
        httpOnly = true,
        secure = true,
        extensions = mapOf("SameSite" to "Lax"),
        path = "/",
        maxAge = 3600
    )
)
```

## Shell
```kotlin
val process = ProcessBuilder("ls", "-l", targetDir)
    .redirectErrorStream(true)
    .start()
val output = process.inputStream.bufferedReader().readText()
// never: Runtime.getRuntime().exec("ls -l $targetDir")
```

## Input validation
```kotlin
require(username.matches(Regex("^[a-zA-Z0-9_-]{3,32}$"))) { "Invalid username format" }
require(age in 18..120) { "Age out of valid range" }
```

## Output encoding
```kotlin
import org.owasp.encoder.Encode

val safeHtml = Encode.forHtml(userInput)
val safeUrl = java.net.URLEncoder.encode(userInput, java.nio.charset.StandardCharsets.UTF_8)
// never: raw user input injected into unescaped template or innerHTML
```

## TLS
```kotlin
import javax.net.ssl.SSLContext

val sslContext = SSLContext.getInstance("TLSv1.3").apply {
    init(null, null, null) // use default trust managers with verification ON
}
```

## Secrets
```kotlin
val apiKey = System.getenv("API_KEY") 
    ?: error("API_KEY environment variable is missing")
```

## Error handling
```kotlin
try {
    processTransaction(data)
} catch (e: Exception) {
    logger.error("Transaction processing error", e)
    call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
}
// never: e.printStackTrace(response.writer)
```

## Secure logging
```kotlin
import org.slf4j.LoggerFactory

val logger = LoggerFactory.getLogger("SecurityLogger")
// never log passwords, tokens, API keys, or raw request credentials
```

## File upload
```kotlin
import java.nio.file.Paths
import java.util.UUID

val allowedExtensions = setOf("png", "jpg", "pdf")
val ext = originalFilename.substringAfterLast('.', "")
require(ext.lowercase() in allowedExtensions) { "Disallowed extension" }

val safeName = "${UUID.randomUUID()}.$ext"
val targetPath = Paths.get("/var/app/uploads").resolve(safeName).normalize()
require(targetPath.startsWith("/var/app/uploads")) { "Path traversal detected" }
```

## Safe redirect
```kotlin
val allowedHosts = setOf("app.example.com", "auth.example.com")

fun getSafeRedirect(targetUrl: String): String {
    return try {
        val uri = java.net.URI(targetUrl)
        if (uri.host in allowedHosts) targetUrl else "/dashboard"
    } catch (e: Exception) {
        "/dashboard"
    }
}
```

## Cache-Control
```kotlin
call.response.header(HttpHeaders.CacheControl, "no-store, no-cache, must-revalidate, private")
call.response.header(HttpHeaders.Pragma, "no-cache")
```

## Session
```kotlin
// Ktor Sessions: regenerate session upon login
call.sessions.clear<UserSession>()
call.sessions.set(UserSession(userId = user.id, token = generateSecureToken()))
```

## Password complexity
```kotlin
fun validatePasswordComplexity(password: String) {
    require(password.length >= 12) { "Password must be at least 12 characters" }
    require(password.any { it.isUpperCase() }) { "Uppercase character required" }
    require(password.any { it.isLowerCase() }) { "Lowercase character required" }
    require(password.any { it.isDigit() }) { "Digit required" }
    require(password.any { !it.isLetterOrDigit() }) { "Special character required" }
}
```

## File permissions
```kotlin
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions

val path = Paths.get("/etc/secrets/app.key")
Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
```

## Encryption at rest
```kotlin
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom

fun encryptField(data: ByteArray, key: SecretKey): ByteArray {
    val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val ct = cipher.doFinal(data)
    return iv + ct
}
```

## Integrity verification
```kotlin
import java.security.MessageDigest

fun verifySha256(data: ByteArray, expectedHex: String): Boolean {
    val actualHash = MessageDigest.getInstance("SHA-256").digest(data)
    val actualHex = actualHash.joinToString("") { "%02x".format(it) }
    return MessageDigest.isEqual(actualHex.toByteArray(), expectedHex.toByteArray())
}
```

## SSRF prevention
```kotlin
import java.net.InetAddress
import java.net.URI

fun isSafeUrl(urlStr: String): Boolean {
    return try {
        val uri = URI(urlStr)
        if (uri.scheme !in listOf("http", "https")) return false
        val addr = InetAddress.getByName(uri.host)
        !addr.isLoopbackAddress && !addr.isSiteLocalAddress && !addr.isLinkLocalAddress
    } catch (e: Exception) {
        false
    }
}
```

## CORS
```kotlin
import io.ktor.server.plugins.cors.routing.*
import io.ktor.http.*

install(CORS) {
    allowHost("app.example.com", schemes = listOf("https"))
    allowCredentials = true
    allowHeader(HttpHeaders.ContentType)
    allowHeader(HttpHeaders.Authorization)
}
```

## Log injection
```kotlin
fun sanitizeLog(msg: String): String {
    // Escape rather than blank out, so the log still shows what was submitted.
    // Escape first: stripping control chars first would delete the CR/LF.
    return msg.replace("\\", "\\\\")
              .replace("\n", "\\n")
              .replace("\r", "\\r")
              .replace("\t", "\\t")
              .replace(Regex("[\\x00-\\x1f\\x7f]"), "")
              .take(500)
}
logger.info("Lookup: {}", sanitizeLog(userParam))
```
