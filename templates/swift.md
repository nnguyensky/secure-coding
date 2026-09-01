# Secure Coding Templates — Swift

Drop-in patterns for Swift applications (Vapor, iOS, macOS, Server-Side Swift).

## Parameterized query
```swift
// Fluent (Vapor ORM)
let user = try await User.query(on: req.db)
    .filter(\.$email == email)
    .filter(\.$isActive == true)
    .first()

// Raw Parameterized SQL via SQLKit
let rows = try await (req.db as! SQLDatabase).raw(
    "SELECT * FROM users WHERE id = \(bind: userId) AND active = \(bind: true)"
).all()
// never: raw string interpolation without \(bind: ...)
```

## Password hashing
```swift
import Vapor

let digest = try await req.password.async.hash(password)
let isValid = try await req.password.async.verify(password, created: digest)
// never: Insecure.SHA1.hash or Insecure.MD5.hash for passwords
```

## Authenticated encryption
```swift
import CryptoKit

func encrypt(data: Data, using key: SymmetricKey) throws -> Data {
    let sealedBox = try AES.GCM.seal(data, using: key)
    return sealedBox.combined ?? Data()
}

func decrypt(combinedData: Data, using key: SymmetricKey) throws -> Data {
    let sealedBox = try AES.GCM.SealedBox(combined: combinedData)
    return try AES.GCM.open(sealedBox, using: key)
}
```

## Secure random
```swift
import Security
import Foundation

func generateSecureToken(count: Int = 32) -> String {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    guard status == errSecSuccess else { fatalError("RNG failed") }
    return Data(bytes).base64EncodedString()
}
// never: Int.random(in:) or drand48() for security tokens
```

## Constant-time
```swift
import CryptoKit
import Foundation

func constantTimeCompare(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var result: UInt8 = 0
    for i in 0..<a.count {
        result |= a[i] ^ b[i]
    }
    return result == 0
}
```

## Temp file
```swift
import Foundation

let tempDir = FileManager.default.temporaryDirectory
let uniqueDir = tempDir.appendingPathComponent(UUID().uuidString, isDirectory: true)
try FileManager.default.createDirectory(at: uniqueDir, withIntermediateDirectories: true, attributes: [
    .posixPermissions: 0o700
])
```

## Secure cookie
```swift
import Vapor

var cookie = HTTPCookies.Value(string: sessionToken)
cookie.isHTTPOnly = true
cookie.isSecure = true
cookie.sameSite = .lax
cookie.maxAge = 3600
cookie.path = "/"
response.cookies["session_id"] = cookie
```

## Shell
```swift
import Foundation

let process = Process()
process.executableURL = URL(fileURLWithPath: "/bin/ls")
process.arguments = ["-l", targetPath]
try process.run()
process.waitUntilExit()
// never: calling /bin/sh -c with concatenated user input
```

## Input validation
```swift
import Vapor

struct CreateUserRequest: Content, Validatable {
    var username: String
    var age: Int
    var email: String

    static func validations(_ validations: inout Validations) {
        validations.add("username", as: String.self, is: .count(3...32) && .characterSet(.alphanumerics))
        validations.add("age", as: Int.self, is: .range(18...120))
        validations.add("email", as: String.self, is: .email)
    }
}
```

## Output encoding
```swift
import Foundation

let safeHtml = userInput
    .replacingOccurrences(of: "&", with: "&amp;")
    .replacingOccurrences(of: "<", with: "&lt;")
    .replacingOccurrences(of: ">", with: "&gt;")
    .replacingOccurrences(of: "\"", with: "&quot;")
    .replacingOccurrences(of: "'", with: "&#39;")
```

## TLS
```swift
import Foundation

let config = URLSessionConfiguration.default
config.tlsMinimumSupportedProtocolVersion = .TLSv13
let session = URLSession(configuration: config)
```

## Secrets
```swift
import Foundation

guard let apiKey = ProcessInfo.processInfo.environment["API_KEY"] else {
    fatalError("API_KEY environment variable is not set")
}
```

## Error handling
```swift
do {
    try await processPayment(payload)
} catch {
    req.logger.error("Payment processing error: \(error)")
    throw Abort(.internalServerError, reason: "Payment could not be completed.")
}
// never: exposing internal database or stack traces in Abort reason
```

## Secure logging
```swift
import Logging

let logger = Logger(label: "Security")
// never log authentication tokens, raw card numbers, or passwords
```

## File upload
```swift
import Vapor

let allowedExtensions = ["png", "jpg", "pdf"]
guard let ext = file.extension?.lowercased(), allowedExtensions.contains(ext) else {
    throw Abort(.badRequest, reason: "Disallowed file type")
}

let filename = "\(UUID().uuidString).\(ext)"
let savePath = "/var/app/uploads/\(filename)"
try await req.fileio.writeFile(file.data, at: savePath)
```

## Safe redirect
```swift
let allowedHosts = ["app.example.com", "auth.example.com"]

func getSafeRedirect(targetUrl: String) -> String {
    guard let url = URL(string: targetUrl), let host = url.host, allowedHosts.contains(host) else {
        return "/dashboard"
    }
    return targetUrl
}
```

## Cache-Control
```swift
response.headers.replaceOrAdd(name: .cacheControl, value: "no-store, no-cache, must-revalidate, private")
response.headers.replaceOrAdd(name: .pragma, value: "no-cache")
```

## Session
```swift
// Vapor Sessions: destroy and re-create session identifier on login
req.session.destroy()
req.session.authenticate(user)
```

## Password complexity
```swift
func isValidPassword(_ pass: String) -> Bool {
    guard pass.count >= 12 else { return false }
    let hasUpper = pass.rangeOfCharacter(from: .uppercaseLetters) != nil
    let hasLower = pass.rangeOfCharacter(from: .lowercaseLetters) != nil
    let hasDigit = pass.rangeOfCharacter(from: .decimalDigits) != nil
    let hasSpecial = pass.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) != nil
    return hasUpper && hasLower && hasDigit && hasSpecial
}
```

## File permissions
```swift
import Foundation

try secretData.write(to: keyUrl, options: .atomic)
try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyUrl.path)
```

## Encryption at rest
```swift
import CryptoKit

func encryptStoredField(_ data: Data, key: SymmetricKey) throws -> Data {
    let sealedBox = try AES.GCM.seal(data, using: key)
    return sealedBox.combined ?? Data()
}
```

## Integrity verification
```swift
import CryptoKit
import Foundation

func verifyIntegrity(data: Data, expectedHex: String) -> Bool {
    let digest = SHA256.hash(data: data)
    let actualHex = digest.compactMap { String(format: "%02x", $0) }.joined()
    return constantTimeCompare(Data(actualHex.utf8), Data(expectedHex.utf8))
}
```

## SSRF prevention
```swift
import Foundation

func isSafeUrl(_ url: URL) -> Bool {
    guard url.scheme == "https" || url.scheme == "http" else { return false }
    guard let host = url.host?.lowercased() else { return false }
    if host == "localhost" || host.hasSuffix(".local") || host.hasSuffix(".internal") {
        return false
    }
    if host.hasPrefix("127.") || host.hasPrefix("10.") || host.hasPrefix("192.168.") || host.hasPrefix("169.254.") {
        return false
    }
    return true
}
```

## CORS
```swift
import Vapor

let corsConfiguration = CORSMiddleware.Configuration(
    allowedOrigin: .custom { origin in
        ["https://app.example.com", "https://admin.example.com"].contains(origin)
    },
    allowedMethods: [.GET, .POST, .PUT, .DELETE, .OPTIONS],
    allowedHeaders: [.accept, .authorization, .contentType, .origin, .xRequestedWith],
    allowCredentials: true
)
app.middleware.use(CORSMiddleware(configuration: corsConfiguration))
```

## Log injection
```swift
func sanitizeForLog(_ str: String) -> String {
    // Escape rather than blank out, so the log still shows what was submitted.
    let escaped = str
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\r", with: "\\r")
        .replacingOccurrences(of: "\t", with: "\\t")
        .replacingOccurrences(of: "[\u{00}-\u{1f}\u{7f}]", with: "", options: .regularExpression)
    return String(escaped.prefix(500))
}
req.logger.info("Search query: \(sanitizeForLog(searchParam))")
```
