# Dart / Flutter — secure snippets

Load only when writing Dart or Flutter. Copy the right shape; adapt names.

## Parameterized query (sqflite / postgres)
```dart
final rows = await db.rawQuery('SELECT id FROM users WHERE email = ?', [email]);
final r = await conn.execute(Sql.named('SELECT id FROM users WHERE email = @e'), parameters: {'e': email});
// never: db.rawQuery("SELECT ... WHERE email = '$email'")
```

## Password hashing — on the server (argon2id)
```dart
final algo = Argon2id(parallelism: 1, memory: 19456, iterations: 2, hashLength: 32);   // package:cryptography
final hash = await algo.deriveKeyFromPassword(password: pw, nonce: salt);
// in a Flutter app: send the password over TLS; never hash-and-store on the device
```

## Authenticated encryption (AES-GCM)
```dart
final aes = AesGcm.with256bits();                   // package:cryptography
final box = await aes.encrypt(plain, secretKey: key);  // nonce generated, MAC included
```

## Secure random
```dart
final rng = Random.secure();
final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
// never: Random() for tokens, keys or salts
```

## Constant-time comparison
```dart
bool same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var d = 0; for (var i = 0; i < a.length; i++) { d |= a[i] ^ b[i]; } return d == 0;
}
```

## Temp files
```dart
final dir = await Directory.systemTemp.createTemp('app-');   // unique directory
final f = File('${dir.path}/data.bin');
```

## Secure cookie (dart:io / shelf)
```dart
final c = Cookie('sid', token)..httpOnly = true..secure = true..sameSite = SameSite.lax;
```

## Shell — argument list, no shell
```dart
final r = await Process.run('convert', [inPath, outPath]);   // runInShell defaults to false
// never: Process.run('sh', ['-c', cmd]) or runInShell: true with outside data
```

## Input validation
```dart
final ok = RegExp(r'^[a-z0-9_-]{1,32}$').hasMatch(name);
final n = int.tryParse(s); if (n == null || n < 1 || n > 100) throw ArgumentError('n');
```

## Output encoding
```dart
const escape = HtmlEscape();
final safe = escape.convert(userText);
// Flutter widgets render text, not HTML: never feed input to an HTML/WebView renderer unescaped
```

## TLS — default validation, optional pinning
```dart
final ctx = SecurityContext(withTrustedRoots: true);
final client = HttpClient(context: ctx);
// never: client.badCertificateCallback = (cert, host, port) => true;
```

## Secrets — none in the app binary
```dart
const storage = FlutterSecureStorage();          // Keychain / Keystore
await storage.write(key: 'refreshToken', value: token);
// --dart-define and assets ship inside the app: anyone can read them. Keep real secrets on the server.
```

## Error handling — no internals to the user
```dart
try { await submit(); } catch (e, st) { log.severe('submit failed', e, st); showError('Something went wrong'); }
```

## Secure logging
```dart
log.info('login user=$userId ok=$ok');   // never tokens, passwords, or full responses; strip print() in release
```

## File upload / path traversal
```dart
final full = p.normalize(p.join(base, name));     // package:path
if (!p.isWithin(base, full)) throw ArgumentError('outside base');
```

## Safe redirect
```dart
final next = uri.queryParameters['next'] ?? '/';
final target = next.startsWith('/') && !next.startsWith('//') ? next : '/';
```

## Cache-Control (shelf)
```dart
Response.ok(body, headers: {'cache-control': 'no-store'});
```

## Session — rotate on login
```dart
// server: issue a new session id after authentication; app: replace stored tokens on login, delete on logout
```

## Password complexity
```dart
final ok = pw.length >= 12 && pw.length <= 128 && !await isBreached(pw);
```

## File permissions
```dart
await Process.run('chmod', ['600', path]);   // desktop/server; mobile apps use the sandbox
```

## Encryption at rest
```dart
// keys in flutter_secure_storage (Keychain/Keystore); encrypt local databases (sqflite_sqlcipher) with them
```

## Integrity verification
```dart
final digest = sha256.convert(bytes);           // package:crypto
if (digest.toString() != expectedHex) throw StateError('checksum');
```

## SSRF prevention
```dart
final u = Uri.parse(url);
if (u.scheme != 'https' || !allowedHosts.contains(u.host)) throw ArgumentError('host');
```

## CORS (shelf)
```dart
// respond with Access-Control-Allow-Origin only for origins in an allowlist; never '*' with credentials
```

## Log injection prevention
```dart
final safe = s.replaceAll(RegExp(r'[\r\n]'), ' ');
```

## Deserialization — typed models
```dart
final order = Order.fromJson(jsonDecode(body) as Map<String, dynamic>);   // validate fields in fromJson
```
