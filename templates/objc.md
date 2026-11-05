# Objective-C — secure snippets

Load only when writing Objective-C. Copy the right shape; adapt names.

## Parameterized query (SQLite)
```objc
sqlite3_stmt *st;
sqlite3_prepare_v2(db, "SELECT id FROM users WHERE email = ?", -1, &st, NULL);
sqlite3_bind_text(st, 1, email.UTF8String, -1, SQLITE_TRANSIENT);
// never: [NSString stringWithFormat:@"... WHERE email = '%@'", email] passed to sqlite3_exec
```

## Password hashing — on the server
Send the password over TLS to your server, which hashes it with argon2id. Do not hash-and-store on the device.

## Authenticated encryption
```objc
// Use CryptoKit AES.GCM from a Swift helper, or CommonCrypto only through a reviewed wrapper.
// never: kCCAlgorithmDES, kCCOptionECBMode
```

## Secure random
```objc
uint8_t bytes[32];
if (SecRandomCopyBytes(kSecRandomDefault, sizeof bytes, bytes) != errSecSuccess) { /* fail */ }
// never: rand(), random() for tokens
```

## Constant-time comparison
```objc
BOOL same = a.length == b.length && timingsafe_bcmp(a.bytes, b.bytes, a.length) == 0;
```

## Temp files
```objc
NSURL *dir = [NSFileManager.defaultManager URLForDirectory:NSItemReplacementDirectory inDomain:NSUserDomainMask
                                           appropriateForURL:target create:YES error:&err];
```

## Secure cookie
```objc
NSHTTPCookie *c = [NSHTTPCookie cookieWithProperties:@{ NSHTTPCookieName: @"sid", NSHTTPCookieValue: token,
    NSHTTPCookieDomain: host, NSHTTPCookiePath: @"/", NSHTTPCookieSecure: @YES, @"HttpOnly": @YES }];
```

## Shell — argument array, no shell (macOS)
```objc
NSTask *t = [NSTask new];
t.executableURL = [NSURL fileURLWithPath:@"/usr/bin/sips"];
t.arguments = @[@"-s", @"format", @"png", inPath, @"--out", outPath];
// never: launchPath = @"/bin/sh" with arguments @[@"-c", cmd]
```

## Input validation
```objc
NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"^[a-z0-9_-]{1,32}$" options:0 error:nil];
BOOL ok = [re numberOfMatchesInString:name options:0 range:NSMakeRange(0, name.length)] == 1;
```

## Output encoding — WebViews
```objc
// pass data to a WKWebView with JSON (NSJSONSerialization), never by string-building JavaScript
```

## TLS — App Transport Security on
```objc
// keep NSAllowsArbitraryLoads off; never call completionHandler(NSURLSessionAuthChallengeUseCredential,
// [NSURLCredential credentialForTrust:...]) without evaluating the trust (SecTrustEvaluateWithError)
```

## Secrets — Keychain, never NSUserDefaults
```objc
NSDictionary *q = @{ (id)kSecClass: (id)kSecClassGenericPassword, (id)kSecAttrAccount: @"refreshToken",
    (id)kSecValueData: tokenData, (id)kSecAttrAccessible: (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly };
SecItemAdd((CFDictionaryRef)q, NULL);
// never: [NSUserDefaults.standardUserDefaults setObject:token forKey:@"token"]; never kSecAttrAccessibleAlways
```

## Error handling
```objc
if (!ok) { os_log_error(log, "save failed: %{public}@", err.domain); [self showMessage:@"Something went wrong"]; }
```

## Secure logging — no secrets, private by default
```objc
os_log_info(log, "login user=%{private}@", userId);
// never: NSLog(@"token %@", token); never NSLog(userText) — the first argument is a format string
```

## File upload / path traversal
```objc
NSString *full = [[base stringByAppendingPathComponent:name] stringByStandardizingPath];
if (![full hasPrefix:[base stringByAppendingString:@"/"]]) { /* reject */ }
```

## Safe redirect
```objc
// open only URLs whose host is in an allowlist; never [UIApplication.sharedApplication openURL:untrustedURL ...]
```

## Cache-Control
```objc
request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;   // and NSURLCache off for sensitive responses
```

## Session
```objc
// replace stored tokens on login; delete them from the Keychain on logout
```

## Password complexity
```objc
BOOL ok = pw.length >= 12 && pw.length <= 128;
```

## File permissions — data protection
```objc
[data writeToURL:url options:NSDataWritingFileProtectionComplete error:&err];
```

## Encryption at rest
```objc
// NSFileProtectionComplete for files; keys in the Keychain or Secure Enclave
```

## Integrity verification
```objc
uint8_t digest[CC_SHA256_DIGEST_LENGTH];
CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
// never: CC_MD5, CC_SHA1
```

## SSRF prevention — N/A
Apps call their own API; validate any user-supplied URL host against an allowlist before loading it.

## CORS — N/A
A server-side setting.

## Log injection prevention
```objc
NSString *safe = [[s componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet] componentsJoinedByString:@" "];
```

## Format strings
```objc
NSString *s = [NSString stringWithFormat:@"%@", userText];
// never: [NSString stringWithFormat:userText], NSLog(userText)
```

## Deserialization — secure coding only
```objc
Settings *s = [NSKeyedUnarchiver unarchivedObjectOfClass:Settings.class fromData:blob error:&err];
// never: [NSKeyedUnarchiver unarchiveObjectWithData:blob]
```
