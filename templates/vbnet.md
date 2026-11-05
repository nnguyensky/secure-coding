# VB.NET — secure snippets

Load only when writing Visual Basic .NET. The .NET APIs in `templates/csharp.md` apply with VB syntax.

## Parameterized query
```vb
Using cmd As New SqlCommand("SELECT Id FROM Users WHERE Email = @email", conn)
    cmd.Parameters.Add("@email", SqlDbType.NVarChar, 256).Value = email
    Dim id = cmd.ExecuteScalar()
End Using
' never: New SqlCommand("... WHERE Email = '" & email & "'", conn)
```

## Password hashing (ASP.NET Core Identity)
```vb
Dim hasher As New PasswordHasher(Of AppUser)()
Dim hash = hasher.HashPassword(user, password)
Dim ok = hasher.VerifyHashedPassword(user, hash, password) <> PasswordVerificationResult.Failed
```

## Authenticated encryption (AES-GCM)
```vb
Dim nonce = RandomNumberGenerator.GetBytes(12)
Dim ct(plain.Length - 1) As Byte, tag(15) As Byte
Using aes As New AesGcm(key, 16)
    aes.Encrypt(nonce, plain, ct, tag)
End Using
```

## Secure random
```vb
Dim token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
' never: New Random() or Rnd() for tokens
```

## Constant-time comparison
```vb
Dim same = CryptographicOperations.FixedTimeEquals(a, b)
```

## Temp files
```vb
Dim path = IO.Path.GetTempFileName()   ' created empty and unique
```

## Secure cookie
```vb
Response.Cookies.Append("sid", token, New CookieOptions With {.HttpOnly = True, .Secure = True, .SameSite = SameSiteMode.Lax})
```

## Shell — argument list
```vb
Dim psi As New ProcessStartInfo("convert.exe")
psi.ArgumentList.Add(inPath) : psi.ArgumentList.Add(outPath)
Process.Start(psi)
' never: Process.Start("cmd.exe", "/c convert " & inPath)
```

## Input validation
```vb
If Not Regex.IsMatch(name, "^[a-z0-9_-]{1,32}$") Then Throw New ArgumentException("name")
```

## Output encoding
```vb
Dim safe = Net.WebUtility.HtmlEncode(userText)
```

## TLS
```vb
' default validation; never ServicePointManager.ServerCertificateValidationCallback = Function(s, c, ch, e) True
```

## Secrets
```vb
Dim key = Environment.GetEnvironmentVariable("API_KEY")
If String.IsNullOrEmpty(key) Then Throw New InvalidOperationException("API_KEY not set")
```

## Error handling
```vb
Try
    Process()
Catch ex As Exception
    logger.LogError(ex, "request failed")
    Return StatusCode(500, "internal error")
End Try
```

## Secure logging
```vb
logger.LogInformation("login {User} ok {Ok}", userId, ok)   ' placeholders, never secrets
```

## File upload / path traversal
```vb
Dim full = IO.Path.GetFullPath(IO.Path.Combine(baseDir, name))
If Not full.StartsWith(baseDir & IO.Path.DirectorySeparatorChar) Then Throw New ArgumentException("outside base")
```

## Safe redirect
```vb
If Url.IsLocalUrl(returnUrl) Then Return LocalRedirect(returnUrl) Else Return RedirectToAction("Index")
```

## Cache-Control
```vb
Response.Headers.CacheControl = "no-store"
```

## Session — rotate on login
```vb
Await HttpContext.SignOutAsync() : Await HttpContext.SignInAsync(principal)   ' new auth cookie
```

## Password complexity
```vb
Dim ok = pw.Length >= 12 AndAlso pw.Length <= 128
```

## File permissions
```vb
Dim fi As New IO.FileInfo(path) : Dim acl = fi.GetAccessControl()
acl.SetAccessRuleProtection(True, False) : fi.SetAccessControl(acl)
```

## Encryption at rest
```vb
' Data Protection API: Dim protector = provider.CreateProtector("Orders.v1") : protector.Protect(data)
```

## Integrity verification
```vb
Dim hash = SHA256.HashData(bytes)
Dim ok = CryptographicOperations.FixedTimeEquals(hash, expected)
```

## SSRF prevention
```vb
Dim u As New Uri(url)
If u.Scheme <> "https" OrElse Not allowedHosts.Contains(u.Host) Then Throw New ArgumentException("host")
```

## CORS
```vb
builder.Services.AddCors(Sub(o) o.AddPolicy("app", Sub(p) p.WithOrigins("https://app.example.com")))
```

## Log injection prevention
```vb
Dim safe = s.Replace(vbCr, " ").Replace(vbLf, " ")
```

## Deserialization
```vb
Dim order = JsonSerializer.Deserialize(Of OrderDto)(json)
' never: BinaryFormatter, or Newtonsoft TypeNameHandling.All
```
