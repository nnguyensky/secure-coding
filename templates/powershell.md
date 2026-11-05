# PowerShell — secure snippets

Load only when writing PowerShell. Copy the right shape; adapt names.

## Parameterized query (SqlClient)
```powershell
$cmd = $conn.CreateCommand()
$cmd.CommandText = 'SELECT Id FROM Users WHERE Email = @email'
[void]$cmd.Parameters.AddWithValue('@email', $Email)
$reader = $cmd.ExecuteReader()
# never: "... WHERE Email = '$Email'" or Invoke-Sqlcmd -Query with $variables inside
```

## Password hashing (PBKDF2-SHA256, .NET 6+)
```powershell
$salt = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
$hash = [System.Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
    [Text.Encoding]::UTF8.GetBytes($Password), $salt, 600000,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256, 32)
# never: Get-FileHash / MD5 / SHA1 of a password
```

## Authenticated encryption (AES-GCM, PowerShell 7)
```powershell
$nonce = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
$ct = [byte[]]::new($plain.Length); $tag = [byte[]]::new(16)
$aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
$aes.Encrypt($nonce, $plain, $ct, $tag)
```

## Secure random
```powershell
$token = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
# never: Get-Random for tokens, keys or salts
```

## Constant-time comparison
```powershell
$same = [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($a, $b)
# never: $a -eq $b for tokens or signatures
```

## Temp files
```powershell
$tmp = New-TemporaryFile          # unique name in the user's temp directory
try { ... } finally { Remove-Item $tmp -Force }
```

## Secure cookie — N/A
Scripts do not set cookies. In ASP.NET, see `templates/csharp.md`.

## Shell — call the program, never Invoke-Expression
```powershell
& 'C:\Tools\convert.exe' '--in' $InputPath '--out' $OutPath
Start-Process -FilePath 'git' -ArgumentList @('clone', $Url) -NoNewWindow -Wait
# never: Invoke-Expression "git clone $Url", iex, cmd /c "$x"
```

## Input validation — declare it on the parameter
```powershell
param(
    [ValidatePattern('^[a-z0-9_-]{1,32}$')] [string]$Name,
    [ValidateSet('dev', 'staging', 'prod')] [string]$Environment,
    [ValidateRange(1, 100)] [int]$Count
)
```

## Output encoding
```powershell
$html = [System.Net.WebUtility]::HtmlEncode($UserText)
$url  = [System.Uri]::EscapeDataString($UserText)
```

## TLS
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
Invoke-RestMethod -Uri $Url        # validates the certificate by default
# never: -SkipCertificateCheck, or ServerCertificateValidationCallback = { $true }
```

## Secrets — SecretManagement, never in the script
```powershell
$apiKey = Get-Secret -Name 'ApiKey' -AsPlainText     # Microsoft.PowerShell.SecretManagement
$cred   = Get-Credential                              # interactive
# never: ConvertTo-SecureString 'P@ss' -AsPlainText -Force in a committed script
```

## Error handling — stop on error, generic message out
```powershell
$ErrorActionPreference = 'Stop'
try { Invoke-Work } catch { Write-Error 'Operation failed'; Write-Verbose $_.Exception.Message; exit 1 }
```

## Secure logging — events, never secrets
```powershell
Write-Information "deploy user=$env:USERNAME env=$Environment ok=$ok"
# Start-Transcript records everything, including secrets typed or printed: avoid it around credentials
```

## File upload / path traversal
```powershell
$base = (Resolve-Path 'C:\data').Path
$full = [System.IO.Path]::GetFullPath((Join-Path $base $Name))
if (-not $full.StartsWith($base + [IO.Path]::DirectorySeparatorChar)) { throw 'outside base' }
```

## Safe redirect — N/A
Scripts do not issue HTTP redirects.

## Cache-Control — N/A
Set in the web server that serves responses.

## Session — N/A
Scripts do not hold web sessions. Remote sessions: `New-PSSession` with Kerberos or certificates, never Basic over HTTP.

## Password complexity
```powershell
$ok = $Password.Length -ge 12 -and $Password.Length -le 128 -and -not (Test-Breached $Password)
```

## File permissions
```powershell
$acl = Get-Acl $Path
$acl.SetAccessRuleProtection($true, $false)       # drop inherited rules
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, 'FullControl', 'Allow'))
Set-Acl -Path $Path -AclObject $acl
```

## Encryption at rest
```powershell
$protected = Protect-CmsMessage -Content $Data -To 'CN=app-data'    # certificate in the store
$plain = Unprotect-CmsMessage -Content $protected
```

## Integrity verification
```powershell
$hash = (Get-FileHash $File -Algorithm SHA256).Hash
if ($hash -ne $Expected) { throw 'checksum mismatch' }
if ((Get-AuthenticodeSignature $Script).Status -ne 'Valid') { throw 'unsigned script' }
```

## SSRF prevention
```powershell
$uri = [Uri]$Url
if ($uri.Scheme -ne 'https' -or $uri.Host -notin $AllowedHosts) { throw 'host not allowed' }
```

## CORS — N/A
Configured on the web server, not in scripts.

## Log injection prevention
```powershell
$safe = $Value -replace '[\r\n]', ' '
```

## Download and run — verify first
```powershell
Invoke-WebRequest $Url -OutFile $file
if ((Get-FileHash $file -Algorithm SHA256).Hash -ne $Expected) { throw 'checksum' }
# never: iex (iwr $Url) or (New-Object Net.WebClient).DownloadString($Url) | iex
```
