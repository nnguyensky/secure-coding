# Groovy / Jenkins pipelines — secure snippets

Load only when writing Groovy, Gradle scripts or Jenkinsfiles. The JVM rules in `templates/java.md` also apply.

## Parameterized query (groovy.sql.Sql)
```groovy
sql.rows("SELECT id FROM users WHERE email = ${email}")   // a GString here becomes bind parameters
sql.rows('SELECT id FROM users WHERE email = ?', [email])
// never: sql.rows('SELECT ... WHERE email = \'' + email + '\'')
```

## Password hashing
```groovy
def encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
def hash = encoder.encode(password)
```

## Authenticated encryption (AES-GCM)
```groovy
def iv = new byte[12]; new SecureRandom().nextBytes(iv)
def c = Cipher.getInstance('AES/GCM/NoPadding'); c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv))
def ct = c.doFinal(plain)
```

## Secure random
```groovy
def bytes = new byte[32]; new SecureRandom().nextBytes(bytes)
```

## Constant-time comparison
```groovy
java.security.MessageDigest.isEqual(a, b)
```

## Temp files
```groovy
def f = File.createTempFile('app-', '.tmp'); f.deleteOnExit()
// Jenkins: use the workspace or pwd(tmp: true), not shared /tmp names
```

## Secure cookie — N/A
Groovy scripts and pipelines do not set cookies; in Grails, set secure, httpOnly and sameSite in the session config.

## Shell — Jenkins: single quotes and environment variables
```groovy
withEnv(["BRANCH=${params.BRANCH}"]) {
    sh 'git checkout "$BRANCH"'                 // the shell expands a quoted variable
}
// never: sh "git checkout ${params.BRANCH}"    — Groovy pastes it into the script
// plain Groovy: ['git', 'checkout', branch].execute(), never "git checkout $branch".execute()
```

## Secrets — withCredentials, single-quoted
```groovy
withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {
    sh 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com'
}
// never: sh "curl -H 'Authorization: Bearer ${TOKEN}' ..." — interpolation leaks it into the build log
```

## Input validation
```groovy
if (!(params.BRANCH ==~ /^[A-Za-z0-9._\/-]{1,100}$/)) error('invalid branch')
```

## Output encoding
```groovy
def safe = groovy.xml.XmlUtil.escapeXml(userText)
```

## TLS
```groovy
// default JVM trust store; never a trust-all TrustManager, never curl -k / --insecure in sh steps
```

## Error handling
```groovy
try { deploy() } catch (e) { echo 'deploy failed'; currentBuild.result = 'FAILURE'; throw e }
```

## Secure logging
```groovy
echo "deploying ${env.BUILD_TAG} to ${params.ENVIRONMENT}"   // never credentials or tokens
```

## File upload / path traversal
```groovy
def full = new File(base, name).canonicalFile
if (!full.path.startsWith(base.canonicalPath + File.separator)) throw new IllegalArgumentException('outside base')
```

## Safe redirect — N/A
Pipelines do not redirect; in Grails, redirect only to allowlisted paths.

## Cache-Control — N/A
Set in the web framework.

## Session — N/A
Pipelines have no sessions.

## Password complexity
```groovy
def ok = pw.size() >= 12 && pw.size() <= 128
```

## File permissions
```groovy
Files.setPosixFilePermissions(path, PosixFilePermissions.fromString('rw-------'))
```

## Encryption at rest
```groovy
// keys from a KMS or Jenkins credentials store; never in the repository or Jenkinsfile
```

## Integrity verification
```groovy
sh 'echo "$EXPECTED_SHA256  artifact.tgz" | sha256sum -c -'
```

## SSRF prevention
```groovy
def u = new URI(url)
if (u.scheme != 'https' || !(u.host in allowedHosts)) error('host not allowed')
```

## CORS — N/A
Configured in the web framework.

## Log injection prevention
```groovy
def safe = s.replaceAll(/[\r\n]/, ' ')
```

## Dynamic code — never from input
```groovy
// never: Eval.me(input), new GroovyShell().evaluate(input), evaluate(readFile(...)) from an untrusted branch
```

## Pipeline supply chain
```groovy
// pin shared libraries: @Library('lib@v1.4.2'); pin plugins and images by version or digest;
// pull_request builds from forks must not get credentials
```
