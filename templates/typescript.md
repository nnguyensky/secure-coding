# Secure Coding Templates — TypeScript

Drop-in patterns for TypeScript applications (Node.js, Deno, Bun, Next.js).

## Parameterized query
```ts
// Prisma
const user = await prisma.user.findFirst({
  where: { email: inputEmail },
});

// Drizzle ORM
const result = await db.select().from(users).where(eq(users.id, userId));

// Raw Parameterized Query (pg / postgres)
const { rows } = await pool.query("SELECT * FROM users WHERE id = $1 AND active = $2", [userId, true]);
// never: `SELECT * FROM users WHERE id = ${userId}`
```

## Password hashing
```ts
import * as argon2 from "argon2";

const hash: string = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
});

const isValid: boolean = await argon2.verify(hash, password);
// never: crypto.createHash("sha256").update(password).digest("hex")
```

## Authenticated encryption
```ts
import { webcrypto } from "crypto";

async function encrypt(plaintext: Uint8Array, key: CryptoKey): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );
  return { iv, ciphertext };
}
// never: AES-CBC without HMAC, AES-ECB, DES, RC4
```

## Secure random
```ts
import crypto from "crypto";

const token: string = crypto.randomBytes(32).toString("base64url");
// never: Math.random().toString(36)
```

## Constant-time
```ts
import crypto from "crypto";

function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
// never: a === b for token/signature verification
```

## Temp file
```ts
import fs from "fs/promises";
import path from "path";
import os from "os";

const dir: string = await fs.mkdtemp(path.join(os.tmpdir(), "app-"));
// never: guessed or static paths in /tmp
```

## Secure cookie
```ts
import { Response } from "express";

function setAuthCookie(res: Response, token: string): void {
  res.cookie("session_id", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 3600 * 1000,
  });
}
```

## Shell
```ts
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const { stdout } = await execFileAsync("ls", ["-l", targetDir]);
// never: exec(`ls -l ${targetDir}`)
```

## Input validation
```ts
import { z } from "zod";

const UserSchema = z.object({
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_-]+$/),
  age: z.number().int().min(18).max(120),
  email: z.string().email(),
});

type UserInput = z.infer<typeof UserSchema>;
const validated: UserInput = UserSchema.parse(req.body);
```

## Output encoding
```ts
import escapeHtml from "escape-html";

const safeHtml: string = escapeHtml(userInput);
// URL: encodeURIComponent(userInput)
// JSON: JSON.stringify(userInput)
// React/Next: <div>{userInput}</div> (auto-escapes)
// never: dangerouslySetInnerHTML with raw userInput
```

## TLS
```ts
import https from "https";

const agent = new https.Agent({
  minVersion: "TLSv1.2",
  rejectUnauthorized: true, // never false in production
});
```

## Secrets
```ts
const apiKey: string = process.env.API_KEY ?? (() => {
  throw new Error("API_KEY environment variable is required");
})();
// never: hardcoded API keys or fallback secrets in source code
```

## Error handling
```ts
try {
  await processPayment(payload);
} catch (err) {
  logger.error("Payment processing failed", { err });
  res.status(500).json({ error: "Unable to process payment. Please try again." });
}
// never: res.status(500).send(err.stack)
```

## Secure logging
```ts
import pino from "pino";

const logger = pino({
  redact: ["req.headers.authorization", "*.password", "*.creditCard", "*.token"],
});
```

## File upload
```ts
import { fileTypeFromBuffer } from "file-type";
import path from "path";
import crypto from "crypto";

const ALLOWED_MIME = new Set(["image/jpeg", "image/png", "application/pdf"]);

async function handleUpload(buffer: Buffer, originalName: string, uploadDir: string): Promise<string> {
  const type = await fileTypeFromBuffer(buffer);
  if (!type || !ALLOWED_MIME.has(type.mime)) {
    throw new Error("Invalid file type");
  }
  const safeFilename = `${crypto.randomUUID()}.${type.ext}`;
  const dest = path.join(uploadDir, safeFilename);
  await fs.writeFile(dest, buffer, { mode: 0o600 });
  return dest;
}
```

## Safe redirect
```ts
const ALLOWED_HOSTS = new Set(["app.example.com", "auth.example.com"]);

function getSafeRedirectUrl(target: string): string {
  try {
    const url = new URL(target, "https://app.example.com");
    if (!ALLOWED_HOSTS.has(url.hostname)) {
      return "/dashboard";
    }
    return url.toString();
  } catch {
    return "/dashboard";
  }
}
```

## Cache-Control
```ts
// Prevent sensitive data caching
res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
res.setHeader("Pragma", "no-cache");
res.setHeader("Expires", "0");
```

## Session
```ts
// Regenerate session identifier after authentication
req.session.regenerate((err) => {
  if (err) throw err;
  req.session.userId = user.id;
  req.session.save();
});
```

## Password complexity
```ts
import { z } from "zod";

const PasswordSchema = z.string()
  .min(12, "Password must be at least 12 characters")
  .max(128)
  .regex(/[A-Z]/, "Must contain uppercase letter")
  .regex(/[a-z]/, "Must contain lowercase letter")
  .regex(/[0-9]/, "Must contain digit")
  .regex(/[^A-Za-z0-9]/, "Must contain special character");
```

## File permissions
```ts
import fs from "fs/promises";

// Write private keys / credentials with owner-only access
await fs.writeFile(keyPath, secretData, { mode: 0o600 });
```

## Encryption at rest
```ts
// Envelope encryption with AES-256-GCM via KMS / Web Crypto
import { webcrypto } from "crypto";

async function encryptData(data: Uint8Array, key: CryptoKey): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { iv, ciphertext };
}
```

## Integrity verification
```ts
import crypto from "crypto";

function verifyChecksum(data: Buffer, expectedSha256Hex: string): boolean {
  const actual = crypto.createHash("sha256").update(data).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expectedSha256Hex));
}
```

## SSRF prevention
```ts
import { isIP } from "net";

function isSafeUrl(targetUrl: string): boolean {
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    const host = parsed.hostname;
    if (host === "localhost" || host.endsWith(".internal") || host.endsWith(".local")) return false;
    if (isIP(host)) {
      // Reject private ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
      if (host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("169.254.")) return false;
    }
    return true;
  } catch {
    return false;
  }
}
```

## CORS
```ts
import cors from "cors";

const allowedOrigins = new Set(["https://app.example.com", "https://admin.example.com"]);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error("CORS policy violation"));
    }
  },
  credentials: true,
}));
```

## Log injection
```ts
function sanitizeLog(input: string): string {
  // Escape rather than blank out, so the log still shows what was submitted.
  return input
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t")
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f]/g, "")
    .slice(0, 500);
}
logger.info(`User lookup: ${sanitizeLog(req.query.search as string)}`);
```
