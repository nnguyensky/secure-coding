# Apex (Salesforce) — secure snippets

Load only when writing Apex, triggers or Visualforce. Copy the right shape; adapt names.

## Parameterized query — bind variables, user mode
```apex
List<Account> a = [SELECT Id, Name FROM Account WHERE Name = :name WITH USER_MODE];
List<Account> b = Database.queryWithBinds(
    'SELECT Id FROM Account WHERE Name = :name', new Map<String, Object>{ 'name' => name },
    AccessLevel.USER_MODE);
// never: Database.query('SELECT ... WHERE Name = \'' + name + '\'')
```

## Sharing and field access — enforce them
```apex
public with sharing class OrderService { ... }       // record-level access
Database.insert(records, AccessLevel.USER_MODE);       // CRUD and field-level security
// never: "without sharing" on a class that serves user requests
```

## Password hashing — N/A
Salesforce handles user passwords. Never store passwords in custom objects.

## Authenticated encryption
```apex
Blob key = Crypto.generateAesKey(256);                    // keep keys in protected custom metadata / Shield
Blob ct = Crypto.encryptWithManagedIV('AES256', key, plain);
// AES-CBC with a random IV; add a MAC (Crypto.generateMac) if tampering matters
```

## Secure random
```apex
String token = EncodingUtil.convertToHex(Crypto.generateAesKey(256));
// never: Math.random() for tokens
```

## Constant-time comparison — N/A
Use `Crypto.verifyHMac` / `Crypto.verify` for MACs and signatures, not `==`.

## Temp files — N/A
No file system. Use ContentVersion with sharing set explicitly.

## Secure cookie
```apex
ApexPages.currentPage().setCookies(new Cookie[]{ new Cookie('pref', value, null, -1, true, 'Lax') });   // isSecure = true
```

## Shell — N/A
Apex cannot run processes.

## Input validation
```apex
if (!Pattern.matches('^[A-Za-z0-9_-]{1,40}$', name)) throw new IllegalArgumentException('name');
```

## Output encoding (Visualforce / LWC)
```html
<apex:outputText value="{!userText}"/>                 <!-- escaped by default -->
<!-- never: escape="false" on user data; in JavaScript contexts use JSENCODE(), in URLs URLENCODE() -->
```

## TLS
```apex
// callouts must be https; Named Credentials hold the endpoint and certificate
```

## Secrets — Named Credentials
```apex
HttpRequest req = new HttpRequest();
req.setEndpoint('callout:Partner_API/orders');           // credentials injected by the platform
// never: req.setHeader('Authorization', 'Basic ' + hardCodedValue)
```

## Error handling
```apex
try { process(); }
catch (Exception e) { Logger.error(e); throw new AuraHandledException('Request failed'); }
```

## Secure logging
```apex
System.debug(LoggingLevel.INFO, 'order ' + orderId + ' ok');   // never tokens, passwords, card data
```

## File upload / path traversal — N/A
No file paths; validate ContentVersion type and size, and share it explicitly.

## Safe redirect
```apex
String next = ApexPages.currentPage().getParameters().get('retURL');
PageReference p = (next != null && next.startsWith('/') && !next.startsWith('//')) ? new PageReference(next) : Page.Home;
```

## Cache-Control
```apex
ApexPages.currentPage().getHeaders().put('Cache-Control', 'no-store');
```

## Session — N/A
Managed by Salesforce; never expose UserInfo.getSessionId() to pages or callouts.

## Password complexity — N/A
Set in the org's password policies.

## File permissions — permission sets
```text
Grant object and field access through permission sets; check it in code with USER_MODE / Security.stripInaccessible
```

## Encryption at rest
```text
Shield Platform Encryption for sensitive fields
```

## Integrity verification
```apex
Blob mac = Crypto.generateMac('HmacSHA256', body, key);
Boolean ok = Crypto.verifyHMac('HmacSHA256', body, key, expectedMac);
```

## SSRF prevention
```apex
// Remote Site Settings / Named Credentials allow only named endpoints; never setEndpoint(userUrl)
```

## CORS
```text
Setup → CORS allowlist: exact origins only
```

## Log injection prevention
```apex
String safe = s.replaceAll('[\\r\\n]', ' ');
```

## Strip fields the user may not see
```apex
SObjectAccessDecision d = Security.stripInaccessible(AccessType.READABLE, records);
return d.getRecords();
```
