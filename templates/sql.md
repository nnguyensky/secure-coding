# SQL (T-SQL, PL/SQL, PL/pgSQL) — secure snippets

Load only when writing stored procedures, functions or migration scripts. Copy the right shape; adapt names.

## Parameterized query — dynamic SQL with bind variables
```sql
-- T-SQL
EXEC sp_executesql N'SELECT Id FROM dbo.Users WHERE Email = @email', N'@email nvarchar(256)', @email = @Email;
-- PL/SQL
EXECUTE IMMEDIATE 'SELECT id FROM users WHERE email = :1' INTO v_id USING p_email;
-- PL/pgSQL
EXECUTE 'SELECT id FROM users WHERE email = $1' INTO v_id USING p_email;
-- never: EXEC('... ''' + @Email + ''''), EXECUTE IMMEDIATE '...' || p_email
```

## Identifiers — quote, never concatenate
```sql
-- T-SQL: QUOTENAME(@table)   PL/SQL: DBMS_ASSERT.SQL_OBJECT_NAME(p_table)   PostgreSQL: format('%I', p_table)
SET @sql = N'SELECT COUNT(*) FROM ' + QUOTENAME(@Table);
```

## Password hashing — N/A in the database
Hash in the application (argon2id). Store only the hash; never compare plaintext passwords in SQL.

## Authenticated encryption — column encryption
```sql
-- SQL Server: Always Encrypted (keys never reach the server).  Oracle: TDE column encryption.
-- PostgreSQL pgcrypto is unauthenticated (pgp_sym_*): prefer encrypting in the application.
```

## Secure random
```sql
SELECT CRYPT_GEN_RANDOM(32);                       -- T-SQL
v_token := DBMS_CRYPTO.RANDOMBYTES(32);            -- PL/SQL
SELECT gen_random_bytes(32);                       -- PostgreSQL pgcrypto
-- never: RAND(), DBMS_RANDOM, random() for tokens
```

## Constant-time comparison — N/A
Compare secrets in the application, not in SQL.

## Temp files — N/A
Use temporary tables (`#temp`, `GLOBAL TEMPORARY`) scoped to the session.

## Secure cookie — N/A
Not applicable to SQL.

## Shell — never from the database
```sql
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;   -- keep it off
-- never: xp_cmdshell, sp_OACreate, DBMS_SCHEDULER external jobs, COPY ... PROGRAM with user data
```

## Input validation — constraints and safe casts
```sql
ALTER TABLE orders ADD CONSTRAINT ck_qty CHECK (qty BETWEEN 1 AND 1000);
IF TRY_CAST(@Id AS int) IS NULL THROW 50001, 'invalid id', 1;
```

## Output encoding — N/A
Encode in the layer that renders the data (HTML, CSV, JSON).

## TLS — encrypted connections only
```sql
-- SQL Server: Force Encryption = Yes; clients use Encrypt=True;TrustServerCertificate=False
-- PostgreSQL pg_hba.conf: hostssl ... scram-sha-256   (no plain "host" lines)
```

## Secrets — no passwords in scripts
```sql
-- use credentials / wallets: CREATE DATABASE SCOPED CREDENTIAL ..., Oracle wallet, PGPASSFILE
-- never: CREATE LOGIN app WITH PASSWORD = 'Prod#2024' in a committed migration
```

## Error handling — generic to caller, detail to the log
```sql
BEGIN TRY ... END TRY
BEGIN CATCH
  INSERT INTO dbo.ErrorLog(Msg) VALUES (ERROR_MESSAGE());
  THROW 50000, 'request failed', 1;
END CATCH
```

## Secure logging — audit, without secret values
```sql
-- SQL Server Audit / Oracle Unified Auditing / pgaudit on logins, DDL and permission changes
```

## File upload / path traversal
```sql
-- BULK INSERT / OPENROWSET / UTL_FILE / COPY: fixed directories only, never a path from input
CREATE DIRECTORY import_dir AS '/srv/import';   -- Oracle: grant READ on this one directory
```

## Safe redirect — N/A
Not applicable to SQL.

## Cache-Control — N/A
Not applicable to SQL.

## Session — N/A
Database sessions are not web sessions.

## Password complexity — database logins
```sql
CREATE LOGIN app WITH PASSWORD = ..., CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
-- never: CHECK_POLICY = OFF
```

## File permissions — least privilege grants
```sql
CREATE ROLE app_rw; GRANT SELECT, INSERT, UPDATE ON dbo.Orders TO app_rw;
GRANT EXECUTE ON dbo.GetOrder TO app_rw;          -- procedures, not tables, where possible
-- never: GRANT ... TO PUBLIC, db_owner / DBA for an application account
```

## Encryption at rest
```sql
-- Transparent Data Encryption for files and backups; keys in an HSM / key vault (EKM)
```

## Integrity verification — signed modules
```sql
ADD SIGNATURE TO dbo.TransferFunds BY CERTIFICATE ModuleSigning;   -- T-SQL
```

## SSRF prevention
```sql
-- Oracle: network ACLs allow only named hosts for UTL_HTTP
-- never: UTL_HTTP.REQUEST(p_url), sp_OACreate MSXML with a URL from input
```

## CORS — N/A
Not applicable to SQL.

## Log injection prevention
```sql
INSERT INTO audit_log(msg) VALUES (REPLACE(REPLACE(@Msg, CHAR(13), ' '), CHAR(10), ' '));
```

## Row-level access — tenancy in the database
```sql
CREATE SECURITY POLICY TenantFilter ADD FILTER PREDICATE dbo.fn_tenant(TenantId) ON dbo.Orders;  -- T-SQL
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;                                                       -- PostgreSQL
```
