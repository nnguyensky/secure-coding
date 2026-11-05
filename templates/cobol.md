# COBOL (IBM Enterprise COBOL, Db2, CICS) — secure snippets

Load only when writing COBOL. Copy the right shape; adapt names. Mainframe controls (RACF, ICSF, AT-TLS)
do much of the work: call them, do not reimplement them.

## Parameterized query — static SQL with host variables
```cobol
           EXEC SQL
               SELECT ACCT_NAME INTO :WS-NAME
                 FROM ACCOUNTS
                WHERE ACCT_ID = :WS-ACCT-ID
           END-EXEC.
      * Dynamic SQL: parameter markers, values bound at EXECUTE
           MOVE 'SELECT ACCT_NAME FROM ACCOUNTS WHERE ACCT_ID = ?' TO WS-STMT.
           EXEC SQL PREPARE S1 FROM :WS-STMT END-EXEC.
           EXEC SQL DECLARE C1 CURSOR FOR S1 END-EXEC.
           EXEC SQL OPEN C1 USING :WS-ACCT-ID END-EXEC.
      * never: STRING the input into WS-STMT, then EXECUTE IMMEDIATE :WS-STMT
```

## Password hashing — do not store passwords
Authenticate users through RACF (`RACROUTE REQUEST=VERIFY` in an assembler stub or the CICS `VERIFY PASSWORD`
command). Never keep passwords, or reversible copies, in VSAM files or Db2 tables.

## Authenticated encryption — ICSF, keys by label
```cobol
      * Call ICSF Symmetric Key Encipher (CSNBSYE) with AES and a key label from the CKDS.
           CALL 'CSNBSYE' USING WS-RC WS-REASON WS-EXIT-LEN WS-EXIT
                                WS-RULE-COUNT WS-RULES WS-KEY-ID-LEN WS-KEY-LABEL ...
      * never: a key in WORKING-STORAGE, home-grown XOR or table "encryption"
```

## Secure random — ICSF
```cobol
           CALL 'CSNBRNG' USING WS-RC WS-REASON WS-EXIT-LEN WS-EXIT
                                WS-FORM WS-RANDOM-8-BYTES.
      * WS-FORM = 'RANDOM  '; call repeatedly for longer values (or CSNBRNGL).
      * never: FUNCTION RANDOM for tokens, keys or one-time codes
```

## Constant-time comparison — N/A
Compare MACs and tokens with ICSF verification services (e.g. CSNBMVR for MACs), not IF A = B.

## Temp files — temporary datasets
```jcl
//WORK     DD DSN=&&WORK,DISP=(NEW,DELETE),SPACE=(CYL,(5,5))
```

## Secure cookie — N/A
CICS web support: set Secure and HttpOnly through `EXEC CICS WEB WRITE HTTPHEADER` when you issue cookies.

## Shell — CALL by literal name only
```cobol
           CALL 'ACCTUPD' USING WS-AREA.
      * never: MOVE input TO WS-PGM, then CALL WS-PGM — the caller chooses which program runs
```

## Input validation — class tests, lengths, allowlists
```cobol
           IF WS-ACCT-ID IS NOT NUMERIC
              PERFORM REJECT-INPUT
           END-IF.
           IF FUNCTION LENGTH(FUNCTION TRIM(WS-NAME)) > 40
              PERFORM REJECT-INPUT
           END-IF.
           INSPECT WS-NAME TALLYING WS-BAD FOR ALL '<' ALL '>' ALL ''''.
```

## Output encoding — N/A
Escape in the layer that renders HTML or JSON (CICS web support, z/OS Connect).

## TLS — AT-TLS or CICS TCPIPSERVICE
```text
TCPIPSERVICE(ACCTSVC) SSL(YES) PRIVACY(REQUIRED) CIPHERS(...TLS 1.2+ suites...)
AT-TLS policy: TTLSEnvironmentAction HandshakeRole ServerWithClientAuth, TLSv1.2 / TLSv1.3 only
```

## Secrets — never in VALUE clauses
```cobol
      * never:  01 WS-DB-PASSWORD PIC X(16) VALUE 'Prod#Passw0rd'.
      * use RACF PassTickets, Db2 trusted contexts, or a protected dataset read at run time.
```

## Error handling — check every return code
```cobol
           IF SQLCODE NOT = 0
              MOVE SQLCODE TO WS-LOG-CODE
              PERFORM LOG-ERROR
              MOVE 'Request failed' TO WS-USER-MSG
           END-IF.
           EXEC CICS READ FILE('ACCTS') INTO(WS-REC) RIDFLD(WS-KEY) RESP(WS-RESP) END-EXEC.
           IF WS-RESP NOT = DFHRESP(NORMAL) PERFORM HANDLE-READ-ERROR END-IF.
```

## Secure logging — no PAN, passwords or PII
```cobol
           MOVE WS-CARD-NUMBER(13:4) TO WS-LOG-LAST4.
           DISPLAY 'PAYMENT OK CARD=************' WS-LOG-LAST4.
      * never: DISPLAY WS-CARD-NUMBER or WS-PASSWORD
```

## File upload / path traversal — fixed dataset names
```cobol
      * Dataset names come from JCL DD statements or configuration, never from user input.
           SELECT ACCT-FILE ASSIGN TO ACCTDD.
```

## Safe redirect — N/A
Not applicable to batch or CICS programs.

## Cache-Control — N/A
Set by the web front end.

## Session — re-check on every task
```cobol
      * Pseudo-conversational CICS: the COMMAREA comes back from the terminal side.
      * Re-validate user and authority on every task; never trust a flag stored in it.
           EXEC CICS QUERY SECURITY RESTYPE('FILE') RESID('ACCTS') READ(WS-READ) END-EXEC.
```

## Password complexity — RACF rules
```text
SETROPTS PASSWORD(RULE1(LENGTH(8:8) ...)) PASSWORD(HISTORY(12) INTERVAL(90)) and enable passphrases
```

## File permissions — RACF dataset profiles
```text
ADDSD 'PROD.ACCT.**' UACC(NONE)
PERMIT 'PROD.ACCT.**' ID(ACCTAPP) ACCESS(UPDATE)
```

## Encryption at rest — z/OS data set encryption
```text
Assign a key label (DFSMS data class or RACF DFP segment) so the dataset is encrypted by ICSF.
```

## Integrity verification — ICSF hash
```cobol
           CALL 'CSNBOWH' USING WS-RC WS-REASON WS-EXIT-LEN WS-EXIT
                                WS-RULE-COUNT WS-RULES-SHA256 WS-TEXT-LEN WS-TEXT ...
```

## SSRF prevention — N/A
Outbound calls go through z/OS Connect or CICS URIMAP definitions: allow only named hosts there.

## CORS — N/A
Configured on the web front end.

## Log injection prevention
```cobol
           INSPECT WS-LOG-TEXT REPLACING ALL X'0D' BY SPACE ALL X'0A' BY SPACE.
```

## Authorization — check before acting
```cobol
           EXEC CICS QUERY SECURITY RESTYPE('TRANSATTACH') RESID('ACUP') ... END-EXEC.
      * Batch: rely on RACF profiles for the job's user; never a hard-coded user-id check.
```
