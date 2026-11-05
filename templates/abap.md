# ABAP (SAP) — secure snippets

Load only when writing ABAP. Copy the right shape; adapt names. SAP's authorization objects, RFC
destinations and SSF do most of the work: use them.

## Parameterized query — Open SQL with host variables
```abap
SELECT carrid, connid FROM spfli
  WHERE carrid = @lv_carrid
  INTO TABLE @DATA(lt_flights).
" dynamic parts: escape or allowlist them
DATA(lv_where) = |carrid = { cl_abap_dyn_prg=>quote( lv_carrid ) }|.
" never: a WHERE (lv_where) built by concatenating user input
```

## Password hashing — N/A
Authentication is SAP user management or an identity provider. Never store passwords in Z-tables.

## Authenticated encryption — SSF / encryption API
```abap
" Use SSF (SSF_KRN_ENVELOPE / SSF_KRN_DEVELOPE) or class CL_SEC_SXML_WRITER with keys in STRUST / PSE files.
" never: home-grown XOR or a key in a CONSTANTS statement
```

## Secure random
```abap
CALL FUNCTION 'GENERATE_SEC_RANDOM'
  EXPORTING length = 32
  IMPORTING random = lv_random.
" never: cl_abap_random for tokens or keys
```

## Constant-time comparison — N/A
Verify MACs and signatures with SSF functions, not with `=`.

## Temp files
```abap
" use logical file names (transaction FILE) under a dedicated directory; delete after use
```

## Secure cookie
```abap
" ICF services: server->response->set_cookie( name = 'sid' value = lv_token secure = 'X' ... ) and HttpOnly in SICF settings
```

## Shell — SM69 external commands only
```abap
CALL FUNCTION 'SXPG_COMMAND_EXECUTE'
  EXPORTING commandname = 'Z_CONVERT'          " defined in SM69, parameters checked there
            additional_parameters = lv_file.    " validated against an allowlist first
" never: CALL 'SYSTEM' ID 'COMMAND' FIELD lv_cmd
```

## Input validation
```abap
IF NOT matches( val = lv_name regex = `^[A-Z0-9_]{1,30}$` ).
  RAISE EXCEPTION TYPE cx_parameter_invalid.
ENDIF.
DATA(lv_table) = cl_abap_dyn_prg=>check_table_name_str( val = lv_input packages = 'ZAPP' ).
```

## Output encoding
```abap
DATA(lv_html) = cl_abap_dyn_prg=>escape_xss_xml_html( lv_text ).
" BSP/Web Dynpro escape by default; never disable it for user data
```

## TLS
```abap
" outbound: SM59 destinations with SSL active and a PSE from STRUST; inbound: HTTPS only in ICM
```

## Secrets — RFC destinations and secure store
```abap
cl_http_client=>create_by_destination( EXPORTING destination = 'Z_PARTNER_API' IMPORTING client = lo_client ).
" credentials live in the SM59 destination; never a password or API key in code
```

## Error handling
```abap
TRY.
    process( ).
  CATCH cx_root INTO DATA(lx).
    log( lx->get_text( ) ).
    MESSAGE e001(zapp).          " generic message to the user
ENDTRY.
```

## Secure logging — application log, no secrets
```abap
" BAL_LOG_CREATE / BAL_LOG_MSG_ADD with business keys only; never passwords, tokens or full card numbers
```

## File upload / path traversal
```abap
CALL FUNCTION 'FILE_VALIDATE_NAME'
  EXPORTING logical_filename = 'Z_UPLOAD_DIR'
  CHANGING  physical_filename = lv_path
  EXCEPTIONS validation_failed = 1 OTHERS = 2.
IF sy-subrc <> 0. RAISE EXCEPTION TYPE cx_sy_file_access_error. ENDIF.
```

## Safe redirect
```abap
" redirect only to fixed ICF paths or an allowlist; never to a URL taken from a request parameter
```

## Cache-Control
```abap
server->response->set_header_field( name = 'Cache-Control' value = 'no-store' ).
```

## Session
```abap
" rely on SAP logon tickets / SAML; ICF stateful sessions end on logout (server->logoff)
```

## Password complexity
```text
Profile parameters login/min_password_lng, login/min_password_digits, login/password_history_size
```

## File permissions — authorization checks
```abap
AUTHORITY-CHECK OBJECT 'S_DATASET'
  ID 'PROGRAM' FIELD sy-repid ID 'ACTVT' FIELD '33' ID 'FILENAME' FIELD lv_path.
IF sy-subrc <> 0. RAISE EXCEPTION TYPE cx_no_authority. ENDIF.
```

## Encryption at rest
```text
Database encryption (HANA data volume / log encryption) and SSF for individual fields
```

## Integrity verification
```abap
cl_abap_message_digest=>calculate_hash_for_raw(
  EXPORTING if_algorithm = 'SHA256' if_data = lv_data
  IMPORTING ef_hashxstring = lv_hash ).
```

## SSRF prevention
```abap
" call partners only through named SM59 destinations; never create_by_url( url = lv_user_url )
```

## CORS — N/A
Configured in the ICF / Gateway layer.

## Log injection prevention
```abap
REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>cr_lf IN lv_text WITH ` `.
```

## Authorization — check before every sensitive read or change
```abap
AUTHORITY-CHECK OBJECT 'Z_ORDER' ID 'ACTVT' FIELD '03' ID 'BUKRS' FIELD ls_order-bukrs.
IF sy-subrc <> 0. RAISE EXCEPTION TYPE cx_no_authority. ENDIF.
" never: SELECT ... CLIENT SPECIFIED / USING CLIENT to read another client's data
```

## Dynamic code — never generated from input
```abap
" never: GENERATE SUBROUTINE POOL or INSERT REPORT with source built from user input
```
