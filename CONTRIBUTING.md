# Contributing

How to add a pattern, fix block, and test case.

## 1. Write the pattern

`patterns/<section>.txt`, tab-separated:

```
id	exts	regex	exclusion	hint	severity
```

Example — detecting `pickle.loads` in Python:

```
deser	py	pickle\.loads?\s*\(	use JSON or a safe format	critical
```

**Columns:**

| # | Required | Content |
|---|----------|---------|
| 1 | yes | Pattern id (unique, lowercase, hyphenated) |
| 2 | yes | Extensions: `*` for all, or comma list (`py,js,go`) |
| 3 | yes | Regex (POSIX ERE, no lookaheads) |
| 4 | no | Exclusion regex (starts with `!`) or fix hint |
| 5 | no | Fix hint (when column 4 is an exclusion) |
| 6 | no | Severity: `critical`, `high`, `medium`, `low` |

**Rules:**

- POSIX ERE only. No `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`.
  BSD grep and macOS don't support them. Use the exclusion column.
- Precision over recall. If the regex fires on safe code, it's wrong.
- Test against the full file content, not individual lines.
- The exclusion column (`!re`) skips files matching that regex.

## 2. Add a fix block

`checks/fixes.md`, one `## id` block:

```markdown
## deser
OWASP: 194,210
Deserializing untrusted data runs code. This is remote code execution.
Wrong: pickle.loads, yaml.load, unserialize
Right: JSON to plain values. yaml.safe_load. Validate the shape.
Watch: "it's our own service" is not trust — the transport can be tampered with.
```

**Required sections:**

- `OWASP:` — comma-separated OWASP SCP item numbers (or cheat sheet name)
- One-line description of why it's dangerous
- `Wrong:` — code that should trigger
- `Right:` — what to write instead
- `Watch:` — edge cases, exceptions, common mistakes

## 3. Add tests

`hooks/test.js`, one `bad()` and one `good()` case per pattern:

```javascript
// bad: must trigger the pattern
bad('myid', 'py', 'pickle.loads(data)', 'deser');

// good: must NOT trigger the pattern
good('myid_ok', 'py', 'json.loads(data)');
```

**bad()** — creates a temp file with the content, runs scan.js,
checks that the fix block appears in output. If it doesn't → test fails.

**good()** — creates a temp file, runs scan.js, checks that output
is empty. If anything appears → false positive, test fails.

Every pattern needs at least one bad and one good case. Add more
for edge cases (different languages, exclusion patterns, etc.).

## 4. Validate

```bash
node hooks/sync.js   # check consistency
node hooks/test.js   # run all tests
```

Both must pass with 0 errors.

## 5. What not to add

- **Style issues** — naming, formatting, file organization. Not security.
- **Context-dependent checks** — "this function should check ownership"
  is a review item, not a pattern. Add to `checks/review.md` instead.
- **Already covered** — check if an existing pattern catches it.
  `node hooks/grep.js --list` shows all pattern ids.
- **Framework-specific best practices** — unless they create a
  concrete security vulnerability detectable by regex.

## File structure

```
patterns/<section>.txt   regex patterns (tab-separated)
checks/fixes.md          fix blocks (## id headers)
checks/review.md         manual review checklist
hooks/test.js            test cases (bad/good)
hooks/scan.js            scanner (reads patterns/)
hooks/sync.js            consistency validator
```
