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
| 3 | yes | Regex (JavaScript `RegExp`, one line) |
| 4 | no | Exclusion regex (`!re` for the line, `!!re` for the whole file) or fix hint |
| 5 | no | Fix hint (when column 4 is an exclusion) |
| 6 | no | Severity: `critical`, `high`, `medium`, `low` |

**Rules:**

- Keep the regex column to plain syntax — no lookarounds. If you need "but
  not when…", put it in the exclusion column, where lookarounds are allowed.
- Precision over recall. If the regex fires on safe code, it's wrong.
- Each line of the file is tested on its own. A regex that can only match
  across lines (e.g. `ingress\s*\{[^}]*0\.0\.0\.0/0`) falls back to the whole
  file, anchored at the first line it touches.
- `!re` skips a matching line. `!!re` skips the whole file when the fix lives
  on another line — an XML factory hardened with `setFeature(...)` later on.
- A call-shaped regex (it contains `\(`, no quote, no `://`, not a secret) is
  matched only in code: a hit inside a string literal or a comment is
  ignored. A regex that mentions a quote is about string contents and sees
  inside literals.
- Never `!a|!b` in the exclusion column — that is two negations; write `!a|b`.
- Use [0-9] rather than `\d` only if you want the pattern to stay readable
  in `grep -E` for manual checks; the scanner itself accepts both.

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

## One defect, one finding

Patterns overlap: a broad rule and a language-specific rule often match the
same line. Each defect must be reported once:

- **Same id** — every regex with that id is checked, and each line is reported
  once. Reuse an existing id for the same defect in another language.
- **Different ids, same line** — the more specific one wins through
  `SUPERSEDES` in `hooks/scan.js` (`secret-aws-key` absorbs `secret`).
- **Two real defects on one line** — both are reported (TLS verification off
  and a missing timeout are different bugs).

Each occurrence is its own finding, tracked by `(file, id, line)`, so fixing
one of three SQL injections closes only that one. Occurrences per rule per file
are capped at 20 (`SECURE_CODING_MAX_OCCURRENCES`).

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
dashboard/               dashboard source (React); npm run dashboard:build
                         writes reports/dashboard.html — commit both
docs/images/             README screenshots
```
