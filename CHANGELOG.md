# Changelog

Versions follow [Semantic Versioning](https://semver.org). To install a
specific version, pin a tag or commit SHA:
`npx github:nnguyensky/secure-coding#<tag-or-sha>`.

## 2.5.0 — 2026-11-05

### Added
- **16 new language templates** (29 in total): C++, PowerShell, SQL (T-SQL,
  PL/SQL), Scala, Dart/Flutter, Groovy/Jenkinsfile, COBOL, VB.NET, ABAP, Apex,
  Objective-C, Perl, Lua, Elixir, Solidity, R. Each covers the same 25
  controls; a control that does not apply says `N/A` and why.
- **Patterns for the new languages** (515 in total, up from 403): SQL built by
  string joining, shell and dynamic code calls, weak crypto, TLS turned off,
  hard-coded secrets, plus language-specific risks — `without sharing` in
  Apex, `CLIENT SPECIFIED` in ABAP, dynamic `CALL` in COBOL, `tx.origin`,
  `delegatecall` and unchecked calls in Solidity, atom exhaustion in Elixir,
  `GRANT ... TO PUBLIC` in SQL, Groovy `sh "${...}"` in Jenkinsfiles.
- 13 new fix blocks in `checks/fixes.md` (168 in total).
- Existing templates gained XXE, unsafe deserialization and JWT sections;
  C gained format strings and integer overflow.
- The scanner recognises the new file types (`.ps1`, `.sql`, `.scala`,
  `.dart`, `.groovy`, `Jenkinsfile`, `.cbl`, `.vb`, `.abap`, `.cls`, `.m`,
  `.pl`, `.lua`, `.ex`, `.sol`, `.r` and their variants), masks their strings
  and comments, and follows taint from ASP.NET `Request.*` and Ktor `call.*`.

### Fixed
- SQL concatenation was missed when the query held a quoted value
  (`"... WHERE name = '" + x`) in Java, Kotlin, Go and PHP; Kotlin string
  templates and Go `fmt.Sprintf` are now caught too.
- Gaps across 32 language/class cells (shell, weak hash, weak crypto, TLS off,
  XXE, open redirect, path traversal, log injection) are closed.
- Upper-case secret names (`API_KEY = "..."`) are now caught; names like
  `PASSWORD_FIELD` are not.
- Rules that fired on safe code: `docker-digest` on digest-pinned images,
  `API-5` on `requireAuth`, the Kubernetes NetworkPolicy and read-only root
  filesystem rules, `npm-audit` on `--ignore-scripts`, `API-7`.
- Templates: TypeScript integrity check now compares lengths before
  `timingSafeEqual`; PHP CSRF check rejects an empty session token.

## 2.4.0 — 2026-11-05

### Added
- **Dashboard** (`node hooks/serve.js`, `npm run dashboard`): a React 19 view
  of the results — posture score, a 3D risk skyline by section, findings over
  time, dependency advisories, and a searchable finding list with each fix's
  wrong/right code. Live mode refreshes and can rescan; `report.js
  --dashboard` writes the same page as one offline file.
- Built once into `reports/dashboard.html` (single file, no CDN), so the
  package still has no runtime dependencies. Source in `dashboard/`; CI
  rebuilds it and fails if the committed bundle differs.
- Local-only server: 127.0.0.1, per-run token in the URL fragment, Host and
  Origin checks (DNS rebinding, cross-site posts), strict CSP with script
  hashes; the only action is a rescan.
- MCP tool `open_dashboard`.

## 2.3.0 — 2026-11-05

### Added
- **Baseline** (`scan.js --baseline`): record a repository's existing
  findings in `.securecoding-baseline.json`; afterwards only new findings
  block. Matched by file, rule and line text, not line number.
- **Edit-scoped hook**: for an Edit/MultiEdit, only findings on the lines the
  edit wrote block the agent; others are named but do not stop it.
  `"hookScope": "file"` restores whole-file blocking.
- **Dependency guard** (`hooks/deps.js`): packages a change adds to
  `package.json`, `requirements*.txt` or `pyproject.toml` are checked against
  npm/PyPI — missing (hallucinated) names and packages under 30 days old
  block; install scripts and sdist-only packages are reported. Runs from the
  write-time hook, `scan.js --staged` and CI. Honours `HTTPS_PROXY`. Only
  names of newly added public dependencies are sent; names from private
  registries/indexes (`.npmrc` scopes, pip `--index-url`) or listed in
  `deps.private` never leave the machine.
- **Secrets in git history** (`scan.js --history`), with whether each key is
  still in `HEAD`.
- MCP: resources (SKILL.md, checks, every fix block), prompts
  (`secure_design_review`, `fix_finding`), and tools `explain_finding`,
  `check_dependencies`, `scan_git_history`.
- HTML report: findings-over-time chart.
- Patterns: Swift (CryptoKit MD5/SHA1, App Transport Security, UserDefaults
  secrets, SQLite interpolation), Android SharedPreferences secrets,
  `Runtime.exec` / shell `ProcessBuilder`, Spring JDBC string SQL,
  `csrf().disable()`, `anyRequest().permitAll()`, Django insecure settings,
  `express.static` on the project root.
- Taint: Go (`r.URL.Query()`, gin/echo `c.Query`, `mux.Vars`), Spring
  `@RequestParam`/`@PathVariable`/`@RequestBody` parameters, JDBC/JPA sinks,
  and request text reaching an LLM system prompt (`taint-prompt-injection`).
- CI: tests on Linux, macOS and Windows with Node 18, 20 and 22; added
  dependencies checked on PRs. Release workflow tags `v<version>` from
  `package.json` and publishes to npm with provenance when `NPM_TOKEN` is set.

### Fixed
- `.tsx`, `.jsx`, `.mjs`, `.cjs`, `.mts`, `.vue`, `.svelte` (and `.kts`)
  files only got the language-neutral patterns.
- `.pre-commit-hooks.yaml` used `node hooks/…` paths that only exist inside
  this repository, so the hooks failed in every consumer repository.
- `scan.js --all` spawned `git` three times per file: 22s → 5s on 2,000 files.
- Taint: a tainted variable used inside an assignment
  (`data, _ := os.ReadFile(f)`) was skipped; a word inside a SQL string was
  mistaken for the tainted variable.
- The test suite runs fixtures in-process: 34s → 15s.

## 2.2.0 — 2026-11-05

Two review rounds. Several changes alter behaviour; read **Changed** before
upgrading.

### Changed
- `secure-coding-ignore: all` / `nosec: all` no longer silence the scanner.
  Name each rule. Every suppression is recorded with its reason and shown in
  the HTML report, the Markdown summary and SARIF (as an in-source suppression).
- The write-time hook prints findings to **stderr** (Claude Code only feeds
  stderr back to the agent on exit code 2).
- `.json` files are scanned for secrets.
- `fix.js --apply` rewrites only the lines the scanner currently reports, with
  type-preserving replacements; `--dry-run` prints `-`/`+` per line. The
  `set +e` autofix was removed (it is usually deliberate and scoped).
- `audit.js` puts every ecosystem on one severity scale: CVSS scores and
  "moderate" are mapped, and a known advisory with no severity counts as high.
- Code-only patterns ignore matches inside string literals and comments.

### Added
- Detection: XSS via `res.send`, request data wrapped in another call
  (`path.join(..., req.query.f)`), `exec` with a template string, `vm` module,
  `jwt.decode()` in JS, prototype pollution through merge helpers, SQL via
  `.format()` and Ruby ORM interpolation, PHP `echo $_GET`, Java XML factories
  without hardening, lxml `resolve_entities=True`, `assert` used for access
  checks, C format strings, Rust `ptr::read`/`ptr::write`, `curl | sh`,
  Terraform public buckets/ingress/databases, GitHub Actions script injection
  and `pull_request_target`, OpenAI `sk-proj-` and Anthropic `sk-ant-` keys.
- `!!re` file-level exclusions in pattern files.
- `audit.js --strict` / `audit.failOnSkipped`.
- Detection benchmark in the test suite (bad and safe fixtures per gap).

### Fixed
- A pattern id with several regexes reported only the first that matched.
- `--staged`, `--diff`, the Done Gate and CI skipped renamed files.
- Parallel hooks could lose findings (state writes are now locked and atomic).
- MCP: a failing tool answered "Parse error" with `id: null`, leaving the
  client waiting; child processes now have timeouts; protocol version is
  negotiated.
- SBOM: nested `node_modules` names, scoped-package purls, version ranges
  recorded as versions, missing `bom-ref`s, VEX `affects` refs that pointed at
  nothing, invalid `analysis.state`/`response` fields.
- Taint: `path.join(` counted as sanitised (`joi` matched `join`); a request
  value passed as a bound parameter was treated like part of the query.
- Installer: unquoted hook path, missing `MultiEdit`/`NotebookEdit`, duplicate
  hooks on re-install, plugin manifest author and version.
- Slow regexes on long lines; hint showing the severity word; `.min.js` skip.
