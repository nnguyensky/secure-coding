# Changelog

Versions follow [Semantic Versioning](https://semver.org). To install a
specific version, pin a tag or commit SHA:
`npx github:nnguyensky/secure-coding#<tag-or-sha>`.

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
