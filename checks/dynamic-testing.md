# 🎯 Dynamic Testing — What Static Analysis Cannot Reach

*References: [SSDF PW.8](https://csrc.nist.gov/pubs/sp/800/218/final) (test executable code) · [The case for memory safe roadmaps](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/the-case-for-memory-safe-roadmaps) (fuzzing)*

This skill is **static analysis**. It reads code and never runs it, so it cannot
observe behaviour: what a parser does on malformed input, whether a check can be
raced, or what a service does under load. SSDF **PW.8** expects executable
testing, and the joint memory-safety guidance names **fuzzing** specifically.

This file does not add a fuzzer. It says what to fuzz, chosen from what the
scanner already found — a targeted plan beats an untargeted campaign.

---

## 1. Let the findings pick the targets

These pattern ids mark a **parser or trust boundary** — the highest-value fuzz
targets, because they take attacker-controlled bytes and interpret them:

| Finding | Fuzz this | Looking for |
|---|---|---|
| `insecure-deserialization` | the deserializer entry point | RCE, type confusion, resource exhaustion |
| `xxe` | the XML parser, with entities and DTDs | entity expansion, file read, SSRF |
| `redos-input` | the regex, with adversarial strings | catastrophic backtracking (measure time, not output) |
| `path-traversal` `zip-slip` | the path builder and archive extractor | escapes via `..`, symlinks, absolute paths, unicode |
| `file-upload` `upload-exec` | the type sniffer | polyglots, renamed executables, zip bombs |
| `nosql-inject` `ssti` | the query/template builder | operator injection, expression evaluation |
| `prototype-pollution` | the object merge/assign | `__proto__`, `constructor`, `prototype` keys |
| `mem` (C/C++/unsafe Rust) | any function taking a buffer and a length | overflow, use-after-free, off-by-one |

**Where there are no findings, fuzz anyway** at every format boundary the
service exposes: request bodies, uploaded files, tokens, and anything read from
another system.

## 2. Tooling by language
Use what the ecosystem already ships; none of this needs a new dependency in
your app.

| Language | Fuzzer | Note |
|---|---|---|
| Go | `go test -fuzz` | built in; corpus checked into the repo |
| Rust | `cargo fuzz` (libFuzzer) | pairs with ASan; the standard for `unsafe` blocks |
| C / C++ | libFuzzer or AFL++ **with `-fsanitize=address,undefined`** | sanitizers are what turn a crash into a diagnosis |
| Python | `atheris` | coverage-guided, works on native extensions |
| Java / Kotlin | `Jazzer` | JVM coverage-guided |
| JS / TS | `fast-check` (property-based) | closest practical equivalent |
| Any HTTP API | schemathesis (from OpenAPI) or ZAP | drives the real endpoint |

## 3. What to assert
A fuzzer only finds what you tell it is wrong. Assert on:
- **Crash, panic, or unhandled exception** — the default, and the weakest signal.
- **Sanitizer reports** — ASan/UBSan/MSan turn silent corruption into a failure.
- **Invariants** — a decoded value must round-trip; a path must stay inside its root; an authz decision must be deny unless explicitly allowed.
- **Time** — a bounded input must complete in bounded time. This is the only way ReDoS shows up; the output is correct, just late.

## 4. Beyond fuzzing
Static analysis is also blind to these; none are fuzzing problems:
- **Race conditions / TOCTOU** — needs concurrent execution. Run the check-then-use path from many threads and assert the invariant holds.
- **Authorization matrices** — enumerate (role × endpoint) and assert every unauthorized pair is denied. This catches the IDOR and missing-authz cases the Done Gate asks about, mechanically.
- **Rate limits and quotas** — only observable under load.
- **Deployed configuration** — TLS versions, headers, and open ports are properties of the running service, not the source.

## 5. Wiring it in
- Run fuzzers **continuously**, not once — they find more with more time. A nightly job beats a CI gate.
- **Commit the corpus and every crash input** as a regression test, so a fixed bug stays fixed.
- CI should run the *existing* corpus on every PR (fast) and extend it on a schedule (slow).
- Feed crashes back as patterns where the shape generalises: if a fuzzer finds a class of bug, add a `patterns/` rule and a test so the scanner catches the next one statically. That is SSDF **RV.3.3**, eradicating the class.
