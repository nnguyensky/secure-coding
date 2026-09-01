# 🧠 Memory Safety & Hardening Reference

*References: [The case for memory safe roadmaps](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/the-case-for-memory-safe-roadmaps) | [Exploring memory safety in critical open source projects](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/exploring-memory-safety-in-critical-open-source-projects) | [CISA/NSA Memory Safety Guidance](https://www.cisa.gov/resources-tools/resources/secure-by-design-and-default)*

---

## 1. The 70% Vulnerability Elimination Imperative
Memory safety errors (spatial violations like buffer overflows; temporal violations like use-after-free, double-free, null pointer dereferences) account for **~70% of all critical CVEs** in major software systems.

---

## 2. The Memory Safe Roadmap (the artifact the guidance actually asks for)
The joint guidance asks manufacturers to **publish** a memory safe roadmap — not merely to write safer code. A roadmap is a Secure by Design transparency signal and should name:
- **A senior owner.** Publicly identify the executive driving the roadmap and empowered to realign resources.
- **Defined prioritisation.** Which components move first, and why.
- **External dependencies.** The plan must cover memory unsafety inherited from third-party and OSS code, not just first-party source.
- **Dates and measurable progress**, so customers can hold the plan to account.

**Prioritisation strategies** (pick the smallest project that still teaches you something):
1. **Replace self-contained unsafe components** — run old and new in parallel, compare outputs, then retire the original.
2. **Security-critical code first**: anything handling user-generated content, secret keys, network connections, authn/authz, or firmware. Review cryptographic components and other roots of trust during prioritisation.
3. **Rewrite what you were rewriting anyway** — if a component is already brittle and due for change, do it in the MSL.
4. **Ramp parallel systems**: shift a small share of traffic to the new implementation, monitor, then increase.
5. **Wrap what you cannot replace** (see §4).

**Training is a bridge, not a control.** Even expert developers write memory safety bugs; training reduces incidence but cannot eliminate the class. Fuzzing helps but is non-deterministic and applied after the mistake — neither substitutes for an MSL.

> **Memory safety is inherited.** ACSC analysis of critical OSS found 52% of projects contain memory-unsafe code, and *every* memory-safe project examined depended on components that were not. Writing in Rust or Go does not make a product memory safe if its dependency tree is C. Audit dependencies, and note that `unsafe` blocks re-introduce the risk inside otherwise safe languages.

---

## 3. Memory Safe Language (MSL) Selection Matrix

| Language | Best Fit Use Cases | Memory Safety Mechanism |
|---|---|---|
| **Rust** | Systems programming, network parsers, cryptography, microservices, OS kernels | Compile-time ownership, affine types, lifetime tracking, borrow checker |
| **Go** | Cloud microservices, distributed systems, API gateways, CLI tools | Garbage collection, bounds checking, safe pointers |
| **Swift** | Mobile apps, systems programming, server-side services | Automatic Reference Counting (ARC), type safety, safe pointers |
| **TypeScript / JS** | Web apps, API backends, serverless functions | V8 Managed runtime, garbage collection, memory virtualization |
| **Java / C#** | Enterprise backends, transaction processing, legacy modernization | JVM / CLR managed runtimes, garbage collection, type safety |

---

## 4. Safe Intermediary Wrapper Pattern (Legacy C/C++)
When legacy C/C++ libraries cannot be immediately rewritten, wrap their interfaces in a memory-safe language wrapper (e.g., Rust FFI):
1. **Strict Bounds & Length Validation**: Never pass raw unvalidated pointers. Validate array lengths and string null-terminators *before* invoking C APIs.
2. **Safe Allocations & Ownership**: Manage memory allocation and deallocation exclusively on the safe side; use RAII wrappers (`Drop` in Rust, `defer` in Go) to prevent use-after-free.
3. **Panic & Error Isolation**: Catch and translate native crashes or non-zero error codes into strongly typed Result/Error objects.

---

## 5. Compiler & Hardware Hardening Checklist (C/C++)
If native C/C++ code must be compiled:
```bash
# Recommended Hardening Compiler Flags (GCC / Clang)
-fstack-protector-strong      # Stack canary protection
-D_FORTIFY_SOURCE=3           # Buffer overflow checks on libc functions
-fPIE -pie                    # Position Independent Executable (ASLR)
-Wl,-z,relro,-z,now           # Full RELRO (read-only GOT relocations)
-fsanitize=address,undefined  # ASan & UBSan for testing / debug builds
-fcf-protection=full          # Intel CET / Control-Flow Integrity
```
- **Hardware Mitigations**: Utilize **ARM Memory Tagging Extension (MTE)** and **CHERI capability hardware** where available.
