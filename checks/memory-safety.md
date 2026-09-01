# 🧠 Memory Safety & Hardening Reference

*References: [The case for memory safe roadmaps](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/the-case-for-memory-safe-roadmaps) | [Exploring memory safety in critical open source projects](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/exploring-memory-safety-in-critical-open-source-projects) | [CISA/NSA Memory Safety Guidance](https://www.cisa.gov/resources-tools/resources/secure-by-design-and-default)*

---

## 1. The 70% Vulnerability Elimination Imperative
Memory safety errors (spatial violations like buffer overflows; temporal violations like use-after-free, double-free, null pointer dereferences) account for **~70% of all critical CVEs** in major software systems.

---

## 2. Memory Safe Language (MSL) Selection Matrix

| Language | Best Fit Use Cases | Memory Safety Mechanism |
|---|---|---|
| **Rust** | Systems programming, network parsers, cryptography, microservices, OS kernels | Compile-time ownership, affine types, lifetime tracking, borrow checker |
| **Go** | Cloud microservices, distributed systems, API gateways, CLI tools | Garbage collection, bounds checking, safe pointers |
| **Swift** | Mobile apps, systems programming, server-side services | Automatic Reference Counting (ARC), type safety, safe pointers |
| **TypeScript / JS** | Web apps, API backends, serverless functions | V8 Managed runtime, garbage collection, memory virtualization |
| **Java / C#** | Enterprise backends, transaction processing, legacy modernization | JVM / CLR managed runtimes, garbage collection, type safety |

---

## 3. Safe Intermediary Wrapper Pattern (Legacy C/C++)
When legacy C/C++ libraries cannot be immediately rewritten, wrap their interfaces in a memory-safe language wrapper (e.g., Rust FFI):
1. **Strict Bounds & Length Validation**: Never pass raw unvalidated pointers. Validate array lengths and string null-terminators *before* invoking C APIs.
2. **Safe Allocations & Ownership**: Manage memory allocation and deallocation exclusively on the safe side; use RAII wrappers (`Drop` in Rust, `defer` in Go) to prevent use-after-free.
3. **Panic & Error Isolation**: Catch and translate native crashes or non-zero error codes into strongly typed Result/Error objects.

---

## 4. Compiler & Hardware Hardening Checklist (C/C++)
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
