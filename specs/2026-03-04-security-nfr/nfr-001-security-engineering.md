---
id: "S-20260304-NFR001"
title: "Global Security Engineering NFR — Memory Safety, Subprocess Isolation, and Cryptographic Hygiene"
status: "implemented"
owners: ["@aheissenberger"]
mode: ["cli"]
platforms: ["Linux", "macOS", "Windows"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/crypto.rs", "src/barrier.rs", "src/identity.rs", "src/repo/drift.rs", "src/commands/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "All functions that decrypt secret material return `Zeroizing<T>` (or `Zeroizing<Vec<u8>>` for byte payloads). No decrypted plaintext is held in a plain `Vec<u8>` or `String` that persists beyond the call frame without explicit justification."
  - id: "AC2"
    text: "No `unsafe` FFI block is present in the codebase when an equivalent safe Rust standard library API (stabilized on the project's minimum `rust-version`) provides the same capability. The only permitted `unsafe` is `File::from_raw_fd` for Unix FD passing (REQ-73/76), with a mandatory safety comment."
  - id: "AC3"
    text: "All `Command::new(\"git\")` invocations in production code paths (not tests) call `.env_remove(\"GIT_DIR\").env_remove(\"GIT_CONFIG\").env_remove(\"GIT_CONFIG_GLOBAL\")` before spawning, unless the call explicitly depends on the inherited repo context (e.g. `find_repo_root`)."
  - id: "AC4"
    text: "HMAC inputs over integer values use canonical big-endian byte encoding (`u64::to_be_bytes()`) rather than decimal string representations."
  - id: "AC5"
    text: "Cryptographic key material loaded from disk is validated for basic entropy (not all-zero) before use. Keys failing this check are rejected with an actionable error."
  - id: "AC6"
    text: "File existence checks (`path.exists()`) are not used as the branch condition before open/read operations on security-sensitive files. Instead, the open/read result is matched directly to eliminate TOCTOU races."
  - id: "AC7"
    text: "No `expect()` or `unwrap()` calls exist in non-test production code paths for operations that can legitimately fail (I/O, parsing, cryptographic operations). Invariants that are guaranteed by types (e.g. fixed-size array to HMAC key) use the typed API that enforces the invariant at compile time."
  - id: "AC8"
    text: "History-scan commands that filter by file-add events (`--diff-filter=A`) also include file-rename events (`--diff-filter=AR`) so that secrets renamed into sensitive paths are detected."
  - id: "AC9"
    text: "Configurable time-to-live values for security tokens have a hard server-side maximum (`MAX_TOKEN_TTL_SECS = 86_400`) enforced in code, independent of any config file value."
  - id: "AC10"
    text: "Functions that produce multiple `git config` subprocess calls for the same key within a single command execution are refactored to call once and share the result."
verification:
  commands:
    - "cargo fmt --all -- --check"
    - "cargo clippy --all-targets -- -D warnings"
    - "cargo test --all"
risk:
  level: "low"
links:
  issue: ""
  pr: ""
---

## Purpose

This document captures global Non-Functional Requirements (NFRs) for security engineering across the entire `gitvault` codebase. These requirements are **cross-cutting**: they apply to every module and every future change. They were derived from a systematic security review conducted on 2026-03-04 and address recurring classes of vulnerability rather than individual bugs.

## Background — Finding Categories

The 2026-03-04 security review identified 13 concrete issues across three major categories:

### Category A — Memory Safety and Zeroization
Decrypted plaintext held in heap memory survives garbage collection and can appear in core dumps, swap files, and memory profiler output. The `Zeroizing<T>` wrapper from the `zeroize` crate overwrites the memory on drop.

**Root cause:** `crypto::decrypt()` returned `Vec<u8>` instead of `Zeroizing<Vec<u8>>`. This allowed callers (rotate, paths) to accumulate unzeroized plaintext across multi-file loops.

**Policy:** Any function that produces decrypted secret bytes MUST return `Zeroizing<Vec<u8>>`. Any intermediate variable holding key material or plaintext MUST be wrapped in `Zeroizing<T>` or `zeroize::Zeroizing`.

### Category B — Cryptographic Hygiene
Cryptographic operations must follow well-established conventions to remain auditable and secure.

**Issues found:**
- HMAC computed over ASCII decimal string of `u64` rather than canonical `to_be_bytes()`.
- HMAC key material (32-byte array and its hex encoding) not zeroized after use.
- All-zero key accepted from disk without entropy validation.
- `expect()` used inside HMAC computation on a path that is statically safe but not proven to the compiler.
- Production token TTL had no hard upper bound.

**Policy:** HMAC and MAC inputs over integers use `to_be_bytes()`. All key material in local variables is wrapped in `Zeroizing`. Keys loaded from disk are validated for non-zero entropy. Compile-time-safe invariants use typed APIs (e.g. `GenericArray::from(*key)`) that eliminate `expect()`. Security token TTLs are capped at `MAX_TOKEN_TTL_SECS`.

### Category C — Subprocess and Environment Isolation
Child processes inherit the parent environment. A compromised or manipulated `GIT_DIR`, `GIT_CONFIG`, or `GIT_CONFIG_GLOBAL` can redirect git operations to attacker-controlled repositories or config files.

**Policy:** All `Command::new("git")` spawns in production code (non-test) that do not require the inherited repo context MUST remove `GIT_DIR`, `GIT_CONFIG`, and `GIT_CONFIG_GLOBAL` from the child environment before spawning. The sole exception is calls that are specifically resolving the repo root.

### Category D — TOCTOU and File System Safety
Checking `path.exists()` then reading the file creates a window where another process can replace the file. This is especially dangerous for security key files.

**Policy:** Security-sensitive file reads use `fs::read_to_string()` / `fs::open()` directly and match on the `NotFound` error kind. No `exists()` pre-check is used for key files.

### Category E — Unsafe Code Minimization
`unsafe` Rust blocks bypass the compiler's safety guarantees. Every `unsafe` block must have a documented justification and must not exist when a safe alternative is available in the project's MSRV.

**Policy:** `unsafe extern "C"` blocks for standard POSIX functions are forbidden when the Rust standard library provides a safe equivalent (MSRV ≥ 1.70 ships `std::io::IsTerminal`). The only permitted `unsafe` blocks are those in REQ-73/76 (`File::from_raw_fd` for FD passing), each with a mandatory `// SAFETY:` comment.

### Category F — History Scan Completeness
Plaintext leak detection must cover all git operations that could introduce sensitive files: adds AND renames.

**Policy:** `git log` history scans for plaintext leaks use `--diff-filter=AR` (Added and Renamed) rather than `--diff-filter=A` alone.

### Category G — DRY and Maintainability for Security-Sensitive Paths
Duplicated subprocess calls for the same piece of information (e.g. `git config user.name`) create inconsistency risk and increase the attack surface.

**Policy:** Security-sensitive data fetches (git config, keyring queries) are performed once per command invocation and the result is shared, not repeated.

## Enforcement

These NFRs are enforced via:
1. `cargo clippy -- -D warnings` (`unsafe_code` lint, `expect_fun_call` hints)
2. Code review checklist (see `docs/review-checklist.md`)
3. Individual REQ specs: REQ-87 through REQ-99 (implementation-level requirements)

## Individual Requirement Mapping

| NFR Category | REQ | Title |
|---|---|---|
| A — Zeroization | REQ-87 | `crypto::decrypt` returns `Zeroizing<Vec<u8>>` |
| B — HMAC encoding | REQ-88 | HMAC inputs use `to_be_bytes()` canonical encoding |
| B — Key zeroization | REQ-89 | HMAC key material zeroized on drop |
| C — Subprocess env | REQ-90 | `git` subprocesses sanitize inherited env |
| D — TOCTOU | REQ-91 | Token key load uses `NotFound`-match not `exists()` |
| B — Entropy | REQ-92 | Loaded HMAC key validated for non-zero entropy |
| E — Unsafe FFI | REQ-93 | `isatty` replaced with `std::io::IsTerminal` |
| B — expect() | REQ-94 | `compute_hmac` uses typed `GenericArray` API |
| F — History scan | REQ-95 | History scan uses `--diff-filter=AR` |
| G — DRY | REQ-96 | `git config user.name` called once per command |
| B — TTL cap | REQ-97 | `allow_prod` enforces `MAX_TOKEN_TTL_SECS` |
