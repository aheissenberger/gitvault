---
id: "S-20260304-031"
title: "Plan: Security hardening — findings #3–#11"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**"]
  touch:
    - "src/structured/armor.rs"
    - "src/structured/helpers.rs"
    - "src/structured/fields.rs"
    - "src/barrier.rs"
    - "src/defaults.rs"
    - "src/repo/drift.rs"
    - "src/materialize.rs"
    - "Cargo.toml"
    - "specs/**"
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-78: `decrypt_armor` and `decrypt_binary_b64` return `Zeroizing<Vec<u8>>`; all callers updated."
  - id: "AC2"
    text: "REQ-79: `allow_prod` writes HMAC-SHA256 authenticated token; `has_valid_token` verifies with constant-time comparison; HMAC key stored in `0600`-protected `.git/gitvault/.token-key`."
  - id: "AC3"
    text: "REQ-80: `atomic_write` `expect()` replaced with `?`; no `expect()`/`unwrap()` in production paths in `helpers.rs`."
  - id: "AC4"
    text: "REQ-81: `check_history_for_plaintext` added to `drift.rs`; `gitvault check` surfaces history leaks; bounded at `HISTORY_SCAN_LIMIT`; `--skip-history-check` escape hatch available."
  - id: "AC5"
    text: "REQ-82: backtick escaped as `` \\` `` and NUL replaced with `\\0` literal (with stderr warning) in `escape_env_value`."
  - id: "AC6"
    text: "REQ-83: `encrypt_armor` and `encrypt_binary_b64` reject more than `MAX_RECIPIENTS` (256) keys with `GitvaultError::Encryption`."
  - id: "AC7"
    text: "REQ-84: recipient key in error messages truncated to 8-char prefix + `…` via `truncate_key_for_log` helper."
  - id: "AC8"
    text: "REQ-85: `GITVAULT_TEST_CONFIRM` env hook removed from `barrier.rs`; affected tests use `check_prod_barrier_with_confirm` with closures; no `unsafe { set_var }` in test module."
  - id: "AC9"
    text: "REQ-86: `now_secs()` returns `Result<u64, GitvaultError>`; clock-before-epoch → explicit error; `has_valid_token` absorbs and warns; `allow_prod` propagates."
  - id: "AC10"
    text: "All existing tests pass (`cargo test --all`). No new panics in production code paths. `cargo clippy --all-targets --all-features -D warnings` clean."
verification:
  commands:
    - "cargo test --all-targets --all-features"
    - "cargo clippy --all-targets --all-features -D warnings"
risk:
  level: "high"
links:
  issue: ""
  pr: ""
---

## Context

A deep security analysis of the `gitvault` codebase identified 9 findings (numbered #3–#11 in the original report; findings #1 and #2 are addressed in plans 29 and 30). This plan covers all remaining findings across three severity tiers.

## Findings Summary

| # | Severity | Location | Finding | REQ |
|---|----------|----------|---------|-----|
| 3 | 🔴 HIGH | `armor.rs:53` | Decrypted `Vec<u8>` not zeroized | REQ-78 |
| 4 | 🔴 HIGH | `barrier.rs:127` | Prod allow token unsigned plain timestamp | REQ-79 |
| 5 | 🟠 MEDIUM | `helpers.rs:23` | `expect()` panic in `atomic_write` | REQ-80 |
| 6 | 🟠 MEDIUM | `repo/drift.rs:43` | Leak detection misses committed history | REQ-81 |
| 7 | 🟠 MEDIUM | `materialize.rs:83` | Backtick/NUL not escaped in `.env` output | REQ-82 |
| 8 | 🟠 MEDIUM | `armor.rs` | No recipient count limit (DoS) | REQ-83 |
| 9 | 🟡 LOW | `armor.rs:11` | Recipient key material in error messages | REQ-84 |
| 10 | 🟡 LOW | `barrier.rs:107` | `GITVAULT_TEST_CONFIRM` test env hook | REQ-85 |
| 11 | 🟡 LOW | `barrier.rs` | Clock failure silently swallowed | REQ-86 |

## Implementation Order

Priority is by severity then by implementation simplicity (lowest effort, highest impact first):

1. **REQ-80** (one line, `helpers.rs`) — replace `expect()` with `?`
2. **REQ-85** (refactor, `barrier.rs`) — remove `unsafe` env var hook
3. **REQ-82** (two lines, `materialize.rs`) — backtick + NUL escaping
4. **REQ-84** (one helper + two format strings, `armor.rs`) — truncate key in errors
5. **REQ-78** (type change + caller updates) — zeroize decrypted plaintext
6. **REQ-83** (one guard, `armor.rs` + `defaults.rs`) — recipient count limit
7. **REQ-86** (signature change, `barrier.rs`) — explicit clock error
8. **REQ-79** (new crypto primitives, `barrier.rs` + `Cargo.toml`) — HMAC token
9. **REQ-81** (new git invocation, `drift.rs`) — history scan

Steps 1–4 are independent and can be implemented in parallel. Steps 5–9 each have minor dependencies (noted below).

## Dependencies Between Changes

- REQ-78 must be implemented before or alongside any changes to callers in `fields.rs` to avoid double-touching the same functions.
- REQ-85 (barrier.rs refactor) should be implemented before REQ-86 (barrier.rs signature change) to reduce merge conflicts.
- REQ-79 depends on new crates (`hmac`, `sha2`, `subtle`) being added to `Cargo.toml` first.

## Conflict Analysis

| REQ | Potentially conflicting existing spec | Resolution |
|-----|--------------------------------------|------------|
| REQ-78 | REQ-40 (`fail-closed on decryption`) | No conflict — zeroize is additive; `Zeroizing<Vec<u8>>` is a `Deref<Target=Vec<u8>>` superset |
| REQ-79 | REQ-14 (`token expires automatically`) | No conflict — HMAC adds tamper-detection; expiry logic unchanged |
| REQ-79 | REQ-15 (`fail closed on barrier`) | No conflict — HMAC verification failure → invalid token → fail closed |
| REQ-80 | spec 11 AC1 (`writes are atomic`) | No conflict — atomicity is preserved; only panic→error conversion |
| REQ-81 | REQ-10 (`reject tracked plaintext`) | Additive: staged check unchanged; history check is a new, separate check |
| REQ-81 | REQ-50 (`preflight check`) | Additive: `gitvault check` output extended with `history_leaks` |
| REQ-82 | spec 11 (`secret values not printed by default`) | Aligned: improving output safety |
| REQ-83 | armor.rs `At least one recipient` guard | Additive: upper bound guard added alongside existing lower bound guard |
| REQ-84 | spec 11 (`logging audited to avoid disclosure`) | Aligned: implements the audit note already in spec 11 |
| REQ-85 | REQ-13/14/15 (`barrier tests`) | No conflict — test refactor only; production behaviour unchanged |
| REQ-86 | REQ-14 (`token expiry`) | Additive: makes expiry check explicit on clock failure instead of silently wrong |

**No existing spec is invalidated or contradicted by any of these changes.**

## New Cargo Dependencies (REQ-79 only)

```toml
hmac = "0.12"
sha2 = "0.10"
subtle = "2"
```

All are part of the RustCrypto ecosystem, well-audited, and `no_std` compatible. `subtle` provides constant-time comparison (`ConstantTimeEq`) to prevent timing side-channels in HMAC verification.

## Test Strategy

Each REQ spec contains its own test plan. Cross-cutting requirements:
- All existing tests must pass after every individual change (no regressions).
- `cargo clippy --all-targets --all-features -D warnings` must be clean after every change.
- REQ-80 and REQ-85 are purely refactoring — test count must not decrease.
- REQ-81 adds new integration tests that require a real git repository; these must run on all three platforms (Linux, macOS, Windows).

## Notes

This plan does not cover findings #1 and #2 (`GITVAULT_IDENTITY` and `GITVAULT_IDENTITY_PASSPHRASE` inline key exposure), which are addressed in plans 29 and 30 respectively.
