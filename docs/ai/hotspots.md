# Architecture Hotspots

Curated from the 2026-03-01 multi-agent review so future agents can jump directly to high-value areas.

## Top Architecture Issues

- `src/repo.rs` is a god-module (~900+ lines, 15+ public functions). Candidate split:
  - `src/repo/paths.rs`
  - `src/repo/hooks.rs`
  - `src/repo/drift.rs`
  - `src/repo/recipients.rs`
- `src/commands/test_helpers.rs` is not `#[cfg(test)]`-gated and may compile into production surfaces.
- `src/error.rs`: `GitvaultError::Drift` currently maps to plaintext-leak semantics; introduce a dedicated drift exit code.
- `src/error.rs`: missing `From<FhsmError> for GitvaultError` leads to repeated `.map_err(...)` boilerplate.
- Public API docs are incomplete across multiple command entrypoints.

## Critical Bugs (Security / Data Loss)

- `--pass` handling mismatch in `src/fhsm.rs` can silently drop env vars.
- Recipient rotation can leave mixed-key state on partial failure (`src/commands/recipients.rs`).
- Pre-commit bypass gap for first-time staged plaintext (`src/repo.rs`).
- Path-traversal guard bypass in certain in-place write paths (`src/commands/encrypt.rs`, `src/commands/decrypt.rs`).
- Potential stale-ciphertext corruption path around env value handling (`src/structured/env_values.rs`).
- Identity key material handling should enforce secrecy semantics (`src/identity.rs`).
- Windows materialization TOCTOU around ACL timing (`src/materialize.rs`, `src/barrier.rs`).
- SSM push currently risks silent partial success on missing inputs (`src/ssm.rs`).

## How to Use This File

- Treat this as prioritization guidance, not proof.
- Confirm behavior with targeted tests before patching.
- Keep updates short and factual; this file is for rapid handoff.
