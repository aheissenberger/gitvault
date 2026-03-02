---
id: "S-20260302-020"
title: "Plan: Optional keyring passphrase fetch"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md"]
  touch: ["src/keyring_store.rs", "src/identity.rs", "src/commands/keyring.rs", "src/commands/**", "README.md", "specs/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC0"
    text: "`identity create` is keyring-first by default and supports optional file export via `--out <path>`."
  - id: "AC1"
    text: "Optional passphrase-fetch from keyring is supported for identity-loading paths without regressing existing keyring `set/get/delete` behavior."
  - id: "AC2"
    text: "Unavailable/locked keyring is treated as `source-not-available`; identity resolution continues by precedence and fails closed if unresolved."
  - id: "AC3"
    text: "No prompt behavior is explicit: `--no-prompt`/CI mode never blocks on keyring interaction and surfaces actionable diagnostics."
verification:
  commands:
    - "cargo xtask spec-verify"
    - "cargo test --all-targets --all-features"
risk:
  level: "medium"
links:
  issue: ""
  pr: ""
---

## Context
Keyring integration exists but optional passphrase-fetch behavior needs a clear contract for runtime and automation contexts.

## Goal
Define safe, deterministic keyring integration for identity creation and optional passphrase-fetch semantics for identity loading and CI usage.

## Non-goals
- Changing keyring service naming or platform backend selection.
- Introducing interactive keyring setup flows in CI paths.

## Constraints
- Existing keyring command UX remains stable.
- Runtime and check-mode must report consistent source-state outcomes.
- Keyring-first create must not print secret identity material by default.
- Optional `--out` artifacts must use restrictive file permissions.

## Requirement Coverage
- REQ-39, REQ-46, REQ-48, REQ-50, REQ-62.

## Acceptance Criteria
- AC0: Identity creation stores into keyring by default and supports optional file output.
- AC1: Optional passphrase-fetch integrates with current keyring contracts.
- AC2: Locked/unavailable keyring degrades deterministically to `source-not-available`.
- AC3: Non-interactive behavior remains fail-closed and script-safe.

## Test Plan
- Tests for keyring-first creation, optional `--out`, and permission hardening.
- Unit tests for keyring fetch success, locked store, unavailable backend.
- Integration tests for identity loading fallback behavior.
- Check-mode tests for source-state diagnostics.

## Notes
This plan-spec keeps keyring storage optional but first-class in deterministic identity resolution.
