---
id: "S-20260302-024"
title: "Plan: lefthook manager plugin integration"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-ui", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md", "docs/**"]
  touch: ["src/repo/**", "src/commands/**", "src/cli.rs", "README.md", "docs/development.md", "specs/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-66: Gitvault supports lefthook via plugin architecture #1 (external command plugin), enabling optional adapter installation after core release."
  - id: "AC2"
    text: "REQ-66: lefthook integration preserves security parity with existing pre-commit plaintext prevention and pre-push drift gating behavior."
  - id: "AC3"
    text: "REQ-66: Integration remains idempotent and deterministic across repeated harden/status checks, including absent-adapter diagnostics in CI/--no-prompt mode."
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
`lefthook` is frequently used in polyglot repositories and should be supported without inflating the core binary with manager-specific runtime dependencies.

## Goal
Define `lefthook` support as an optional external command adapter, preserving deterministic safety contracts.

## Non-goals
- Building custom task orchestration features beyond hook integration.
- Replacing native lefthook configuration semantics.

## Constraints
- Integration logic must remain idempotent.
- Core binary remains operational without adapter presence.
- All automation-mode behavior is deterministic and non-interactive.

## Common Adapter Contract (Normative)
- Adapter integration is additive to REQ-31 hardening protections and does not remove existing safety guarantees.
- Manager mode selection is deterministic: effective gitvault config (`.gitvault/config.toml` with optional user-global fallback per REQ-68) + discoverable adapter enables manager integration path.
- In CI/`--no-prompt`, missing adapter/runtime prerequisites fail deterministically with actionable diagnostics.
- Failure signaling must remain machine-consumable and aligned with existing automation contracts (REQ-47/REQ-48), without requiring new exit-code semantics in this requirement.
- Repeated harden/status/integration checks are idempotent and must not duplicate managed hook content.

## Requirement Coverage
- REQ-66.

## Acceptance Criteria
- AC1: Install-later adapter path exists for `lefthook` under external command plugin architecture.
- AC2: Existing hardening security outcomes remain unchanged.
- AC3: Repeated runs and missing-adapter scenarios produce stable outcomes.

## Test Plan
- Spec verification for schema compliance.
- Integration tests for adapter lifecycle detection and deterministic diagnostics.
- Regression tests for plaintext and drift protections under `lefthook` orchestration.

## Implementation-facing Acceptance Scenarios
- Scenario L1 (selection success): Given effective gitvault config selects `lefthook` and adapter is available, when integration check runs, then adapter is selected deterministically.
- Scenario L2 (install-later activation): Given core binary is already installed, when adapter is later installed or updated, then next run uses it without core rebuild.
- Scenario L3 (missing adapter in automation): Given effective gitvault config selects `lefthook` but adapter is missing, when run in CI/`--no-prompt`, then failure contract is deterministic with install guidance.
- Scenario L4 (pre-commit parity): Given staged plaintext secret material, when lefthook pre-commit pipeline executes gitvault checks, then commit is blocked.
- Scenario L5 (pre-push parity): Given drift is detected, when lefthook pre-push pipeline executes gitvault checks, then push is blocked.
- Scenario L6 (idempotency): Given stable repo/configuration, when harden/status and manager checks are run repeatedly, then no duplicate managed sections or divergent outputs appear.
- Scenario L7 (manager coexistence): Given existing non-gitvault lefthook tasks, when gitvault adapter is added, then unrelated tasks remain unaffected.

## Notes
This plan intentionally standardizes on plugin architecture #1 for simplicity and packaging safety.
