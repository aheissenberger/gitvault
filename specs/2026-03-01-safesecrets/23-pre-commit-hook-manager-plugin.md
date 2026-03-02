---
id: "S-20260302-023"
title: "Plan: pre-commit hook manager plugin integration"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-ui", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md", "docs/**"]
  touch: ["src/repo/**", "src/commands/**", "src/cli.rs", "README.md", "docs/development.md", "specs/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-65: Gitvault supports pre-commit via plugin architecture #1 (external command plugin), permitting post-install adapter enablement without rebuilding the core binary."
  - id: "AC2"
    text: "REQ-65: pre-commit integration guarantees enforcement parity for plaintext staged-content prevention and pre-push drift checks."
  - id: "AC3"
    text: "REQ-65: Plugin invocation contracts are deterministic in CI/--no-prompt mode and return stable machine-parseable failure outcomes when adapter/runtime prerequisites are missing."
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
Many repositories standardize on Python-based `pre-commit`; Gitvault must integrate safely without forcing Python tooling into the core package.

## Goal
Specify `pre-commit` integration through an optional external command adapter with deterministic contracts.

## Non-goals
- Managing `pre-commit` virtual environments.
- Auto-modifying user-maintained `.pre-commit-config.yaml` content beyond explicit integration paths.

## Constraints
- Automation behavior must not rely on interactive prompts.
- Existing hardening checks remain mandatory regardless of manager.
- Adapter installation is optional and decoupled from core shipment.

## Common Adapter Contract (Normative)
- Adapter integration is additive to REQ-31 hardening protections and does not remove existing safety guarantees.
- Manager mode selection is deterministic: manager configuration + discoverable adapter enables manager integration path.
- In CI/`--no-prompt`, missing adapter/runtime prerequisites fail deterministically with actionable diagnostics.
- Failure signaling must remain machine-consumable and aligned with existing automation contracts (REQ-47/REQ-48), without requiring new exit-code semantics in this requirement.
- Repeated harden/status/integration checks are idempotent and must not duplicate managed hook content.

## Requirement Coverage
- REQ-65.

## Acceptance Criteria
- AC1: Install-later adapter contract is defined for `pre-commit`.
- AC2: Existing hardening protections are preserved under manager orchestration.
- AC3: Failure and diagnostics remain deterministic in non-interactive execution.

## Test Plan
- Spec verification for schema compliance.
- Integration tests covering adapter discovery, missing runtime handling, and deterministic error contracts.
- Regression coverage for plaintext and drift enforcement paths.

## Implementation-facing Acceptance Scenarios
- Scenario P1 (discovery success): Given `.pre-commit-config.yaml` integration entry and adapter on PATH, when integration check runs, then adapter is selected deterministically.
- Scenario P2 (missing python/runtime in CI): Given adapter or Python runtime prerequisites are unavailable, when run in CI/`--no-prompt`, then failure is machine-parseable and includes remediation steps.
- Scenario P3 (install-later activation): Given core was shipped without adapter, when adapter is installed later, then next run enables manager integration without recompiling gitvault.
- Scenario P4 (pre-commit parity): Given staged plaintext secret content, when `pre-commit` invokes gitvault check hook, then commit is blocked with stable diagnostics.
- Scenario P5 (pre-push parity): Given drift condition is present, when push hook chain executes through `pre-commit` configuration, then push is rejected with deterministic output.
- Scenario P6 (config preservation): Given existing user-managed `.pre-commit-config.yaml`, when integration validation runs, then no silent destructive rewrite occurs.
- Scenario P7 (repeatability): Given repeated harden/status execution, when environment is unchanged, then outputs and exit codes remain stable.

## Notes
This plan inherits plugin architecture #1 to avoid Rust ABI coupling and simplify distribution.
