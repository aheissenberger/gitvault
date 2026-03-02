---
id: "S-20260302-022"
title: "Plan: Husky hook manager plugin integration"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-ui", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md", "docs/**"]
  touch: ["src/repo/**", "src/commands/**", "src/cli.rs", "README.md", "docs/development.md", "specs/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-64: Gitvault supports Husky via plugin architecture #1 (external command plugin), allowing core shipping without Husky adapter binaries and later installation without recompiling core."
  - id: "AC2"
    text: "REQ-64: Husky integration preserves existing protection parity: plaintext staged-content block on pre-commit and drift gate on pre-push."
  - id: "AC3"
    text: "REQ-64: Missing Husky plugin in non-interactive/CI mode fails deterministically with actionable install guidance and no prompts."
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
Gitvault hardening must interoperate with Husky while keeping the core binary minimal and independently shippable.

## Goal
Define Husky integration as an optional external command plugin that can be installed after core release without changing core behavior guarantees.

## Non-goals
- Auto-installing Node.js or Husky.
- Replacing existing direct hook-hardening flows.

## Constraints
- External command plugin discovery must be deterministic.
- CI and `--no-prompt` flows must remain non-interactive.
- Existing safety checks remain authoritative.

## Common Adapter Contract (Normative)
- Adapter integration is additive to REQ-31 hardening protections and does not remove existing safety guarantees.
- Manager mode selection is deterministic: manager configuration + discoverable adapter enables manager integration path.
- In CI/`--no-prompt`, missing adapter/runtime prerequisites fail deterministically with actionable diagnostics.
- Failure signaling must remain machine-consumable and aligned with existing automation contracts (REQ-47/REQ-48), without requiring new exit-code semantics in this requirement.
- Repeated harden/status/integration checks are idempotent and must not duplicate managed hook content.

## Requirement Coverage
- REQ-64.

## Acceptance Criteria
- AC1: Optional install-later Husky adapter contract is defined using external command plugin architecture.
- AC2: Pre-commit and pre-push protections retain parity with existing hardening guarantees.
- AC3: Missing adapter path produces deterministic error contracts in automation contexts.

## Test Plan
- Spec verification for schema compliance.
- Integration tests validating Husky adapter discovery and deterministic missing-adapter behavior.
- Regression tests confirming plaintext and drift protections remain enforced.

## Implementation-facing Acceptance Scenarios
- Scenario H1 (discovery success): Given Husky is configured and adapter binary is on PATH, when `harden` or manager integration check runs, then adapter is discovered and selected without prompts.
- Scenario H2 (install-later flow): Given core is installed without Husky adapter, when adapter is installed later and command is re-run, then integration activates without core rebuild.
- Scenario H3 (missing adapter in CI): Given Husky config exists and adapter is missing, when run with `--no-prompt` or CI env, then command fails with stable exit code and actionable install message.
- Scenario H4 (pre-commit parity): Given staged plaintext secret material, when Husky pre-commit path invokes gitvault checks, then commit is blocked with deterministic diagnostics.
- Scenario H5 (pre-push parity): Given repository drift relative to protected expectations, when Husky pre-push path invokes gitvault checks, then push is blocked deterministically.
- Scenario H6 (idempotent repeats): Given integration already configured, when hardening/check commands run repeatedly, then outcomes and managed markers remain stable and non-duplicative.
- Scenario H7 (explicit override precedence): Given explicit identity/config flags are provided, when Husky plugin path executes, then existing precedence and safety semantics remain unchanged.

## Notes
This plan intentionally selects plugin pattern #1 (external command plugins) as the default architecture.
