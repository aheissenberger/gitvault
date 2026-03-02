---
id: "S-20260302-019"
title: "Plan: SSH identity requirements"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md"]
  touch: ["src/identity.rs", "src/fhsm.rs", "src/commands/**", "src/cli.rs", "src/dispatch.rs", "README.md", "specs/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC0"
    text: "An `identity` command section includes `identity create` with explicit profile selection: `--profile classic|hybrid`."
  - id: "AC1"
    text: "Identity resolution precedence is deterministic: `--identity -> GITVAULT_IDENTITY -> keyring -> ssh-agent (optional)` across all identity-consuming command paths."
  - id: "AC2"
    text: "If multiple usable ssh-agent keys are present without explicit selector, command execution fails closed with actionable diagnostics."
  - id: "AC3"
    text: "A usable key and source-state outcomes (`resolved`, `source-not-available`, `ambiguous`) are defined consistently for runtime and check-mode output."
verification:
  commands:
    - "cargo xtask spec-verify"
    - "cargo test --all-targets --all-features"
risk:
  level: "high"
links:
  issue: ""
  pr: ""
---

## Context
Current identity behavior and newer plan requirements must be unified into one deterministic contract across CLI and CI paths.

## Goal
Codify SSH identity source behavior and identity creation command contracts, including selector/ambiguity policy and fail-closed semantics.

## Non-goals
- Replacing existing keyring command semantics (`set/get/delete`).
- Changing AWS/SSM backend behavior.

## Constraints
- No implicit key picking from ssh-agent.
- Non-interactive mode must not prompt for identity selection.
- Contract must remain backward-compatible for explicit `--identity` and `GITVAULT_IDENTITY` usage.
- `identity create --profile hybrid` must produce hybrid-PQ-capable identity material and stable machine-readable metadata.
- `identity create --profile classic` remains available for compatibility workflows.

## Requirement Coverage
- REQ-39, REQ-46, REQ-48, REQ-50, REQ-61.

## Acceptance Criteria
- AC0: `identity create` exists with `classic` and `hybrid` profile options.
- AC1: Deterministic source precedence applies to all identity-consuming command paths.
- AC2: Ambiguous ssh-agent key sets fail closed unless explicit selection is provided.
- AC3: Source-state reporting is deterministic and machine-readable.

## Test Plan
- Command-contract tests for `identity create --profile classic|hybrid` and output metadata.
- Unit tests for precedence and ambiguity handling.
- Integration tests for decrypt/materialize/run/check/rotate/recipient flows.
- CI non-interactive tests validating fail-closed outcomes.

## Notes
This plan-spec is additive and cross-references existing REQ-level specs rather than redefining REQ IDs.
