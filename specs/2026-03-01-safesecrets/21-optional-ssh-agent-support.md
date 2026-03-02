---
id: "S-20260302-021"
title: "Plan: Optional SSH-agent support"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md"]
  touch: ["src/identity.rs", "src/fhsm.rs", "src/commands/**", "src/cli.rs", "src/dispatch.rs", "README.md", "specs/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC0"
    text: "Identity creation profiles support `classic` and `hybrid`, and selector behavior remains deterministic regardless of profile."
  - id: "AC1"
    text: "SSH-agent is an optional identity source after keyring; explicit sources (`--identity`, `GITVAULT_IDENTITY`) remain higher precedence."
  - id: "AC2"
    text: "When ssh-agent exposes zero usable keys, behavior is fail-closed after evaluating all configured sources."
  - id: "AC3"
    text: "When ssh-agent exposes multiple usable keys and no explicit selector is provided, behavior is fail-closed with explicit ambiguity diagnostics."
  - id: "AC4"
    text: "Selector contract is deterministic (`--identity-selector` over `GITVAULT_IDENTITY_SELECTOR`) and applies consistently in interactive and CI modes."
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
Automation-safe support for ssh-agent requires strict selection semantics to avoid accidental decryption under the wrong identity.

## Goal
Add optional ssh-agent support and profile-aware identity creation behavior without sacrificing determinism, safety, or CI compatibility.

## Non-goals
- Interactive chooser UX for selecting one of many agent keys.
- Implicit best-match or first-match key selection.

## Constraints
- All behavior must be script-safe and reproducible.
- Ambiguity and missing identity cases must fail closed.
- Source-state and precedence decisions must be observable in check-mode output.
- Classic and hybrid profile identities must share the same fail-closed ambiguity semantics for agent-backed resolution.

## Requirement Coverage
- REQ-39, REQ-46, REQ-48, REQ-50, REQ-63.

## Acceptance Criteria
- AC0: Classic and hybrid identities are both valid for deterministic selector/source handling.
- AC1: Optional source ordering is consistent with existing precedence rules.
- AC2: Zero/multiple usable key scenarios produce deterministic fail-closed outcomes.
- AC3: Selector precedence and diagnostics are stable across command paths.

## Test Plan
- Profile compatibility tests for classic/hybrid identities under identical selector and ambiguity conditions.
- Unit tests for agent key discovery and ambiguity handling.
- Integration tests for command-path coverage (decrypt/materialize/run/check/rotate/recipient).
- CI tests ensuring no prompts and deterministic error contracts.

## Notes
This plan-spec formalizes optional ssh-agent support as an additive source, not a replacement for explicit identity inputs.
