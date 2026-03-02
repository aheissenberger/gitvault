---
id: "S-20260302-026"
title: "Plan: Optional user-global config layer at ~/.config/gitvault/config.toml"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-ui", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md", "docs/**"]
  touch: ["src/config.rs", "src/commands/**", "src/cli.rs", "README.md", "docs/development.md", "specs/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-68: Gitvault supports optional user-global config at ~/.config/gitvault/config.toml with no behavior change when absent."
  - id: "AC2"
    text: "REQ-68: Effective configuration precedence is deterministic as CLI/env > repo > global > defaults."
  - id: "AC3"
    text: "REQ-68: Unknown keys/invalid values are Usage errors and deterministic automation behavior remains unchanged."
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
REQ-67 established `.gitvault/config.toml` as canonical repository-level configuration. Users also need optional personal defaults that do not override repository policy or weaken CI determinism.

## Goal
Define a strict, deterministic two-file configuration model where user-global config is a fallback layer only.

## Non-goals
- Replacing repository-level canonical config.
- Introducing manager-specific auto-discovery from third-party config files.
- Adding interactive-only resolution logic.

## Constraints
- Repo config remains canonical for project policy.
- Precedence order is fixed and deterministic.
- Worktree isolation, fail-closed behavior, and non-interactive CI contracts remain unchanged.
- Parser behavior follows strict schema validation with actionable `Usage` diagnostics.

## Requirement Coverage
- REQ-68.

## Acceptance Criteria
- AC1: Optional global file path and absence behavior are explicitly specified.
- AC2: Deterministic precedence order is specified and testable.
- AC3: Strict unknown-key/invalid-value behavior and automation determinism are specified.

## Test Plan
- Spec verification for schema compliance.
- Unit tests for all precedence combinations and absent-file behavior.
- Unit tests for unknown keys/invalid values in both repo and global config.
- Integration tests for CI/`--no-prompt` deterministic behavior with mixed config layers.

## Implementation-facing Acceptance Scenarios
- Scenario G1 (no global file): Given `~/.config/gitvault/config.toml` is absent, when command runs, then current repo/default behavior is unchanged.
- Scenario G2 (global fallback): Given only global config defines a key, when command runs, then that value is applied.
- Scenario G3 (repo overrides global): Given both files define the same key, when command runs, then repo value wins.
- Scenario G4 (CLI/env overrides both): Given CLI/env supplies the key, when command runs, then CLI/env value wins.
- Scenario G5 (strict validation): Given unknown key/invalid value in either file, when command runs, then command fails with `Usage` and actionable diagnostics.
- Scenario G6 (worktree determinism): Given multiple worktrees sharing one home directory, when commands run independently, then effective values resolve deterministically without cross-worktree side effects.

## Notes
This plan extends configuration layering while preserving REQ-67 canonical repository config semantics.
