---
id: "S-20260301-015"
title: "Cross-platform testing matrix"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: [".github/workflows/**", "src/**"]
  touch: [".github/workflows/**", "README.md"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "Matrix includes macOS, Linux, and Windows with consistent pass criteria."
  - id: "AC2"
    text: "Scenarios include multi-worktree, parallel edits, merge conflicts, CI run mode, prod barrier, SSM integration, key rotation, and drift detection."
  - id: "AC3"
    text: "All Rust source files (`*.rs`) are covered by automated tests with full line coverage."
verification:
  commands:
    - "cargo test --all"
    - "cargo llvm-cov --workspace --all-features --fail-under-lines 100"
risk:
  level: "medium"
links:
  issue: ""
  pr: ""
---

## Context
The requirements define explicit platform and scenario coverage expectations.

## Goal
Convert the testing matrix statement into an executable test planning artifact.

## Non-goals
- Defining every single unit test case.

## Constraints
- Matrix should be realizable in CI with deterministic jobs.

## Coverage Scope
- Platform set: macOS, Linux, Windows.
- Scenario set: multi-worktree, parallel edits, merge conflicts, CI run mode, production barrier, SSM integration, key rotation, drift detection.
- Language coverage rule: Rust files (`*.rs`) require full line coverage by automated tests.

## Acceptance Criteria
- AC1: CI matrix is defined with platform parity.
- AC2: Each required scenario is represented by at least one automated test/integration job.
- AC3: Rust source files meet full line coverage in CI.

## Test Plan
- Add/maintain workflow matrix and scenario-specific integration tasks.
- Enforce Rust coverage gate with `cargo llvm-cov` at 100% line coverage.

## Notes
This file captures the matrix section from the consolidated source document.

## Current Verification Status
- AC1 and AC2 are implemented in CI workflow definitions and scenario coverage.
- AC3 remains open until `cargo llvm-cov --workspace --all-features --fail-under-lines 100` passes in CI.
- Latest local verification snapshot reports total Rust line coverage at `95.43%`, below the `100%` gate.
