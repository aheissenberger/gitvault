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
  - id: "AC4"
    text: "REQ-59 (NFR): external dependencies are mockable in tests using `mockall` (e.g., AWS SDK/SSM clients), avoiding mandatory live cloud calls in non-integration test paths."
  - id: "AC5"
    text: "REQ-60 (NFR): platform-specific security behavior is validated in CI, including Windows ACL enforcement for secret files."
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
- NFR testability rule (REQ-59): external/service dependencies expose mockable boundaries and are validated with `mockall` in automated tests.
- NFR platform-security rule (REQ-60): Windows lanes validate ACL restriction behavior for secret material paths.

## Acceptance Criteria
- AC1: CI matrix is defined with platform parity.
- AC2: Each required scenario is represented by at least one automated test/integration job.
- AC3: Rust source files meet full line coverage in CI.
- AC4: External cloud/service interactions are testable via `mockall`-based mocks without requiring live infrastructure for standard test runs.
- AC5: Windows CI coverage includes assertions for ACL-based permission restriction behavior.

## Test Plan
- Add/maintain workflow matrix and scenario-specific integration tasks.
- Enforce Rust coverage gate with `cargo llvm-cov` at 100% line coverage.
- Add trait-boundary tests that use `mockall` for AWS-facing paths (including SSM workflows) and keep live-cloud checks in dedicated integration/e2e lanes.
- Add Windows-runner checks that assert ACL restriction outcomes for generated `.env`/materialized secret files.

## Notes
This file captures the matrix section from the consolidated source document.

## Current Verification Status
- AC1 and AC2 are implemented in CI workflow definitions and scenario coverage; 206 unit tests + 6 integration tests passing.
- AC3 remains open until `cargo llvm-cov --workspace --all-features --fail-under-lines 100` passes in CI.
- Latest local verification snapshot (2026-03-02) reports total Rust line coverage at `93.72% line / 95.63% region`, below the `100%` gate.
- Tracking item (REQ-18): expand CI verification for Windows `.env` ACL behavior (currently implemented via `icacls` but not fully validated by automated Windows permission assertions).
- REQ-60 is defined as the NFR umbrella for this platform-specific ACL verification work; CI expansion remains in progress.
