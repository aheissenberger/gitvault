---
id: "S-20260301-016"
title: "Release signing and deterministic versioning"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: [".github/workflows/**", "src/**"]
  touch: [".github/workflows/**", "README.md", "src/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-54: release artifacts are signed and signature metadata is publishable/verifyable."
  - id: "AC2"
    text: "REQ-55: format/version identifiers are deterministic and backward-compatible."
  - id: "AC3"
    text: "REQ-58 (NFR): final release binaries are stripped and only include platform-available code paths/features for the target platform."
verification:
  commands:
    - "cargo test --all"
risk:
  level: "medium"
links:
  issue: ""
  pr: ""
---

## Context
Release integrity requirements protect downstream trust in distributed binaries and encrypted format behavior.

## Goal
Define artifact signing, deterministic format version controls, and minimal platform-specific release binaries.

## Non-goals
- Distribution channel marketing/release notes.

## Constraints
- Signing should integrate into release automation and support verification.
- Release builds should compile and strip per target platform, excluding unsupported platform-specific code paths.

## Requirement Coverage
- REQ-54, REQ-55, REQ-58.

## Acceptance Criteria
- AC1: Signed artifacts are emitted in release workflows.
- AC2: Format versioning is explicit, deterministic, and test-covered.
- AC3: Release artifacts are stripped and platform-scoped to target-available features/code.

## Test Plan
- CI release dry-run checks and version compatibility tests.

## Notes
Version bumps should be intentional and governed by compatibility policy.
Binary size and symbol-table checks should be part of release verification.
