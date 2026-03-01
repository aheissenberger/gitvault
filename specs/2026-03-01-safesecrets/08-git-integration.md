---
id: "S-20260301-008"
title: "Git hardening and drift checks"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**", ".gitignore", ".git/hooks/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-31: harden command updates gitignore, installs pre-commit hook, and installs pre-push drift checks."
  - id: "AC2"
    text: "REQ-32: status --fail-if-dirty fails in CI/automation when drift exists."
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
Repository-level safety controls must be enforceable and easy to apply.

## Goal
Provide first-class hardening and drift detection integrated with Git workflows.

## Non-goals
- Merge-driver configuration internals.

## Constraints
- Hooks must be idempotent and safely reinstallable.

## Requirement Coverage
- REQ-31, REQ-32.

## Acceptance Criteria
- AC1: Harden creates required ignore and hook protections.
- AC2: Dirty status detection is script-friendly and deterministic.

## Test Plan
- End-to-end tests in disposable repos validating hook behavior.

## Notes
Hook scripts should degrade gracefully when tool binary is unavailable.
