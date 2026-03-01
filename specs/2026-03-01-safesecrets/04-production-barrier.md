---
id: "S-20260301-004"
title: "Production barrier enforcement"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-13: prod access requires --env prod, --prod, and valid allow token or explicit interactive confirmation."
  - id: "AC2"
    text: "REQ-14 and REQ-15: allow token expires automatically and operations fail closed if any barrier condition is unmet."
verification:
  commands:
    - "cargo test --all"
risk:
  level: "high"
links:
  issue: ""
  pr: ""
---

## Context
Production secrets require stricter controls than non-production environments.

## Goal
Enforce explicit multi-signal authorization for prod materialization and runtime use.

## Non-goals
- Non-prod behavior hardening beyond baseline auth checks.

## Constraints
- Fail-closed semantics are mandatory.

## Requirement Coverage
- REQ-13, REQ-14, REQ-15.

## Acceptance Criteria
- AC1: Missing any required flag or authorization blocks prod access.
- AC2: Expired or absent token cannot be reused.

## Test Plan
- Barrier matrix tests for all combinations of env/flags/token states.

## Notes
Token storage and expiry validation must be deterministic and auditable.
