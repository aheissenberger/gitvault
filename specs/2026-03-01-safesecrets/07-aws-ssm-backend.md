---
id: "S-20260301-007"
title: "Optional AWS SSM backend"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-26..REQ-28: backend selection supports vault or ssm, references-only repository storage in ssm mode, and pull/diff/set/push operations."
  - id: "AC2"
    text: "REQ-29 and REQ-30: SSM writes require production barrier and diffs avoid value disclosure unless --reveal is set."
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
Production-grade teams may store secrets in AWS SSM while keeping Git as reference state.

## Goal
Implement optional SSM synchronization workflows with secure diff and write controls.

## Non-goals
- Mandatory cloud dependency for all environments.

## Constraints
- Repository storage must contain references only when backend is `ssm`.

## Requirement Coverage
- REQ-26, REQ-27, REQ-28, REQ-29, REQ-30.

## Acceptance Criteria
- AC1: SSM commands function for SecureString references and synchronization.
- AC2: Secret values are redacted by default in diffs.

## Test Plan
- Mocked and integration tests for SSM API interactions and reveal/redact behavior.

## Notes
Authentication should support profile and role assumptions through shared config.
