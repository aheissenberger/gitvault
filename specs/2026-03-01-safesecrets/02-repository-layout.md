---
id: "S-20260301-002"
title: "Repository layout and tracked plaintext protection"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**", ".gitignore"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-7..REQ-9: encrypted artifacts are under secrets/, plaintext materialization is under .secrets/plain/<env>/, and root .env is generated and gitignored."
  - id: "AC2"
    text: "REQ-10: tool fails closed when plaintext secrets are detected in tracked paths."
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
Repository layout must enforce separation between encrypted and plaintext artifacts.

## Goal
Ensure plaintext cannot be accidentally committed and layout is consistent across environments.

## Non-goals
- Runtime process injection behavior.

## Constraints
- Detection checks must be reliable against Git tracked state.

## Requirement Coverage
- REQ-7, REQ-8, REQ-9, REQ-10.

## Acceptance Criteria
- AC1: Paths and outputs match required directories.
- AC2: `status` or equivalent hard-fails on tracked plaintext.

## Test Plan
- Integration tests using temporary Git repos with staged plaintext files.

## Notes
Validation should use Git plumbing commands for deterministic results.
