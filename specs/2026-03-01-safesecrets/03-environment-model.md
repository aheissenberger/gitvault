---
id: "S-20260301-003"
title: "Environment resolution and worktree isolation"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-11: environment resolution priority is SECRETS_ENV, then .secrets/env, then default dev."
  - id: "AC2"
    text: "REQ-12: each worktree resolves environments independently without cross-contamination."
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
Concurrent multi-worktree development requires independent environment selection.

## Goal
Implement deterministic and isolated environment resolution.

## Non-goals
- Production barrier and auth workflows.

## Constraints
- Resolution order is normative and immutable unless explicitly configured.

## Requirement Coverage
- REQ-11, REQ-12.

## Acceptance Criteria
- AC1: Priority resolution behaves exactly as specified.
- AC2: Two worktrees can run with different active environments concurrently.

## Test Plan
- Multi-worktree simulation tests with independent `.secrets/env` files.

## Notes
Environment state should be resolved from current working tree root.
