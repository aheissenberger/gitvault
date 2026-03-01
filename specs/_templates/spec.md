---
id: "S-YYYYMMDD-001"
title: "Short human title"
status: "draft" # draft|active|done|archived
owners: ["@you"]
mode: ["vscode-ui", "vscode-bg", "cli"] # execution targets
scope:
  repoAreas: ["crate_a", "crates/*", "apps/*"]
  touch: ["src/**", "tests/**"]
  avoid: ["**/generated/**", "**/vendor/**"]
acceptance:
  - id: "AC1"
    text: "Given ..., when ..., then ..."
  - id: "AC2"
    text: "`cargo test` passes"
verification:
  commands:
    - "cargo fmt --check"
    - "cargo clippy --all-targets --all-features -D warnings"
    - "cargo test --all"
risk:
  level: "low" # low|medium|high
links:
  issue: ""
  pr: ""
---

## Context
What problem are we solving?

## Goal
What is the desired outcome?

## Non-goals
What is explicitly not part of this?

## Constraints
Perf, security, compatibility, “do not touch”.

## Acceptance Criteria
- AC1: …
- AC2: …

## Test Plan
Exact commands + expected outcomes.

## Notes
Anything else that helps an agent not drift.