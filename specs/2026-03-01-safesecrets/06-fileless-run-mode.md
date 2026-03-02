---
id: "S-20260301-006"
title: "Fileless run mode and process environment injection"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-21..REQ-24: run command injects secrets into child environment without writing files, propagates exit code, and supports --no-prompt, --clear-env, --pass."
  - id: "AC2"
    text: "REQ-25: run --env prod requires production barrier."
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
Deployment and CI workflows require secrets injection without plaintext file materialization.

## Goal
Provide a secure `run` subcommand for environment injection and command execution.

## Non-goals
- Persistent shell session management.

## Constraints
- No plaintext file output may occur in `run` mode.

## Requirement Coverage
- REQ-21, REQ-22, REQ-23, REQ-24, REQ-25.

## Acceptance Criteria
- AC1: Child process receives expected vars with no plaintext files created.
- AC2: Prod execution is blocked without barrier satisfaction.

## Test Plan
- Integration tests around env inheritance, clear-env behavior, and exit code passthrough.

## Notes
Variable precedence and passthrough behavior must be documented and stable.

## Current Verification Status
cargo test --all passes. run subcommand injects env vars via src/run.rs without writing plaintext files; exit code propagated; prod barrier enforced.
