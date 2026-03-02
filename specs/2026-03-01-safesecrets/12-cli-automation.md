---
id: "S-20260301-012"
title: "CLI automation contracts"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**", "README.md"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-45 and REQ-46: all commands support --json and --no-prompt consistently."
  - id: "AC2"
    text: "REQ-47: exit codes are stable and documented."
  - id: "AC3"
    text: "CLI path flags are stable: `encrypt --keep-path` preserves repo-relative paths under `secrets/<env>/...`; `decrypt --output <path>` overrides target; bare `decrypt --output` enables repo-relative restore from `secrets/<env>/...`."
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
Automation requires stable machine-oriented interfaces.

## Goal
Define command behavior contracts for scripts, CI, and other tooling.

## Non-goals
- Backend-specific implementation details.

## Constraints
- JSON and non-interactive behavior must be universal across commands.
- Path-flag parsing must be deterministic and backward compatible for automation.

## Requirement Coverage
- REQ-45, REQ-46, REQ-47.

## Acceptance Criteria
- AC1: Every command path supports parseable JSON output.
- AC2: Exit code table exists and remains backward compatible.
- AC3: `--keep-path` and bare `--output` parsing remain stable in CLI tests.

## Test Plan
- Contract tests validating output schemas and exit statuses.
- CLI parsing tests for `encrypt --keep-path` and `decrypt --output` (no value).

## Notes
Documented exit codes should include security and policy failures.
