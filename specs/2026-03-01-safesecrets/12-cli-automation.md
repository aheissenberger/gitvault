---
id: "S-20260301-012"
title: "CLI automation contracts"
status: "active"
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
  - id: "AC4"
    text: "Identity source selection is script-safe: precedence is deterministic and any SSH-agent multi-key ambiguity requires explicit key selection (no implicit interactive pick)."
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
- Identity source behavior must remain deterministic for automation and CI usage.
- `--no-prompt` mode must fail clearly when identity selection is ambiguous.
- Explicit agent-key selector contract: `--identity-selector <value>` and `GITVAULT_IDENTITY_SELECTOR`; CLI flag wins over env var.

## Requirement Coverage
- REQ-45, REQ-46, REQ-47.

## Acceptance Criteria
- AC1: Every command path supports parseable JSON output.
- AC2: Exit code table exists and remains backward compatible.
- AC3: `--keep-path` and bare `--output` parsing remain stable in CLI tests.
- AC4: Identity precedence and explicit ambiguity handling are enforced in non-interactive paths.

## Test Plan
- Contract tests validating output schemas and exit statuses.
- CLI parsing tests for `encrypt --keep-path` and `decrypt --output` (no value).
- CLI tests for deterministic identity precedence and ambiguous SSH-agent key failure behavior.

## Notes
Documented exit codes should include security and policy failures.
Identity precedence and selector semantics in this file are automation contracts for REQ-46 and are cross-referenced by REQ-48/REQ-50 runtime behavior.
