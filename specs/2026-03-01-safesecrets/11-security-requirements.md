---
id: "S-20260301-011"
title: "Security failure modes and write guarantees"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-40..REQ-43: decryption failures fail closed, secret values are not printed by default, path traversal is prevented, and writes are atomic."
  - id: "AC2"
    text: "REQ-44: status checks avoid unnecessary decryption."
  - id: "AC3"
    text: "REQ-57: parsing of complex configuration/data formats uses vetted libraries rather than handwritten parsers."
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
Security guarantees must hold even under partial failures and malformed inputs.

## Goal
Centralize hard security invariants and failure behavior.

## Non-goals
- UX-level command grouping.

## Constraints
- All write paths must be traversal-safe and atomic.
- Complex formats must be parsed with maintained libraries (e.g., TOML, JSON, YAML, `.env`) instead of ad-hoc custom parsers.

## Requirement Coverage
- REQ-40, REQ-41, REQ-42, REQ-43, REQ-44, REQ-57.

## Acceptance Criteria
- AC1: Unsafe operations are rejected by default.
- AC2: Status command performs minimal secret exposure/decryption.
- AC3: Complex format parsing is delegated to established parser libraries.

## Test Plan
- Negative tests for traversal attempts, decode failures, and output redaction.

## Notes
Logging must be audited to avoid accidental value disclosure.
