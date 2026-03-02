---
id: "S-20260301-005"
title: "Root-level .env generation and safety"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**", ".gitignore"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-16..REQ-19: root .env generation is supported, atomic, permission-restricted, deterministic, and canonically quoted/sorted."
  - id: "AC2"
    text: "REQ-20: .env cannot be committed and is blocked by gitignore and pre-commit controls."
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
Root-level `.env` compatibility is required for local tooling while maintaining strict secrecy guarantees.

## Goal
Materialize `.env` safely and deterministically without enabling accidental source control leaks.

## Non-goals
- Fileless runtime execution behavior.

## Constraints
- POSIX mode `0600` and Windows restricted ACL semantics are required.

## Requirement Coverage
- REQ-16, REQ-17, REQ-18, REQ-19, REQ-20.

## Acceptance Criteria
- AC1: Repeated materializations produce identical file content and secure permissions.
- AC2: Staging `.env` is prevented by repository hardening controls.

## Test Plan
- Permission and atomic-write tests across OS-specific CI runners.

## Notes
Quoting/canonicalization logic must be fully deterministic.
