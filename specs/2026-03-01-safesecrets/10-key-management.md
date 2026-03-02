---
id: "S-20260301-010"
title: "Recipient and key management"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-36..REQ-38: multiple recipients, recipient add/remove, and key rotation are implemented."
  - id: "AC2"
    text: "REQ-39: OS keyring integration supports save/status/delete on macOS, Windows, and Linux."
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
Team membership and trust relationships evolve over time.

## Goal
Support secure recipient lifecycle management with cross-platform key handling.

## Non-goals
- External KMS policy management.

## Constraints
- Recipient removal must prevent future decryption after rotation/re-encryption.

## Requirement Coverage
- REQ-36, REQ-37, REQ-38, REQ-39.

## Acceptance Criteria
- AC1: Recipient lifecycle commands function as expected.
- AC2: Keyring operations behave consistently per platform.

## Test Plan
- Unit and integration tests for keyring-backed key retrieval and rotation flows.

## Notes
Cross-platform abstractions should isolate OS-specific keyring details.
