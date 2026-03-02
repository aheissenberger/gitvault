---
id: "S-20260301-010"
title: "Recipient and key management"
status: "active"
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
    text: "REQ-39: OS keyring integration supports save/status/delete on macOS, Windows, and Linux, including optional keyring passphrase fetch for identity loading."
  - id: "AC3"
    text: "SSH identity resolution supports deterministic precedence `--identity -> GITVAULT_IDENTITY -> keyring -> ssh-agent (optional)` and fail-closed handling for missing/ambiguous keys."
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
- Identity source selection must be deterministic and non-interactive by default.
- SSH-agent support is optional and must never implicitly choose among multiple usable agent keys.
- A usable SSH-agent key is an age-compatible identity key that can be selected for decrypt/materialize/run operations.
- Source availability behavior is explicit: unavailable/locked keyring or missing/inaccessible SSH agent is treated as source-not-available and resolution continues; if no source yields identity material, operations fail closed with actionable error output.

## Requirement Coverage
- REQ-36, REQ-37, REQ-38, REQ-39.

## Acceptance Criteria
- AC1: Recipient lifecycle commands function as expected.
- AC2: Keyring operations behave consistently per platform, including optional passphrase retrieval.
- AC3: Identity source precedence and fail-closed ambiguity behavior are enforced.

## Test Plan
- Unit and integration tests for keyring-backed key retrieval, passphrase fetch, and rotation flows.
- Identity resolution tests covering precedence and ambiguous SSH-agent key cases.
- Command-path coverage includes encrypt, decrypt, materialize, run, check, and recipient/rotate flows that resolve local identity.

## Notes
Cross-platform abstractions should isolate OS-specific keyring details.
