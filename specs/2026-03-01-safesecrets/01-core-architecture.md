---
id: "S-20260301-001"
title: "Core architecture and encryption format"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**", "Cargo.toml"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-1..REQ-3: age file format is used, Rust-native crypto implementation is used, and multi-recipient encryption is supported."
  - id: "AC2"
    text: "REQ-4..REQ-6: field-level encryption supports JSON/YAML/TOML with deterministic serialization; .env defaults to whole-file encryption unless explicitly configured."
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
Encryption and format choices define interoperability, merge behavior, and operational safety.

## Goal
Implement deterministic encryption behavior with explicit support for structured and unstructured secret artifacts.

## Non-goals
- Backend-specific storage concerns.
- Git hook installation.

## Constraints
- Use native Rust implementation only.
- Preserve deterministic outputs for structured inputs.

## Requirement Coverage
- REQ-1, REQ-2, REQ-3, REQ-4, REQ-5, REQ-6.

## Acceptance Criteria
- AC1: Encrypted artifacts are valid `age` and decrypt without external binaries.
- AC2: Structured encryption behavior is deterministic and minimally noisy in diffs.

## Test Plan
- Golden tests for stable serialization output.
- Multi-recipient add/remove tests validating future decryptability.

## Notes
All deterministic behavior should be enforced with canonical ordering and encoding rules.

## Current Verification Status
cargo test --all passes. age encryption, multi-recipient, field-level JSON/YAML/TOML, and .env whole-file mode all implemented in src/crypto.rs and src/structured.rs.
