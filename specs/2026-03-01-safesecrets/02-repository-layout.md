---
id: "S-20260301-002"
title: "Repository layout and tracked plaintext protection"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**", ".gitignore"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-7..REQ-9: encrypted artifacts are under secrets/, plaintext materialization is under .secrets/plain/<env>/, root .env is generated and gitignored, and `encrypt --keep-path` preserves repo-relative source paths under `secrets/<env>/...`."
  - id: "AC2"
    text: "REQ-10: tool fails closed when plaintext secrets are detected in tracked paths."
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
Repository layout must enforce separation between encrypted and plaintext artifacts.

## Goal
Ensure plaintext cannot be accidentally committed and layout is consistent across environments.

## Non-goals
- Runtime process injection behavior.

## Constraints
- Detection checks must be reliable against Git tracked state.
- `--keep-path` path mapping is repo-root relative and must not allow traversal outside repository root.
- When decrypting with bare `--output` (`--output` without value), paths under `secrets/<env>/...` must be restored to repo-relative plaintext paths.
- Missing directories required by mapped output paths must be created automatically.
- Existing overwrite semantics for target files remain unchanged.

## Requirement Coverage
- REQ-7, REQ-8, REQ-9, REQ-10.

## Acceptance Criteria
- AC1: Paths and outputs match required directories.
- AC2: `status` or equivalent hard-fails on tracked plaintext.
- AC3: `encrypt --keep-path` maps `repo/sub/dir/file.env` to `secrets/<env>/sub/dir/file.env.age`.
- AC4: `decrypt --output` (bare flag) restores `secrets/<env>/sub/dir/file.env.age` to `sub/dir/file.env`.

## Test Plan
- Integration tests using temporary Git repos with staged plaintext files.
- Integration tests for multi-subdirectory `encrypt --keep-path` and `decrypt --output` roundtrip.
- Unit tests for missing-directory creation on mapped output paths.

## Notes
Validation should use Git plumbing commands for deterministic results.

## Current Verification Status
cargo test --all passes. Encrypted artifacts under secrets/, plaintext under .secrets/plain/<env>/, root .env generated and gitignored, tracked plaintext detection implemented in src/repo.rs.
