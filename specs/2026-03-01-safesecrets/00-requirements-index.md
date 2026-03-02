---
id: "S-20260301-000"
title: "SafeSecrets requirements index and traceability"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["specs/**"]
  touch: ["specs/2026-03-01-safesecrets/**"]
  avoid: ["src/**"]
acceptance:
  - id: "AC1"
    text: "Each baseline REQ identifier from REQ-1 to REQ-60 maps to exactly one individual spec file; approved extension REQs map to dedicated extension spec files."
  - id: "AC2"
    text: "All individual spec files contain valid frontmatter accepted by spec verifier."
verification:
  commands:
    - "cargo spec-verify"
risk:
  level: "low"
links:
  issue: ""
  pr: ""
---

## Context
The base document is a consolidated requirements specification that must be split into non-overlapping individual implementation specs.

## Goal
Provide a one-to-one traceability map from the consolidated requirement IDs to individual spec files.

## Non-goals
- Rewriting or altering requirement intent.
- Implementing production code.

## Constraints
- Every REQ must be covered once and only once.
- Individual specs must remain deterministic and scoped.

## Requirement Coverage Map
- REQ-1..REQ-6 -> `01-core-architecture.md`
- REQ-7..REQ-10 -> `02-repository-layout.md`
- REQ-11..REQ-12 -> `03-environment-model.md`
- REQ-13..REQ-15 -> `04-production-barrier.md`
- REQ-16..REQ-20 -> `05-root-env-handling.md`
- REQ-21..REQ-25 -> `06-fileless-run-mode.md`
- REQ-26..REQ-30 -> `07-aws-ssm-backend.md`
- REQ-31..REQ-32 -> `08-git-integration.md`
- REQ-33..REQ-35 -> `09-merge-optimization.md`
- REQ-36..REQ-39 -> `10-key-management.md`
- REQ-40..REQ-44, REQ-57, REQ-60 -> `11-security-requirements.md`
- REQ-45..REQ-47 -> `12-cli-automation.md`
- REQ-48..REQ-50 -> `13-cicd-compatibility.md`
- REQ-51..REQ-53 -> `14-performance.md`
- Testing matrix section + Rust full-coverage requirement for `*.rs` + REQ-59 (mock external dependencies with `mockall`) -> `15-testing-matrix.md`
- REQ-54..REQ-55, REQ-58 -> `16-release-integrity.md`
- REQ-56 -> `18-requirement-governance.md`

## Extension Requirement Coverage Map
- REQ-61 -> `19-ssh-identity-requirements.md`
- REQ-62 -> `20-optional-keyring-passphrase-fetch.md`
- REQ-63 -> `21-optional-ssh-agent-support.md`
- REQ-64 -> `22-husky-hook-manager-plugin.md`
- REQ-65 -> `23-pre-commit-hook-manager-plugin.md`
- REQ-66 -> `24-lefthook-hook-manager-plugin.md`
- REQ-67 -> `25-hook-adapter-config.md`
- REQ-68 -> `26-global-config-layer.md`

## Plan Specs (Additive)
- `19-ssh-identity-requirements.md` -> Plan: SSH identity requirements
- `20-optional-keyring-passphrase-fetch.md` -> Plan: Optional keyring passphrase fetch
- `21-optional-ssh-agent-support.md` -> Plan: Optional SSH-agent support
- `22-husky-hook-manager-plugin.md` -> Plan: Husky hook manager plugin integration
- `23-pre-commit-hook-manager-plugin.md` -> Plan: pre-commit hook manager plugin integration
- `24-lefthook-hook-manager-plugin.md` -> Plan: lefthook hook manager plugin integration
- `25-hook-adapter-config.md` -> Plan: .gitvault/config.toml canonical config and hook-adapter selection
- `26-global-config-layer.md` -> Plan: optional user-global config fallback and precedence

## Acceptance Criteria
- AC1: Coverage map exists and is complete.
- AC2: Files validate with spec verifier.

## Test Plan
- Run `cargo spec-verify` and confirm all files pass.

## Notes
This index is the canonical source for requirement-to-spec traceability.

## Current Verification Status
cargo xtask spec-verify passes. Coverage map is complete for baseline REQ-1..REQ-60 and extension REQ-61..REQ-68.
