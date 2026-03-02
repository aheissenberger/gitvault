---
id: "S-20260301-013"
title: "CI/CD compatibility and auth"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["src/**", ".github/workflows/**"]
  touch: ["src/**", "README.md", ".github/workflows/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-48 and REQ-50: fully non-interactive CI execution and explicit --check preflight mode are supported."
  - id: "AC2"
    text: "REQ-49: AWS role-based authentication supports profile and role ARN usage."
  - id: "AC3"
    text: "Non-interactive identity resolution in CI remains deterministic with precedence `--identity -> GITVAULT_IDENTITY -> keyring -> ssh-agent (optional)` and fail-closed ambiguity behavior."
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
CI and deployment pipelines require non-interactive and repeatable behavior.

## Goal
Guarantee script-safe operation and cloud auth compatibility for automated workflows.

## Non-goals
- Interactive local UX improvements.

## Constraints
- No prompts in CI paths; failures must be explicit and actionable.
- Optional SSH-agent support must not introduce interactive key selection in CI.
- When multiple usable agent keys are present without explicit selector, CI paths fail with actionable error output.
- CI selector behavior is deterministic: `--identity-selector` overrides `GITVAULT_IDENTITY_SELECTOR`.
- CI source availability behavior is deterministic: unavailable keyring or missing/inaccessible SSH agent is treated as source-not-available; unresolved identity after all configured sources fails closed.

## Requirement Coverage
- REQ-48, REQ-49, REQ-50.

## Acceptance Criteria
- AC1: CI jobs run without TTY interaction.
- AC2: IAM profile/role modes are validated for SSM workflows.
- AC3: Identity selection in CI is deterministic and fail-closed for ambiguity.

## Test Plan
- Headless integration tests in CI environment with mocked/real AWS auth profiles.
- Headless tests for keyring and optional SSH-agent identity loading in non-interactive mode.
- CI tests for selector precedence and source-not-available fallback semantics.

## Notes
Check mode should validate policy, access, and drift without mutation.

## Current Verification Status
REQ-48 (non-interactive CI): baseline support is complete (`GITVAULT_IDENTITY` + CI auto-detection), now extended in-progress to cover deterministic optional keyring/SSH-agent precedence and ambiguity handling. REQ-50 (preflight check): baseline check command is complete and remains in scope for validating new identity-source preconditions. REQ-49 (AWS role-based auth): complete and unchanged by this extension.
