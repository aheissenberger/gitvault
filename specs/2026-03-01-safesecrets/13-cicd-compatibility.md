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

## Requirement Coverage
- REQ-48, REQ-49, REQ-50.

## Acceptance Criteria
- AC1: CI jobs run without TTY interaction.
- AC2: IAM profile/role modes are validated for SSM workflows.

## Test Plan
- Headless integration tests in CI environment with mocked/real AWS auth profiles.

## Notes
Check mode should validate policy, access, and drift without mutation.

## Current Verification Status
REQ-48 (non-interactive CI): done — GITVAULT_IDENTITY env var + CI auto-detection via ci_is_non_interactive(). REQ-50 (preflight check): done — gitvault check subcommand implemented in src/commands/admin.rs cmd_check. REQ-49 (AWS role-based auth): done — AwsConfig::build_client() in src/aws_config.rs supports profile and role ARN via AssumeRoleProvider; SSM backend (REQ-26..30) fully implemented in src/ssm.rs.
