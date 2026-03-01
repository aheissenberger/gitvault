---
id: "S-20260301-018"
title: "Requirement governance and spec gating"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-ui", "vscode-bg"]
scope:
  repoAreas: [".copilot/**", "specs/**"]
  touch: [".copilot/instructions.*.md", "specs/**"]
  avoid: ["src/**", "target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-56: before implementing newly requested work, the agent asks whether it belongs to an existing requirement or a new requirement."
  - id: "AC2"
    text: "REQ-56: new requirements are not implemented unless an approved spec entry exists."
  - id: "AC3"
    text: "REQ-56: after implementing a requirement, the agent updates the corresponding requirement spec status to reflect completion."
verification:
  commands:
    - "cargo xtask instructions-lint"
    - "cargo xtask spec-verify"
risk:
  level: "low"
links:
  issue: ""
  pr: ""
---

## Context
Requirement growth must remain controlled and traceable across CLI and VS Code agent modes.

## Goal
Define governance for requirement classification and enforce a spec-first gate for newly introduced requirements.

## Non-goals
- Implementing functional product features in `src/**`.

## Constraints
- Governance behavior must be consistent in CLI, VS Code UI, and background agent instruction profiles.
- New requirements must have explicit spec coverage before implementation begins.

## Requirement Coverage
- REQ-56.

## Acceptance Criteria
- AC1: Agent asks whether a new ask maps to an existing requirement or defines a new requirement.
- AC2: Agent blocks implementation of truly new requirements without an approved spec entry.
- AC3: Agent updates the corresponding requirement spec status after implementing a requirement.

## Test Plan
- Run instruction lint and spec verification checks.

## Notes
This file acts as the main spec-set placeholder for REQ-56 and links to the detailed per-REQ artifact in `specs/2026-03-01-safesecrets-req/req-056.md`.
