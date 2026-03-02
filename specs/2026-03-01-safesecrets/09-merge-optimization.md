---
id: "S-20260301-009"
title: "Merge optimization and conflict behavior"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-33 and REQ-35: no single encrypted mega-blob and structured encryption minimizes diff noise."
  - id: "AC2"
    text: "REQ-34: optional merge driver support for .env conflict handling is provided."
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
Parallel multi-agent development needs deterministic merge surfaces.

## Goal
Optimize secret storage and serialization for conflict isolation and predictable merges.

## Non-goals
- Runtime environment injection behavior.

## Constraints
- Keep secret artifacts split by file/key where possible.

## Requirement Coverage
- REQ-33, REQ-34, REQ-35.

## Acceptance Criteria
- AC1: Independent key edits merge with minimal conflicts.
- AC2: Same-key edits produce meaningful conflict markers.

## Test Plan
- Git merge simulation tests across independent and colliding key modifications.

## Notes
Merge driver must be optional and documented.

## Current Verification Status
cargo test --all passes. Per-file secret storage avoids mega-blob; merge driver with pure merge_env_content implemented and tested with 6 table-driven tests; field-level age-armor minimizes diff noise.
