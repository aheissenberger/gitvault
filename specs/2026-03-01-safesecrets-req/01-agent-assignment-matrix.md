---
id: "S-20260301-RM01"
title: "SafeSecrets agent assignment matrix"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-bg"]
scope:
  repoAreas: ["specs/**", "src/**", ".github/workflows/**"]
  touch: ["specs/2026-03-01-safesecrets-req/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "Defines execution order with dependencies for REQ-1..REQ-55."
  - id: "AC2"
    text: "Provides per-REQ effort estimates and parallelization guidance for multi-agent delivery."
verification:
  commands: ["cargo xtask spec-verify"]
risk:
  level: "low"
links: { issue: "", pr: "" }
---

## Context
This matrix enables parallel delivery across multiple agents while preserving prerequisite order and minimizing merge contention.

## Goal
Provide a practical assignment and sequencing plan for implementing [00-index.md](specs/2026-03-01-safesecrets-req/00-index.md) and [req-001.md](specs/2026-03-01-safesecrets-req/req-001.md) through [req-055.md](specs/2026-03-01-safesecrets-req/req-055.md).

## Effort Legend
- S: 0.5 to 1 day
- M: 1 to 2 days
- L: 2 to 4 days

## Dependency Waves

### Wave 0 (Foundation)
- REQ-1 (M), REQ-2 (M), REQ-3 (M), REQ-4 (L), REQ-5 (M), REQ-6 (S)
- Rationale: crypto and deterministic serialization are prerequisites for most downstream features.

### Wave 1 (Repository and environment controls)
- REQ-7 (S), REQ-8 (S), REQ-9 (M), REQ-10 (M), REQ-11 (S), REQ-12 (M)
- Depends on: Wave 0

### Wave 2 (Prod safety and materialization)
- REQ-13 (M), REQ-14 (S), REQ-15 (M), REQ-16 (S), REQ-17 (M), REQ-18 (M), REQ-19 (M), REQ-20 (M)
- Depends on: Wave 1

### Wave 3 (Run mode and backend)
- REQ-21 (S), REQ-22 (L), REQ-23 (S), REQ-24 (M), REQ-25 (M)
- REQ-26 (S), REQ-27 (M), REQ-28 (L), REQ-29 (M), REQ-30 (M)
- Depends on: Waves 1-2

### Wave 4 (Git workflow and merge behavior)
- REQ-31 (M), REQ-32 (S), REQ-33 (M), REQ-34 (S), REQ-35 (M)
- Depends on: Waves 0-3

### Wave 5 (Key lifecycle and security hardening)
- REQ-36 (S), REQ-37 (S), REQ-38 (M), REQ-39 (L), REQ-40 (M), REQ-41 (M), REQ-42 (M), REQ-43 (M), REQ-44 (M)
- Depends on: Waves 0-4

### Wave 6 (Automation, CI, and performance)
- REQ-45 (S), REQ-46 (S), REQ-47 (S), REQ-48 (M), REQ-49 (M), REQ-50 (S), REQ-51 (M), REQ-52 (M), REQ-53 (M)
- Depends on: Waves 3-5

### Wave 7 (Release integrity)
- REQ-54 (M), REQ-55 (S)
- Depends on: Waves 0-6

## Suggested 6-Agent Split

### Agent A: Crypto Core
- REQ-1..REQ-6
- Critical path owner for deterministic format behavior.

### Agent B: Workspace Safety
- REQ-7..REQ-12, REQ-31, REQ-32
- Owns tracked plaintext prevention and Git hardening.

### Agent C: Production Controls
- REQ-13..REQ-20, REQ-25, REQ-29
- Owns barriers, token expiry, and secure materialization.

### Agent D: Runtime and SSM
- REQ-21..REQ-24, REQ-26..REQ-30, REQ-49
- Owns run-mode and cloud backend operations.

### Agent E: Merge and Key Management
- REQ-33..REQ-39, REQ-51..REQ-53
- Owns diff quality, merge mechanics, and key lifecycle.

### Agent F: Security and Automation Contracts
- REQ-40..REQ-48, REQ-50, REQ-54, REQ-55
- Owns fail-closed semantics, CLI contracts, CI behavior, and release integrity.

## Merge Strategy
- Rebase/merge order by wave, not by agent.
- Enforce shared contract tests for deterministic serialization, barrier checks, and redaction.
- Protect common touchpoints (`src/main.rs`, CLI arg parsing, status command) with short-lived feature branches.

## Exit Criteria Per Wave
- All associated req files in this folder have implementation PR links added.
- Acceptance tests for each req pass in CI.
- No plaintext leakage regression in hooks/status/run mode.
