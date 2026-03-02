# Agent Start Guide

This is the first file every AI agent should read before touching code.

## Goal

Minimize repeated source-code exploration by giving agents a shared map, fixed workflow, and known risk areas.

## Fast Context

- Product: `gitvault` (Rust CLI for Git-native secrets with age)
- Main crate root: `src/lib.rs`
- Binary entrypoint: `src/main.rs`
- Automation entrypoint: `xtask/src/main.rs`
- Requirement corpus: `specs/2026-03-01-safesecrets-req/`
- Architecture notes: `docs/ai/hotspots.md`
- Generated code index: `docs/ai/code-index.json` (run `cargo xtask ai-index`)

## Required Workflow for Agents

1. Read this file and `docs/ai/hotspots.md`.
2. If missing/stale, run `cargo xtask ai-index` and read `docs/ai/code-index.json`.
3. Scope to the smallest impacted modules first; avoid broad repo scans.
4. Append findings/assumptions to task output so the next agent can reuse context.
5. Validate with targeted checks first, then broader checks if needed.

## Module Ownership Map (High Level)

- `src/commands/*`: CLI command handlers
- `src/repo/*` + `src/repo.rs`: repository safety checks, hooks, drift, recipients
- `src/fhsm.rs`: fileless run mode env injection and pass-through handling
- `src/materialize.rs`: decrypt/materialize into `.env`
- `src/ssm.rs`: AWS SSM sync and diff flows
- `src/error.rs`: domain error mapping and exit code semantics

## Known Priority Risks

See `docs/ai/hotspots.md` for the curated list of critical and architectural issues.

## Done Criteria for Agent Tasks

- Root-cause fix (not symptom workaround)
- Narrowly scoped patch
- `cargo fmt` clean
- Relevant tests/checks executed and reported
- Any follow-up risks documented
