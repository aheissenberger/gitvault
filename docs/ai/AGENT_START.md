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

## Runtime Constraints (Mandatory)

- Python is not installed in this environment.
- Do not generate, run, or recommend Python tooling (`python`, `python3`, `pip`, `pipx`, `venv`, `poetry`, `conda`, `.py`).
- For helper automation, ad hoc utilities, and quick scripts, always use `rust-script`.

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
- **`docs/ai/skill.md` updated** if any CLI commands, options, flags, env vars, or exit codes were added or changed (this file is embedded in the binary and is the canonical AI reference for the tool)
- Before updating `README.md`, run `cargo xtask cli-help` to regenerate `docs/ai/cli-help.json`

## Documentation Structure

| File | Purpose |
|------|---------|
| `README.md` | User-facing reference (CLI, configuration, exit codes, identity resolution) |
| `docs/identity-setup.md` | Identity setup guide (OS keyring, age files, SSH keys, SSH agent, FD-based) |
| `docs/recipient-management.md` | Recipient lifecycle: onboarding, offboarding, rekeying, team scaling patterns |
| `docs/cicd-recipes.md` | CI/CD best practices (GitHub Actions, Docker, Kubernetes recipes) |
| `docs/secret-formats.md` | Secret formats cookbook (.env, JSON, YAML, TOML) |
| `docs/ai/skill.md` | AI skill reference (embedded in binary; canonical AI reference for the tool) |
| `docs/ai/hotspots.md` | Architecture hotspots and curated risk areas (read before touching core modules) |
