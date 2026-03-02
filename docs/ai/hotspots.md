# Architecture Hotspots

Curated from the 2026-03-01 multi-agent review so future agents can jump directly to high-value areas.
Last updated: 2026-03-02 (post-refactor review pass).

## Resolved Issues (no longer actionable)

The following items from the original hotspot list have been fully addressed:

- `src/repo.rs` god-module → **split** into `src/repo/{mod,paths,hooks,drift,recipients}.rs`.
- `src/commands/test_helpers` not `#[cfg(test)]`-gated → **fixed**: declared as `#[cfg(test)] pub mod test_helpers` in `commands/mod.rs`.
- `src/error.rs`: `Drift` exit code → **fixed**: `EXIT_DRIFT = 6`, maps correctly in `exit_code()`.
- `src/error.rs`: missing `From<FhsmError> for GitvaultError` → **implemented**: boilerplate eliminated.
- Recipient rotation mixed-key state → **fixed**: phase-1 pre-flight decrypts all files before any write.
- Windows materialize TOCTOU around ACL timing → **fixed**: `enforce_owner_rw` runs on the temp file before `tmp.persist()`.
- SSM push silent partial success → **fixed**: returns `GitvaultError::Other` when any keys are skipped.
- Identity key material secrecy → **addressed**: `load_identity` returns `Zeroizing<String>` throughout.
- Pre-commit bypass for first-time staged plaintext → **fixed**: `check_no_tracked_plaintext` uses `git diff --cached` which catches untracked files staged for the first time.

## Current Architecture Issues

### Medium Priority

- `src/aws_config.rs` at 54.55% line coverage (below the 70% per-file gate). The `build_client` async path
  requires the AWS SDK which in some CI runners may need explicit SSM feature flag activation.
  Two skeleton tests have been added but the `AssumeRole` branch remains uncovered.
- Public API docs are incomplete for `src/merge.rs` (private helpers lack rustdoc), `src/env.rs`,
  and `src/run.rs`. Not blocking but degrades developer experience.
- `src/ssm.rs` (894 lines) is the largest single module. Could benefit from an internal split into
  `ssm/backend.rs`, `ssm/commands.rs`, and `ssm/refs.rs` if the module grows further.

### Low Priority

- `src/structured/fields.rs` (628 lines) mixes JSON, YAML, and `.env` field handlers. A future split
  into format-specific submodules would improve discoverability.
- `src/commands/effects.rs` (591 lines) includes the `EffectRunner` trait, its default implementation,
  and all `execute_effects_with` logic. Extracting the `DefaultRunner` to its own file would help.

## Current Bug: SSM `--all-features` test

- `test_cmd_ssm_diff_with_in_sync` in `src/ssm.rs` referenced an undefined `mock` variable.
  **Fixed** in review/code-quality: a proper `MockSsmBackend::new()` with `expect_fetch_params`
  returning the matching parameter is now in place. The `--all-features` build now compiles and
  all 344 tests pass.

## Coverage Status (2026-03-02, with SSM fix)

- Overall line coverage: **96.38%** (gate: ≥95%) ✅
- Overall region coverage: **95.07%** (gate: ≥95%) ✅
- Per-file below 70%: `aws_config.rs` at **54.55%** ⚠️ (real AWS build_client branches require live credentials)

## How to Use This File

- Treat this as prioritization guidance, not proof.
- Confirm behavior with targeted tests before patching.
- Keep updates short and factual; this file is for rapid handoff.

