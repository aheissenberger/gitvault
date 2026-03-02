# Architecture Hotspots

Curated from the 2026-03-01 multi-agent review so future agents can jump directly to high-value areas.
Last updated: 2026-03-02 (second refactor pass — all critical bugs resolved).

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
- SSM `--all-features` test compilation failure → **fixed**: `test_cmd_ssm_diff_with_in_sync` now declares its own `MockSsmBackend` with the correct expectation.
- `aws_config.rs` line coverage below 70% gate → **fixed**: added `build_client_without_role_returns_ok` and `build_client_with_profile_returns_ok` tokio tests; coverage is now 84.48%.

## Current Architecture Issues

### Medium Priority

- `src/repo/paths.rs`: `get_encrypted_path` and `get_plain_path` carry `#[allow(dead_code)]` attributes.
  Both functions are part of the public re-export surface (`src/repo/mod.rs`) but are not called within
  the crate itself. Remove the attributes if the functions are meant to be public API, or remove the
  functions entirely if they are truly unused.
- Public API docs are incomplete for `src/merge.rs` (private helpers lack rustdoc), `src/env.rs`,
  and `src/run.rs`. Not blocking but degrades developer experience.
- `src/commands/run_cmd.rs` and `src/commands/decrypt.rs` use `#[allow(clippy::too_many_arguments)]`.
  A parameter struct (`RunOptions`, `DecryptOptions`) would express the intent more clearly and satisfy
  clippy without the suppress attribute.
- `src/ssm.rs` (902 lines) is the largest single module. Could benefit from an internal split into
  `ssm/backend.rs`, `ssm/commands.rs`, and `ssm/refs.rs` if the module grows further.

### Low Priority

- `src/structured/fields.rs` (628 lines) mixes JSON, YAML, and `.env` field handlers. A future split
  into format-specific submodules would improve discoverability.
- `src/commands/effects.rs` (591 lines) includes the `EffectRunner` trait, its default implementation,
  and all `execute_effects_with` logic. Extracting the `DefaultRunner` to its own file would help.
- Tests in `src/identity.rs`, `src/commands/test_helpers.rs`, and elsewhere use
  `unsafe { std::env::set_var/remove_var }` blocks. In Rust edition 2024, these are safe in single-
  threaded test helpers but the global test lock pattern must be maintained rigorously.

## Unfulfilled Acceptance Criteria (by spec)

| Spec | AC | Status | Notes |
|------|----|--------|-------|
| S-20260301-015 (testing-matrix) | AC5 | ⚠️ Partial | Windows ACL assertions in CI are implemented via `icacls` injection but not validated by a Windows runner job in the current CI definition. `enforce_windows_acl_with` is unit-tested on all platforms. |
| S-20260301-011 (security-requirements) | AC4 | ⚠️ Partial | REQ-60: Windows ACL enforcement is implemented and unit-tested; full CI validation on Windows runner remains outstanding (same as spec-15 AC5). |

All other acceptance criteria across all 19 spec files are satisfied.

## Coverage Status (2026-03-02, second refactor pass)

- Overall line coverage: **96.56%** (gate: ≥95%) ✅
- Overall region coverage: **95.24%** (gate: ≥95%) ✅
- All files above 70% per-file gate ✅ (lowest: `aws_config.rs` at 84.48%)
- Total tests: **346 unit + 18 integration = 364** passing

## How to Use This File

- Treat this as prioritization guidance, not proof.
- Confirm behavior with targeted tests before patching.
- Keep updates short and factual; this file is for rapid handoff.


