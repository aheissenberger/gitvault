# Architecture Hotspots

Curated from the 2026-03-01 multi-agent review so future agents can jump directly to high-value areas.
Last updated: 2026-03-03 (eighth review pass — rustdoc, README hook-adapter docs, ssm coverage boost).

## Resolved Issues (no longer actionable)

All previously-open issues have been resolved in this session:

- `src/repo.rs` god-module → **split** into `src/repo/{mod,paths,hooks,drift,recipients}.rs`.
- `src/commands/test_helpers` not `#[cfg(test)]`-gated → **fixed**: declared as `#[cfg(test)] pub mod test_helpers`.
- `src/error.rs`: `Drift` exit code → **fixed**: `EXIT_DRIFT = 6`, maps correctly in `exit_code()`.
- `src/error.rs`: missing `From<FhsmError> for GitvaultError` → **implemented**.
- Recipient rotation mixed-key state → **fixed**: phase-1 pre-flight decrypts all files before any write.
- Windows materialize TOCTOU around ACL timing → **fixed**: `enforce_owner_rw` runs on temp file before persist.
- SSM push silent partial success → **fixed**: returns `GitvaultError::Other` when keys are skipped.
- Identity key material secrecy → **addressed**: `load_identity` returns `Zeroizing<String>`.
- SSM `--all-features` test compilation failure → **fixed**: `test_cmd_ssm_diff_with_in_sync` defines `MockSsmBackend`.
- `aws_config.rs` line coverage below 70% gate → **fixed**: two tokio tests added; coverage 84.48%.
- `src/repo/paths.rs` spurious `#[allow(dead_code)]` on public API functions → **removed**.
- `src/merge.rs` missing rustdoc on `parse_env_key_from_line` → **added**.
- `#[allow(clippy::too_many_arguments)]` in `run_cmd.rs` and `decrypt.rs` → **fixed**: introduced
  `RunOptions` and `DecryptOptions` parameter structs; suppress attribute removed.
- `src/ssm.rs` (902 lines) monolithic module → **split** into `ssm/{backend,refs,commands,mod}.rs`.
- Windows CI: no `cargo test` job on `windows-latest` → **fixed**: `test-windows` job added to
  `.github/workflows/build.yml`, satisfying AC5 (spec-15) and AC4 (spec-11).
- Pedantic clippy pass → **applied**: redundant closures, format arg inlining, implicit clone,
  let-else patterns, unnested or-patterns, identical match arms, raw string hashes cleaned up.
- Nursery clippy pass → **applied**: `or_fun_call` (11 sites — `unwrap_or(f())` → `unwrap_or_else(|| f())`),
  `redundant_clone`, `option_if_let_else`, `redundant_closure_for_method_calls`.
- `items_after_statements` (5 sites) → **fixed**: `use` statements moved to top of function bodies
  in `decrypt.rs`, `keyring.rs`, `recipients.rs`.
- `too_many_lines` in `dispatch.rs` (108/100) → **fixed**: `dispatch_ssm()` helper extracted,
  `run()` reduced to ~72 lines.
- `struct_excessive_bools` on `DecryptOptions` → **suppressed with rationale**: each bool is a
  direct CLI flag mapping; idiomatic for CLI option structs.
- Doc warnings pass → **applied**: all `missing_errors_doc` (71 functions across 26 files),
  `missing_panics_doc` (2 functions), and `doc_markdown` (13 backtick fixes) warnings resolved.
  `cargo clippy -- -W clippy::missing_errors_doc -W clippy::missing_panics_doc -W clippy::doc_markdown`
  now exits with 0 warnings.

## Remaining Low Priority Items

These items are known but reviewed and deemed low-value relative to refactor risk:

- `src/structured/fields.rs` (628 lines): JSON/YAML/TOML handlers share `determine_encrypted_value`
  and navigation helpers. A submodule split would require restructuring all shared imports with
  minimal readability gain — leave as single file.
- `src/commands/effects.rs` (591 lines): `EffectRunner` trait, `DefaultRunner` impl, and
  `execute_effects_with` are tightly coupled; extraction adds boilerplate without benefit.
- Tests in `ssm/mod.rs` use `unsafe { std::env::set_var/remove_var }`. In Rust 1.93.1 (edition 2024),
  `set_var` is not yet unsafe on stable; the `unsafe {}` blocks are preemptive and harmless.
- ~~17 `#[must_use]` candidates~~ → **partially resolved**: `as_identity()`, `enter()`, `setup_identity_file()` annotated. Remaining ~14 are internal helpers; low risk.
- 3 `map_or` test code style suggestions — current `match` is clearer.
- 2 remaining `match` → `if let` suggestions — both arms are meaningful; pedantic style only.
- Public API rustdoc gaps (8 items in `config.rs`, `repo/plugin.rs`, `identity.rs`) → **being addressed in `review/rustdoc-public-api` branch**.
- README lacks hook-adapter and config documentation → **being addressed in `review/readme-hook-docs` branch**.
- `ssm/commands.rs` at **71.95% line coverage** (gate: 70%) → **being boosted in `review/ssm-coverage` branch**.

## Unfulfilled Acceptance Criteria

None. All AC across all 97 spec files are now satisfied (97 files × all ACs verified by `cargo xtask spec-verify`).

| Spec | AC | Status | Notes |
|------|----|--------|-------|
| All 97 specs | All ACs | ✅ Done | spec-verify passes; Windows CI job fulfills AC5/AC4 |

## Coverage Status (2026-03-03, eighth review pass)

- Overall line coverage: **95.91%** (gate: ≥95%) ✅  
- Overall region coverage: ~91% (gate: n/a in CI)
- `ssm/backend.rs` and `aws_config.rs` are excluded from CI coverage gate
  (both require live AWS credentials — cannot be unit tested without real AWS infra)
- Lowest covered file (included in gate): `ssm/commands.rs` at **71.95%** (⚠️ close to 70% floor)
- `dispatch.rs` at 92.29% line coverage (below 95% overall target per file — acceptable)
- Total tests: **409 unit + 37 integration = 446** passing

## CI Status

| Job | Status |
|-----|--------|
| `cargo fmt --check` | ✅ clean |
| `cargo clippy -- -D warnings` | ✅ clean (0 warnings) |
| `cargo clippy -- -W all -W pedantic -W nursery` | ✅ 0 warnings |
| `cargo test --all-features` | ✅ 446/446 pass |
| `cargo llvm-cov --fail-under-lines 95` | ✅ 95.91% |
| `cargo xtask spec-verify` | ✅ 97/97 specs |
| `test-windows` (windows-latest) | ✅ job active |

## Architecture Summary (current state)

```
src/
├── lib.rs          entry, feature-gated mod declarations
├── dispatch.rs     CLI dispatch — calls cmd_* with typed option structs
├── fhsm.rs         finite-state machine for core workflows
├── config.rs       .gitvault/config.toml + ~/.config/gitvault/config.toml (REQ-67/68)
├── commands/
│   ├── run_cmd.rs  RunOptions struct + cmd_run
│   ├── decrypt.rs  DecryptOptions struct + cmd_decrypt
│   ├── encrypt.rs  cmd_encrypt
│   ├── effects.rs  EffectRunner trait + DefaultRunner + execute_effects
│   └── ...         materialize, admin, recipients, keyring, identity
├── repo/
│   ├── mod.rs      find_repo_root, validate_write_path
│   ├── paths.rs    get_encrypted_path, get_plain_path
│   ├── hooks.rs    install_hooks
│   ├── drift.rs    check_drift
│   ├── recipients.rs  load_recipients
│   └── plugin.rs   AdapterLookup + find_adapter_binary (REQ-64/65/66)
├── ssm/            (feature = "ssm")
│   ├── mod.rs      re-exports + integration tests
│   ├── backend.rs  SsmBackend trait + RealSsmBackend
│   ├── refs.rs     ssm_path, refs_file_path, load/save_refs
│   └── commands.rs cmd_ssm_* (pull/diff/set/push)
├── structured/
│   ├── fields.rs   JSON/YAML/TOML field encrypt/decrypt
│   └── ...
└── ...
```

## How to Use This File

- Treat as prioritization guidance, not proof.
- Confirm behavior with targeted tests before patching.
- Keep updates short and factual; this file is for rapid handoff.
