# Development guide

This document covers local development workflows for gitvault contributors.

## Contents

- [Interactive sandbox shell](#interactive-sandbox-shell)
- [Verification commands](#verification-commands)
- [All xtask commands](#all-xtask-commands)
- [Architecture: FHSM and testability](#architecture-fhsm-and-testability)
- [Multi-worktree workflow](#multi-worktree-workflow)
- [Local development environment](#local-development-environment)

## Interactive sandbox shell

```bash
cargo xtask dev-shell
```

Builds the current debug binary, creates an isolated temp git repo pre-loaded with sample secret
files and a generated age identity, opens your `$SHELL` with `gitvault` on `PATH` and
`GITVAULT_IDENTITY` set, then removes the sandbox on exit.

## Verification commands

```bash
cargo verify          # fmt + clippy + instructions-lint + test + build
cargo verify-fmt
cargo verify-clippy
cargo verify-test
cargo verify-build
cargo spec-verify     # validate spec frontmatter
cargo llvm-cov --summary-only                        # show per-file line coverage
cargo llvm-cov --fail-under-lines 95                 # enforce ≥95% line coverage gate
```

Release-flow note:
- Prefer `cargo verify-fmt`, `cargo verify-clippy`, `cargo instructions-lint`, and `cargo llvm-cov` over `cargo verify` for release prep.
- `cargo llvm-cov` already compiles and runs tests; `cargo verify` would duplicate test/build work.
- Multi-target release binaries are built in CI, so local pre-tag release builds are optional for speed-focused release workflows.

All source files maintain ≥95% line coverage (LCOV). Current coverage highlights:

| File | Coverage |
|------|----------|
| `src/fhsm.rs` | 99.6% |
| `src/merge.rs` | 98.1% |
| `src/identity.rs` | 100% |
| `src/main.rs` | 98.0% |

## All xtask commands

| Command | Description |
|---------|-------------|
| `cargo xtask dev-shell` | Open interactive sandbox shell for CLI testing |
| `cargo xtask verify` | Run fmt + clippy + instructions-lint + test + build (default) |
| `cargo xtask fmt` | Check formatting |
| `cargo xtask clippy` | Run clippy |
| `cargo xtask test` | Run tests |
| `cargo xtask build` | Release build |
| `cargo xtask release-check` | Validate release tag/version parity and release hygiene |
| `cargo xtask spec-init <name>` | Scaffold a new spec folder |
| `cargo xtask spec-verify` | Validate all spec frontmatter |
| `cargo xtask instructions-lint` | Lint Copilot instruction files |
| `cargo xtask wt-list` | List git worktrees |
| `cargo xtask wt-create <branch> <dir>` | Create a new worktree |
| `cargo xtask wt-remove <dir>` | Remove a worktree |

Release procedures are documented in the maintainer runbook: [releasing.md](releasing.md).

## Architecture: FHSM and testability

### Pure/impure separation

Command handlers are split into two layers:

1. **Pure FHSM core** (`src/fhsm.rs`): `transition(&Event) -> Result<Vec<Effect>, FhsmError>`.
   No I/O. Takes an `Event` (e.g. `Event::Run`, `Event::Materialize`) and returns an ordered list of
   `Effect` values (e.g. `CheckProdBarrier`, `ResolveIdentity`, `DecryptSecrets`, `RunCommand`).
   Fully tested with table-driven unit tests — no filesystem, process, or keyring access required.

2. **Effect executor** (`src/main.rs` — `execute_effects_with`): Walks the effect list in order,
   accumulating resolved state (`identity_opt`, `secrets_opt`) between effects. All I/O goes through
   the `EffectRunner` trait.

### EffectRunner trait

```rust
pub trait EffectRunner {
    fn check_prod_barrier(&self, repo_root: &Path) -> Result<(), GitvaultError>;
    fn load_identity(&self, source: &IdentitySource) -> Result<Box<dyn age::Identity>, GitvaultError>;
    fn decrypt_secrets(&self, ...) -> Result<Vec<(String, String)>, GitvaultError>;
    fn run_command(&self, ...) -> Result<i32, GitvaultError>;
    fn materialize_secrets(&self, ...) -> Result<(), GitvaultError>;
}
```

- `RealEffectRunner`: production implementation, calls real barrier/crypto/run/materialize functions.
- `FakeEffectRunner` (test-only, `#[cfg(test)]`): stores pre-configured `Result<T, String>` values,
  allowing unit tests to cover every branch of `execute_effects_with` without any real I/O.

### Writing tests for FHSM

**Transition tests** (in `src/fhsm.rs`): call `transition(&event)` and assert the exact `Vec<Effect>`
returned. No setup required.

```rust
let effects = transition(&Event::Run { no_prompt: false, prod: false, args: vec![] }).unwrap();
assert!(effects.contains(&Effect::ResolveIdentity));
```

**Executor tests** (in `src/main.rs`): build a `FakeEffectRunner` with the desired return values,
call `execute_effects_with(effects, repo_root, &fake)`, and assert the outcome or error message.

```rust
let fake = FakeEffectRunner { decrypt_result: Ok(vec![("KEY".into(), "val".into())]), ..Default::default() };
execute_effects_with(effects, &repo_root, &fake).unwrap();
```

### Pure helpers

| Function | Location | Tests |
|----------|----------|-------|
| `merge_env_content(base, ours, theirs)` | `src/merge.rs` | 9 table-driven (in `merge.rs`) |
| `parse_env_key_from_line(line)` | `src/merge.rs` | 5 unit tests (in `merge.rs`) |
| `rewrite_env_assignment_line(line, val)` | `src/merge.rs` | 5 unit tests (in `merge.rs`) |
| `parse_env_pairs(content)` | `src/merge.rs` | 1 unit test (in `merge.rs`) |
| `find_repo_root_from(start)` | `src/main.rs` | 3 (in `main.rs`) |
| `load_identity_source(source, name)` | `src/identity.rs` | 3 unit tests (in `main.rs`) |
| `load_identity_with(path, keyring_fn)` | `src/identity.rs` | 2 unit tests (in `main.rs`) |
| `resolve_recipient_keys(root, keys)` | `src/identity.rs` | 4 unit tests (in `main.rs`) |
| `resolve_identity_source(path, ...)` | `src/fhsm.rs` | 5 via fhsm tests |

### Source module overview

| Module | Purpose |
|--------|---------|
| `src/main.rs` | CLI dispatch (`run`), `cmd_*` command handlers, `EffectRunner` trait + `RealEffectRunner`, `execute_effects_with` |
| `src/identity.rs` | Identity key loading: `load_identity*`, `extract_identity_key`, `resolve_recipient_keys` |
| `src/merge.rs` | Env file parsing and three-way merge: `merge_env_content`, `parse_env_pairs`, `parse_env_key_from_line`, `rewrite_env_assignment_line` |
| `src/fhsm.rs` | Pure finite state machine: `transition(&Event) -> Vec<Effect>` |
| `src/crypto.rs` | age encryption/decryption wrappers |
| `src/structured.rs` | Field-level encryption for JSON/YAML/TOML |
| `src/repo.rs` | Repository layout helpers (paths, recipients file, git hooks) |
| `src/barrier.rs` | Production barrier (allow-token check) |
| `src/run.rs` | Child process execution with secret injection |
| `src/materialize.rs` | Root `.env` materialization |
| `src/keyring_store.rs` | OS keyring integration |
| `src/env.rs` | Environment resolution (`SECRETS_ENV` → `.secrets/env` → `dev`) |
| `src/permissions.rs` | POSIX/Windows file permission helpers |
| `src/aws_config.rs` | AWS profile/role-ARN config for future SSM backend |
| `src/cli.rs` | clap CLI struct definitions |
| `src/error.rs` | `GitvaultError` enum and exit codes |

## Multi-worktree workflow

```bash
git clone <repo-url> gitvault
cd gitvault
git worktree add ../gitvault-agent-a -b agent-a
git worktree add ../gitvault-agent-b -b agent-b
```

Each worktree resolves its own environment via `.secrets/env` or `SECRETS_ENV`, enabling parallel
multi-agent development without environment cross-contamination.

## Local development environment

- Devcontainer tracks Rust `stable`
- Multi-worktree-friendly git defaults and shared Cargo caches (named Docker volumes)
- Target directory: `/workspaces/.cargo-target` (shared across worktrees)
- Apple signing/notarization runs on `macos-14` GitHub Actions runners; development stays in the
  Linux devcontainer

```bash
rustc --version   # stable channel version
cargo --version
```

## Quality Checks

 /fleet As a senior developer for rust and as a software architect i do a deep review of best practice rust coding and structuring. read all specs and compare with implementation. suggest improvement to code quality and architecture. list all not fullfilled
  acceptance criterias based on specs. use worktrees to isolate multiple parallel ai coding agents. 