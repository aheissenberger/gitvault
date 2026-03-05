# Development guide

This document covers local development workflows for gitvault contributors.

## Contents

- [Interactive sandbox shell](#interactive-sandbox-shell)
- [Verification commands](#verification-commands)
- [All xtask commands](#all-xtask-commands)
- [Architecture: FHSM and testability](#architecture-fhsm-and-testability)
- [Centralized defaults and configuration](#centralized-defaults-and-configuration)
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

Release procedures: [releasing.md](releasing.md). CLI reference: [reference.md](reference.md).

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
| `src/main.rs` | Binary entry point; parses CLI and calls `gitvault::dispatch::run` |
| `src/dispatch.rs` | CLI dispatch; maps parsed `Cli` to command implementations |
| `src/commands/` | Command handler modules (`encrypt`, `decrypt`, `run`, `materialize`, and more) |
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
| `src/defaults.rs` | Centralized built-in default constants — all hardcoded fallback values live here; new configurable defaults should be added here first |
| `src/permissions.rs` | POSIX/Windows file permission helpers |
| `src/aws_config.rs` | AWS profile/role-ARN config for future SSM backend |
| `src/cli.rs` | clap CLI struct definitions |
| `src/error.rs` | `GitvaultError` enum and exit codes |

## Centralized defaults and configuration

All hardcoded fallback values are collected in **`src/defaults.rs`**. This single file is the
canonical source of truth for every built-in default — no literals should be scattered across
implementation files.

### Adding a new configurable default

1. **Define the constant** in `src/defaults.rs` with a `///` doc-comment explaining its role.
2. **Replace the call-site literal** with `crate::defaults::THE_CONST`.
3. **Add a config key** in the appropriate section struct in `src/config.rs` (e.g. `[env]`,
   `[barrier]`, `[paths]`, `[keyring]`):
   - Add an `Option<T>` field to the raw TOML struct and the resolved struct.
   - Add a resolver method that calls `.unwrap_or(defaults::THE_CONST)`.
   - Wire the merge in `effective_config_impl` using `.or()` (repo wins, global fills in).
4. **Thread the resolved value** from `effective_config(repo_root)?` down to the function that
   needs it.
5. **Document the key** in `README.md` and in the relevant spec file under `specs/`.

### Currently configured defaults

| Constant | Value | Config key |
|----------|-------|-----------|
| `defaults::DEFAULT_ENV` | `dev` | `[env] default` |
| `defaults::DEFAULT_PROD_ENV` | `prod` | `[env] prod_name` |
| `defaults::ENV_FILE` | `.git/gitvault/env` | `[env] env_file` |
| `defaults::DEFAULT_BARRIER_TTL_SECS` | `3600` | `[barrier] ttl_secs` |
| `defaults::RECIPIENTS_DIR` | `.gitvault/recipients` | `[paths] recipients_dir` |
| `defaults::MATERIALIZE_OUTPUT` | `.env` | `[materialize] output_filename` |
| `defaults::KEYRING_SERVICE` | `gitvault` | `[keyring] service` |
| `defaults::KEYRING_ACCOUNT` | `age-identity` | `[keyring] account` |
| `defaults::BARRIER_TOKEN_FILE` | `.git/gitvault/.prod-token` | *(not yet configurable)* |
| `defaults::SECRETS_DIR` | `.gitvault/store` | *(not yet configurable)* |
| `defaults::PLAIN_BASE_DIR` | `.git/gitvault/plain` | *(not yet configurable)* |

---

## Multi-worktree workflow

```bash
git clone <repo-url> gitvault
cd gitvault
git worktree add ../gitvault-agent-a -b agent-a
git worktree add ../gitvault-agent-b -b agent-b
```

Each worktree resolves its own environment via `.git/gitvault/env` or `GITVAULT_ENV`, enabling parallel
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

