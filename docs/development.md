# Development guide

This document covers local development workflows for gitvault contributors.

## Contents

- [Interactive sandbox shell](#interactive-sandbox-shell)
- [Verification commands](#verification-commands)
- [All xtask commands](#all-xtask-commands)
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
cargo llvm-cov --workspace --all-features --fail-under-lines 100
cargo llvm-cov --workspace --all-features --summary-only
```

When coverage gate work is in progress, use the summary command to inspect current line coverage
before re-running the strict `--fail-under-lines 100` command.

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
