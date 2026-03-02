# Releasing gitvault

This runbook documents maintainer-owned release and CI/CD workflows.

## Contents

- [Preconditions](#preconditions)
- [1) Bump crate version](#1-bump-crate-version)
- [2) Run local verification](#2-run-local-verification)
- [3) Create and push annotated tag](#3-create-and-push-annotated-tag)
- [4) Run release gate check](#4-run-release-gate-check)
- [Versioning and tags policy](#versioning-and-tags-policy)
- [5) Confirm CI workflows](#5-confirm-ci-workflows)
- [CI/CD overview](#cicd-overview)
- [6) Validate published binary version output](#6-validate-published-binary-version-output)
- [Troubleshooting](#troubleshooting)

## Preconditions

- You are on `main` with latest changes pulled.
- GitHub Actions is green for current `main`.
- You can create and push tags to the repository.

## 1) Bump crate version

Update `[package].version` in `Cargo.toml`.

Example: `0.1.0` -> `0.1.1`.

## 2) Run local verification

```bash
cargo verify
```

`cargo verify` must pass before tagging.

## 3) Create and push annotated tag

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
```

Use the exact crate version for `X.Y.Z`.

## 4) Run release gate check

```bash
cargo xtask release-check
git push origin vX.Y.Z
```

`cargo xtask release-check` enforces:
- HEAD is exactly on a `v<version>` tag matching `Cargo.toml`
- working tree is clean
- tag is annotated (not lightweight)

## Versioning and tags policy

- `Cargo.toml` is the single source of truth for the CLI semantic version.
- Git tags must use `v<version>` format (example: `v0.1.0`).
- Tag builds must pass `cargo xtask release-check`.

## 5) Confirm CI workflows

After tag push or manual dispatch, verify this workflow:
- [build.yml](../.github/workflows/build.yml) runs and publishes release artifacts.

## CI/CD overview

- **Unified release workflow**: [build.yml](../.github/workflows/build.yml)
  - Triggers only on tag pushes matching `v*` and manual dispatch.
  - Runs `cargo fmt`, `clippy`, tests, and tag consistency checks.
  - Builds release binaries for Linux, Windows, and macOS (arm64 + x86_64).
  - Uploads binaries as workflow artifacts.
  - Publishes release assets automatically on tag runs.
  - On manual runs, publishes release assets only when `publish_release=true`.

### Required secrets

No repository secrets are required for the current unified workflow.

## 6) Validate published binary version output

Confirm released binary reports expected version and metadata:

```bash
gitvault --version
```

Long output includes:
- semantic version from `Cargo.toml`
- format version line
- git SHA
- git commit date

## Troubleshooting

- `release-check` fails with `no tag exactly matches`: create the local annotated tag first (`git tag -a v<version> -m "v<version>"`).
- `release-check` fails on tag mismatch: create the correct `v<version>` tag for current `Cargo.toml`.
- `release-check` fails on lightweight tag: recreate as annotated (`git tag -a ...`).
- `release-check` fails on dirty tree: commit or discard local changes before tagging.
