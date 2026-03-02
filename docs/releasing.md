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

After tag push, verify these workflows:
- [build.yml](../.github/workflows/build.yml) runs and passes release consistency checks.
- [release-tag.yml](../.github/workflows/release-tag.yml) runs release build/signing steps.

Optional fast-check workflow (non-release gate):
- [ci-verify.yml](../.github/workflows/ci-verify.yml)

## CI/CD overview

- **Fast verify workflow**: [ci-verify.yml](../.github/workflows/ci-verify.yml)
  - Runs on push to `main` and pull requests.
  - Enforces `cargo fmt`, `clippy`, and tests.
  - Does not build release binaries.

- **Build workflow**: [build.yml](../.github/workflows/build.yml)
  - Runs on pull requests and pushes to `main`.
  - Also runs on tag pushes matching `v*`.
  - On tag builds, enforces release/tag consistency with `cargo run -p xtask -- release-check`.

- **Release build workflow**: [release-tag.yml](../.github/workflows/release-tag.yml)
  - Triggers on `v*` tags and manual dispatch.
  - Runs verification once, then builds platform binaries.
  - Produces Linux and Windows cosign-signed binaries.
  - Produces separate macOS arm64 and x86_64 binaries, signs and notarizes both.

### Required secrets

| Secret | Purpose |
|--------|---------|
| `MACOS_CERTIFICATE_P12_BASE64` | Code signing certificate |
| `MACOS_CERTIFICATE_PASSWORD` | Certificate password |
| `MACOS_KEYCHAIN_PASSWORD` | Keychain password |
| `MACOS_SIGNING_IDENTITY` | Signing identity name |
| `APPLE_API_KEY_ID` | App Store Connect API key ID |
| `APPLE_API_ISSUER_ID` | App Store Connect issuer ID |
| `APPLE_API_PRIVATE_KEY_P8_BASE64` | Base64-encoded App Store Connect `.p8` private key |

### API key setup (notarization)

1. In App Store Connect, open [Users and Access → Integrations → App Store Connect API](https://appstoreconnect.apple.com/access/integrations/api), create an API key, and copy the key metadata.
   - Required role: `Developer` or higher (`App Manager`, `Admin`, or `Account Holder`).
2. Save the key ID as GitHub secret `APPLE_API_KEY_ID`.
3. Save the issuer ID as GitHub secret `APPLE_API_ISSUER_ID`.
4. Base64-encode the downloaded `AuthKey_<KEY_ID>.p8` file and save it as `APPLE_API_PRIVATE_KEY_P8_BASE64`.
5. Keep the four macOS signing secrets above (`MACOS_*`) unchanged.

### Migration note (from Apple ID auth)

If no other workflow depends on Apple ID-based notarization, you can remove these old secrets:

- `APPLE_ID`
- `APPLE_APP_SPECIFIC_PASSWORD`
- `APPLE_TEAM_ID`

Example (macOS) to encode `.p8`:

```bash
base64 -i AuthKey_<KEY_ID>.p8 | pbcopy
```

Example (Linux) to encode `.p8`:

```bash
base64 -w 0 AuthKey_<KEY_ID>.p8
```

### Optional Homebrew tap automation

Set secret `HOMEBREW_TAP_TOKEN` (PAT with repo write access) and variables `HOMEBREW_TAP_REPO` /
`HOMEBREW_TAP_FORMULA_PATH` to auto-open formula update PRs on tagged releases.

For this repository:
- `HOMEBREW_TAP_REPO=aheissenberger/homebrew-tools`
- `HOMEBREW_TAP_FORMULA_PATH=Formula/gitvault.rb`

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
