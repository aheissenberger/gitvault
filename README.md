# Rust 1.93.1 Devcontainer + macOS Signed Release

This repository is bootstrapped for deterministic Rust development in a devcontainer and macOS signed/notarized release artifacts in GitHub Actions.

## What is included

- Devcontainer pinned to Rust `1.93.1`
- Multi-worktree-friendly git defaults and shared cargo caches
- Minimal Rust CLI scaffold (`gitvault` binary)
- CI validation workflow for formatting, clippy, tests, and release build
- macOS release workflow that builds universal binary, signs, notarizes, uploads artifact
- Optional Homebrew tap formula update PR in a separate tap repository

## Local development

1. Open this repository in VS Code.
2. Reopen in container.
3. Verify toolchain:

   ```bash
   rustc --version
   cargo --version
   ```

Expected Rust version is `1.93.1`.

Run full local verification (inside devcontainer):

```bash
cargo verify
```

Available targets:

```bash
cargo xtask help
```

Also available via cargo aliases:

```bash
cargo verify-fmt
cargo verify-clippy
cargo verify-test
cargo verify-build
```

Spec/worktree tasks via xtask:

```bash
cargo xtask spec-init 2026-03-01-feature-x
cargo xtask spec-verify
cargo xtask wt-list
cargo xtask wt-create spec/2026-03-01-feature-x/t1 ../wt-feature-x-t1
cargo xtask wt-remove ../wt-feature-x-t1
```

Equivalent aliases are available:

```bash
cargo spec-init -- 2026-03-01-feature-x
cargo spec-verify
cargo wt-list
cargo wt-create -- spec/2026-03-01-feature-x/t1 ../wt-feature-x-t1
cargo wt-remove -- ../wt-feature-x-t1
```

## Spec-driven agent workflow

- Spec template: `specs/_templates/spec.md` (YAML frontmatter + plan/tasks/progress docs)
- Copilot instruction packs:
  - `/.copilot/context.md`
  - `/.copilot/instructions.vscode-ui.md`
  - `/.copilot/instructions.vscode-bg.md`
  - `/.copilot/instructions.cli.md`
- Helper scripts:
  - `tools/spec_init.sh`
  - `tools/spec_verify.sh`
  - `tools/worktree.sh`
- Rust verifier implementation:
  - `tools/specguard/Cargo.toml`
  - `tools/specguard/src/main.rs`

`tools/spec_verify.sh` is language-adaptive and currently prefers Rust when `Cargo.toml`/`Cargo.lock` exists.

## Multi-worktree workflow

Recommended structure (outside container):

```bash
git clone <repo-url> gitvault
cd gitvault
git worktree add ../gitvault-agent-a -b agent-a
git worktree add ../gitvault-agent-b -b agent-b
```

Each worktree can be opened in its own VS Code window and re-opened in container. Cargo registry/git/rustup caches are shared via named Docker volumes for speed.

## CI workflow

- Workflow: `.github/workflows/build.yml`
- Runs on push to `main` and on pull requests.
- Executes when `Cargo.toml` is present.
- Enforces spec frontmatter validation via `cargo spec-verify`.

### Optional CI badges

Replace `<OWNER>` and `<REPO>` with your GitHub repository coordinates:

```md
![Build](https://github.com/<OWNER>/<REPO>/actions/workflows/build.yml/badge.svg)
![Release macOS](https://github.com/<OWNER>/<REPO>/actions/workflows/release-macos-sign-notarize.yml/badge.svg)
```

## macOS release workflow

- Workflow: `.github/workflows/release-macos-sign-notarize.yml`
- Triggers on tags `v*` and manual dispatch.
- Produces universal Apple Darwin CLI archive (`tar.gz`) and notarizes it.
- `binary_name` input is optional and auto-detected from Cargo metadata.
- Enforces spec frontmatter validation via `cargo spec-verify` before build/sign/notarize.

### Required repository secrets

- `MACOS_CERTIFICATE_P12_BASE64`
- `MACOS_CERTIFICATE_PASSWORD`
- `MACOS_KEYCHAIN_PASSWORD`
- `MACOS_SIGNING_IDENTITY`
- `APPLE_ID`
- `APPLE_APP_SPECIFIC_PASSWORD`
- `APPLE_TEAM_ID`

### Optional Homebrew tap automation

To auto-open a PR in a separate tap repo on tagged releases (`v*`):

- Add secret: `HOMEBREW_TAP_TOKEN` (PAT with repo write access to tap repository)
- Provide either workflow inputs or repository variables:
  - `tap_repo`: `owner/homebrew-tap-repo`
  - `tap_formula_path`: e.g. `Formula/mycli.rb`
  - or repo variables `HOMEBREW_TAP_REPO` and `HOMEBREW_TAP_FORMULA_PATH`

The workflow updates `url`, `sha256`, and `version` in the formula and creates a PR.

## Notes on signing/notarization boundary

Apple signing and notarization require macOS tooling and credentials. Development remains in Linux devcontainer; release signing/notarization runs on `macos-14` GitHub Actions.