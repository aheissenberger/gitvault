# gitvault

A Git-native secrets manager for multi-developer and multi-agent workflows. Secrets are encrypted
with [age](https://age-encryption.org) and stored in your repository — never plaintext.

## Features (MVP — 31% of full spec)

- **age encryption** — standard file format, native Rust, no external binaries required (REQ-1, 2)
- **Multi-recipient** — encrypt once for every team member; any recipient can decrypt (REQ-3)
- **Repository layout** — encrypted artifacts under `secrets/`, plaintext outputs under
  `.secrets/plain/<env>/` (REQ-7, 8)
- **Plaintext leak detection** — refuses to operate if `.env` or plaintext secrets are tracked by
  Git (REQ-10)
- **Environment model** — resolves active environment from `SECRETS_ENV` → `.secrets/env` → `dev`;
  each worktree is independent (REQ-11, 12)
- **Root `.env` materialization** — atomic write, `0600` permissions, deterministic sorted output,
  auto-added to `.gitignore` (REQ-16–20)
- **JSON output & non-interactive mode** — all commands accept `--json` and `--no-prompt` (REQ-45, 46)
- **Stable exit codes** — documented, machine-readable (REQ-47)

---

## Installation

```bash
cargo build --release
# binary is at target/release/gitvault (or /workspaces/.cargo-target/release/gitvault in devcontainer)
```

---

## Quick start

### 1 — Generate an age identity (one-time per developer)

```bash
# Using age-keygen (install via https://age-encryption.org):
age-keygen -o ~/.age/identity.key
# Public key is printed — share it with team members for multi-recipient encryption.

# Or use the dev sandbox (no setup needed):
cargo xtask dev-shell
```

### 2 — Harden the repository

```bash
gitvault harden
# Adds .env and .secrets/plain/ to .gitignore.
```

### 3 — Encrypt a secret file

```bash
# Whole-file encryption (.env, arbitrary text/binary):
gitvault encrypt app.env \
  --recipient age1abc...  \   # your key
  --recipient age1xyz...      # teammate's key

# Output: secrets/app.env.age  (safe to commit)
```

### 4 — Materialize secrets to `.env`

```bash
# Uses GITVAULT_IDENTITY env var or --identity flag:
export GITVAULT_IDENTITY=~/.age/identity.key
gitvault materialize

# Or for a specific environment:
gitvault materialize --env staging --identity ~/.age/identity.key
```

### 5 — Check repository safety

```bash
gitvault status          # human-readable
gitvault --json status   # machine-readable
```

---

## CLI reference

```
gitvault [OPTIONS] <COMMAND>

Options:
  --json        Output as JSON (all commands)
  --no-prompt   Non-interactive / CI mode (all commands)

Commands:
  encrypt     Encrypt a file → secrets/<name>.age
  decrypt     Decrypt a .age file
  materialize Decrypt all secrets/*.age → root .env
  status      Check repo safety (exit 3 if plaintext is tracked)
  harden      Add safety entries to .gitignore
  help        Print help
```

### `encrypt`

```
gitvault encrypt <FILE> [--recipient <PUBKEY>...]
```

Reads `<FILE>`, encrypts it for all recipients, writes `secrets/<FILE>.age`.
If no `--recipient` is provided, the current local identity is used as the default recipient.

### `decrypt`

```
gitvault decrypt <FILE> [--identity <KEY_FILE>] [--output <PATH>]
```

Decrypts `<FILE>` (a `.age` artifact). Output defaults to stripping the `.age` suffix.
Identity is read from `--identity`, or `GITVAULT_IDENTITY` env var.

### `materialize`

```
gitvault materialize [--env <ENV>] [--identity <KEY_FILE>]
```

Decrypts every `secrets/*.age` file, parses `KEY=VALUE` pairs, and writes a deterministic root
`.env` (sorted keys, canonical quoting, `0600` permissions, atomic rename).

### `status`

```
gitvault status
```

Fails with exit code `3` if `.env` or `.secrets/plain/` are tracked by Git.
Reports the resolved environment name.

### `harden`

```
gitvault harden
```

Ensures `.env` and `.secrets/plain/` are present in `.gitignore`.

---

## Environment resolution

Priority order (REQ-11):

| Priority | Source |
|----------|--------|
| 1 | `SECRETS_ENV` environment variable |
| 2 | `.secrets/env` file in the worktree root |
| 3 | `dev` (default) |

Each Git worktree resolves its environment independently (REQ-12).

---

## Exit codes (REQ-47)

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (I/O, encryption failure) |
| `2` | Usage / argument error |
| `3` | Plaintext secret detected in tracked files |
| `4` | Decryption error (wrong key, corrupt file) |

---

## Repository layout

```
<repo>/
├── secrets/               # encrypted artifacts (commit these)
│   ├── app.env.age
│   └── db.json.age
├── .secrets/
│   └── plain/
│       └── dev/           # decrypted plaintext (gitignored)
├── .env                   # materialized root env (gitignored)
└── .gitignore             # managed by `gitvault harden`
```

---

## Developer tooling

### Interactive sandbox shell

```bash
cargo xtask dev-shell
```

Builds the current debug binary, creates an isolated temp git repo pre-loaded with sample secret
files and a generated age identity, opens your `$SHELL` with `gitvault` on `PATH` and
`GITVAULT_IDENTITY` set, then removes the sandbox on exit. Useful for manual CLI testing without
touching your real repository.

### Full verification

```bash
cargo verify          # fmt + clippy + instructions-lint + test + build
cargo verify-fmt
cargo verify-clippy
cargo verify-test
cargo verify-build
cargo spec-verify     # validate spec frontmatter
```

### All xtask commands

| Command | Description |
|---------|-------------|
| `cargo xtask dev-shell` | Open interactive sandbox shell for CLI testing |
| `cargo xtask verify` | Run fmt + clippy + instructions-lint + test + build (default) |
| `cargo xtask fmt` | Check formatting |
| `cargo xtask clippy` | Run clippy |
| `cargo xtask test` | Run tests |
| `cargo xtask build` | Release build |
| `cargo xtask spec-init <name>` | Scaffold a new spec folder |
| `cargo xtask spec-verify` | Validate all spec frontmatter |
| `cargo xtask instructions-lint` | Lint Copilot instruction files |
| `cargo xtask wt-list` | List git worktrees |
| `cargo xtask wt-create <branch> <dir>` | Create a new worktree |
| `cargo xtask wt-remove <dir>` | Remove a worktree |

---

## Multi-worktree workflow

```bash
git clone <repo-url> gitvault
cd gitvault
git worktree add ../gitvault-agent-a -b agent-a
git worktree add ../gitvault-agent-b -b agent-b
```

Each worktree resolves its own environment via `.secrets/env` or `SECRETS_ENV`, enabling true
parallel multi-agent development without environment cross-contamination.

---

## CI / CD

- **Workflow**: `.github/workflows/build.yml`
- Runs on push to `main` and pull requests.
- Enforces `cargo spec-verify` (spec frontmatter validation).
- Enforces `cargo fmt`, `clippy`, tests, and release build.

### macOS signed release

- **Workflow**: `.github/workflows/release-macos-sign-notarize.yml`
- Triggers on `v*` tags and manual dispatch.
- Produces a universal Apple Darwin binary, signs and notarizes it.

#### Required secrets

| Secret | Purpose |
|--------|---------|
| `MACOS_CERTIFICATE_P12_BASE64` | Code signing certificate |
| `MACOS_CERTIFICATE_PASSWORD` | Certificate password |
| `MACOS_KEYCHAIN_PASSWORD` | Keychain password |
| `MACOS_SIGNING_IDENTITY` | Signing identity name |
| `APPLE_ID` | Apple ID for notarization |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password |
| `APPLE_TEAM_ID` | Apple team ID |

#### Optional Homebrew tap automation

Set secret `HOMEBREW_TAP_TOKEN` (PAT with repo write access) and variables `HOMEBREW_TAP_REPO` /
`HOMEBREW_TAP_FORMULA_PATH` to auto-open formula update PRs on tagged releases.

---

## Local development environment

- Devcontainer pinned to Rust `1.93.1`
- Multi-worktree-friendly git defaults and shared Cargo caches (named Docker volumes)
- Target directory: `/workspaces/.cargo-target` (shared across worktrees)
- Apple signing/notarization runs on `macos-14` GitHub Actions runners; development stays in the
  Linux devcontainer

```bash
rustc --version   # 1.93.1
cargo --version
```