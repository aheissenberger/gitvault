# gitvault

A Git-native secrets manager for multi-developer and multi-agent workflows. Secrets are encrypted
with [age](https://age-encryption.org) and stored in your repository — never plaintext.

## Features (MVP — 96% of full spec)

- **age encryption** — standard file format, native Rust, no external binaries required (REQ-1, 2)
- **Multi-recipient** — encrypt once for every team member; any recipient can decrypt (REQ-3)
- **Field-level encryption** — encrypt individual fields in JSON, YAML, and TOML files; values
  stored as age ASCII armor inline in the document (REQ-4)
- **Deterministic re-encryption** — unchanged field values retain existing ciphertext so git diffs
  stay minimal (REQ-5, 35)
- **Whole-file / value-only modes** — `.env` files default to whole-file encryption; opt in to
  per-value encryption with `--value-only` (REQ-6)
- **Repository layout** — encrypted artifacts under `secrets/`, plaintext outputs under
  `.secrets/plain/<env>/`; one `.age` file per secret (REQ-7, 8, 33)
- **Plaintext leak detection** — refuses to operate if `.env` or plaintext secrets are tracked by
  Git (REQ-10)
- **Environment model** — resolves active environment from `SECRETS_ENV` → `.secrets/env` → `dev`;
  each worktree is independent (REQ-11, 12)
- **Production barrier** — timed allow-token required to materialize or run against `prod`;
  interactive confirmation fallback (REQ-13–15)
- **Root `.env` materialization** — atomic write, `0600` permissions, deterministic sorted output,
  auto-added to `.gitignore` (REQ-16–20)
- **Fileless run mode** — injects secrets directly into child process environment without writing
  `.env`; supports `--clear-env` and `--pass` (REQ-21–25)
- **Git hooks + merge driver** — `harden` installs pre-commit / pre-push hooks; optional
  `gitvault merge-driver` for key-level `.env` merges (REQ-31, 32, 34)
- **Recipient management** — persistent `.secrets/recipients` file; `recipient add/remove/list`;
  `rotate` re-encrypts all secrets for the current recipient set (REQ-36, 37, 38)
- **OS keyring** — `keyring set/get/delete`; `GITVAULT_KEYRING=1` loads identity from system
  keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager) (REQ-39)
- **Security hardening** — fail-closed on decrypt error, `--reveal` required to print secrets,
  path-traversal guard, atomic writes everywhere, `status` never decrypts (REQ-40–44)
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

# Field-level encryption (JSON/YAML/TOML — only named fields are encrypted):
gitvault encrypt config.json --fields db.password,api_key \
  --recipient age1abc...
# Only the db.password and api_key values are replaced with age armor inline.
# Repeat runs leave unchanged fields identical in git diff (REQ-5).
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
  encrypt       Encrypt a file → secrets/<name>.age  (or field-level for JSON/YAML/TOML)
  decrypt       Decrypt a .age file  (or field-level)
  materialize   Decrypt all secrets/*.age → root .env
  status        Check repo safety (exit 3 if plaintext is tracked)
  harden        Update .gitignore and install git hooks
  run           Run a command with secrets injected into its environment
  allow-prod    Write a timed production allow-token
  recipient     Manage persistent recipients (add / remove / list)
  rotate        Re-encrypt all secrets with the current recipients list
  keyring       Store/retrieve identity key in the OS keyring
  merge-driver  Git merge driver for key-level .env merges
  help          Print help
```

### `encrypt`

```
gitvault encrypt <FILE> [--recipient <PUBKEY>...] [--fields <FIELDS>] [--value-only]
```

**Whole-file mode** (default): reads `<FILE>`, encrypts it for all recipients, writes `secrets/<FILE>.age`.
If no `--recipient` is provided the local identity's public key is used.

**Field-level mode** (`--fields KEY1,KEY2`): for `.json`, `.yaml`/`.yml`, and `.toml` files, only
the specified fields are encrypted in-place using age ASCII armor. Unchanged fields keep their
existing ciphertext unchanged (REQ-5: deterministic, git-diff-friendly).

**Value-only mode** (`--value-only`): for `.env` files, encrypts each `KEY=VALUE` value
individually instead of the whole file.

### `decrypt`

```
gitvault decrypt <FILE> [--identity <KEY_FILE>] [--output <PATH>] [--fields <FIELDS>]
```

Decrypts `<FILE>`. Without `--fields`, strips the `.age` extension and writes plaintext.
With `--fields`, decrypts only the specified inline fields (JSON/YAML/TOML).
Identity is read from `--identity` or `GITVAULT_IDENTITY` env var.

### `materialize`

```
gitvault materialize [--env <ENV>] [--identity <KEY_FILE>] [--prod]
```

Decrypts every `secrets/*.age` file, parses `KEY=VALUE` pairs, and writes a deterministic root
`.env` (sorted keys, canonical quoting, `0600` permissions, atomic rename). Use `--prod` to
activate the production barrier check (REQ-13).

### `status`

```
gitvault status [--fail-if-dirty]
```

Reports the resolved environment and checks for tracked plaintext (exit `3` if found).
`--fail-if-dirty` also exits `3` if `secrets/` has uncommitted changes (REQ-32).

### `harden`

```
gitvault harden
```

Ensures `.env` and `.secrets/plain/` are in `.gitignore` and installs idempotent pre-commit /
pre-push hooks that block accidental plaintext commits and detect drift.

### `run`

```
gitvault run [--env <ENV>] [--identity <KEY_FILE>] [--prod] [--clear-env] [--pass <VARS>] -- <CMD> [ARGS...]
```

Decrypts secrets and injects them into `<CMD>`'s environment without writing `.env` (REQ-21).
Child exit code is propagated directly (REQ-23).

| Flag | Effect |
|------|--------|
| `--clear-env` | Start the child with an empty environment (REQ-24) |
| `--pass VARS` | Comma-separated vars to pass through when `--clear-env` is set (REQ-24) |
| `--prod` | Require production barrier (REQ-25) |

### `allow-prod`

```
gitvault allow-prod [--ttl <SECONDS>]
```

Writes a timed allow-token to `.secrets/.prod-token` (default TTL: 3600 s). While valid, `--prod`
commands skip the interactive confirmation prompt (REQ-14).

### `recipient`

```
gitvault recipient <add <PUBKEY> | remove <PUBKEY> | list>
```

Manages the persistent recipients file at `.secrets/recipients`. When `encrypt` or `rotate` is run
without `--recipient`, this file is used automatically.

```bash
gitvault recipient add age1abc...    # register a team member
gitvault recipient remove age1xyz... # revoke access (then rotate)
gitvault recipient list              # show current recipients
```

### `rotate`

```
gitvault rotate [--identity <KEY_FILE>]
```

Re-encrypts every `secrets/*.age` file with the current `.secrets/recipients` list (REQ-38).
Run after adding or removing a recipient to enforce the new access set.

### `keyring`

```
gitvault keyring <set [--identity <KEY_FILE>] | get | delete>
```

Stores or retrieves the age identity key in the OS keyring (macOS Keychain, Linux Secret Service,
Windows Credential Manager). Set `GITVAULT_KEYRING=1` to load the identity from the keyring
automatically instead of using `GITVAULT_IDENTITY` or `--identity` (REQ-39).

```bash
gitvault keyring set --identity ~/.age/identity.key  # store once
GITVAULT_KEYRING=1 gitvault materialize              # use keyring identity
gitvault keyring delete                              # remove
```

### `merge-driver`

```
gitvault merge-driver <BASE> <OURS> <THEIRS>
```

Runs as a Git merge driver performing key-level three-way merge of `.env` files (REQ-34).
Exit `0` on clean merge; exit `1` with conflict markers on same-key conflict.

Register once per repository:

```bash
git config merge.gitvault-env.driver "gitvault merge-driver %O %A %B"
echo '.env merge=gitvault-env' >> .gitattributes
```

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
| `3` | Plaintext secret detected in tracked files, or drift detected with `--fail-if-dirty` |
| `4` | Decryption error (wrong key, corrupt file) |
| `5` | Production barrier not satisfied (REQ-13) |

---

## Repository layout

```
<repo>/
├── secrets/               # encrypted artifacts (commit these; one .age per secret file)
│   ├── app.env.age
│   └── db.json.age
├── .secrets/
│   ├── recipients         # persistent recipient public keys (one per line)
│   ├── env                # active environment name (optional)
│   ├── .prod-token        # timed production allow-token (gitignored)
│   └── plain/
│       └── dev/           # decrypted plaintext (gitignored)
├── .env                   # materialized root env (gitignored)
├── .gitattributes         # optional: register merge driver for .env
└── .gitignore             # managed by `gitvault harden`
```

---

## Identity resolution

Priority order for loading the age identity:

| Priority | Source |
|----------|--------|
| 1 | `--identity <file>` flag |
| 2 | `GITVAULT_IDENTITY` environment variable (key file path or raw `AGE-SECRET-KEY-` string) |
| 3 | OS keyring when `GITVAULT_KEYRING=1` |

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