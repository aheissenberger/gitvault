# gitvault

A Git-native secrets manager for multi-developer and multi-agent workflows. Secrets are encrypted
with [age](https://age-encryption.org) and stored in your repository — never plaintext.

## Features (implementation highlights)

- **age encryption** — standard file format, native Rust, no external binaries required
- **Multi-recipient** — encrypt once for every team member; any recipient can decrypt
- **Field-level encryption** — encrypt individual fields in JSON, YAML, and TOML files; values
  stored as age ASCII armor inline in the document
- **Deterministic re-encryption** — unchanged field values retain existing ciphertext so git diffs
  stay minimal
- **Whole-file / value-only modes** — `.env` files default to whole-file encryption; opt in to
  per-value encryption with `--value-only`
- **Repository layout** — encrypted artifacts under `secrets/<env>/` (with legacy `secrets/*.age`
  fallback), plaintext outputs under `.secrets/plain/<env>/`; one `.age` file per secret
- **Plaintext leak detection** — refuses to operate if `.env` or plaintext secrets are tracked by
  Git
- **Environment model** — resolves active environment from `GITVAULT_ENV` → `.secrets/env` → `dev`;
  each worktree is independent
- **Production barrier** — timed allow-token required to materialize or run against `prod`;
  interactive confirmation fallback
- **Production token revoke** — `revoke-prod` removes the allow-token immediately
- **Root `.env` materialization** — atomic write, restricted permissions (`0600` on POSIX,
  restricted ACL on Windows), deterministic sorted output, auto-added to `.gitignore`
- **Fileless run mode** — injects secrets directly into child process environment without writing
  `.env`; supports `--clear-env` and `--pass`
- **Git hooks + merge driver** — `harden` installs pre-commit / pre-push hooks (`pre-push`
  enforces drift checks with `--fail-if-dirty`); optional `gitvault merge-driver` for key-level
  `.env` merges
- **Recipient management** — persistent `.secrets/recipients` file; `recipient add/remove/list`;
  `rotate` re-encrypts all secrets for the current recipient set
- **OS keyring** — `keyring set/get/delete`; `GITVAULT_KEYRING=1` loads identity from system
  keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager)
- **Identity bootstrap** — `identity create` generates local identities (classic/hybrid profile)
  and can store to keyring or export to file
- **Security hardening** — fail-closed on decrypt error, `--reveal` required to print secrets,
  path-traversal guard, atomic writes everywhere, `status` never decrypts
- **JSON output & non-interactive mode** — all commands accept `--json` and `--no-prompt`;
  `CI=true` auto-enables non-interactive mode
- **Preflight check** — `gitvault check` validates identity, recipients, and secrets dir without
  side effects
- **Streaming crypto** — encryption and decryption are streaming-capable; no full-file buffering
  for large files
- **AWS SSM backend** — `gitvault ssm pull/push/diff/set` sync secrets with AWS SSM Parameter Store;
  enable with `--features ssm`; uses `--aws-profile` / `--aws-role-arn`
- **Signed releases** — CI produces cosign-signed binaries for Linux, macOS, and Windows
- **Format versioning** — format version visible in `gitvault --version` output
- **Build metadata in version output** — `gitvault --version --long` includes git SHA and commit date
- **Tag/version release gate** — `cargo xtask release-check` enforces `Cargo.toml` version ↔ git tag parity (`vX.Y.Z`), clean tree, and annotated tags
- **Stable exit codes** — documented, machine-readable
- **Spec gate** — `cargo xtask spec-verify` enforces frontmatter on every requirement spec

---

## Installation

### macOS (Homebrew)

```bash
# 1) Add the tap that publishes gitvault formula updates
brew tap aheissenberger/tools

# 2) Install
brew install gitvault

# 3) Verify
gitvault --version
```

One-line install (without pre-tapping):

```bash
brew install aheissenberger/tools/gitvault
```

### Build from source (all platforms)

```bash
cargo build --release
# binary is at target/release/gitvault (or /workspaces/.cargo-target/release/gitvault in devcontainer)
```

### Download prebuilt binaries (GitHub Releases)

Prefer compressed assets for smaller downloads:

- Linux: `gitvault-linux-x86_64.tar.gz`
- macOS Apple Silicon: `gitvault-macos-aarch64.tar.gz`
- macOS Intel: `gitvault-macos-x86_64.tar.gz`
- Windows: `gitvault-windows-x86_64.zip`

All assets are published with `SHA256SUMS` plus Sigstore cosign `.sig` / `.pem` files.

---

## Quick start

### 1 — Generate an age identity (one-time per developer)

```bash
# Using the builtin identity command:
gitvault identity create
# Your identity is saved and public key is printed — share it with team members for multi-recipient encryption.

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
# Output: secrets/<active-env>/app.env.age  (safe to commit)

# Encrypt into a specific environment:
gitvault encrypt app.env --env staging --recipient age1abc...
# Output: secrets/staging/app.env.age

# Field-level encryption (JSON/YAML/TOML — only named fields are encrypted):
gitvault encrypt config.json --fields db.password,api_key \
  --recipient age1abc...
# Only the db.password and api_key values are replaced with age armor inline.
# Repeat runs leave unchanged fields identical in git diff.
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

Core options (available on all commands):
  --json
  --no-prompt
  --identity-selector <IDENTITY_SELECTOR>
  --aws-profile <AWS_PROFILE>
  --aws-role-arn <AWS_ROLE_ARN>

Commands:
  encrypt       Encrypt a secret file
  decrypt       Decrypt a .age encrypted file
  materialize   Materialize secrets to root .env
  status        Check repository safety status
  harden        Harden repository (update .gitignore, install hooks)
  run           Run a command with secrets injected as environment variables
  allow-prod    Write a timed production allow token
  revoke-prod   Revoke the production allow token immediately
  merge-driver  Run as git merge driver for .env files
  recipient     Manage persistent recipients
  rotate        Re-encrypt all secrets with the current recipients list
  keyring       Manage identity key in OS keyring
  identity      Manage local identity keys (`identity create`)
  check         Run preflight validation without side effects
  ai            AI tooling helpers (skill and context print)
  help          Print help
```

> This section is synchronized with live CLI help output (`gitvault --help`, `gitvault <command> --help`).
> If built with `--features ssm`, an additional `ssm` command group is available.

### Operator quick map

| Task | Command |
|------|---------|
| Encrypt whole file | `gitvault encrypt <file> -r <age_pubkey>` |
| Encrypt selected fields (JSON/YAML/TOML) | `gitvault encrypt <file> --fields a.b,c` |
| Encrypt `.env` per value | `gitvault encrypt .env --value-only` |
| Decrypt to file | `gitvault decrypt <file.age> -i <identity>` |
| Decrypt and print to stdout | `gitvault decrypt <file.age> --reveal` |
| Materialize root `.env` | `gitvault materialize -i <identity>` |
| Run command with injected secrets | `gitvault run -- <cmd> [args...]` |
| Strict safety check (CI-friendly) | `gitvault status --fail-if-dirty --no-prompt` |
| Validate setup without changes | `gitvault check [--env <env>]` |
| Enable prod operation window | `gitvault allow-prod [--ttl <secs>]` |
| Revoke prod operation window | `gitvault revoke-prod` |
| Manage recipients | `gitvault recipient add|remove|list ...` |
| Re-encrypt after recipient changes | `gitvault rotate -i <identity>` |
| Store/use OS keyring identity | `gitvault keyring set|get|delete` + `GITVAULT_KEYRING=1 ...` |
| Create new identity | `gitvault identity create [--profile classic|hybrid]` |
| Print embedded skill reference      | `gitvault ai skill print` |
| Print embedded agent context        | `gitvault ai context print` |

### High-signal command details

- `encrypt`: supports `--env`, `--keep-path`, `--fields`, and `--value-only`.
- `decrypt`: supports optional `--output [path]`, `--fields`, `--value-only`, and `--reveal`.
- `run`: supports `--clear-env` plus `--pass <VARS>` for controlled pass-through.
- `harden`: installs/updates hooks; with adapter config it delegates to external hook manager.
- `merge-driver`: repository registration shortcut is `gitvault harden`.
- `ai`: `skill print` and `context print` emit content embedded at compile time; use `--json` for MCP-style envelope output.

---

## Environment variables

### `GITVAULT_*`

| Variable | Purpose |
|----------|---------|
| `GITVAULT_ENV` | Active environment name; overrides `.secrets/env` file and the `dev` default |
| `GITVAULT_IDENTITY` | Path to age identity key file (alternative to `--identity`) |
| `GITVAULT_IDENTITY_SELECTOR` | SSH-agent key selector for disambiguation (alternative to `--identity-selector`) |
| `GITVAULT_SSH_AGENT` | Set to `1` to enable SSH-agent as an identity source |

### System

| Variable | Purpose |
|----------|---------|
| `CI` | Set to `1`, `true`, or `yes` to enable non-interactive mode automatically |
| `SSH_AUTH_SOCK` | Standard SSH socket; presence enables SSH-agent as an identity source |
| `AWS_PROFILE` | AWS profile for the SSM backend (alternative to `--aws-profile`) |
| `AWS_ROLE_ARN` | AWS role ARN to assume for the SSM backend (alternative to `--aws-role-arn`) |

## Environment resolution

Priority order:

| Priority | Source |
|----------|--------|
| 1 | `GITVAULT_ENV` environment variable |
| 2 | `.secrets/env` file in the worktree root |
| 3 | `dev` (default) |

Each Git worktree resolves its environment independently. The active environment can also be overridden per-command with `--env` (on `encrypt`, `materialize`, `run`, and `check`).

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (I/O, encryption failure) |
| `2` | Usage / argument error |
| `3` | Plaintext secret detected in tracked files |
| `4` | Decryption error (wrong key, corrupt file) |
| `5` | Production barrier not satisfied |
| `6` | Secrets drift detected (uncommitted changes in encrypted files) |

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

## Configuration

gitvault supports two optional TOML configuration file layers. Both files are optional — a missing file (or missing section) silently uses built-in defaults.

| File | Scope |
|------|-------|
| `.gitvault/config.toml` | Repository-level; committed with the project |
| `~/.config/gitvault/config.toml` | User-global; personal defaults for all repos |

**Precedence** (highest → lowest):

1. CLI flags / environment variables
2. Project `.gitvault/config.toml`
3. User-global `~/.config/gitvault/config.toml`
4. Built-in defaults

---

### `[env]` section

Controls environment resolution (which environment name is active).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default` | string | `dev` | Environment name used when neither `GITVAULT_ENV` nor the `.secrets/env` file is set. |
| `prod_name` | string | `prod` | The environment name that triggers the production barrier check. Change this if your production environment is named differently (e.g. `production`). |
| `env_file` | string | `.secrets/env` | Repository-relative path of the file that stores the active environment name. |

**Example:**

```toml
# .gitvault/config.toml
[env]
default = "staging"         # treat staging as the default environment
prod_name = "production"    # barrier triggers on "production" instead of "prod"
```

---

### `[barrier]` section

Controls the production allow-token behaviour.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ttl_secs` | integer | `3600` | Lifetime in seconds for a production allow-token written by `gitvault allow-prod`. The `--ttl` flag overrides this per invocation. |

**Example:**

```toml
# .gitvault/config.toml
[barrier]
ttl_secs = 1800   # 30-minute production windows instead of 60
```

---

### `[paths]` section

Controls repository-relative file locations.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `recipients_file` | string | `.secrets/recipients` | Repository-relative path of the persistent recipients list read and written by `recipient add/remove/list` and `rotate`. |
| `materialize_output` | string | `.env` | Repository-relative path written by `gitvault materialize`. Change to `.env.local` or any other filename your toolchain expects. |

**Example:**

```toml
# .gitvault/config.toml
[paths]
materialize_output = ".env.local"
recipients_file = ".gitvault/recipients"
```

---

### `[keyring]` section

Controls which OS keyring slot gitvault uses to store and retrieve the age identity.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `service` | string | `gitvault` | OS keyring service name used to namespace gitvault credentials. |
| `account` | string | `age-identity` | OS keyring account / username under which the age identity key is stored. |

**Example:**

```toml
# ~/.config/gitvault/config.toml
[keyring]
service = "my-company-gitvault"   # avoid collisions if running multiple gitvault instances
account = "default-identity"
```

---

### `[hooks]` section

Controls how `gitvault harden` installs Git hooks into the repository.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `adapter` | string | *(none)* | Hook-manager adapter to delegate to. When set, `gitvault harden` delegates to the adapter's binary instead of writing native Git hooks directly. Accepted values: `husky`, `pre-commit`, `lefthook`. An empty string is treated as unset and the next precedence layer applies. |

**Adapter binaries invoked:**

| Value | Binary on `PATH` |
|-------|-----------------|
| `husky` | `gitvault-husky` |
| `pre-commit` | `gitvault-pre-commit` |
| `lefthook` | `gitvault-lefthook` |

**Example — project config:**

```toml
# .gitvault/config.toml
[hooks]
adapter = "husky"   # delegate hook installation to gitvault-husky
```

**Example — user-global config:**

```toml
# ~/.config/gitvault/config.toml
[hooks]
adapter = "lefthook"   # personal default; overridden by any project config
```

> **Validation:** unknown keys inside any known section produce a `Usage` error (exit `2`) with an actionable message. Unknown top-level sections are silently ignored for forward compatibility.

---

## Contributor and maintainer docs

- Development workflows (sandbox, verification commands, xtask, worktrees, local environment):
  [docs/development.md](docs/development.md)
- AI agent onboarding and architecture hotspots:
  [docs/ai/AGENT_START.md](docs/ai/AGENT_START.md), [docs/ai/hotspots.md](docs/ai/hotspots.md)
- Regenerate AI code index map:
  `cargo xtask ai-index` → `docs/ai/code-index.json`
- Maintainer release and CI/CD runbook (versioning/tags, release checklist, workflows, secrets):
  [docs/releasing.md](docs/releasing.md)
