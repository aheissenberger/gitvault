# gitvault CLI Reference

→ [README](../README.md) for quick start and how-to guides navigation.

> **How-to guides:** [Identity Setup](identity-setup.md) · [CI/CD Recipes](cicd-recipes.md) · [Secret Formats](secret-formats.md) · [Recipient Management](recipient-management.md)

## Contents

- [Commands](#commands)
  - [Global Options](#global-options)
  - [init](#init)
  - [harden](#harden)
  - [encrypt](#encrypt)
  - [decrypt](#decrypt)
  - [materialize](#materialize)
  - [status](#status)
  - [run](#run)
  - [allow-prod / revoke-prod](#allow-prod--revoke-prod)
  - [recipient](#recipient)
  - [rekey](#rekey)
  - [keyring](#keyring)
  - [identity](#identity)
  - [check](#check)
  - [ai](#ai)
- [Environment Variables](#environment-variables)
- [Configuration Files](#configuration-files)
- [Exit Codes](#exit-codes)
- [Repository Layout](#repository-layout)
- [Identity Resolution](#identity-resolution)
- [Environment Resolution](#environment-resolution)

---

## Commands

### Global Options

These flags are accepted by every command.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | off | Output results as JSON |
| `--no-prompt` | off | Disable interactive prompts |
| `--identity-stdin` | off | Read identity key from stdin instead of a file path (pipe-friendly; stdin must not be a TTY) |
| `--identity-selector <FINGERPRINT\|COMMENT>` | — | Select which SSH-agent key to use when multiple keys are loaded. Also `GITVAULT_IDENTITY_SELECTOR` |

> **Feature-gated flags:** `--aws-profile` and `--aws-role-arn` are only available when compiled with `--features ssm`.

---

### init

Interactive onboarding: set up identity, recipients, harden repo, and create config.

```
gitvault init [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --env <ENV>` | — | Target environment to activate (writes to `.secrets/env`) |
| `--output <PATH>` | — | Export the newly created identity key to this file instead of storing in OS keyring |

---

### harden

Harden repository and optionally import plain files as encrypted secrets. When `FILES` are provided, each file is encrypted, removed from git tracking, and added to `.gitignore`. When omitted, only repo hardening (gitignore, hooks) is performed.

```
gitvault harden [OPTIONS] [FILES]...
```

| Flag | Default | Description |
|------|---------|-------------|
| `[FILES]...` | — | Plain text file(s) to encrypt and import (supports globs, e.g. `.env*`) |
| `-e, --env <ENV>` | — | Target environment for encrypted files (e.g. `--env dev`) |
| `-n, --dry-run` | off | Print what would happen without writing any files |
| `--delete-source` | off | Delete source file after encrypting (default: keep source) |
| `-r, --recipient <PUBKEY>` | — | Additional recipient keys (`age1…`) on top of `.secrets/recipients/` |

---

### encrypt

Encrypt a secret file.

```
gitvault encrypt [OPTIONS] <FILE>
```

| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | File to encrypt |
| `-r, --recipient <PUBKEY>` | local identity | Recipient age public key (repeat for multi-recipient) |
| `-e, --env <ENV>` | — | Environment to use (overrides `GITVAULT_ENV` and `.secrets/env`) |
| `--keep-path` | off | Preserve input path relative to repo root under `secrets/<env>/` |
| `--fields <FIELDS>` | — | Fields to encrypt (comma-separated key paths, for JSON/YAML/TOML field-level encryption) |
| `--value-only` | off | Encrypt `.env` values individually instead of whole-file |

---

### decrypt

Decrypt a `.age` encrypted file.

```
gitvault decrypt [OPTIONS] <FILE>
```

| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | Encrypted `.age` file to decrypt |
| `-i, --identity <IDENTITY>` | — | Identity key file path. Also `GITVAULT_IDENTITY` |
| `-o, --output [<OUTPUT>]` | strip `.age` extension | Output file path; use `-o -` to write to stdout |
| `--fields <FIELDS>` | — | Fields to decrypt (comma-separated key paths, for JSON/YAML/TOML) |
| `--reveal` | off | Print decrypted content to stdout instead of writing to file (shorthand for `-o -`) |
| `--value-only` | off | Decrypt `.env` values individually (reverse of `encrypt --value-only`) |

---

### materialize

Materialize secrets to root `.env`.

```
gitvault materialize [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --env <ENV>` | — | Environment to use (overrides `GITVAULT_ENV` and `.secrets/env`) |
| `-i, --identity <IDENTITY>` | — | Identity key file path. Also `GITVAULT_IDENTITY` |
| `--prod` | off | Require production barrier for prod env |

---

### status

Show repository safety status (gitignore, hooks, recipients, encrypted files).

```
gitvault status [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-if-dirty` | off | Exit with code `6` if `secrets/` directory has uncommitted changes |

---

### run

Run a command with secrets injected as environment variables. The `--` separator is required before the command.

```
gitvault run [OPTIONS] -- <COMMAND>...
```

| Flag | Default | Description |
|------|---------|-------------|
| `<COMMAND>...` | — | Command and arguments to run |
| `-e, --env <ENV>` | — | Environment to use |
| `-i, --identity <IDENTITY>` | — | Identity key file path. Also `GITVAULT_IDENTITY` |
| `--prod` | off | Require production barrier (pass when deploying to the prod environment) |
| `--clear-env` | off | Start child with empty environment |
| `--keep-vars <VARS>` | — | Comma-separated env vars to pass through when `--clear-env` is set |

---

### allow-prod / revoke-prod

Write or revoke a timed production allow token at `.git/gitvault/.prod-token`.

```
gitvault allow-prod [OPTIONS]
gitvault revoke-prod [OPTIONS]
```

**allow-prod flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--ttl <TTL>` | `3600` | Token lifetime in seconds (config: `barrier.ttl_secs`) |

`revoke-prod` takes no additional flags beyond global options.

---

### recipient

Manage persistent recipients.

```
gitvault recipient <SUBCOMMAND>
```

| Subcommand | Description |
|-----------|-------------|
| `add <PUBKEY>` | Add a recipient age public key (`age1…`) |
| `remove <PUBKEY>` | Remove a recipient age public key (`age1…`) |
| `list` | List current recipients |
| `add-self` | Add own public key to the recipients directory |

---

### rekey

Re-encrypt all secrets with the current recipients list.

```
gitvault rekey [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --identity <IDENTITY>` | — | Identity key file path. Also `GITVAULT_IDENTITY` |
| `-e, --env <ENV>` | — | Only rekey files in the given environment subtree (e.g. `--env dev`) |
| `-n, --dry-run` | off | Print what would be rekeyed without writing any files |

---

### keyring

Manage identity key in OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager).

```
gitvault keyring <SUBCOMMAND>
```

| Subcommand | Description |
|-----------|-------------|
| `set [-i, --identity <IDENTITY>]` | Store identity key in OS keyring |
| `get` | Show public key of stored identity |
| `delete` | Remove stored identity from OS keyring |
| `set-passphrase` | Store the SSH identity file passphrase in OS keyring; retrieved automatically when loading an encrypted SSH identity |
| `get-passphrase` | Show whether an SSH identity passphrase is stored (does not print the value) |
| `delete-passphrase` | Remove the stored SSH identity passphrase from OS keyring |

---

### identity

Manage local identity keys.

```
gitvault identity <SUBCOMMAND>
```

**`identity create` flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--profile <PROFILE>` | `classic` | Identity profile: `classic` (age X25519) or `hybrid` (age X25519 with post-quantum-ready annotation) |
| `--output <PATH>` | — | Export identity to file (default: store in OS keyring) |
| `--add-recipient` | off | After creating identity, add own public key to `.secrets/recipients/` (equivalent to `recipient add-self`) |

**`identity pubkey`:** Print the age public key of the current identity. No additional flags.

---

### check

Run preflight validation without side effects.

```
gitvault check [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --env <ENV>` | — | Environment to validate |
| `-i, --identity <IDENTITY>` | — | Identity key file path. Also `GITVAULT_IDENTITY` |
| `-H, --skip-history-check` | off | Skip the committed-history plaintext leak scan |

---

### ai

AI tooling: print skill or context files for Copilot/agent integration.

```
gitvault ai <SUBCOMMAND>
```

| Subcommand | Description |
|-----------|-------------|
| `skill` | Print canonical gitvault skill content for Copilot usage |
| `context` | Print concise project AI context for agent onboarding |

---

## Environment Variables

Precedence (highest → lowest): CLI flag → `GITVAULT_*` env var → project `.gitvault/config.toml` → user-global `~/.config/gitvault/config.toml` → built-in default.

| Variable | Default | Description |
|----------|---------|-------------|
| `GITVAULT_ENV` | `dev` | Active environment (overrides config `[env] default`) |
| `GITVAULT_IDENTITY` | — | Identity key file path or raw `AGE-SECRET-KEY-…` string |
| `GITVAULT_IDENTITY_FD` | — | Unix only: file descriptor number to read the identity key from |
| `GITVAULT_IDENTITY_PASSPHRASE` | — | SSH identity file passphrase (CI-safe; emits a warning — suppress with `GITVAULT_NO_PASSPHRASE_WARN=1`) |
| `GITVAULT_IDENTITY_PASSPHRASE_FD` | — | Unix only: file descriptor number to read the SSH passphrase from |
| `GITVAULT_IDENTITY_SELECTOR` | — | Select SSH-agent key by fingerprint or comment |
| `GITVAULT_SSH_AGENT` | off | Set to `1` to enable SSH-agent identity lookup |
| `GITVAULT_NO_INLINE_KEY_WARN=1` | — | Suppress warning emitted when a raw key is passed via `GITVAULT_IDENTITY` |
| `GITVAULT_NO_PASSPHRASE_WARN=1` | — | Suppress warning emitted when `GITVAULT_IDENTITY_PASSPHRASE` is set |
| `CI=1` | — | Auto-enables non-interactive mode (equivalent to `--no-prompt`; most CI systems set this automatically) |
| `AWS_PROFILE` | — | AWS profile for SSM commands (`--features ssm`) |
| `AWS_ROLE_ARN` | — | AWS role ARN for SSM commands (`--features ssm`) |

---

## Configuration Files

Two optional TOML config layers; missing files or sections silently use built-in defaults.

| File | Scope |
|------|-------|
| `.gitvault/config.toml` | Repository-level; commit with the project |
| `~/.config/gitvault/config.toml` | User-global; personal defaults for all repos |

**Full TOML key reference:**

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[env]` | `default` | `"dev"` | Default active environment |
| `[env]` | `prod_name` | `"prod"` | Name that triggers the production barrier |
| `[env]` | `env_file` | `".git/gitvault/env"` | Path to the env-name file |
| `[barrier]` | `ttl_secs` | `3600` | Production allow-token lifetime in seconds |
| `[paths]` | `recipients_dir` | `".gitvault/recipients"` | Recipients directory |
| `[paths]` | `materialize_output` | `".env"` | Output file for `materialize` |
| `[keyring]` | `service` | `"gitvault"` | OS keyring service name |
| `[keyring]` | `account` | `"age-identity"` | OS keyring account name |
| `[hooks]` | `adapter` | *(none)* | Hook manager: `husky`, `pre-commit`, or `lefthook` |

> **Validation:** Unknown keys inside a known section produce a `Usage` error (exit `2`). Unknown top-level sections are silently ignored for forward compatibility.

Hook manager adapters require the corresponding binary on `PATH` (`gitvault-husky`, `gitvault-pre-commit`, `gitvault-lefthook`).

**Repository-level example:**

```toml
# .gitvault/config.toml

[env]
default = "staging"         # default environment (built-in: "dev")
prod_name = "production"    # name that triggers the production barrier (built-in: "prod")
env_file = ".config/env"    # path to env-name file (built-in: ".git/gitvault/env")

[barrier]
ttl_secs = 1800             # production allow-token lifetime in seconds (built-in: 3600)

[paths]
materialize_output = ".env.local"            # built-in: ".env"
recipients_dir = ".gitvault/recipients"      # built-in: ".gitvault/recipients"

[hooks]
adapter = "husky"           # hook manager: husky | pre-commit | lefthook
```

**User-global example:**

```toml
# ~/.config/gitvault/config.toml
[keyring]
service = "my-company-gitvault"   # avoid collisions with other gitvault instances
account = "default-identity"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (I/O, encryption failure) |
| `2` | Usage / argument error |
| `3` | Plaintext secret detected in tracked files or committed history |
| `4` | Decryption error (wrong key, corrupt file) |
| `5` | Production barrier not satisfied |
| `6` | Secrets drift detected (uncommitted changes in encrypted files) |

---

## Repository Layout

```
<repo>/
├── .gitvault/
│   ├── store/<env>/         # encrypted artifacts (commit these)
│   │   └── app.env.age
│   ├── recipients/          # one .pub file per recipient (commit these)
│   │   ├── alice.pub
│   │   └── bob.pub
│   ├── plain/<env>/         # decrypted plaintext (gitignored)
│   └── config.toml          # optional repo-level config
├── .git/gitvault/
│   ├── env                  # active environment name (optional, gitignored)
│   └── .prod-token          # timed production allow-token (gitignored)
├── .env                     # materialized root env (gitignored)
├── .gitattributes           # optional: register merge driver for .env
└── .gitignore               # managed by `gitvault harden`
```

---

## Identity Resolution

Priority order for loading the age identity (highest → lowest):

| Priority | Source |
|----------|--------|
| 0 | `--identity-stdin` global flag (pipe-friendly; stdin must not be a TTY) |
| 1 | `-i, --identity <FILE>` flag |
| 1b | `GITVAULT_IDENTITY_FD` (Unix only: file descriptor number; key is read from the FD) |
| 2 | `GITVAULT_IDENTITY` environment variable (key file path or raw `AGE-SECRET-KEY-…` string) |
| 3 | OS keyring (always tried automatically) |
| 4 | SSH-agent when `GITVAULT_SSH_AGENT=1` or `SSH_AUTH_SOCK` is set |

> **Security note:** Using a raw `AGE-SECRET-KEY-…` inline in `GITVAULT_IDENTITY` exposes the key in process listings and shell history. Prefer `GITVAULT_IDENTITY_FD` (Unix) or a key file path. A warning is emitted when an inline key is detected; suppress with `GITVAULT_NO_INLINE_KEY_WARN=1`.

**SSH passphrase unlock (highest → lowest priority):**

| Priority | Source |
|----------|--------|
| 1a | `GITVAULT_IDENTITY_PASSPHRASE_FD` (Unix only) |
| 1b | `GITVAULT_IDENTITY_PASSPHRASE` env var (CI-safe; warns if set — suppress with `GITVAULT_NO_PASSPHRASE_WARN=1`) |
| 2 | OS keyring passphrase store |

In CI (`--no-prompt` / `CI=1`) only the env var / FD sources are tried.

Manage the stored passphrase with:

```bash
gitvault keyring set-passphrase [<passphrase>]   # store (omit arg to read from env var)
gitvault keyring get-passphrase                  # check if stored
gitvault keyring delete-passphrase               # remove
```

---

## Environment Resolution

The active environment is resolved in this order (first match wins):

1. `-e, --env <ENV>` flag on individual commands (`encrypt`, `materialize`, `run`, `check`)
2. `GITVAULT_ENV` environment variable
3. `.git/gitvault/env` file (per-worktree; written by `init --env` or manually)
4. `[env] default` in config files
5. Built-in default: `dev`

Each Git worktree resolves its active environment independently.
