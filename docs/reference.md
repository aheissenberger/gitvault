# gitvault CLI Reference

> **[← README](../README.md)** · [Identity Setup](identity-setup.md) · [Recipient Management](recipient-management.md) · [CI/CD Recipes](cicd-recipes.md) · [Seal vs Encrypt](seal-vs-encrypt.md) · CLI Reference

Use this file as the canonical command reference. For task-oriented examples, see `README.md` and the guides in `docs/`.

## Source of Truth

Regenerate command metadata before editing CLI docs:

```bash
cargo xtask cli-help
```

Generated file:
- `docs/ai/cli-help.json`

## Table of Contents

- [Source of Truth](#source-of-truth)
- [Commands](#commands)
- [Global Options](#global-options)
- [Command Details](#command-details)
  - [`encrypt`](#encrypt)
  - [`decrypt`](#decrypt)
  - [`seal`](#seal)
  - [`unseal`](#unseal)
  - [`edit`](#edit)
  - [`get`](#get)
  - [`set`](#set)
  - [`materialize`](#materialize)
  - [`status`](#status)
  - [`init`](#init)
  - [`harden`](#harden)
  - [`run`](#run)
  - [`allow-prod` / `revoke-prod`](#allow-prod--revoke-prod)
  - [`recipient`](#recipient)
  - [`rekey`](#rekey)
  - [`keyring`](#keyring)
  - [`check`](#check)
  - [`identity`](#identity)
  - [`ai`](#ai)
  - [`ssm` (feature-gated)](#ssm-feature-gated)
- [Environment Variables](#environment-variables)
- [Configuration File](#configuration-file)
  - [`[hooks]`](#hooks)
  - [`[env]`](#env)
  - [`[barrier]`](#barrier)
  - [`[paths]`](#paths)
  - [`[keyring]`](#keyring-1)
  - [Rule-based command filtering (`[[seal.rule]]`, `[[materialize.rule]]`, `[[run.rule]]`)](#rule-based-command-filtering-sealrule-materializerule-runrule)
  - [`[materialize]`](#materialize-1)
  - [`[run]`](#run-1)
  - [`[editor]`](#editor)
- [Complete Example](#complete-example)
- [Exit Codes](#exit-codes)
- [Identity Resolution](#identity-resolution)

## Commands

```text
gitvault [OPTIONS] <COMMAND>
```

Top-level commands:
- `encrypt`
- `decrypt`
- `materialize`
- `status`
- `init`
- `harden`
- `run`
- `allow-prod`
- `revoke-prod`
- `recipient`
- `rekey`
- `keyring`
- `check`
- `identity`
- `ai`
- `seal`
- `unseal`
- `edit`
- `get`
- `set`
- `ssm` (feature-gated with `--features ssm`)

## Global Options

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |
| `--no-prompt` | Disable interactive prompts |
| `--identity-selector <IDENTITY_SELECTOR>` | Select which SSH-agent key to use, by fingerprint or comment |
| `--identity-stdin` | Read identity key from stdin instead of a file path |

Feature-gated globals (`--features ssm`):
- `--aws-profile <AWS_PROFILE>`
- `--aws-role-arn <AWS_ROLE_ARN>`

## Command Details

### `encrypt`

```bash
gitvault encrypt [OPTIONS] <FILE>
```

| Flag | Description |
|------|-------------|
| `<FILE>` | File to encrypt |
| `-r, --recipient <PUBKEY>` | Recipient age public key (repeat for multi-recipient; defaults to local identity if omitted) |
| `-e, --env <ENV>` | Environment to use (overrides `GITVAULT_ENV` and `.git/gitvault/env`) |

Notes:
- Stores encrypted output under `.gitvault/store/<env>/` and mirrors the source path.
- For in-place field/value encryption of JSON/YAML/TOML/.env, use `seal`.

### `decrypt`

```bash
gitvault decrypt [OPTIONS] <FILE>
```

| Flag | Description |
|------|-------------|
| `<FILE>` | Original source path (for store lookup) or explicit `.age` store path |
| `-i, --identity <IDENTITY>` | Identity key file path (or `GITVAULT_IDENTITY`) |
| `-e, --env <ENV>` | Environment for store path resolution |
| `--reveal` | Print decrypted content to stdout instead of writing to `.git/gitvault/plain/` |

Notes:
- For in-place field/value decryption of JSON/YAML/TOML/.env, use `unseal`.

### `seal`

```bash
gitvault seal [OPTIONS] <FILE>
```

| Flag | Description |
|------|-------------|
| `<FILE>` | File to seal (`.json`, `.yaml`, `.yml`, `.toml`, `.env`, `.env.<suffix>`) |
| `-r, --recipient <PUBKEY>` | Additional recipient age public keys (repeat for multiple) |
| `-e, --env <ENV>` | Environment to use for recipient key resolution |
| `--fields <FIELDS>` | Only seal listed dot-path fields (comma-separated) |

### `unseal`

```bash
gitvault unseal [OPTIONS] <FILE>
```

| Flag | Description |
|------|-------------|
| `<FILE>` | File to unseal |
| `-i, --identity <IDENTITY>` | Identity key file path (or `GITVAULT_IDENTITY`) |
| `--fields <FIELDS>` | Only decrypt listed fields (comma-separated) |
| `--reveal` | Print decrypted content to stdout instead of writing back to file |

### `edit`

Open a sealed or encrypted file in an editor, then re-seal / re-encrypt on save.

```bash
gitvault edit [OPTIONS] <FILE>
```

| Flag | Description |
|------|-------------|
| `<FILE>` | File to edit — sealed format (`.json`, `.yaml`, `.yml`, `.toml`, `.env`) **or** `.age` store file / source path |
| `-i, --identity <IDENTITY>` | Identity key file path (or `GITVAULT_IDENTITY`) |
| `-e, --env <ENV>` | Environment for store-path resolution and recipient lookup |
| `--fields <FIELDS>` | Only unseal/re-seal listed dot-path fields (sealed-file mode only) |
| `--editor <CMD>` | Override editor command for this run |

**Input modes** (auto-detected by file extension):

- **Sealed-file mode** (`.json`, `.yaml`, `.yml`, `.toml`, `.env`): values are decrypted in
  memory, written to a temp file, opened in the editor, then re-sealed on save.
- **Store-file mode** (`.age` extension or source path that resolves to `.gitvault/store/`):
  the archive is decrypted, written to a temp file, opened in the editor, then re-encrypted
  to the same store path on save.

The temp file is created in `$TMPDIR/<random>/` with the **same filename** as the original
(e.g. editing `conf/dbsecrets.json` creates `$TMPDIR/<random>/dbsecrets.json`), so editors
apply correct syntax highlighting.

**Editor resolution** (first non-empty wins, all platforms):

1. `--editor <CMD>` CLI flag
2. `[editor] command` in `.gitvault/config.toml`
3. `$VISUAL` environment variable
4. `$EDITOR` environment variable
5. Platform fallback: `open -W -n` (macOS), `notepad.exe` (Windows), `vi` (Linux/other)

```toml
# .gitvault/config.toml
[editor]
command = "code --wait"
```

Notes:
- `--fields` is not supported in store-file mode (edit the full decrypted content directly).
- If content is unchanged after the editor exits, no re-sealing or re-encrypting occurs.
- The temp file is zeroized (overwritten with zeros) and deleted before the command exits.

### `get`

Read the plaintext value of a single key from a sealed or encrypted file.

```bash
gitvault get [OPTIONS] <FILE> <KEY>
```

| Flag | Description |
|------|-------------|
| `<FILE>` | Sealed file or `.age` store file / source path |
| `<KEY>` | Dot-path key for JSON/YAML/TOML (e.g. `db.password`), variable name for `.env` |
| `-i, --identity <IDENTITY>` | Identity key file path (or `GITVAULT_IDENTITY`) |
| `-e, --env <ENV>` | Environment for store-path resolution |
| `--json` | Output `{"file":…,"key":…,"value":…}` instead of raw value |

Prints the raw plaintext value to stdout followed by a newline — ideal for shell assignments:

```bash
export DB_PASS=$(gitvault get conf/secrets.json db.password)
```

**Key format** by file type:

| File type | Example key |
|-----------|-------------|
| `.json` | `db.password` or `server.port` |
| `.yaml` / `.yml` | `server.tls.cert` |
| `.toml` | `database.password` |
| `.env` | `API_KEY` (no dot-path) |
| `.age` (store) | Same rules as the stem extension (`secrets.json.age` → JSON rules) |

Notes:
- Exits with error if `<KEY>` does not exist in the file.
- Dot-path keys are not supported for `.env` files.

### `set`

Update or create a single key's value in a sealed or encrypted file.

```bash
gitvault set [OPTIONS] <FILE> <KEY> [VALUE]
```

| Flag | Description |
|------|-------------|
| `<FILE>` | Sealed file or `.age` store file / source path |
| `<KEY>` | Dot-path key for JSON/YAML/TOML, variable name for `.env` |
| `[VALUE]` | New value (omit when using `--stdin`) |
| `--stdin` | Read new value from stdin — recommended for secrets (avoids shell history) |
| `-i, --identity <IDENTITY>` | Identity key file path (or `GITVAULT_IDENTITY`) |
| `-e, --env <ENV>` | Environment for store-path resolution |

**Upsert semantics**: if the key exists its value is updated; if it is absent a new entry is
created at the top level. Nested path creation (multi-segment paths to a non-existent parent)
is not supported — create the parent key manually first.

```bash
# Positional value
gitvault set conf/secrets.json db.password newpass

# Stdin (recommended for secrets — avoids shell history)
echo "newpass" | gitvault set conf/secrets.json db.password --stdin

# Store file
gitvault set .gitvault/store/prod/config.json.age db.password --stdin --env prod
```

Notes:
- TOML files are updated with `toml_edit`, preserving comments and formatting.
- `.env` files preserve all comment lines, blank lines, and variable ordering.
- The file is re-sealed / re-encrypted atomically after the update.

### `materialize`

```bash
gitvault materialize [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-e, --env <ENV>` | Environment to use |
| `-i, --identity <IDENTITY>` | Identity key file path |
| `--prod` | Require production barrier for prod env |

Behavior:
- Decrypts store files for the selected environment and writes merged values to
  `[materialize].output_filename` (default: `.env`).
- Supports multi-format store sources (`.env.age`, `.json.age`, `.yaml/.yml.age`, `.toml.age`).
- `[[materialize.rule]]` can also select sealed repository files with `source = "sealed"`.
- For sealed sources, `path` is matched against repository-relative working-tree paths.
- Fails if decryption fails or secret content is invalid for its detected format.

Examples:

```bash
# Default output (.env)
gitvault materialize --env dev

# CI-style identity injection without writing key to environment
GITVAULT_IDENTITY_FD=3 gitvault materialize --no-prompt --env prod 3<<<"$SECRET_KEY"
```

### `status`

```bash
gitvault status [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--fail-if-dirty` | Exit with code `6` if `.gitvault/store/` has uncommitted changes |

### `init`

```bash
gitvault init [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-e, --env <ENV>` | Target environment to activate (writes to `.git/gitvault/env`) |
| `--output <PATH>` | Export new identity key to this file instead of OS keyring |

Notes:
- On first run, `init` writes `.gitvault/config.toml` with commented (deactivated) starter examples for `[[seal.rule]]`, `[[materialize.rule]]`, and `[[run.rule]]`.
- Uncomment and adapt those rule blocks when you are ready to enforce filtering/prefix behavior.

### `harden`

```bash
gitvault harden [OPTIONS] [FILES]...
```

| Flag | Description |
|------|-------------|
| `[FILES]...` | Plain-text file(s) to encrypt and import |
| `-e, --env <ENV>` | Target environment for encrypted files |
| `-n, --dry-run` | Print what would happen without writing files |
| `--delete-source` | Delete source file after encrypting |
| `-r, --recipient <PUBKEY>` | Additional recipient keys on top of `.gitvault/recipients/` |

### `run`

```bash
gitvault run [OPTIONS] -- <COMMAND>...
```

| Flag | Description |
|------|-------------|
| `<COMMAND>...` | Command and arguments to run |
| `-e, --env <ENV>` | Environment to use |
| `-i, --identity <IDENTITY>` | Identity key file path |
| `--prod` | Require production barrier |
| `--clear-env` | Start child with empty environment |
| `--keep-vars <VARS>` | Comma-separated env vars to pass through when `--clear-env` is set |

Behavior:
- Decrypts secrets for the selected environment and injects them into the child process env.
- Does not write plaintext files to disk.
- Uses the same multi-format store parsing as `materialize`.
- `[[run.rule]]` can also select sealed repository files with `source = "sealed"`.
- For sealed sources, `path` is matched against repository-relative working-tree paths.

Examples:

```bash
# Inject secrets into a process while keeping inherited env vars
gitvault run --env dev -- node server.js

# Strict environment with selected pass-through vars
gitvault run --env prod --clear-env --keep-vars PATH,HOME -- ./bin/service
```

### `allow-prod` / `revoke-prod`

```bash
gitvault allow-prod [OPTIONS]
gitvault revoke-prod
```

`allow-prod` options:
- `--ttl <TTL>` token lifetime in seconds (default from config `barrier.ttl_secs`, then `3600`).

### `recipient`

```bash
gitvault recipient <SUBCOMMAND>
```

Subcommands:
- `add <PUBKEY>`
- `remove <PUBKEY>`
- `list`
- `add-self`

### `rekey`

```bash
gitvault rekey [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-i, --identity <IDENTITY>` | Identity key file path |
| `-e, --env <ENV>` | Rekey only files in environment subtree |
| `-n, --dry-run` | Print what would be rekeyed without writing |

### `keyring`

```bash
gitvault keyring <SUBCOMMAND>
```

Subcommands:
- `set [-i, --identity <IDENTITY>]`
- `get`
- `delete`
- `set-passphrase [PASSPHRASE]`
- `get-passphrase`
- `delete-passphrase`

### `check`

```bash
gitvault check [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-e, --env <ENV>` | Environment to validate |
| `-i, --identity <IDENTITY>` | Identity key file path |
| `-H, --skip-history-check` | Skip committed-history plaintext leak scan |

### `identity`

```bash
gitvault identity <SUBCOMMAND>
```

Subcommands:
- `create [--profile classic|hybrid] [--output <PATH>] [--add-recipient]`
- `pubkey`

### `ai`

```bash
gitvault ai <SUBCOMMAND>
```

Subcommands:
- `skill`
- `context`

### `ssm` (feature-gated)

When compiled with `--features ssm`:
- `gitvault ssm pull [--env <ENV>]`
- `gitvault ssm diff [--env <ENV>] [--reveal]`
- `gitvault ssm set <KEY> <VALUE> [--env <ENV>] [--prod]`
- `gitvault ssm push [--env <ENV>] [--prod]`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITVAULT_ENV` | Active environment |
| `GITVAULT_IDENTITY` | Identity key path or raw `AGE-SECRET-KEY-...` |
| `GITVAULT_IDENTITY_FD` | Unix FD number to read identity key from |
| `GITVAULT_IDENTITY_PASSPHRASE` | SSH identity passphrase |
| `GITVAULT_IDENTITY_PASSPHRASE_FD` | Unix FD number for SSH passphrase |
| `GITVAULT_IDENTITY_SELECTOR` | SSH-agent key selector |
| `GITVAULT_SSH_AGENT` | Enable SSH-agent identity source when set |
| `GITVAULT_NO_INLINE_KEY_WARN` | Suppress raw-key warning |
| `GITVAULT_NO_PASSPHRASE_WARN` | Suppress inline passphrase warning |
| `CI` | Enables non-interactive behavior |
| `AWS_PROFILE` | AWS profile (SSM feature) |
| `AWS_ROLE_ARN` | AWS role ARN (SSM feature) |

## Configuration File

Configuration is loaded from `.gitvault/config.toml` (repository-level) with fallback to `~/.config/gitvault/config.toml` (user-global). All settings are optional — missing keys use built-in defaults.

### `[hooks]`

Hook-manager adapter configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `adapter` | string | none | Hook manager to use: `husky`, `pre-commit`, or `lefthook` |

**Example:**
```toml
[hooks]
adapter = "pre-commit"
```

### `[env]`

Environment resolution configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default` | string | `"dev"` | Default environment when `GITVAULT_ENV` and `.git/gitvault/env` are both absent |
| `prod_name` | string | `"prod"` | Environment name that triggers production barrier checks |

**Example:**
```toml
[env]
default = "dev"
prod_name = "production"
```

### `[barrier]`

Production barrier configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ttl_secs` | integer | `3600` | Token lifetime in seconds (1 hour) |

**Example:**
```toml
[barrier]
ttl_secs = 7200  # 2 hours
```

### `[paths]`

Repository path layout configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `recipients_dir` | string | `".gitvault/recipients"` | Directory containing recipient public keys |
| `store_dir` | string | `".gitvault/store"` | Encrypted secrets store directory |

**Example:**
```toml
[paths]
recipients_dir = ".secrets/recipients"
store_dir = ".gitvault/store"
```

### `[keyring]`

OS keyring configuration (macOS Keychain, Linux Secret Service, Windows Credential Manager).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `service` | string | `"gitvault"` | Keyring service name |
| `account` | string | `"age-identity"` | Keyring account/username |

**Example:**
```toml
[keyring]
service = "my-gitvault"
account = "identity-key"
```

### Rule-based command filtering (`[[seal.rule]]`, `[[materialize.rule]]`, `[[run.rule]]`)

Matcher rules are defined as array-of-table entries with `action`, `path`, and optional keys.

| Key | Type | Description |
|-----|------|-------------|
| `action` | string | `allow` or `deny` |
| `path` | string | Repo-relative glob path to match |
| `keys` | array of strings | Optional key globs (applies to `allow` rules) |
| `source` | string | Optional (`materialize`/`run` rules): `store` (default) or `sealed` |
| `dir_prefix` | bool | Optional (`materialize`/`run` rules): include directory components as key prefix |
| `path_prefix` | bool | Optional (`materialize`/`run` rules): include filename stem as key prefix |
| `custom_prefix` | string | Optional (`materialize`/`run` rules): append custom token before key |

Notes:
- Rules are evaluated in file order; later matches override earlier matches.
- `keys` filters emitted key/value pairs for matching files.
- `source` defaults to `store` when omitted.
- `source = "store"` matches `.gitvault/store/<env>/**/*.age` inputs.
- `source = "sealed"` matches repository-relative working-tree files (`.env`, `.env.<suffix>`, `<name>.env`, `.json`, `.yaml`, `.yml`, `.toml`; `.envrc` excluded).
- Runtime commands support global prefix defaults via `[materialize]` and `[run]` keys: `dir_prefix` and `path_prefix`.
- Prefix order is deterministic: `<DIR_PREFIX>_<FILENAME_PREFIX>_<CUSTOM_PREFIX>_<KEY>` (missing parts are skipped).
- Unknown keys in rule entries fail config parsing.

### `[materialize]`

Global defaults for `gitvault materialize` runtime key prefixing.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `output_filename` | string | `".env"` | Filename written by `gitvault materialize` |
| `dir_prefix` | bool | `false` | Prefix flattened keys with env-store subdirectory components |
| `path_prefix` | bool | `false` | Prefix flattened keys with source filename stem |

Rule-level values in `[[materialize.rule]]` override these globals for matching files.

**Example:**
```toml
[materialize]
output_filename = ".env.decrypted"
dir_prefix = true
path_prefix = false
```

### `[run]`

Global defaults for `gitvault run` runtime key prefixing.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dir_prefix` | bool | `false` | Prefix flattened keys with env-store subdirectory components |
| `path_prefix` | bool | `false` | Prefix flattened keys with source filename stem |

Rule-level values in `[[run.rule]]` override these globals for matching files.

**Example:**
```toml
[run]
dir_prefix = false
path_prefix = true
```

**Example:**
```toml
[[seal.rule]]
action = "allow"
path = "conf/*.json"
keys = ["Password", "db.*"]

[[seal.rule]]
action = "deny"
path = "conf/public.json"

[[materialize.rule]]
action = "allow"
source = "sealed"
path = "services/web/.env.local"
custom_prefix = "MAT"

[[materialize.rule]]
action = "allow"
source = "store"
path = ".gitvault/store/dev/*.env.age"
dir_prefix = true
path_prefix = true

[[run.rule]]
action = "allow"
source = "sealed"
path = "services/api/.env.local"
keys = ["DATABASE_URL", "API_*"]

[[run.rule]]
action = "allow"
source = "store"
path = ".gitvault/store/dev/conf/*.json.age"
keys = ["DATABASE_*", "REDIS_*"]
dir_prefix = false
path_prefix = true
custom_prefix = "RUNTIME"
```

### `[editor]`

Editor configuration for `gitvault edit`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `command` | string | none | Editor command (falls back to `$VISUAL`, `$EDITOR`, or platform default) |

**Example:**
```toml
[editor]
command = "code --wait"
```

### Complete Example

```toml
[hooks]
adapter = "pre-commit"

[env]
default = "dev"
prod_name = "production"

[barrier]
ttl_secs = 7200

[paths]
recipients_dir = ".gitvault/recipients"
store_dir = ".gitvault/store"

[keyring]
service = "gitvault"
account = "age-identity"

[materialize]
output_filename = ".env"
dir_prefix = true
path_prefix = true

[[seal.rule]]
action = "allow"
path = "config/*.json"
keys = ["password", "api_key"]

[[seal.rule]]
action = "deny"
path = "config/test-*.json"

[[materialize.rule]]
action = "allow"
source = "sealed"
path = "services/web/.env.local"
custom_prefix = "MAT"

[[materialize.rule]]
action = "allow"
source = "store"
path = ".gitvault/store/dev/*.env.age"

[run]
dir_prefix = false
path_prefix = true

[[run.rule]]
action = "allow"
source = "sealed"
path = "services/api/.env.local"
keys = ["DATABASE_URL", "API_*"]

[[run.rule]]
action = "allow"
source = "store"
path = ".gitvault/store/dev/conf/*.json.age"
keys = ["DATABASE_*", "REDIS_*"]

[editor]
command = "vim"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Usage / argument error |
| `3` | Plaintext secret detected |
| `4` | Decryption error |
| `5` | Production barrier not satisfied |
| `6` | Secrets drift detected |

## Identity Resolution

Priority (high to low):
1. `--identity-stdin`
2. `--identity`
3. `GITVAULT_IDENTITY_FD` (Unix)
4. `GITVAULT_IDENTITY`
5. OS keyring
6. SSH-agent (`GITVAULT_SSH_AGENT=1` or `SSH_AUTH_SOCK`)
