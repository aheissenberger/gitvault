# gitvault CLI Reference

Use this file as the canonical command reference. For task-oriented examples, see `README.md` and the guides in `docs/`.

## Source of Truth

Regenerate command metadata before editing CLI docs:

```bash
cargo xtask cli-help
```

Generated file:
- `docs/ai/cli-help.json`

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

### `materialize`

```bash
gitvault materialize [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-e, --env <ENV>` | Environment to use |
| `-i, --identity <IDENTITY>` | Identity key file path |
| `--prod` | Require production barrier for prod env |

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
