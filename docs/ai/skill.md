# gitvault — AI Agent Skill Reference

Canonical AI-facing command reference embedded in the binary (`gitvault ai skill`).

## CLI Sources

Use these commands before changing docs or automation:

```bash
cargo xtask cli-help
gitvault --help
gitvault <command> --help
gitvault ai skill
gitvault ai context
```

Primary generated source:
- `docs/ai/cli-help.json`

## Global Options

| Flag | Env var | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON output |
| `--no-prompt` | `CI` | Disable interactive prompts |
| `--identity-selector <IDENTITY_SELECTOR>` | `GITVAULT_IDENTITY_SELECTOR` | SSH-agent key selector |
| `--identity-stdin` | — | Read identity from stdin |

Feature-gated globals (`--features ssm`):
- `--aws-profile <AWS_PROFILE>`
- `--aws-role-arn <AWS_ROLE_ARN>`

## Identity Resolution

Order (high to low):
1. `--identity-stdin`
2. `--identity`
3. `GITVAULT_IDENTITY_FD` (Unix)
4. `GITVAULT_IDENTITY`
5. OS keyring
6. SSH-agent (`GITVAULT_SSH_AGENT=1` or `SSH_AUTH_SOCK`)

SSH passphrase sources:
1. `GITVAULT_IDENTITY_PASSPHRASE_FD` (Unix)
2. `GITVAULT_IDENTITY_PASSPHRASE`
3. OS keyring passphrase store

## Environment Resolution

Order (high to low):
1. Command `--env`
2. `GITVAULT_ENV`
3. `.git/gitvault/env`
4. `[env] default` in config
5. Built-in `dev`

## Top-level Commands

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
- `ssm` (feature-gated)

## Command Reference

### `gitvault encrypt [OPTIONS] <FILE>`

Archive encryption into `.gitvault/store/<env>/` using mirrored source path.

Options:
- `-r, --recipient <PUBKEY>`
- `-e, --env <ENV>`

### `gitvault decrypt [OPTIONS] <FILE>`

Archive decryption from source path or explicit `.age` store path.

Options:
- `-i, --identity <IDENTITY>`
- `-e, --env <ENV>`
- `--reveal`

### `gitvault seal [OPTIONS] <FILE>`

In-place encryption for `.json/.yaml/.yml/.toml/.env`.

Options:
- `-r, --recipient <PUBKEY>`
- `-e, --env <ENV>`
- `--fields <FIELDS>`

### `gitvault unseal [OPTIONS] <FILE>`

In-place decryption for `.json/.yaml/.yml/.toml/.env`.

Options:
- `-i, --identity <IDENTITY>`
- `--fields <FIELDS>`
- `--reveal`

### `gitvault materialize [OPTIONS]`

Options:
- `-e, --env <ENV>`
- `-i, --identity <IDENTITY>`
- `--prod`

### `gitvault status [OPTIONS]`

Options:
- `--fail-if-dirty`

### `gitvault init [OPTIONS]`

Options:
- `-e, --env <ENV>`
- `--output <PATH>`

### `gitvault harden [OPTIONS] [FILES]...`

Options:
- `-e, --env <ENV>`
- `-n, --dry-run`
- `--delete-source`
- `-r, --recipient <PUBKEY>`

### `gitvault run [OPTIONS] -- <COMMAND>...`

Options:
- `-e, --env <ENV>`
- `-i, --identity <IDENTITY>`
- `--prod`
- `--clear-env`
- `--keep-vars <VARS>`

### `gitvault allow-prod [OPTIONS]`

Options:
- `--ttl <TTL>`

### `gitvault revoke-prod`

No command-specific flags.

### `gitvault recipient <SUBCOMMAND>`

Subcommands:
- `add <PUBKEY>`
- `remove <PUBKEY>`
- `list`
- `add-self`

### `gitvault rekey [OPTIONS]`

Options:
- `-i, --identity <IDENTITY>`
- `-e, --env <ENV>`
- `-n, --dry-run`

### `gitvault keyring <SUBCOMMAND>`

Subcommands:
- `set [-i, --identity <IDENTITY>]`
- `get`
- `delete`
- `set-passphrase [PASSPHRASE]`
- `get-passphrase`
- `delete-passphrase`

### `gitvault check [OPTIONS]`

Options:
- `-e, --env <ENV>`
- `-i, --identity <IDENTITY>`
- `-H, --skip-history-check`

### `gitvault identity <SUBCOMMAND>`

Subcommands:
- `create [--profile classic|hybrid] [--output <PATH>] [--add-recipient]`
- `pubkey`

### `gitvault ai <SUBCOMMAND>`

Subcommands:
- `skill`
- `context`

### `gitvault ssm <SUBCOMMAND>` (feature-gated)

Subcommands:
- `pull`
- `diff`
- `set`
- `push`

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Usage error |
| `3` | Plaintext leak detected |
| `4` | Decryption error |
| `5` | Production barrier missing |
| `6` | Secrets drift |
