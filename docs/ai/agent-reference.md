---
name: managing-gitvault-secrets
description: Guides agents to operate gitvault safely and predictably. Use when the user mentions gitvault, encrypted secrets, .age files, materialize/run workflows, production barrier, recipient rotation, or CI/CD secret handling.
---

# Managing GitVault Secrets

## When to use this skill

- User asks how to encrypt, decrypt, materialize, run, rotate, or audit secrets with `gitvault`.
- User needs CI-safe secret operations.
- User needs production-gated operations (`allow-prod`, `revoke-prod`, `--prod`).
- User needs AI helper outputs (`gitvault ai skill`, `gitvault ai context`).

## Canonical CLI References

Always confirm commands against the live CLI before responding:

```bash
cargo xtask cli-help
gitvault --help
gitvault <command> --help
gitvault ai skill
gitvault ai context
```

Generated index:
- `docs/ai/cli-help.json`

## Core model

- Archive mode: `encrypt`/`decrypt` read and write `.gitvault/store/<env>/...`.
- In-place mode: `seal`/`unseal` modify supported structured files directly.
- `run` injects secrets without writing `.env`.
- `materialize` writes decrypted values to configured output (`.env` by default).

## Plan-Validate-Execute

1. Confirm environment and identity source.
2. Run preflight checks (`gitvault check`, `gitvault status`).
3. Execute with explicit flags (`--env`, `--prod`, `--no-prompt`, `--json`).
4. Re-validate drift/status.

## Global options

- `--json`
- `--no-prompt`
- `--identity-selector <IDENTITY_SELECTOR>`
- `--identity-stdin`

Feature-gated (`--features ssm`):
- `--aws-profile <AWS_PROFILE>`
- `--aws-role-arn <AWS_ROLE_ARN>`

## Identity resolution

1. `--identity-stdin`
2. `--identity`
3. `GITVAULT_IDENTITY_FD` (Unix)
4. `GITVAULT_IDENTITY`
5. OS keyring
6. SSH-agent (`GITVAULT_SSH_AGENT=1` or `SSH_AUTH_SOCK`)

## Command catalog

### Archive commands

- `gitvault encrypt [OPTIONS] <FILE>`
- `gitvault decrypt [OPTIONS] <FILE>`

`encrypt` options:
- `-r, --recipient <PUBKEY>`
- `-e, --env <ENV>`

`decrypt` options:
- `-i, --identity <IDENTITY>`
- `-e, --env <ENV>`
- `--reveal`

### In-place commands

- `gitvault seal [OPTIONS] <FILE>`
- `gitvault unseal [OPTIONS] <FILE>`

`seal` options:
- `-r, --recipient <PUBKEY>`
- `-e, --env <ENV>`
- `--fields <FIELDS>`

`unseal` options:
- `-i, --identity <IDENTITY>`
- `--fields <FIELDS>`
- `--reveal`

### Runtime and safety commands

- `gitvault materialize [OPTIONS]`
- `gitvault run [OPTIONS] -- <COMMAND>...`
- `gitvault status [OPTIONS]`
- `gitvault check [OPTIONS]`

### Lifecycle commands

- `gitvault init [OPTIONS]`
- `gitvault harden [OPTIONS] [FILES]...`
- `gitvault recipient <SUBCOMMAND>`
- `gitvault rekey [OPTIONS]`
- `gitvault keyring <SUBCOMMAND>`
- `gitvault identity <SUBCOMMAND>`
- `gitvault allow-prod [OPTIONS]`
- `gitvault revoke-prod`
- `gitvault ai <SUBCOMMAND>`

### Optional backend command

- `gitvault ssm <SUBCOMMAND>` (feature-gated)

## CI-safe patterns

```bash
export CI=true
gitvault check --json --no-prompt
gitvault status --fail-if-dirty --no-prompt
gitvault run --no-prompt --env dev -- ./start-server
```

## Exit codes

- `0`: success
- `1`: general error
- `2`: usage error
- `3`: plaintext leak detected
- `4`: decryption error
- `5`: production barrier missing
- `6`: secrets drift
