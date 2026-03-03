---
name: managing-gitvault-secrets
description: Guides agents to operate gitvault safely and predictably. Use when the user mentions gitvault, encrypted secrets, .age files, materialize/run workflows, production barrier, recipient rotation, or CI/CD secret handling.
---

# Managing GitVault Secrets

## When to use this skill
- User asks how to encrypt, decrypt, materialize, run, rotate, or audit secrets with `gitvault`.
- User needs CI/CD-safe secret handling with deterministic git diffs and stable exit codes.
- User needs production-gated operations (`allow-prod` / `revoke-prod`, `--prod`).
- User needs identity setup via age key file, env var, keyring, or SSH agent.
- User needs AI helper output (`gitvault ai skill print`, `gitvault ai context print`).

## Core model
- `gitvault` stores age-encrypted files in `secrets/<env>/...`.
- Plaintext is never committed; guardrails detect leakage and enforce barriers.
- Environment selection and identity resolution are deterministic.
- Exit codes are stable and suitable for automation.

## Plan-Validate-Execute workflow

### Checklist
- [ ] Confirm active repo/worktree and intended target environment.
- [ ] Confirm identity source and recipient expectations.
- [ ] Run preflight (`gitvault check` and/or `gitvault status`).
- [ ] Execute the requested command(s) with minimal side effects.
- [ ] Re-validate state (`gitvault status`, git diff cleanliness, expected outputs).
- [ ] Report exact command(s), outputs, and follow-up actions.

### Validation loop
1. **Plan**: choose command path (file-based vs fileless), environment, and identity source.
2. **Validate**: run no-side-effect checks first when possible.
3. **Execute**: perform operation with explicit flags (`--env`, `--prod`, `--json`, `--no-prompt`) as needed.
4. **Re-validate**: confirm no plaintext drift and expected artifact changes.

If uncertain about a command or flags, run:
```bash
gitvault <command> --help
```

## Global options

| Flag | Env var | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON on stdout |
| `--no-prompt` | `CI=true` | Fail instead of prompting; auto-enabled when `CI=true` |
| `--identity-selector <SEL>` | `GITVAULT_IDENTITY_SELECTOR` | SSH-agent key disambiguation hint |
| `--aws-profile <PROFILE>` | `AWS_PROFILE` | AWS profile for SSM backend |
| `--aws-role-arn <ARN>` | `AWS_ROLE_ARN` | AWS role ARN to assume for SSM backend |
| `-h, --help` | — | Print help |
| `-V, --version` | — | Print version |

## Environment variables

| Variable | Default | Config file key | Description |
|----------|---------|-----------------|-------------|
| `GITVAULT_ENV` | `dev` | `[env] default` | Active environment name; overrides `.secrets/env` |
| `GITVAULT_IDENTITY` | — | — | Path to identity file or raw `AGE-SECRET-KEY-...` |
| `GITVAULT_IDENTITY_SELECTOR` | — | — | Key disambiguation hint for keyring / SSH agent |
| `GITVAULT_SSH_AGENT` | off | — | Set `1` to enable SSH-agent as identity source |
| `CI` | off | — | Set `true` to auto-enable `--no-prompt` |

## Resolution order

### Identity (highest → lowest)
1. `-i / --identity <file>` on command
2. `GITVAULT_IDENTITY`
3. OS keyring (always tried automatically)
4. SSH-agent when `GITVAULT_SSH_AGENT=1` or `SSH_AUTH_SOCK` is set

### Environment (highest → lowest)
1. `GITVAULT_ENV`
2. `.secrets/env` (path overridable via `[env] env_file`)
3. `[env] default` in config
4. built-in default `dev`

Each git worktree resolves independently.

## Configuration layers
Missing files are ignored.

| File | Scope |
|------|-------|
| `.gitvault/config.toml` | Repository-level defaults |
| `~/.config/gitvault/config.toml` | User-global defaults |

### Defaults quick reference

| Setting | Default | Config key | `GITVAULT_*` env var |
|---------|---------|------------|----------------------|
| Active environment | `dev` | `[env] default` | `GITVAULT_ENV` |
| Production env name | `prod` | `[env] prod_name` | — |
| Env name file | `.secrets/env` | `[env] env_file` | — |
| Prod token TTL (s) | `3600` | `[barrier] ttl_secs` | — |
| Recipients file | `.secrets/recipients` | `[paths] recipients_file` | — |
| Materialize output | `.env` | `[paths] materialize_output` | — |
| Keyring service | `gitvault` | `[keyring] service` | — |
| Keyring account | `age-identity` | `[keyring] account` | — |
| Hook adapter | *(none)* | `[hooks] adapter` | — |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (I/O, encryption failure) |
| `2` | Usage / argument error |
| `3` | Plaintext secret detected in tracked files |
| `4` | Decryption error (wrong key or corrupt file) |
| `5` | Production barrier not satisfied |
| `6` | Secrets drift (uncommitted changes in `secrets/`) |

## Repository layout

```text
<repo>/
├── secrets/<env>/          # encrypted artifacts (commit these)
│   └── app.env.age
├── .secrets/
│   ├── recipients          # recipient public keys (one per line)
│   ├── env                 # active environment (optional)
│   ├── .prod-token         # timed production allow-token (gitignored)
│   └── plain/<env>/        # decrypted plaintext (gitignored)
├── .env                    # materialized root env (gitignored)
└── .gitignore              # managed by `gitvault harden`
```

## Command catalog

### `gitvault encrypt <FILE> [OPTIONS]`
Encrypt secret file content into `secrets/<env>/<name>.age` (whole-file) or transform content in field/value modes.

| Option | Description |
|--------|-------------|
| `-r, --recipient <PUBKEY>` | age public key (repeatable; defaults to local identity) |
| `-e, --env <ENV>` | Environment override for output path and policy |
| `--keep-path` | Preserve relative input path under `secrets/<env>/` |
| `--fields <FIELDS>` | Comma-separated JSON/YAML/TOML key paths |
| `--value-only` | Encrypt each `.env` value as `KEY=enc:base64` |

### `gitvault decrypt <FILE> [OPTIONS]`
Decrypt `.age` file content.

| Option | Description |
|--------|-------------|
| `-i, --identity <FILE>` | Identity key path (or use `GITVAULT_IDENTITY`) |
| `-o, --output [<PATH>]` | Output path; bare `--output` preserves source path |
| `--fields <FIELDS>` | Field-level decryption for structured files |
| `--reveal` | Print plaintext to stdout |
| `--value-only` | Reverse of value-only encryption |

### `gitvault materialize [OPTIONS]`
Decrypt all active-env secrets and write root `.env` atomically with restricted permissions.

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment override |
| `-i, --identity <FILE>` | Identity key path |
| `--prod` | Required for prod environment |

### `gitvault run [OPTIONS] -- <COMMAND>...`
Inject secrets into child process environment without writing `.env`.

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment override |
| `-i, --identity <FILE>` | Identity key path |
| `--prod` | Required for prod environment |
| `--clear-env` | Start child process with empty env |
| `--pass <VARS>` | Comma-separated passthrough list for `--clear-env` |

### `gitvault status [OPTIONS]`
Safety status check; never decrypts.

| Option | Description |
|--------|-------------|
| `--fail-if-dirty` | Exit `6` when `secrets/` has uncommitted changes |

### `gitvault check [OPTIONS]`
Preflight validation (identity, recipients, secrets dir), no side effects.

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment to validate |
| `-i, --identity <FILE>` | Identity key path |

### `gitvault harden`
Updates `.gitignore`, installs git hooks, and registers `.env` merge driver. Delegates to configured adapter (`husky` / `lefthook` / `pre-commit`) when set.

### `gitvault allow-prod [OPTIONS]`
Write timed prod allow-token to `.secrets/.prod-token`.

| Option | Description |
|--------|-------------|
| `--ttl <SECONDS>` | Token lifetime, default: `[barrier] ttl_secs` then `3600` |

### `gitvault revoke-prod`
Revoke production allow-token immediately.

### `gitvault recipient <SUBCOMMAND>`
Manage `.secrets/recipients`.

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `add` | `<PUBKEY>` | Add recipient |
| `remove` | `<PUBKEY>` | Remove recipient |
| `list` | — | List recipients |

### `gitvault rotate [OPTIONS]`
Re-encrypt all `secrets/` files for current recipients. Uses decrypt-all-before-write strategy to avoid mixed-key state.

| Option | Description |
|--------|-------------|
| `-i, --identity <FILE>` | Identity key path |

### `gitvault keyring <SUBCOMMAND>`
Manage age identity in OS keyring.

| Subcommand | Options | Description |
|------------|---------|-------------|
| `set` | `-i, --identity <FILE>` | Store identity |
| `get` | — | Show public key of stored identity |
| `delete` | — | Remove stored identity |

### `gitvault identity <SUBCOMMAND>`
Manage local age identity keys.

| Subcommand | Options | Description |
|------------|---------|-------------|
| `create` | `--profile classic\|hybrid`, `--out <PATH>` | Generate identity; stores in keyring unless `--out` is given |

Profiles:
- `classic`: age X25519 (default)
- `hybrid`: age X25519 with PQ-ready label

### `gitvault merge-driver <BASE> <OURS> <THEIRS>`
Merge driver for `.env` files.

```bash
git config merge.gitvault-env.driver "gitvault merge-driver %O %A %B"
# or run:
gitvault harden
```

### `gitvault ai <SUBCOMMAND>`
Embedded AI helper content.

| Subcommand | Description |
|------------|-------------|
| `skill print` | Print embedded canonical skill doc |
| `context print` | Print embedded agent onboarding context |

`--json` envelope format:
```json
{"protocol":"gitvault-ai/1","tool":"gitvault","success":true,"payload":{"content":"…","format":"markdown"}}
```

### `gitvault ssm <SUBCOMMAND>` *(optional feature)*
Enable with `cargo build --features ssm`.

| Subcommand | Options | Description |
|------------|---------|-------------|
| `pull` | `-e, --env <ENV>` | Compare SSM values with local references |
| `diff` | `-e, --env <ENV>`, `--reveal` | Show local reference vs SSM diff |
| `set` | `<KEY> <VALUE>`, `-e, --env`, `--prod` | Set one SSM parameter and record local reference |
| `push` | `-e, --env <ENV>`, `--prod` | Push local SSM references to Parameter Store |

AWS credentials can come from `--aws-profile` / `--aws-role-arn` or standard AWS env vars.

## Recommended command patterns

### Bootstrap
```bash
gitvault identity create --out ~/.age/id.key
gitvault harden
gitvault recipient add age1abc...
```

### Encrypt and commit
```bash
gitvault encrypt app.env -r age1abc...
git add secrets/ && git commit -m "chore: encrypt secrets"
```

### CI-safe execution
```bash
export GITVAULT_IDENTITY="$SECRET_AGE_KEY"
export CI=true
gitvault check --json
gitvault materialize
gitvault run -- ./start-server
```

### Recipient change + rotation
```bash
gitvault recipient add age1xyz...
gitvault rotate -i ~/.age/id.key
git add secrets/ .secrets/recipients && git commit -m "chore: rotate recipients"
```

## Guardrails
- Prefer `gitvault run` for ephemeral secret injection when possible.
- Use `--json` and explicit non-interactive flags in automation.
- Require `--prod` plus valid token for production operations.
- Never persist plaintext secrets outside approved gitignored paths.

## Resources
- Canonical command list: `gitvault --help`
- AI onboarding context: `gitvault ai context print`
- Embedded skill output: `gitvault ai skill print`
