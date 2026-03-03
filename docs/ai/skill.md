# gitvault — AI Agent Skill Reference

`gitvault` is a Git-native secrets manager. Secrets are age-encrypted and stored as `.age` files
under `secrets/<env>/` in the repository. Any authorised recipient can decrypt; deterministic
re-encryption keeps git diffs minimal. A production barrier, plaintext-leak detection, and stable
exit codes make it CI/CD safe.

---

## Global options (available on every command)

| Flag | Env var | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON on stdout |
| `--no-prompt` | `CI=true` | Fail instead of prompting; auto-enabled when `CI=true` |
| `--identity-selector <SEL>` | `GITVAULT_IDENTITY_SELECTOR` | SSH-agent key disambiguation hint |
| `--aws-profile <PROFILE>` | `AWS_PROFILE` | AWS profile for SSM backend |
| `--aws-role-arn <ARN>` | `AWS_ROLE_ARN` | AWS role ARN to assume for SSM backend |
| `-h, --help` | — | Print help |
| `-V, --version` | — | Print version |

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `GITVAULT_IDENTITY` | Path to age identity key file **or** raw `AGE-SECRET-KEY-…` string |
| `GITVAULT_KEYRING` | Set `1` to load identity from OS keyring (macOS Keychain / Linux Secret Service / Windows Credential Manager) |
| `SECRETS_ENV` | Active environment name; overrides `.secrets/env` file |
| `CI` | Set `true` to auto-enable `--no-prompt` |
| `GITVAULT_IDENTITY_SELECTOR` | Key disambiguation hint passed to keyring / SSH agent |

---

## Identity resolution order (highest → lowest priority)

1. `-i / --identity <file>` flag (per-command)
2. `GITVAULT_IDENTITY` environment variable
3. OS keyring when `GITVAULT_KEYRING=1`

---

## Environment resolution order (highest → lowest priority)

1. `SECRETS_ENV` environment variable
2. `.secrets/env` file in the worktree root
3. `dev` (built-in default)

Each Git worktree resolves independently.

---

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

---

## Repository layout

```
<repo>/
├── secrets/<env>/          # encrypted artifacts (commit these)
│   └── app.env.age
├── .secrets/
│   ├── recipients          # persistent recipient public keys (one per line)
│   ├── env                 # active environment name (optional)
│   ├── .prod-token         # timed production allow-token (gitignored)
│   └── plain/<env>/        # decrypted plaintext (gitignored)
├── .env                    # materialized root env (gitignored)
└── .gitignore              # managed by `gitvault harden`
```

---

## Commands

### `gitvault encrypt <FILE> [OPTIONS]`

Encrypt a secret file. Output: `secrets/<env>/<name>.age` (whole-file) or in-place (field/value modes).

| Option | Description |
|--------|-------------|
| `-r, --recipient <PUBKEY>` | age public key (repeat for multi-recipient; defaults to local identity) |
| `--keep-path` | Preserve input path relative to repo root under `secrets/<env>/` |
| `--fields <FIELDS>` | Comma-separated key paths for JSON/YAML/TOML field-level encryption |
| `--value-only` | Encrypt each `.env` VALUE individually (`KEY=enc:base64`) instead of whole file |

**Examples:**
```bash
gitvault encrypt app.env -r age1abc...                    # whole-file
gitvault encrypt config.json --fields db.password,api_key  # field-level
gitvault encrypt .env --value-only                          # per-value
```

---

### `gitvault decrypt <FILE> [OPTIONS]`

Decrypt a `.age` encrypted file.

| Option | Description |
|--------|-------------|
| `-i, --identity <FILE>` | Identity key file path (or use `GITVAULT_IDENTITY`) |
| `-o, --output [<PATH>]` | Output path (default: strip `.age`); bare `--output` preserves original path |
| `--fields <FIELDS>` | Comma-separated key paths for JSON/YAML/TOML field-level decryption |
| `--reveal` | Print decrypted content to stdout instead of writing to file |
| `--value-only` | Decrypt each `.env` VALUE individually (reverse of `--value-only` encrypt) |

**Examples:**
```bash
gitvault decrypt secrets/dev/app.env.age -i ~/.age/id.key
gitvault decrypt secrets/dev/app.env.age --reveal           # stdout only
gitvault decrypt config.json.age --fields db.password       # field-level
```

---

### `gitvault materialize [OPTIONS]`

Decrypt all secrets for the active environment and write a root `.env` (atomic, `0600`/restricted ACL).

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment to use (overrides `SECRETS_ENV` and `.secrets/env`) |
| `-i, --identity <FILE>` | Identity key file path |
| `--prod` | Require production barrier (mandatory when env=prod) |

**Example:**
```bash
GITVAULT_IDENTITY=~/.age/id.key gitvault materialize --env staging
gitvault materialize --env prod --prod   # requires prior allow-prod
```

---

### `gitvault run [OPTIONS] -- <COMMAND>...`

Inject secrets as environment variables into a child process — no `.env` written to disk.

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment to use |
| `-i, --identity <FILE>` | Identity key file path |
| `--prod` | Require production barrier (mandatory when env=prod) |
| `--clear-env` | Start child with an empty environment |
| `--pass <VARS>` | Comma-separated vars to pass through when `--clear-env` is set |

**Examples:**
```bash
gitvault run -- ./start-server
gitvault run --env prod --prod -- python manage.py migrate
gitvault run --clear-env --pass PATH,HOME -- make test
```

---

### `gitvault status [OPTIONS]`

Check repository safety status. Never decrypts.

| Option | Description |
|--------|-------------|
| `--fail-if-dirty` | Exit `6` if `secrets/` has uncommitted changes |

**Example:**
```bash
gitvault --json status --fail-if-dirty   # CI-friendly
```

---

### `gitvault check [OPTIONS]`

Preflight validation of identity, recipients, and secrets dir — no side effects.

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment to validate |
| `-i, --identity <FILE>` | Identity key file path |

---

### `gitvault harden`

Add `.env` and `.secrets/plain/` to `.gitignore`, install pre-commit / pre-push git hooks, and
register the `.env` merge driver in `.gitattributes`. Delegates to external hook manager
(husky / lefthook / pre-commit) when configured in `.gitvault/config.toml`.

---

### `gitvault allow-prod [OPTIONS]`

Write a timed production allow-token to `.secrets/.prod-token`.

| Option | Description |
|--------|-------------|
| `--ttl <SECONDS>` | Token lifetime (default: `3600`) |

---

### `gitvault revoke-prod`

Revoke the production allow-token immediately.

---

### `gitvault recipient <SUBCOMMAND>`

Manage persistent recipients stored in `.secrets/recipients`.

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `add` | `<PUBKEY>` | Add an age public key |
| `remove` | `<PUBKEY>` | Remove an age public key |
| `list` | — | List current recipients |

---

### `gitvault rotate [OPTIONS]`

Re-encrypt all secrets in `secrets/` for the current recipient list. Phase-1 decrypts all files
before any write to avoid mixed-key state on failure.

| Option | Description |
|--------|-------------|
| `-i, --identity <FILE>` | Identity key file path |

---

### `gitvault keyring <SUBCOMMAND>`

Manage the age identity key in the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager).

| Subcommand | Options | Description |
|------------|---------|-------------|
| `set` | `-i, --identity <FILE>` | Store identity key in OS keyring |
| `get` | — | Show public key of stored identity |
| `delete` | — | Remove stored identity from OS keyring |

---

### `gitvault identity <SUBCOMMAND>`

Manage local age identity keys.

| Subcommand | Options | Description |
|------------|---------|-------------|
| `create` | `--profile classic\|hybrid`, `--out <PATH>` | Generate a new identity key; stores in keyring unless `--out` is given |

`--profile classic` — age X25519 (default)  
`--profile hybrid` — age X25519 with PQ-ready label

---

### `gitvault merge-driver <BASE> <OURS> <THEIRS>`

Git merge driver for `.env` files. Register with:
```bash
git config merge.gitvault-env.driver "gitvault merge-driver %O %A %B"
# or run: gitvault harden   (registers automatically)
```

---

### `gitvault ai <SUBCOMMAND>`

AI tooling helpers. Content is embedded in the binary at build time.

| Subcommand | Description |
|------------|-------------|
| `skill print` | Print this canonical skill document (embedded `docs/ai/skill.md`) |
| `context print` | Print project AI onboarding context (embedded `docs/ai/AGENT_START.md`) |

Use `--json` for MCP-style envelope output:
```json
{"protocol":"gitvault-ai/1","tool":"gitvault","success":true,"payload":{"content":"…","format":"markdown"}}
```

---

### `gitvault ssm <SUBCOMMAND>` *(optional feature)*

AWS SSM Parameter Store backend. Enable with `cargo build --features ssm`.

| Subcommand | Options | Description |
|------------|---------|-------------|
| `pull` | `-e, --env <ENV>` | Read SSM values and compare with local references |
| `diff` | `-e, --env <ENV>`, `--reveal` | Show diff between local refs and SSM |
| `set` | `<KEY> <VALUE>`, `-e, --env`, `--prod` | Set a single SSM parameter and record reference locally |
| `push` | `-e, --env <ENV>`, `--prod` | Push all local SSM references to Parameter Store |

AWS credentials: `--aws-profile` / `--aws-role-arn` (global options) or standard AWS env vars.

---

## Typical agent workflow

```bash
# Bootstrap
gitvault identity create --out ~/.age/id.key   # one-time: generate identity
gitvault harden                                  # install hooks, update .gitignore
gitvault recipient add age1abc...               # add team member

# Encrypt and commit
gitvault encrypt app.env -r age1abc...
git add secrets/ && git commit -m "chore: encrypt secrets"

# CI — materialize and run
export GITVAULT_IDENTITY="$SECRET_AGE_KEY"
export CI=true
gitvault check --json                 # preflight; exits non-zero on misconfiguration
gitvault materialize                  # writes .env (0600, atomic)
gitvault run -- ./start-server        # fileless injection (preferred over .env)

# Rotate after adding/removing a recipient
gitvault recipient add age1xyz...
gitvault rotate -i ~/.age/id.key
git add secrets/ .secrets/recipients && git commit -m "chore: rotate recipients"
```

