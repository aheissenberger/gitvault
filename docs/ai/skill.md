# gitvault — AI Agent Skill Reference

`gitvault` is a Git-native secrets manager. Secrets are age-encrypted and stored as `.age` files
under `.gitvault/store/<env>/` in the repository. Any authorised recipient can decrypt; deterministic
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

| Variable | Default | Config file key | Description |
|----------|---------|-----------------|-------------|
| `GITVAULT_ENV` | `dev` | `[env] default` | Active environment name; overrides `.git/gitvault/env` file |
| `GITVAULT_IDENTITY` | — | — | Path to age identity key file **or** raw `AGE-SECRET-KEY-…` string |
| `GITVAULT_IDENTITY_PASSPHRASE` | — | — | Passphrase for passphrase-encrypted SSH identity keys; checked before OS keyring; CI-safe |
| `GITVAULT_IDENTITY_SELECTOR` | — | — | Key disambiguation hint for keyring / SSH agent |
| `GITVAULT_SSH_AGENT` | off | — | Set `1` to enable SSH-agent as an identity source |
| `CI` | off | — | Set `true` to auto-enable `--no-prompt` |

---

## Identity resolution order (highest → lowest priority)

1. `-i / --identity <file>` flag (per-command)
2. `GITVAULT_IDENTITY` environment variable
3. OS keyring (always tried automatically)
4. SSH-agent when `GITVAULT_SSH_AGENT=1` or `SSH_AUTH_SOCK` is set

**SSH passphrase unlock:** passphrase-encrypted SSH keys are unlocked automatically via
`GITVAULT_IDENTITY_PASSPHRASE` (env var, CI-safe) or the OS keyring passphrase store.
Manage with `gitvault keyring set-passphrase | get-passphrase | delete-passphrase`.

---

## Environment resolution order (highest → lowest priority)

1. `GITVAULT_ENV` environment variable
2. `.git/gitvault/env` file in the worktree root (path overridable via `[env] env_file` config)
3. `[env] default` in config file
4. `dev` (built-in default)

Each Git worktree resolves independently.

---

## Configuration files

Two optional TOML layers override built-in defaults. Missing files are silently ignored.

| File | Scope |
|------|-------|
| `.gitvault/config.toml` | Repository-level (commit with project) |
| `~/.config/gitvault/config.toml` | User-global personal defaults |

**Defaults & overrides quick reference:**

| Setting | Default | Config key | `GITVAULT_*` env var |
|---------|---------|------------|----------------------|
| Active environment | `dev` | `[env] default` | `GITVAULT_ENV` |
| Production env name | `prod` | `[env] prod_name` | — |
| Env name file | `.git/gitvault/env` | `[env] env_file` | — |
| Prod token TTL (s) | `3600` | `[barrier] ttl_secs` | — |
| Recipients directory | `.gitvault/recipients/` | `[paths] recipients_dir` | — |
| Encrypted secrets dir | `.gitvault/store/` | — | — |
| Materialize output | `.env` | `[paths] materialize_output` | — |
| Keyring service | `gitvault` | `[keyring] service` | — |
| Keyring account | `age-identity` | `[keyring] account` | — |
| Hook adapter | *(none)* | `[hooks] adapter` | — |

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
└── .gitignore               # managed by `gitvault harden`
```

---

## Commands

### `gitvault init`

Interactive onboarding for a new team member. Runs through identity creation, recipient
registration, and repository hardening in a single guided flow.

Steps performed:
1. Creates an age identity (stored in OS keyring by default)
2. Adds own public key to `.gitvault/recipients/<your-name>.pub`
3. Hardens the repo (`.gitignore`, git hooks, `.gitattributes`)
4. Creates `.gitvault/config.toml` if missing

**Recipient ceremony flow:**
```bash
# New member runs:
gitvault init
git add .gitvault/recipients/ && git commit -m "onboard: add <name> as recipient"
git push && gh pr create

# Maintainer merges PR then rekeyes:
gitvault rekey
git add .gitvault/ && git commit -m "rekey: add <name>"
git push

# New member pulls and materializes:
git pull && gitvault materialize
```

---

### `gitvault encrypt <FILE> [OPTIONS]`

Encrypt a secret file. Output: `.gitvault/store/<env>/<name>.age` (whole-file) or in-place (field/value modes).

| Option | Description |
|--------|-------------|
| `-r, --recipient <PUBKEY>` | age public key (repeat for multi-recipient; defaults to local identity) |
| `-e, --env <ENV>` | Environment to use (overrides `GITVAULT_ENV` and `.git/gitvault/env`); controls output path `.gitvault/store/<ENV>/` |
| `--keep-path` | Preserve input path relative to repo root under `.gitvault/store/<env>/` |
| `--fields <FIELDS>` | Comma-separated key paths for JSON/YAML/TOML field-level encryption |
| `--value-only` | Encrypt each `.env` VALUE individually (`KEY=enc:base64`) instead of whole file |

**Examples:**
```bash
gitvault encrypt app.env -r age1abc...                    # whole-file, active env
gitvault encrypt app.env -r age1abc... --env staging      # whole-file, staging env
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
gitvault decrypt .gitvault/store/dev/app.env.age -i ~/.age/id.key
gitvault decrypt .gitvault/store/dev/app.env.age --reveal        # stdout only
gitvault decrypt config.json.age --fields db.password            # field-level
```

---

### `gitvault materialize [OPTIONS]`

Decrypt all secrets for the active environment and write a root `.env` (atomic, `0600`/restricted ACL). Output path configurable via `[paths] materialize_output`.

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment to use (overrides `GITVAULT_ENV` and `.git/gitvault/env`) |
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

### `gitvault harden [<FILE>] [OPTIONS]`

Without a file argument: add `.env` and `.gitvault/plain/` to `.gitignore`, install pre-commit /
pre-push git hooks, and register the `.env` merge driver in `.gitattributes`. Delegates to
external hook manager (husky / lefthook / pre-commit) when configured in `.gitvault/config.toml`.

With a file argument: imports an existing plaintext file — encrypts it, runs `git rm --cached`,
and adds it to `.gitignore`.

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Target environment for the imported file |
| `--dry-run` | Show what would happen without making changes |
| `--remove` | Delete the plaintext source file after encrypting |
| `-r, --recipient <PUBKEY>` | Recipient key (repeat for multi-recipient) |

**Examples:**
```bash
gitvault harden                          # repo hardening only
gitvault harden .env --env dev           # import, encrypt, gitignore .env
gitvault harden secrets.yaml --env prod --dry-run
```

---

### `gitvault allow-prod [OPTIONS]`

Write a timed production allow-token to `.git/gitvault/.prod-token`.

| Option | Description |
|--------|-------------|
| `--ttl <SECONDS>` | Token lifetime; default from `[barrier] ttl_secs` config, then `3600` |

---

### `gitvault revoke-prod`

Revoke the production allow-token immediately.

---

### `gitvault recipient <SUBCOMMAND>`

Manage persistent recipients stored in `.gitvault/recipients/` (one `.pub` file per person).

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `add` | `<PUBKEY> [--name <NAME>]` | Add an age public key; saves to `<name>.pub` |
| `remove` | `<NAME\|PUBKEY>` | Remove a recipient by name or public key |
| `list` | — | List current recipients |
| `add-self` | `[--name <NAME>]` | Resolve own public key from keyring and add as recipient |

**Examples:**
```bash
gitvault recipient add age1abc... --name alice
gitvault recipient add-self --name bob
gitvault recipient list
gitvault recipient remove alice
```

---

### `gitvault rekey [OPTIONS]`

Re-encrypt all secrets in `secrets/` for the current recipient list. Phase-1 decrypts all files
before any write to avoid mixed-key state on failure.

| Option | Description |
|--------|-------------|
| `-i, --identity <FILE>` | Identity key file path |
| `--dry-run` | Show which files would be re-encrypted without writing |
| `-e, --env <ENV>` | Rekey only the specified environment |
| `--json` | Emit machine-readable JSON output |

**Example:**
```bash
gitvault rekey                          # rekey all envs
gitvault rekey --dry-run                # preview only
gitvault rekey --env staging --json
```

---

### `gitvault keyring <SUBCOMMAND>`

Manage the age identity key and SSH passphrase in the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager).

| Subcommand | Options | Description |
|------------|---------|-------------|
| `set` | `-i, --identity <FILE>` | Store identity key in OS keyring |
| `get` | — | Show public key of stored identity |
| `delete` | — | Remove stored identity from OS keyring |
| `set-passphrase` | `[<PASSPHRASE>]` | Store SSH identity passphrase (omit arg to read from `GITVAULT_IDENTITY_PASSPHRASE`) |
| `get-passphrase` | — | Report whether an SSH passphrase is stored |
| `delete-passphrase` | — | Remove stored SSH passphrase from OS keyring |

---

### `gitvault identity <SUBCOMMAND>`

Manage local age identity keys.

| Subcommand | Options | Description |
|------------|---------|-------------|
| `create` | `--profile classic\|hybrid`, `--out <PATH>`, `--add-recipient` | Generate a new identity key; stores in keyring unless `--out` is given; `--add-recipient` immediately registers the public key |
| `pubkey` | — | Print own public key (from keyring or `GITVAULT_IDENTITY`) for piping |

`--profile classic` — age X25519 (default)  
`--profile hybrid` — age X25519 with PQ-ready label

**Examples:**
```bash
gitvault identity create                          # stores in keyring
gitvault identity create --out ~/.age/id.key      # export to file
gitvault identity create --add-recipient          # create + register as recipient
gitvault identity pubkey                          # print public key
gitvault identity pubkey | gitvault recipient add # pipe to add
```

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
# Bootstrap (new member)
gitvault init                                    # interactive: identity + recipient + harden
# OR manual:
gitvault identity create --add-recipient         # generate identity and register as recipient
git add .gitvault/recipients/ && git commit -m "onboard: add me as recipient"
git push && gh pr create                         # PR for maintainer to merge + rekey

# Encrypt and commit
gitvault encrypt app.env -r age1abc...
git add .gitvault/store/ && git commit -m "chore: encrypt secrets"

# CI — materialize and run
export GITVAULT_IDENTITY="$SECRET_AGE_KEY"
export CI=true
gitvault check --json                 # preflight; exits non-zero on misconfiguration
gitvault materialize                  # writes .env (0600, atomic)
gitvault run -- ./start-server        # fileless injection (preferred over .env)

# Rekey after adding/removing a recipient
gitvault recipient add age1xyz... --name alice
gitvault rekey --dry-run              # preview
gitvault rekey
git add .gitvault/ && git commit -m "rekey: add alice"
```

