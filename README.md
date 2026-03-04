# gitvault

Git-native secrets manager for multi-developer and AI-agent workflows. Secrets are encrypted with
[age](https://age-encryption.org) and stored in your repository — never plaintext, no external
services required.

## Features

| Category | Highlights |
|---|---|
| **Encryption** | age standard format; whole-file or per-field (JSON/YAML/TOML); streaming crypto |
| **Multi-recipient** | encrypt once for every team member; per-person `.pub` files |
| **Deterministic diffs** | unchanged field values keep existing ciphertext → minimal git noise |
| **Environments** | `GITVAULT_ENV` → `.secrets/env` → `dev`; per-worktree resolution |
| **Onboarding** | `gitvault init` guides identity → recipient → hardening in one command |
| **Recipient ceremony** | PR-based zero-shared-secret onboarding; `identity pubkey`, `recipient add-self` |
| **Rekeying** | `rekey` re-encrypts all secrets to current recipient set; `--dry-run` supported |
| **Runtime injection** | `run` injects secrets into child process env; no `.env` file written |
| **Production barrier** | timed allow-token required for prod operations; `revoke-prod` clears it immediately |
| **Identity sources** | `--identity` flag → `GITVAULT_IDENTITY` → OS keyring → SSH agent |
| **OS keyring** | macOS Keychain, Linux Secret Service, Windows Credential Manager |
| **Git safety** | pre-commit/pre-push hooks; drift detection; leak detection; merge driver |
| **CI friendly** | `--json`, `--no-prompt`; `CI=1` auto-enables non-interactive mode; stable exit codes |
| **AWS SSM** | `gitvault ssm pull/push/diff/set`; `--features ssm` |

## Installation

```bash
# macOS
brew install aheissenberger/tools/gitvault

# Build from source
cargo build --release

# Prebuilt binaries — see GitHub Releases
# gitvault-linux-x86_64.tar.gz | gitvault-macos-aarch64.tar.gz | gitvault-windows-x86_64.zip
# Each release ships SHA256SUMS + cosign .sig/.pem files
```

## Quick Start

### New team member

```bash
gitvault init              # identity → add-self → harden → config.toml

# Commit your public key and open a PR:
git add .secrets/recipients/ && git commit -m "onboard: add <your-name>"
git push && gh pr create
```

After a maintainer merges and rekeyes: `git pull && gitvault materialize`

### First repo setup

```bash
gitvault identity create   # generate age identity (stored in OS keyring by default)
gitvault recipient add-self
gitvault harden            # .gitignore + git hooks

# Encrypt a file and register it with the repo:
gitvault harden .env --env dev   # encrypts, git rm --cached, gitignores .env

# Or encrypt explicitly:
gitvault encrypt .env --env dev
```

### Rekey after membership change

```bash
gitvault rekey             # re-encrypt all secrets to current recipients
git add .secrets/ && git commit -m "rekey: update recipients"
```

### CI/CD

```bash
# Use GITVAULT_IDENTITY to pass the age secret key; enable non-interactive mode:
GITVAULT_IDENTITY="$SECRET_KEY" gitvault materialize --no-prompt --env prod
# Or inject directly without writing .env:
GITVAULT_IDENTITY="$SECRET_KEY" gitvault run --no-prompt -- node server.js
```

> Set `CI=1` (most CI systems do this automatically) to suppress interactive prompts globally.

---

## CLI reference

```
gitvault [OPTIONS] <COMMAND>

Global options:  --json  --no-prompt  --identity-selector  --aws-profile  --aws-role-arn

Commands:
  init          Onboard a new team member (identity, recipient, repo hardening)
  encrypt       Encrypt a secret file (--env, --keep-path, --fields, --value-only)
  decrypt       Decrypt a .age file (--output, --fields, --value-only, --reveal)
  materialize   Materialize secrets to root .env
  status        Check repository safety status
  harden        Harden repo (hooks, .gitignore); or import+encrypt a file with harden <file>
  run           Inject secrets into child process env (--clear-env, --pass)
  allow-prod    Write a timed production allow token
  revoke-prod   Revoke the production allow token immediately
  merge-driver  Git merge driver for .env files (register via `gitvault harden`)
  recipient     Manage recipients: add | remove | list | add-self
  rekey         Re-encrypt all secrets for current recipients (--dry-run, --env, --json)
  keyring       Manage identity key in OS keyring: set | get | delete
  identity      Manage identities: create [--add-recipient] | pubkey
  check         Preflight validation without side effects
  ai            Print embedded skill/context for AI agents (--json for MCP envelope)
  ssm           AWS SSM Parameter Store sync (--features ssm)
```

### Operator quick map

| Task | Command |
|------|---------|
| Onboard new team member | `gitvault init` |
| Encrypt whole file | `gitvault encrypt <file> --env <env>` |
| Encrypt selected fields | `gitvault encrypt <file> --fields a.b,c` |
| Encrypt `.env` per-value | `gitvault encrypt .env --value-only` |
| Import + encrypt existing file | `gitvault harden <file> --env <env>` |
| Decrypt to stdout | `gitvault decrypt <file.age> --reveal` |
| Materialize root `.env` | `gitvault materialize` |
| Run command with injected secrets | `gitvault run -- <cmd> [args...]` |
| Safety check (CI-friendly) | `gitvault status --fail-if-dirty --no-prompt` |
| Validate setup (no side effects) | `gitvault check [--env <env>]` |
| Enable prod operation window | `gitvault allow-prod [--ttl <secs>]` |
| Revoke prod window | `gitvault revoke-prod` |
| Manage recipients | `gitvault recipient add\|remove\|list\|add-self` |
| Re-encrypt after membership change | `gitvault rekey [--dry-run] [--env <env>]` |
| Create identity | `gitvault identity create [--profile classic\|hybrid] [--add-recipient]` |
| Print own public key | `gitvault identity pubkey` |
| OS keyring | `gitvault keyring set\|get\|delete` |

---

## Defaults & configuration reference

All built-in defaults can be overridden via config file and, where marked, via a `GITVAULT_*`
environment variable. Precedence (highest → lowest): CLI flag → `GITVAULT_*` env var → project
`.gitvault/config.toml` → user-global `~/.config/gitvault/config.toml` → built-in default.

| Setting | Default | Config file key | `GITVAULT_*` env var |
|---------|---------|-----------------|----------------------|
| Active environment | `dev` | `[env] default` | `GITVAULT_ENV` |
| Production env name | `prod` | `[env] prod_name` | — |
| Environment name file | `.secrets/env` | `[env] env_file` | — |
| Prod allow-token TTL (s) | `3600` | `[barrier] ttl_secs` | — |
| Recipients directory | `.secrets/recipients/` | `[paths] recipients_dir` | — |
| Materialize output file | `.env` | `[paths] materialize_output` | — |
| Keyring service name | `gitvault` | `[keyring] service` | — |
| Keyring account name | `age-identity` | `[keyring] account` | — |
| Hook manager adapter | *(none)* | `[hooks] adapter` | — |
| Prod allow-token file | `.secrets/.prod-token` | *(planned)* | — |
| Encrypted secrets dir | `secrets/` | *(planned)* | — |
| Decrypted plaintext dir | `.secrets/plain/` | *(planned)* | — |
| Identity key path/string | — | — | `GITVAULT_IDENTITY` |
| SSH-agent key selector | — | — | `GITVAULT_IDENTITY_SELECTOR` |
| SSH-agent enabled | off | — | `GITVAULT_SSH_AGENT=1` |
| Non-interactive mode | off | — | `CI=1` |
| AWS profile (SSM) | — | — | `AWS_PROFILE` |
| AWS role ARN (SSM) | — | — | `AWS_ROLE_ARN` |

Each Git worktree resolves its active environment independently. The environment can also be
overridden per-command with `--env` (on `encrypt`, `materialize`, `run`, and `check`).

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
│   ├── recipients/        # one .pub file per recipient (e.g. alice.pub, bob.pub)
│   │   ├── alice.pub
│   │   └── bob.pub
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
| 3 | OS keyring (always tried automatically) |
| 4 | SSH-agent when `GITVAULT_SSH_AGENT=1` or `SSH_AUTH_SOCK` is set |

---

## Configuration

Two optional TOML config layers (both optional — missing file/section silently uses defaults):

| File | Scope |
|------|-------|
| `.gitvault/config.toml` | Repository-level; commit with the project |
| `~/.config/gitvault/config.toml` | User-global; personal defaults for all repos |

```toml
# .gitvault/config.toml

[env]
default = "staging"         # default environment (built-in: "dev")
prod_name = "production"    # name that triggers the production barrier (built-in: "prod")
env_file = ".config/env"    # path to env-name file (built-in: ".secrets/env")

[barrier]
ttl_secs = 1800             # production allow-token lifetime in seconds (built-in: 3600)

[paths]
materialize_output = ".env.local"            # built-in: ".env"
recipients_dir = ".gitvault/recipients"      # built-in: ".secrets/recipients"

[hooks]
adapter = "husky"           # hook manager: husky | pre-commit | lefthook
```

```toml
# ~/.config/gitvault/config.toml
[keyring]
service = "my-company-gitvault"   # avoid collisions with other gitvault instances
account = "default-identity"
```

Hook manager adapters require the corresponding binary on `PATH` (`gitvault-husky`,
`gitvault-pre-commit`, `gitvault-lefthook`).

> **Validation:** unknown keys inside a known section produce a `Usage` error (exit `2`).
> Unknown top-level sections are silently ignored for forward compatibility.

---

## Contributor and maintainer docs

- Development workflows: [docs/development.md](docs/development.md)
- AI agent onboarding and architecture hotspots: [docs/ai/AGENT_START.md](docs/ai/AGENT_START.md), [docs/ai/hotspots.md](docs/ai/hotspots.md)
- Regenerate AI code index: `cargo xtask ai-index` → `docs/ai/code-index.json`
- Release runbook: [docs/releasing.md](docs/releasing.md)

---

## Alternatives

| Tool | Approach |
|------|----------|
| [SOPS](https://github.com/getsops/sops) | Structured file encryption (YAML/JSON/.env); great for KMS-backed workflows |
| [git-crypt](https://github.com/AGWA/git-crypt) | Transparent whole-file encryption via Git filters |
| [git-secret](https://github.com/sobolevn/git-secret) | Simple GPG-based secret sharing inside Git |
| [BlackBox](https://github.com/StackExchange/blackbox) | Team-oriented GPG encryption/decryption |
| [transcrypt](https://github.com/elasticdog/transcrypt) | Lightweight transparent encryption for selected paths |

GitVault differentiators: age-native, deterministic per-field re-encryption for minimal diffs, structured leak prevention, and runtime injection for AI-agent workflows.

---

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
