# Secret Formats Cookbook

A practical guide to encrypting different file types with gitvault — copy-pastable examples for real-world workflows.

---

## Overview

gitvault supports three encryption modes, each suited to different use cases:

| Mode | Flag | Best For |
|------|------|----------|
| **Whole-file** | *(default)* | Binary configs, any file you want fully opaque |
| **Per-field** | `--fields key.path` | JSON/YAML/TOML where non-sensitive config should stay readable |
| **Per-value** | `--value-only` | `.env` files shared across a team; minimizes git diff noise |

**Quick rule of thumb:**
- New secret file you fully own → whole-file
- Config file mixing secret and non-secret keys → per-field
- `.env` edited by multiple developers → per-value

---

## .env Files

### Whole-file encryption (simplest)

Encrypts the entire `.env` as a single blob. Best when the file is small or you don't mind the whole file being opaque.

```bash
# Encrypt entire .env
gitvault encrypt .env --env dev
# Stored at: .gitvault/store/dev/.env.age

# Inspect contents without writing to disk
gitvault decrypt .gitvault/store/dev/.env.age --reveal

# Materialize to root .env for local dev tools
gitvault materialize
```

**Example `.env`:**
```dotenv
DATABASE_URL=postgres://user:supersecret@localhost:5432/myapp
REDIS_URL=redis://:redissecret@localhost:6379
API_KEY=sk-abc123def456
SESSION_SECRET=a-very-long-random-string
DEBUG=false
PORT=3000
```

> **Tip:** `gitvault materialize` writes the decrypted `.env` to your project root. Keep `.env` in `.gitignore` — gitvault tracks `.gitvault/store/` instead.

---

### Per-value encryption (minimal diff noise)

Encrypts each value individually while leaving key names in plaintext. When only one value changes, only that value's ciphertext changes — the rest of the file is stable in git history.

```bash
# Encrypt each value individually
gitvault encrypt .env --value-only --env dev
# Stored at: .gitvault/store/dev/.env.age

# Decrypt all values
gitvault decrypt .gitvault/store/dev/.env.age --value-only
```

**What the stored file looks like** (keys visible, values encrypted):
```dotenv
DATABASE_URL=age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs...
REDIS_URL=age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs...
API_KEY=age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs...
SESSION_SECRET=age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp...
DEBUG=false
PORT=3000
```

> **When to prefer per-value:** Large `.env` files edited by multiple developers. When Alice changes `DATABASE_URL` and Bob changes `API_KEY`, their commits show only the affected ciphertext lines changing — not the entire file re-encrypted.

> **Note:** Key names are visible in the repository. If key names themselves are sensitive, use whole-file encryption instead.

---

### Import existing .env (recommended first-time workflow)

`gitvault harden` is the one-command workflow for taking an existing `.env` and securing it:

```bash
# harden does three things automatically:
#   1. Encrypts .env  →  .gitvault/store/dev/.env.age
#   2. Runs git rm --cached .env  (removes from git tracking)
#   3. Adds .env to .gitignore
gitvault harden .env --env dev

# Optionally also delete the plaintext source file
gitvault harden .env --env dev --delete-source
```

After hardening, commit the result:
```bash
git add .gitvault/store/dev/.env.age .gitignore
git commit -m "secrets: harden .env for dev environment"
```

---

## JSON Secrets

### Whole-file encryption

```bash
gitvault encrypt config/secrets.json --env prod
# Stored at: .gitvault/store/prod/config/secrets.json.age

# Inspect without writing to disk
gitvault decrypt .gitvault/store/prod/config/secrets.json.age --reveal

# POSIX equivalent (pipe to jq, etc.)
gitvault decrypt .gitvault/store/prod/config/secrets.json.age -o - | jq .
```

---

### Per-field encryption

Encrypts only the fields you specify. The rest of the JSON structure remains in plaintext — useful when non-sensitive config (ports, feature flags, hostnames) should stay readable in code review.

```bash
# Encrypt only the sensitive fields
gitvault encrypt config/app.json --fields database.password,api.key --env prod

# Decrypt to get the full file with decrypted fields
gitvault decrypt .gitvault/store/prod/config/app.json.age \
  --fields database.password,api.key
```

**Example: `config/app.json` before and after**

```json
// Before encryption
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "password": "supersecret123"
  },
  "api": {
    "key": "sk-abc123",
    "timeout": 30
  },
  "debug": false,
  "log_level": "info"
}
```

```json
// After: gitvault encrypt app.json --fields database.password,api.key --env prod
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "password": "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs..."
  },
  "api": {
    "key": "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs...",
    "timeout": 30
  },
  "debug": false,
  "log_level": "info"
}
```

Non-sensitive fields (`host`, `port`, `timeout`, `debug`, `log_level`) remain readable in git history and code review. Only `password` and `key` are encrypted.

> **Tip:** Use dot-notation for nested fields: `database.password` → `{"database": {"password": ...}}`. For array elements, use index notation: `servers.0.token`.

---

## YAML Secrets

### Whole-file encryption

```bash
# Encrypt a Kubernetes Secret manifest
gitvault encrypt k8s/secrets.yaml --env prod

# Preserve directory structure in the store (recommended for monorepos)
gitvault encrypt k8s/secrets.yaml --env prod --keep-path
# Stored at: .gitvault/store/prod/k8s/secrets.yaml.age
```

---

### Per-field encryption

Common for Helm values files and docker-compose overrides where most config is non-sensitive.

```bash
# Helm values: encrypt only the auth passwords
gitvault encrypt helm/values.yaml \
  --fields postgresql.auth.password,redis.auth.password \
  --env prod

# docker-compose: encrypt only secrets
gitvault encrypt docker-compose.override.yaml \
  --fields services.app.environment.DATABASE_PASSWORD,services.app.environment.API_KEY \
  --env dev
```

**Example: `helm/values.yaml` before and after**

```yaml
# Before: helm/values.yaml
postgresql:
  auth:
    username: myapp
    password: "supersecret"
    database: myapp_prod
  primary:
    persistence:
      size: 8Gi

redis:
  auth:
    password: "redissecret"
  replica:
    replicaCount: 2

ingress:
  enabled: true
  hostname: myapp.example.com
```

```yaml
# After: gitvault encrypt values.yaml --fields postgresql.auth.password,redis.auth.password --env prod
postgresql:
  auth:
    username: myapp
    password: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs..."
    database: myapp_prod
  primary:
    persistence:
      size: 8Gi

redis:
  auth:
    password: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs..."
  replica:
    replicaCount: 2

ingress:
  enabled: true
  hostname: myapp.example.com
```

Non-sensitive Helm config (`username`, `database`, `persistence.size`, `ingress`) stays readable. Secrets are encrypted in place.

> **Kubernetes manifests:** Prefer whole-file encryption for `kind: Secret` manifests — they're opaque by design and the base64 values add no readability benefit when per-field encrypted.

---

## TOML Secrets

### Whole-file encryption

```bash
gitvault encrypt config.toml --env prod
# Stored at: .gitvault/store/prod/config.toml.age
```

---

### Per-field encryption

```bash
# Rocket.toml: encrypt only production secrets
gitvault encrypt Rocket.toml \
  --fields production.secret_key,production.databases.postgres.password \
  --env prod
```

**Example: `Rocket.toml`**

```toml
# Before: Rocket.toml
[default]
address = "0.0.0.0"
log_level = "normal"

[production]
port = 8080
secret_key = "hPRYyVRiMyxpw5sBB1XeCMN1kFsDCqKvBi2QJxBVHQk="

[production.databases.postgres]
url = "postgres://myapp:supersecret@db.example.com:5432/myapp_prod"
pool_size = 10
```

```toml
# After: gitvault encrypt Rocket.toml --fields production.secret_key,production.databases.postgres.url --env prod
[default]
address = "0.0.0.0"
log_level = "normal"

[production]
port = 8080
secret_key = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs..."

[production.databases.postgres]
url = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs..."
pool_size = 10
```

Non-sensitive settings (`address`, `log_level`, `port`, `pool_size`) remain readable.

> **Tip:** For Rust apps using `config` crate with multiple files (`config/default.toml`, `config/production.toml`), encrypt only the production file that contains secrets.

---

## Multiple Secret Files in One Repo

### Environment-based organization

```bash
# Dev secrets
gitvault encrypt .env --env dev
gitvault encrypt config/dev.json --env dev

# Staging secrets
gitvault encrypt .env.staging --env staging
gitvault encrypt config/app.json --fields database.password,api.key --env staging

# Production secrets
gitvault encrypt .env.prod --env prod
gitvault encrypt k8s/secrets.yaml --env prod --keep-path

# Check what's tracked and the active environment
gitvault status
```

Resulting store layout:
```
.gitvault/store/
├── dev/
│   ├── .env.age
│   └── config/
│       └── dev.json.age
├── staging/
│   ├── .env.staging.age
│   └── config/
│       └── app.json.age
└── prod/
    ├── .env.prod.age
    └── k8s/
        └── secrets.yaml.age
```

---

### Materialize + inject workflow

```bash
# Write .env to disk for local dev tools that need a file (webpack, jest, etc.)
gitvault materialize --env dev
# Writes decrypted secrets to .env in project root (gitignored)

# Run app with secrets injected into the process environment — no file written
gitvault run --env dev -- npm start
gitvault run --env dev -- cargo run
gitvault run --env prod -- ./myapp --config config.toml
```

> **Prefer `gitvault run` over `gitvault materialize`** in production and CI — secrets are injected into the child process environment and never written to disk.

---

## Working with Secret Files in Git

### First-time repo setup

```bash
# After encrypting your secrets:
git add .gitvault/store/ .gitvault/recipients/
git commit -m "secrets: add encrypted secrets for dev and prod"

# Verify nothing plaintext slipped in
git show --stat HEAD
```

> **Warning:** Never commit `.gitvault/plain/` — it contains decrypted plaintext. Add it to `.gitignore`:
> ```
> .gitvault/plain/
> ```

---

### After decryption (local dev)

```bash
# Option A: materialize to .env (gitignored)
gitvault materialize --env dev

# Option B: decrypt a specific file to a specific path
gitvault decrypt .gitvault/store/dev/.env.age -o .env

# Option C: decrypt to stdout and pipe
gitvault decrypt .gitvault/store/prod/config/app.json.age --reveal | jq '.database'
```

---

### Onboarding a new team member

> **See also:** Full onboarding ceremony instructions are in [README.md § Quick Start](../README.md#new-team-member). The steps below focus only on the secret-management side.

```bash
# New developer generates their identity and adds themselves as a recipient
gitvault init
gitvault recipient add-self

# Open a PR with the new .pub file in .gitvault/recipients/
# Existing team member re-encrypts all secrets for the new recipient
gitvault rekey

# Commit and push — new developer can now decrypt
git add .gitvault/store/ .gitvault/recipients/
git commit -m "secrets: rekey for new team member"
```

---

## Tips and Best Practices

| Tip | Detail |
|-----|--------|
| Use `--value-only` for shared `.env` files | Key names stay visible; only changed values produce new ciphertext on commit |
| Use `--fields` for mixed config files | Keep non-sensitive config readable in PRs; encrypt only what must be secret |
| Use `--keep-path` in monorepos | Preserves directory structure under `.gitvault/store/<env>/` — avoids name collisions |
| Prefer `gitvault run` over `materialize` in CI | Secrets never touch the filesystem; no cleanup needed after the job |
| Always commit `.gitvault/store/` and `.gitvault/recipients/` | These are the encrypted artifacts — they belong in git |
| Never commit `.gitvault/plain/` | Add it to `.gitignore` immediately after `gitvault init` |
| Use `gitvault harden` for existing files | One command handles encrypt + gitignore + git rm --cached |
| Run `gitvault status` after changes | Confirms active environment and shows drift between store and working tree |

> **Security reminder:** age encryption is strong, but your identity key is only as safe as the machine it lives on. Store your identity in the OS keyring (`gitvault identity create`, which stores in the keyring by default) rather than a plaintext file where possible. See [docs/identity-setup.md](identity-setup.md) for all identity storage options.
