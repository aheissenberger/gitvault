# Choosing Between `seal` and `encrypt` in gitvault

> **[← README](../README.md)** · [Identity Setup](identity-setup.md) · [Recipient Management](recipient-management.md) · [CI/CD Recipes](cicd-recipes.md) · Seal vs Encrypt · [CLI Reference](reference.md)

gitvault provides two main approaches for handling file secrets: `seal` and `encrypt`.
This guide gives a quick overview of each approach, compares them side-by-side, and shows practical use cases.

---

## Table of Contents

1. [Quick Introduction](#quick-introduction)
2. [Comparison Table](#comparison-table)
3. [Example Use Cases](#example-use-cases)
4. [How to Decide Quickly](#how-to-decide-quickly)
5. [Format Quick Recipes](#format-quick-recipes)
6. [Multi-environment Archive Layout](#multi-environment-archive-layout)
7. [Runtime and Git Workflow Notes](#runtime-and-git-workflow-notes)
8. [Advanced `seal` Configuration](#advanced-seal-configuration)
9. [Rule of Thumb](#rule-of-thumb)

---

## Quick Introduction

### `seal`: keep the same file, encrypt selected values

Use `seal` when you want to keep a structured file (`.json`, `.yaml`, `.toml`, `.env`) in place, but encrypt sensitive values inside it.

- File path stays the same
- Non-secret content remains readable
- Secret fields are encrypted in place

This is ideal for config files where teams still need to review non-secret keys in pull requests.

### `encrypt`: protect the whole file into the encrypted store

Use `encrypt` when you want to protect the entire file as one encrypted artifact.

- Original file path is mirrored under `.gitvault/store/<env>/...`
- Output is a full-file `.age` blob
- Decryption restores full plaintext content

This is ideal when nearly all content is sensitive, or when you want strong separation between source files and encrypted store artifacts.

---

## Comparison Table

| Topic | `seal` | `encrypt` |
|------|--------|-----------|
| Unit of protection | Selected fields/values | Entire file |
| Source file location | In-place (same path) | Stored under `.gitvault/store/<env>/...` |
| Supported inputs | Structured files: `.json`, `.yaml/.yml`, `.toml`, `.env` | Any file |
| Reviewability in Git | High: non-secret structure remains visible | Low: encrypted blob only |
| Typical decrypt flow | `unseal` file or fields | `decrypt` full file (or reveal) |
| Best fit | App config with mixed public + secret values | Files that are mostly or fully secret |

---

## Example Use Cases

### Use `seal` when structure should remain reviewable

A team keeps `config/app.yaml` in Git and wants only credentials encrypted:

```bash
gitvault seal config/app.yaml --fields db.password,api.token
```

Typical scenarios:
- Application configs where reviewers need to see non-secret defaults
- Ops files with only a handful of sensitive keys
- Incremental adoption in existing repositories

### Use `encrypt` when the file should be fully opaque

A team stores `certs/private-bundle.pem` or a secret-heavy config and does not need partial visibility:

```bash
gitvault encrypt certs/private-bundle.pem --env prod
```

Typical scenarios:
- TLS private key bundles
- License files, service credentials, binary secrets
- Files where nearly every line is sensitive

### Hybrid strategy (common in real repositories)

Many teams combine both:
- `seal` for human-readable app config (`.yaml`, `.toml`, `.env`)
- `encrypt` for fully sensitive artifacts (keys, cert bundles, secret-heavy files)

---

## How to Decide Quickly

- Choose `seal` when your team needs to review file structure and non-secret defaults in pull requests.
- Choose `encrypt` when the file should be fully opaque and handled as a single secret artifact.
- Choose both when your repo contains a mix of structured config and fully sensitive files.

---

## Format Quick Recipes

### `.env`

```bash
# Archive mode
gitvault encrypt .env --env dev
gitvault decrypt .env --env dev --reveal

# In-place mode
gitvault seal .env
gitvault unseal .env --reveal

# Selected keys only
gitvault seal .env --fields DATABASE_URL,API_KEY
gitvault unseal .env --fields DATABASE_URL,API_KEY --reveal
```

### JSON

```bash
# Archive mode
gitvault encrypt config/app.json --env prod
gitvault decrypt config/app.json --env prod --reveal | jq .

# In-place mode
gitvault seal config/app.json --fields database.password,api.key
gitvault unseal config/app.json --fields database.password,api.key --reveal | jq .

# Auto mode (all encryptable/decryptable values)
gitvault seal config/app.json
gitvault unseal config/app.json --reveal | jq .
```

### YAML

```bash
# Archive mode
gitvault encrypt k8s/secrets.yaml --env prod
gitvault decrypt k8s/secrets.yaml --env prod --reveal

# In-place mode
gitvault seal helm/values.yaml --fields postgresql.auth.password,redis.auth.password
gitvault unseal helm/values.yaml --reveal
```

### TOML

```bash
# Archive mode
gitvault encrypt Rocket.toml --env prod
gitvault decrypt Rocket.toml --env prod --reveal

# In-place mode
gitvault seal Rocket.toml --fields production.secret_key,production.databases.postgres.url
gitvault unseal Rocket.toml --reveal
```

---

## Multi-environment Archive Layout

```bash
gitvault encrypt .env --env dev
gitvault encrypt config/dev.json --env dev
gitvault encrypt .env.prod --env prod
```

Expected archive tree:

```text
.gitvault/store/
|- dev/
|  |- .env.age
|  \- config/
|     \- dev.json.age
\- prod/
	\- .env.prod.age
```

---

## Runtime and Git Workflow Notes

Prefer fileless runtime injection when possible:

```bash
gitvault run --env dev -- npm start
gitvault run --env prod --prod -- ./myapp
```

Use materialization only when a tool strictly requires a `.env` file:

```bash
gitvault materialize --env dev
```

Commit workflow for encrypted artifacts:

```bash
git add .gitvault/store/ .gitvault/recipients/
git commit -m "secrets: update encrypted artifacts"
```

Never commit plaintext outputs (`.env`, `.gitvault/plain/`).

---

## Advanced `seal` Configuration

If you need policy-driven sealing behavior across a repository, extend `.gitvault/config.toml` with
`[[seal.rule]]` entries (for example: allow/deny path matching and key filters).

- Config schema and examples: [CLI Reference - Rule-based command filtering](reference.md#rule-based-command-filtering-sealrule-materializerule-runrule)
- Full config layout: [CLI Reference - Configuration File](reference.md#configuration-file)

---

## Rule of Thumb

- Choose `seal` if you want to preserve file readability and only protect sensitive values.
- Choose `encrypt` if the entire file should be treated as secret.

If you are unsure, start with `seal` for structured config and use `encrypt` for everything that should remain fully opaque.

---

*For architecture details and the full CLI reference, see the [README](../README.md) and other files in [`docs/`](.).*

---

*For adding CI service accounts as recipients and the full onboarding ceremony, see [docs/recipient-management.md](recipient-management.md).*

## See also
- [CLI Reference — `seal`](reference.md#seal)
- [CLI Reference — `encrypt`](reference.md#encrypt)
- [CLI Reference — `unseal`](reference.md#unseal)
- [CLI Reference — `decrypt`](reference.md#decrypt)
- [CI/CD Recipes](cicd-recipes.md)
