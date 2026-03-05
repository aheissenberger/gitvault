# Secret Formats Cookbook

> **[← README](../README.md)** · [CLI Reference](reference.md)

Practical format-specific patterns for `gitvault` using the current command set.

## Command Model

- Use `encrypt` / `decrypt` for archive files under `.gitvault/store/<env>/`.
- Use `seal` / `unseal` for in-place field/value encryption in structured files.

## `.env` Files

### Archive mode (`encrypt` / `decrypt`)

```bash
gitvault encrypt .env --env dev
gitvault decrypt .env --env dev --reveal
```

Output archive path mirrors source path:
- `.gitvault/store/dev/.env.age`

### In-place mode (`seal` / `unseal`)

```bash
gitvault seal .env
gitvault unseal .env --reveal
```

Seal only selected keys:

```bash
gitvault seal .env --fields DATABASE_URL,API_KEY
gitvault unseal .env --fields DATABASE_URL,API_KEY --reveal
```

## JSON

### Archive mode

```bash
gitvault encrypt config/app.json --env prod
gitvault decrypt config/app.json --env prod --reveal | jq .
```

### In-place mode

```bash
gitvault seal config/app.json --fields database.password,api.key
gitvault unseal config/app.json --fields database.password,api.key --reveal | jq .
```

Auto mode (all encryptable/decryptable values):

```bash
gitvault seal config/app.json
gitvault unseal config/app.json --reveal | jq .
```

## YAML

### Archive mode

```bash
gitvault encrypt k8s/secrets.yaml --env prod
gitvault decrypt k8s/secrets.yaml --env prod --reveal
```

### In-place mode

```bash
gitvault seal helm/values.yaml --fields postgresql.auth.password,redis.auth.password
gitvault unseal helm/values.yaml --reveal
```

## TOML

### Archive mode

```bash
gitvault encrypt Rocket.toml --env prod
gitvault decrypt Rocket.toml --env prod --reveal
```

### In-place mode

```bash
gitvault seal Rocket.toml --fields production.secret_key,production.databases.postgres.url
gitvault unseal Rocket.toml --reveal
```

## Multi-environment layout

```bash
gitvault encrypt .env --env dev
gitvault encrypt config/dev.json --env dev
gitvault encrypt .env.prod --env prod
```

Expected archive tree:

```text
.gitvault/store/
├── dev/
│   ├── .env.age
│   └── config/
│       └── dev.json.age
└── prod/
    └── .env.prod.age
```

## Runtime usage

Prefer fileless runtime injection when possible:

```bash
gitvault run --env dev -- npm start
gitvault run --env prod --prod -- ./myapp
```

Use materialization only when a tool strictly requires a `.env` file:

```bash
gitvault materialize --env dev
```

## Git workflow

```bash
git add .gitvault/store/ .gitvault/recipients/
git commit -m "secrets: update encrypted artifacts"
```

Never commit plaintext outputs (`.env`, `.gitvault/plain/`).

## Best practices

- Use `seal`/`unseal` when you want readable non-secret config and encrypted secret fields.
- Use `encrypt`/`decrypt` when you want fully opaque archive artifacts in `.gitvault/store/`.
- Use `gitvault status --fail-if-dirty` in CI before deploy steps.
- Use `gitvault <command> --help` to confirm flags before automation changes.
