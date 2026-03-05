# CI/CD Best Practices & Recipes for gitvault

> **[← README](../README.md)** · [Identity Setup](identity-setup.md) · [Recipient Management](recipient-management.md) · CI/CD Recipes · [Secret Formats](secret-formats.md) · [CLI Reference](reference.md)

gitvault is a Git-native, age-encrypted secrets manager. This guide covers how to integrate it safely into CI/CD pipelines, container builds, and orchestration platforms.

---

## Table of Contents

1. [Security Principles](#security-principles)
2. [Identity Resolution Order](#identity-resolution-order)
3. [Exit Codes Reference](#exit-codes-reference)
4. [Environment Variables Reference](#environment-variables-reference)
5. [GitHub Actions Recipes](#github-actions-recipes)
6. [Docker Recipes](#docker-recipes)
7. [Kubernetes Recipes](#kubernetes-recipes)
8. [materialize vs run — When to Use Each](#materialize-vs-run--when-to-use-each)
9. [Anti-patterns to Avoid](#anti-patterns-to-avoid)

---

## Security Principles

These principles apply regardless of which CI/CD platform you use.

| Principle | Why it matters |
|-----------|---------------|
| **Keep private keys in memory as briefly as possible** | Minimises the window in which a key can be extracted from a running process |
| **Prefer FD-passing over environment variables** | Keys passed via file descriptor do not appear in `/proc/<pid>/environ` or `ps` output |
| **Never write private keys to disk in CI** | Disk artifacts persist beyond the process lifetime and may be captured in build caches or logs |
| **Prefer `gitvault run` over `materialize`** | Secrets are injected directly into the child process env; they never touch the filesystem |
| **Revoke production tokens immediately after use** | Short-lived tokens and instant revocation limit blast radius if a pipeline is compromised |
| **Always pass `--no-prompt` (or set `CI=1`)** | Interactive prompts cause pipelines to hang indefinitely; most CI systems set `CI=true` automatically |

> **Security:** The safest way to supply a key in CI is via a file descriptor (`GITVAULT_IDENTITY_FD`). The key is read once, held in process memory, and is never visible in the process environment listing.

---

## Identity Resolution Order

Identity is resolved in this order: `--identity-stdin` → `--identity` / `GITVAULT_IDENTITY_FD` → `GITVAULT_IDENTITY` → OS keyring → SSH agent. → [Full resolution table](reference.md#identity-resolution)

In headless CI environments you will almost always use `GITVAULT_IDENTITY_FD` (most secure) or `GITVAULT_IDENTITY`.

> **See also:** [docs/identity-setup.md](identity-setup.md) for a detailed breakdown of every identity method with setup instructions.

---

## Exit Codes Reference

→ Exit codes reference: [docs/reference.md § Exit Codes](reference.md#exit-codes)

Exit code `3` (plaintext secret detected) and `6` (drift) will automatically fail CI steps — use them as gates in your pipeline.

---

## Environment Variables Reference

> **All environment variables:** [docs/reference.md § Environment Variables](reference.md#environment-variables)

Key variables used in the recipes below: `GITVAULT_IDENTITY_FD` (most secure key supply), `GITVAULT_IDENTITY` (simpler alternative), `GITVAULT_NO_INLINE_KEY_WARN=1` (suppress inline-key warning), `CI=1` (auto-enables `--no-prompt`).

---

## GitHub Actions Recipes

### Basic secret injection — fd-passing (recommended)

File descriptor 3 is opened from the Actions secret and passed directly to gitvault. The key never appears in the environment.

```yaml
- name: Inject secrets and run
  run: |
    GITVAULT_IDENTITY_FD=3 gitvault run --no-prompt --env prod -- ./deploy.sh \
      3<<<"${{ secrets.GITVAULT_KEY }}"
```

> **Security:** The `3<<<` here-string opens file descriptor 3 in the subprocess. The key is not exported as an environment variable and will not appear in `/proc/<pid>/environ`.

---

### Alternative: environment variable injection (simpler, slightly less secure)

Use this when fd-passing is not available (e.g. some third-party action wrappers).

```yaml
- name: Deploy
  env:
    GITVAULT_IDENTITY: ${{ secrets.GITVAULT_KEY }}
    GITVAULT_NO_INLINE_KEY_WARN: "1"
  run: gitvault run --no-prompt --env prod -- ./deploy.sh
```

> **Note:** With `GITVAULT_IDENTITY`, the key is visible in `/proc/<pid>/environ` for the lifetime of the process. Prefer fd-passing for production deployments.

---

### Safety preflight check

Run this early in every workflow to catch plaintext secrets committed accidentally.

```yaml
- name: Verify no plaintext secrets committed
  run: gitvault check --no-prompt --env prod
```

Exit code `3` (plaintext secret detected) or `6` (drift) will automatically fail the step.

---

### Complete GitHub Actions workflow

```yaml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production   # triggers environment protection rules

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install gitvault
        run: |
          curl -sSfL https://github.com/your-org/gitvault/releases/latest/download/gitvault-linux-amd64 \
            -o /usr/local/bin/gitvault
          chmod +x /usr/local/bin/gitvault

      - name: Preflight — verify secrets integrity
        run: gitvault check --no-prompt --env prod
        # Fails on exit code 3 (plaintext) or 6 (drift)

      - name: Preflight — status overview
        run: gitvault status --no-prompt

      - name: Enable production window (5-minute TTL)
        run: gitvault allow-prod --ttl 300 --no-prompt

      - name: Deploy with secrets injected via fd
        run: |
          GITVAULT_IDENTITY_FD=3 gitvault run --no-prompt --env prod -- ./scripts/deploy.sh \
            3<<<"${{ secrets.GITVAULT_KEY }}"

      - name: Revoke production window
        if: always()   # runs even when previous steps fail
        run: gitvault revoke-prod --no-prompt
```

> **Security:** The `if: always()` on the revoke step ensures the production barrier is revoked even if the deploy step fails or is cancelled.

### Real-world: migration job with `materialize` then app deploy with `run`

Use this pattern when one step requires a `.env` file (for example, ORM migrations), but the main app can run fileless.

```yaml
- name: DB migration (expects .env on disk)
  run: |
    GITVAULT_IDENTITY_FD=3 gitvault materialize --no-prompt --env prod \
      3<<<"${{ secrets.GITVAULT_KEY }}"
    npm run migrate
    rm -f .env

- name: Deploy API (fileless)
  run: |
    GITVAULT_IDENTITY_FD=3 gitvault run --no-prompt --env prod -- ./scripts/deploy-api.sh \
      3<<<"${{ secrets.GITVAULT_KEY }}"
```

> **Operational note:** remove the materialized file immediately after the file-bound step. Keep `run` for long-lived service commands.

---

### Production deployment with barrier (explicit steps)

```yaml
- name: Enable production window
  run: gitvault allow-prod --ttl 300 --no-prompt

- name: Deploy
  run: |
    GITVAULT_IDENTITY_FD=3 gitvault run --no-prompt --env prod -- ./deploy.sh \
      3<<<"${{ secrets.GITVAULT_KEY }}"

- name: Revoke production window
  if: always()
  run: gitvault revoke-prod --no-prompt
```

> **Note:** Keep `--ttl` as short as your deploy takes plus a small buffer. Prefer `revoke-prod` immediately after deploy rather than relying on TTL expiry.

---

## Docker Recipes

### Using Docker BuildKit secrets (most secure)

BuildKit secrets are mounted as temporary files under `/run/secrets/` and are never baked into an image layer.

```dockerfile
# Dockerfile
FROM node:22-alpine AS builder

RUN --mount=type=secret,id=gitvault_key \
    GITVAULT_IDENTITY_FD=3 \
    gitvault materialize --no-prompt --env prod \
    3</run/secrets/gitvault_key \
    && npm ci && npm run build
```

```bash
# Build command — key is never written to disk
docker build \
  --secret id=gitvault_key,src=<(echo "$GITVAULT_KEY") \
  --tag myapp:latest .
```

> **Security:** BuildKit secrets are mounted read-only and removed after the `RUN` step completes. They do not appear in `docker history` or image layers.

---

### Multi-stage build — secrets available only in builder stage

```dockerfile
# ── Stage 1: build with secrets ─────────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app
COPY . .

RUN --mount=type=secret,id=gitvault_key \
    GITVAULT_IDENTITY_FD=3 \
    gitvault materialize --no-prompt --env prod \
    3</run/secrets/gitvault_key \
    && npm ci && npm run build

# ── Stage 2: lean runtime image — no key, no gitvault ───────────────────────
FROM node:22-alpine AS runtime
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
# .env produced by materialize is NOT copied — supply at runtime
CMD ["node", "dist/server.js"]
```

> **Note:** Never copy a `.env` produced by `materialize` into the final image. Supply secrets at runtime via `gitvault run` or your orchestrator's secret injection.

---

### Docker Compose with environment secrets

```yaml
# docker-compose.yml
secrets:
  gitvault_key:
    environment: GITVAULT_KEY   # sourced from host env, not written to disk

services:
  app:
    image: myapp:latest
    secrets:
      - gitvault_key
    command: >
      sh -c 'exec GITVAULT_IDENTITY_FD=3
             gitvault run --no-prompt --env prod
             -- node server.js
             3</run/secrets/gitvault_key'
```

> **Security:** Docker Compose secrets are mounted under `/run/secrets/` inside the container and are not visible in `docker inspect` environment output.

---

### Entrypoint pattern — clean environment for child process

Use this when your container needs to bootstrap with a key and then `exec` the main process without the key in its environment.

```bash
#!/bin/sh
# entrypoint.sh
# The key is used once to decrypt secrets, then exec replaces the shell.
# --clear-env removes all inherited vars from the child process.
# --keep-vars ensures the child still has a functional environment.
exec GITVAULT_IDENTITY_FD=3 \
  gitvault run \
    --no-prompt \
    --env prod \
    --clear-env \
    --keep-vars PATH,HOME,TZ,LANG \
  -- "$@" \
  3<<<"$GITVAULT_KEY"
```

```dockerfile
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["node", "server.js"]
```

> **Security:** `--clear-env --keep-vars PATH,HOME,TZ` ensures `GITVAULT_KEY` (and every other variable from the outer environment) is stripped before the child process starts. The child process inherits only the decrypted secret values that gitvault injects, plus the explicitly kept variables.

### Real-world: one-off admin task in a running container (`run`)

Use `run` for operational commands (schema checks, cache warmup, smoke tests) without generating files:

```bash
docker run --rm \
  -e GITVAULT_KEY="$GITVAULT_KEY" \
  myapp:latest \
  sh -lc 'GITVAULT_IDENTITY_FD=3 gitvault run --no-prompt --env prod -- ./bin/smoke-test 3<<<"$GITVAULT_KEY"'
```

This keeps secrets ephemeral and avoids leaking `.env` into container layers or mounted volumes.

---

### Key lifecycle — preventing key leakage to child processes

```bash
# BAD: GITVAULT_KEY is exported and visible to all child processes
export GITVAULT_KEY="AGE-SECRET-KEY-..."
./deploy.sh   # deploy.sh and all its children can read GITVAULT_KEY

# GOOD: key scoped to gitvault run, stripped before child starts
GITVAULT_IDENTITY_FD=3 \
  gitvault run --no-prompt --clear-env --keep-vars PATH,HOME -- ./deploy.sh \
  3<<<"$GITVAULT_KEY"
# deploy.sh receives only the injected secrets, not GITVAULT_KEY
```

---

## Kubernetes Recipes

### Supplying the identity via a Kubernetes Secret

Store the age private key as a Kubernetes Secret and reference it in your Pod spec.

```bash
# Create the secret (run once, from a secure workstation)
kubectl create secret generic gitvault-identity \
  --from-literal=key="$(cat ~/.config/gitvault/identity.txt)" \
  --namespace=production
```

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:latest
          command: ["gitvault", "run", "--no-prompt", "--env", "prod", "--", "node", "server.js"]
          env:
            - name: GITVAULT_IDENTITY
              valueFrom:
                secretKeyRef:
                  name: gitvault-identity
                  key: key
            - name: GITVAULT_NO_INLINE_KEY_WARN
              value: "1"
```

> **Note:** With `GITVAULT_IDENTITY`, the key is visible in the process environment. For higher security, use the init container + fd pattern below.

---

### Init container pattern — materialize secrets to a shared volume

Use this when your application expects a `.env` file or a config directory at startup.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  volumes:
    - name: secrets-volume
      emptyDir:
        medium: Memory   # tmpfs — secrets never touch node disk

  initContainers:
    - name: gitvault-init
      image: myapp:latest   # or a dedicated gitvault image
      command:
        - sh
        - -c
        - |
          GITVAULT_IDENTITY_FD=3 \
          gitvault materialize --no-prompt --env prod \
          3<<<"$GITVAULT_KEY"
      env:
        - name: GITVAULT_KEY
          valueFrom:
            secretKeyRef:
              name: gitvault-identity
              key: key
      volumeMounts:
        - name: secrets-volume
          mountPath: /secrets

  containers:
    - name: app
      image: myapp:latest
      command: ["node", "server.js"]
      envFrom:
        - prefix: ""
          secretRef: {}   # or source the /secrets/.env in your entrypoint
      volumeMounts:
        - name: secrets-volume
          mountPath: /secrets
          readOnly: true
```

> **Security:** Using `emptyDir.medium: Memory` mounts a `tmpfs` volume. The materialized secrets exist only in RAM and are automatically cleaned up when the Pod terminates. The init container exits (and the gitvault process terminates) before the main container starts.

### Real-world: sidecar-free deployment using `run` in Kubernetes

If your app consumes environment variables directly, skip init-container materialization and run your process through gitvault:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
spec:
  template:
    spec:
      containers:
        - name: app
          image: myorg/payments:latest
          command:
            - sh
            - -lc
            - |
              exec GITVAULT_IDENTITY_FD=3 \
                gitvault run --no-prompt --env prod -- ./payments-api \
                3<<<"$GITVAULT_KEY"
          env:
            - name: GITVAULT_KEY
              valueFrom:
                secretKeyRef:
                  name: gitvault-identity
                  key: key
```

Use this for stateless services; use init-container + `materialize` only when the app strictly requires a config file.

---

### CronJob — short-lived identity

For scheduled jobs, request a short-lived token and revoke immediately after.

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-sync
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: sync
              image: myapp:latest
              command:
                - sh
                - -c
                - |
                  set -e
                  gitvault allow-prod --ttl 120 --no-prompt
                  GITVAULT_IDENTITY_FD=3 \
                  gitvault run --no-prompt --env prod -- ./sync.sh \
                  3<<<"$GITVAULT_KEY"
                  gitvault revoke-prod --no-prompt
              env:
                - name: GITVAULT_KEY
                  valueFrom:
                    secretKeyRef:
                      name: gitvault-identity
                      key: key
```

---

## materialize vs run — When to Use Each

| | `gitvault materialize` | `gitvault run` |
|---|---|---|
| **What it does** | Writes secrets to a `.env` file on disk | Injects secrets into child process environment; no file written |
| **Secrets touch disk?** | ✅ Yes | ❌ No |
| **Suitable for containers?** | Only with tmpfs or BuildKit secrets | ✅ Yes, preferred |
| **Works with arbitrary commands?** | Requires app to read `.env` | ✅ Yes — wraps any command |
| **Use in Docker `RUN`?** | Only with `--mount=type=secret` | Not applicable (no long-running process) |
| **Use in CI pipelines?** | Acceptable when disk write is audited | ✅ Preferred |
| **Use in Kubernetes?** | Init container + `emptyDir` (Memory) | ✅ Preferred for single-process pods |
| **Best for** | Legacy apps that read `.env`; init container pattern | All greenfield workloads; any app that accepts env vars |

> **Note:** Prefer `gitvault run` in almost all CI/CD contexts. Use `materialize` only when your application cannot be wrapped (e.g. it reads config exclusively from a file at startup) and you have ensured the output path is on a memory-backed filesystem.

---

## Anti-patterns to Avoid

### ❌ Key in shell history via `echo`

```bash
# NEVER do this — the key appears in shell history and in process listings
echo "$GITVAULT_KEY" | gitvault run --no-prompt --env prod -- node server.js
```

Use `GITVAULT_IDENTITY_FD` with a here-string or file descriptor redirect instead.

---

### ❌ Key committed to source control or baked into an image

```dockerfile
# NEVER do this — the key is baked into the image layer forever
COPY identity.txt /root/.config/gitvault/identity.txt
RUN gitvault materialize --no-prompt --env prod
```

Supply the key at build time via `--mount=type=secret` (BuildKit) or at runtime via an orchestrator secret.

---

### ❌ `materialize` in a `RUN` step without BuildKit secrets

```dockerfile
# NEVER do this — the key and the .env are committed to the image layer
ARG GITVAULT_KEY
RUN GITVAULT_IDENTITY="$GITVAULT_KEY" gitvault materialize --no-prompt --env prod
```

Use `RUN --mount=type=secret` so the key and output file are never written to a layer.

---

### ❌ Long-lived production allow tokens

```bash
# AVOID — token valid for 24 hours is a large blast radius
gitvault allow-prod --ttl 86400

# PREFER — token valid only as long as the deploy takes
gitvault allow-prod --ttl 300
./deploy.sh
gitvault revoke-prod   # revoke immediately, don't wait for TTL
```

---

### ❌ Hardcoded `--identity` flag in checked-in scripts

```bash
# AVOID — key path (or key value) is visible in source control
gitvault run --identity /home/ci/.ssh/age-key --no-prompt --env prod -- node server.js
```

Use `GITVAULT_IDENTITY_FD` or `GITVAULT_IDENTITY` supplied at runtime from your secrets store.

---

### ❌ Exporting the key into the shell environment

```bash
# AVOID — exported vars are inherited by every subsequent subprocess
export GITVAULT_IDENTITY="$SECRET"
./build.sh        # build.sh and all children see GITVAULT_IDENTITY
./test.sh         # test processes also see the key
./deploy.sh
```

Scope the variable only to the gitvault invocation:

```bash
# GOOD — key visible only to gitvault, not to child processes
GITVAULT_IDENTITY_FD=3 gitvault run --no-prompt --env prod -- ./deploy.sh \
  3<<<"$SECRET"
```

---

*For architecture details and the full CLI reference, see the [README](../README.md) and other files in [`docs/`](.).*

---

*For adding CI service accounts as recipients and the full onboarding ceremony, see [docs/recipient-management.md](recipient-management.md).*

## See also
- [CLI Reference — Environment Variables](reference.md#environment-variables)
- [CLI Reference — Exit Codes](reference.md#exit-codes)
- [Identity Setup](identity-setup.md) — configuring your identity for CI
