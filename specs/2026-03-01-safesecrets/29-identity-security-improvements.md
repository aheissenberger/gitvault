---
id: "S-20260304-029"
title: "Plan: GITVAULT_IDENTITY security improvements"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md", "docs/**"]
  touch:
    - "src/identity.rs"
    - "src/env.rs"
    - "src/cli.rs"
    - "src/dispatch.rs"
    - "README.md"
    - "docs/ai/skill.md"
    - "specs/**"
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-75: a runtime warning is emitted to stderr when `GITVAULT_IDENTITY` contains a raw `AGE-SECRET-KEY-…` value; warning is suppressed in `--json` mode and when the value is a file path."
  - id: "AC2"
    text: "REQ-74: `--identity-stdin` flag is available on all identity-consuming commands; reads key from stdin pipe into `Zeroizing<String>`; fails closed on TTY stdin; mutually exclusive with `--identity`."
  - id: "AC3"
    text: "REQ-73: `GITVAULT_IDENTITY_FD=<n>` reads the age private key from file descriptor `n` on Unix; priority between `--identity` and `GITVAULT_IDENTITY`; unsupported on Windows (documented warning + skip)."
  - id: "AC4"
    text: "Updated identity resolution precedence is documented and enforced across all identity-consuming command paths: `--identity` / `--identity-stdin` → `GITVAULT_IDENTITY_FD` → `GITVAULT_IDENTITY` → keyring → ssh-agent (optional)."
  - id: "AC5"
    text: "README and `docs/ai/skill.md` include a 'Secure CI/CD identity passing' section documenting the recommended patterns in priority order: (1) OIDC + external vault, (2) `--identity-stdin` with `/dev/shm` temp file, (3) `GITVAULT_IDENTITY_FD` (non-GHA), (4) `GITVAULT_IDENTITY` file path, (5) `GITVAULT_IDENTITY` inline (legacy, warned)."
  - id: "AC6"
    text: "Existing identity resolution tests, CI workflows, and dev-shell scripts continue to pass without modification. No breaking changes to existing behaviour."
verification:
  commands:
    - "cargo test --all-targets --all-features"
    - "cargo clippy --all-targets --all-features -D warnings"
risk:
  level: "medium"
links:
  issue: ""
  pr: ""
---

## Context

`GITVAULT_IDENTITY` is the primary non-interactive identity mechanism for CI and scripted usage. It currently accepts both file paths and raw `AGE-SECRET-KEY-…` values inline. The inline form exposes private key material in `/proc/<PID>/environ` (Linux), `ps auxe` output, and any audit log that captures process environments — for the full lifetime of the `gitvault` process.

The ecosystem pattern (SOPS, age, Docker, gpg) has converged on two secure alternatives:
1. **Stdin piping** (`--password-stdin`, `--passphrase-fd 0`): key arrives via kernel pipe buffer; never in env.
2. **File descriptor passing** (`GITVAULT_IDENTITY_FD`): FD integer in env (not secret); key content read inside the process.

For GitHub Actions specifically, the industry-standard pattern is to write the secret to `/dev/shm` (tmpfs, never hits disk) and pass the file path — or to use OIDC authentication with an external vault so the private key never enters GitHub secrets storage at all.

## Goal

Harden `GITVAULT_IDENTITY`-based identity loading with three additive improvements:
1. **Warn** users who use the inline key form about the exposure risk (REQ-75 — zero breaking changes).
2. **Add `--identity-stdin`** for pipeline-safe key injection (REQ-74 — recommended for GitHub Actions).
3. **Add `GITVAULT_IDENTITY_FD`** for systemd/Docker/script callers (REQ-73 — Unix only).

## Non-goals

- Removing `GITVAULT_IDENTITY` inline key support (backward compatibility is preserved).
- Modifying existing keyring, SSH-agent, or `--identity` flag behaviour.
- Windows FD semantics (documented limitation; `/dev/shm` equivalent does not exist on Windows).
- Addressing `GITVAULT_IDENTITY_PASSPHRASE` exposure (separate security finding; not in this plan).

## Constraints

- All three changes are additive; no existing env var, flag, or precedence level is altered.
- `GITVAULT_IDENTITY_FD` is `#[cfg(unix)]`; Windows compile must not reference Unix-only APIs.
- Key material at every new loading path must be placed in `Zeroizing<String>` immediately upon read.
- Warning (REQ-75) must never appear in `--json` mode; it goes to stderr only.
- Implementation order: REQ-75 first (lowest risk, highest visibility), then REQ-74, then REQ-73.

## Updated Identity Resolution Precedence

```
1. --identity <path>          (explicit flag — highest priority)
   --identity-stdin           (explicit flag — same level, mutually exclusive with --identity)
2. GITVAULT_IDENTITY_FD=<n>  (Unix only; FD int in env, key material not in env)
3. GITVAULT_IDENTITY=<value> (file path or inline key; inline form emits deprecation warning)
4. OS keyring                 (platform-native: macOS Keychain, Windows Credential Manager, Linux keyutils)
5. SSH-agent                  (optional; explicit selector required for ambiguous multi-key sets)
```

All existing specs that reference the precedence chain as
`--identity -> GITVAULT_IDENTITY -> keyring -> ssh-agent`
remain accurate for the positions they describe; this plan inserts two new entries between positions 1 and 3 without displacing any existing source.

## Requirement Coverage

- REQ-73, REQ-74, REQ-75.

## Acceptance Criteria

- AC1: Inline key warning (REQ-75) works as specified; no regressions.
- AC2: `--identity-stdin` (REQ-74) works on all platforms; TTY guard functions.
- AC3: `GITVAULT_IDENTITY_FD` (REQ-73) works on Unix; Windows emits warning and skips gracefully.
- AC4: Updated precedence chain is enforced across all identity-consuming command paths.
- AC5: README and docs updated with secure CI/CD patterns.
- AC6: All existing tests pass; CI green on Linux, macOS, Windows.

## Test Plan

See individual REQ specs (req-073.md, req-074.md, req-075.md) for per-feature test plans.

Cross-cutting integration tests:
- All three sources in sequence: `--identity-stdin` wins over `GITVAULT_IDENTITY_FD` wins over `GITVAULT_IDENTITY`.
- `gitvault check` reports all three new sources in probe output.
- GitHub Actions recipe from README works end-to-end in CI (`printf ... | gitvault decrypt --identity-stdin`).

## GitHub Actions Recommended Patterns (documentation target)

### Tier 1 — OIDC + external vault (key never in GHA)
```yaml
- uses: hashicorp/vault-action@v3
  with:
    method: jwt
    secrets: secret/data/gitvault age_key | AGE_KEY ;
- run: printf '%s' "$AGE_KEY" | gitvault decrypt --identity-stdin
```

### Tier 2 — `/dev/shm` temp file + `--identity-stdin`
```yaml
- env:
    AGE_KEY: ${{ secrets.AGE_IDENTITY_KEY }}
  run: printf '%s' "$AGE_KEY" | gitvault decrypt --identity-stdin
```

### Tier 3 — `/dev/shm` temp file + file path (no `--identity-stdin`)
```yaml
- env:
    AGE_KEY: ${{ secrets.AGE_IDENTITY_KEY }}
  run: |
    KEY_FILE=$(mktemp /dev/shm/gv-XXXXXX)
    chmod 600 "$KEY_FILE"
    printf '%s' "$AGE_KEY" > "$KEY_FILE"
    unset AGE_KEY
    GITVAULT_IDENTITY="$KEY_FILE" gitvault decrypt
    rm -f "$KEY_FILE"
```

### Tier 4 — Legacy inline (warned, still works)
```yaml
- env:
    GITVAULT_IDENTITY: ${{ secrets.AGE_IDENTITY_KEY }}
  run: gitvault decrypt   # emits deprecation warning to stderr
```

## Notes

This plan is additive. It does not conflict with any existing spec. Specs that state the precedence chain as `--identity -> GITVAULT_IDENTITY -> keyring -> ssh-agent` are describing the existing positions of those sources; the new sources (`--identity-stdin` at level 1, `GITVAULT_IDENTITY_FD` at level 2) are inserted without reordering any existing entry.

Cross-references:
- `10-key-management.md` AC3 — precedence chain (extended by this plan, not replaced)
- `13-cicd-compatibility.md` AC3 — CI precedence (extended)
- `19-ssh-identity-requirements.md` AC1 — deterministic precedence (extended)
- `req-048.md` AC2 — CI identity resolution (extended)
