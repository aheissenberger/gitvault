---
id: "S-20260304-030"
title: "Plan: GITVAULT_IDENTITY_PASSPHRASE security improvements"
status: "active"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md", "docs/**"]
  touch:
    - "src/identity.rs"
    - "src/env.rs"
    - "src/commands/keyring.rs"
    - "README.md"
    - "docs/ai/skill.md"
    - "specs/**"
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-77: a runtime warning is emitted to stderr whenever `GITVAULT_IDENTITY_PASSPHRASE` is set to any non-empty value; warning is suppressed in `--json` mode; warning lists OS keyring, `GITVAULT_IDENTITY_PASSPHRASE_FD`, and native age identity as alternatives."
  - id: "AC2"
    text: "REQ-76: `GITVAULT_IDENTITY_PASSPHRASE_FD=<n>` reads the SSH identity passphrase from file descriptor `n` on Unix; priority is `GITVAULT_IDENTITY_PASSPHRASE_FD` → `GITVAULT_IDENTITY_PASSPHRASE` → OS keyring → interactive prompt; unsupported on Windows (documented warning + skip to next source)."
  - id: "AC3"
    text: "Updated passphrase resolution chain is documented and enforced in `try_fetch_ssh_passphrase` and all callers."
  - id: "AC4"
    text: "README and `docs/ai/skill.md` include a 'Secure SSH passphrase handling' section documenting alternatives in priority order: (1) OS keyring, (2) `GITVAULT_IDENTITY_PASSPHRASE_FD` (Unix), (3) `GITVAULT_IDENTITY_PASSPHRASE` env var (legacy, warned), (4) native age identity (eliminates passphrase entirely)."
  - id: "AC5"
    text: "Existing passphrase-related tests, CI workflows, and keyring tests continue to pass without modification. No breaking changes to existing behaviour."
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

`GITVAULT_IDENTITY_PASSPHRASE` provides CI-safe SSH identity passphrase unlock. Unlike `GITVAULT_IDENTITY` (which can safely hold a file path), **every non-empty value of `GITVAULT_IDENTITY_PASSPHRASE` is raw sensitive material** — there is no file-path form. This means the raw passphrase is exposed in `/proc/<PID>/environ`, `ps auxe`, and any audit system that captures process environments.

The OS keyring (`gitvault keyring set-passphrase`) already exists as a secure alternative but requires prior setup on a machine with a running keyring daemon — not always available in ephemeral CI runners. FD passing (`GITVAULT_IDENTITY_PASSPHRASE_FD`) fills the CI gap on Unix.

This plan is the passphrase equivalent of `29-identity-security-improvements.md`, and the two should be implemented in coordination so that warning format, suppression mechanics, and documentation are consistent.

### Key differences from the `GITVAULT_IDENTITY` improvement set

| Aspect | `GITVAULT_IDENTITY` (plan 29) | `GITVAULT_IDENTITY_PASSPHRASE` (this plan) |
|--------|-------------------------------|---------------------------------------------|
| File-path alternative | ✅ safe file path form exists | ❌ always raw material |
| Warning condition | Only when value starts with `AGE-SECRET-KEY-` | Always when non-empty |
| `--stdin` flag equivalent | `--identity-stdin` (REQ-74) | ❌ conflicts with `--identity-stdin`; FD is the solution |
| Existing secure alternative | None (new) | OS keyring already implemented |
| Elimination option | Switch to file path | Switch to native age key (no passphrase) |

## Goal

Harden `GITVAULT_IDENTITY_PASSPHRASE`-based passphrase loading with two additive improvements:
1. **Warn** users that the env var exposes raw passphrase material, and list secure alternatives (REQ-77 — zero breaking changes).
2. **Add `GITVAULT_IDENTITY_PASSPHRASE_FD`** for FD-based passphrase injection in Unix CI/scripted contexts (REQ-76).

## Non-goals

- Removing `GITVAULT_IDENTITY_PASSPHRASE` (backward compatibility preserved).
- A `--passphrase-stdin` flag (conflicts with `--identity-stdin`; FD approach is the correct solution).
- Modifying existing keyring, SSH-agent, or `--identity` flag behaviour.
- Covering age native key passphrases (age native keys have no passphrase; this applies only to SSH identities).
- Windows FD semantics (document limitation; OS keyring is the secure alternative on Windows).

## Constraints

- Both changes are additive; no existing env var, flag, or precedence level is altered.
- `GITVAULT_IDENTITY_PASSPHRASE_FD` is `#[cfg(unix)]`; Windows compile must not reference Unix-only APIs.
- Passphrase at every new loading path must be placed in `Zeroizing<String>` immediately upon read.
- Warning (REQ-77) must never appear in `--json` mode; goes to stderr only.
- Implementation order: REQ-77 first (lowest risk, highest visibility), then REQ-76.
- Warning suppression mechanics (`GITVAULT_NO_PASSPHRASE_WARN=1`) must mirror those of REQ-75 (`GITVAULT_NO_INLINE_KEY_WARN=1`) for consistency.

## Updated Passphrase Resolution Chain

```
1. GITVAULT_IDENTITY_PASSPHRASE_FD=<n>  (Unix only; FD int in env, passphrase not in env)
2. GITVAULT_IDENTITY_PASSPHRASE=<value> (all platforms; always raw material — emits deprecation warning)
3. OS keyring                            (platform-native; requires prior setup via keyring set-passphrase)
4. Interactive prompt                    (interactive mode only; blocked in --no-prompt / CI mode)
```

This updates `try_fetch_ssh_passphrase` in `src/identity.rs` and the passphrase resolution in `src/commands/keyring.rs`.

## Requirement Coverage

- REQ-76, REQ-77.

## Acceptance Criteria

- AC1: Passphrase warning (REQ-77) works as specified; no regressions.
- AC2: `GITVAULT_IDENTITY_PASSPHRASE_FD` (REQ-76) works on Unix; Windows emits warning and skips gracefully.
- AC3: Updated passphrase resolution chain enforced in `try_fetch_ssh_passphrase` and all callers.
- AC4: README and docs updated with secure passphrase patterns.
- AC5: All existing tests pass; CI green on Linux, macOS, Windows.

## Test Plan

See individual REQ specs (req-076.md, req-077.md) for per-feature test plans.

Cross-cutting integration tests:
- Both FD sources in sequence: `GITVAULT_IDENTITY_PASSPHRASE_FD` wins over `GITVAULT_IDENTITY_PASSPHRASE`.
- `GITVAULT_IDENTITY_FD` + `GITVAULT_IDENTITY_PASSPHRASE_FD` together (distinct FD numbers) work in a single invocation.
- `gitvault check` reports `GITVAULT_IDENTITY_PASSPHRASE_FD` in probe output.
- GitHub Actions recipe from README works end-to-end in CI.

## GitHub Actions Recommended Patterns (documentation target)

### Tier 1 — OS keyring (not available in GitHub-hosted runners; self-hosted only)
```bash
# Pre-configured on self-hosted runner
gitvault keyring set-passphrase  # done once; passphrase stored securely
# CI job: no env var needed; keyring resolves passphrase automatically
```

### Tier 2 — `GITVAULT_IDENTITY_PASSPHRASE_FD` (Unix runners)
```bash
# Both key and passphrase via FDs; neither in child process env
GITVAULT_IDENTITY_FD=3 GITVAULT_IDENTITY_PASSPHRASE_FD=4 \
  gitvault decrypt 3<<<"$AGE_KEY" 4<<<"$SSH_PASSPHRASE"
```

### Tier 3 — `GITVAULT_IDENTITY_PASSPHRASE` env var (legacy, warned)
```yaml
- env:
    GITVAULT_IDENTITY_PASSPHRASE: ${{ secrets.SSH_KEY_PASSPHRASE }}
  run: gitvault decrypt   # emits deprecation warning to stderr
```

### Tier 4 — Eliminate the problem: use a native age key
```bash
# age native keys have no passphrase — GITVAULT_IDENTITY_PASSPHRASE is never needed
age-keygen -o identity.age
GITVAULT_IDENTITY=identity.age gitvault decrypt
```

## Notes

This plan is additive and does not conflict with any existing spec. Existing specs that mention `GITVAULT_IDENTITY_PASSPHRASE` (req-048.md AC verification, req-039.md AC3, 13-cicd-compatibility.md notes) continue to be accurate; this plan adds two new sources before and a warning around the existing env var, without changing its semantics.

Cross-references:
- `29-identity-security-improvements.md` — coordinate warning format and suppression mechanics
- `20-optional-keyring-passphrase-fetch.md` — keyring passphrase fetch (existing; unmodified)
- `req-039.md` AC3 — `try_fetch_ssh_passphrase` (entry point for the new FD step)
- `req-048.md` verification — CI passphrase usage (extended by REQ-76/77, not replaced)
