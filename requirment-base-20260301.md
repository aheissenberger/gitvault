> ⚠️ **Note**: This document exists for historical reasons and should not be used by AI agents for code generation or implementation decisions. It may contain outdated information, superseded design choices, or constraints that are no longer relevant. Please refer to the current implementation and active design documentation instead.

Below is a **fully consolidated, non-overlapping, strictly defined requirement specification** for a Rust-based secrets tool optimized for:

* Multi-developer workflows
* Multi-agent parallel Git worktrees
* Deterministic merges
* Root-level `.env` support
* Fileless environment injection for CI/local deploy
* Optional AWS SSM production backend
* Strict safety guarantees

All requirements are uniquely identified and written as **normative acceptance criteria**.

---

# SafeSecrets – Consolidated Requirements Specification (v1.0)

---

# 1. Scope

Develop a Rust-based, cross-platform CLI tool that:

1. Prevents plaintext secrets from being committed to Git.
2. Supports structured and unstructured secrets.
3. Supports multiple parallel Git worktrees.
4. Supports environment-scoped secrets (dev, staging, prod).
5. Supports fileless deployment via environment variable injection.
6. Optionally integrates with AWS SSM Parameter Store.
7. Enforces strict production safety barriers.
8. Is deterministic and merge-friendly.

---

# 2. Definitions

* **Encrypted Artifact**: Secret material stored encrypted in Git.
* **Plaintext Artifact**: Decrypted material written to disk.
* **Materialization**: Writing decrypted secrets to disk.
* **Fileless Execution**: Injecting decrypted secrets directly into a child process environment.
* **Environment**: Logical profile (dev, staging, prod).
* **Worktree**: Git worktree directory.
* **Barrier**: Explicit mechanism required before accessing prod secrets.

---

# 3. Core Architecture

## 3.1 Encryption Format

**REQ-1** The tool SHALL use the standard `age` file format for whole-file encryption.

**REQ-2** The tool SHALL implement encryption/decryption natively in Rust and SHALL NOT require external binaries.

**REQ-3** The tool SHALL support multiple recipients per encrypted artifact.

**Acceptance:**

* Encrypted file is valid `.age` format.
* Decryption succeeds using internal implementation.
* Recipient removal prevents future decryption.

---

## 3.2 Structured File Support

**REQ-4** The tool SHALL support field-level encryption for JSON, YAML, and TOML.

**REQ-5** Structured encryption SHALL be deterministic (stable serialization).

**REQ-6** `.env` files SHALL default to whole-file encryption unless explicitly configured for value-only mode.

**Acceptance:**

* Encrypting same structured input twice produces identical output.
* Only encrypted fields change when modifying a single key.

---

# 4. Repository Layout

**REQ-7** Encrypted artifacts SHALL reside under `secrets/`.

**REQ-8** Plaintext outputs SHALL reside under `.secrets/plain/<env>/`.

**REQ-9** Root `.env` SHALL be generated and gitignored.

**REQ-10** Tool SHALL refuse to operate if plaintext secrets are detected in tracked paths.

**Acceptance:**

* `git ls-files` never lists plaintext secret outputs.
* `tool status` fails if plaintext is tracked.

---

# 5. Environment Model

**REQ-11** Tool SHALL support environment selection by:

Priority:

1. `SECRETS_ENV`
2. `.secrets/env` (gitignored)
3. Default: `dev`

**REQ-12** Each worktree SHALL have independent environment resolution.

**Acceptance:**

* Two worktrees can use different environments simultaneously.

---

# 6. Production Barrier

**REQ-13** Accessing `prod` secrets SHALL require:

* `--env prod`
* `--prod`
* Active allow token OR interactive confirmation

**REQ-14** Allow token SHALL expire automatically.

**REQ-15** Tool SHALL fail closed if barrier is not satisfied.

**Acceptance:**

* `tool materialize --env prod` fails without barrier.
* `tool run --env prod` fails without barrier.

---

# 7. Root-Level `.env` Handling

**REQ-16** Tool SHALL support generation of root-level `.env`.

**REQ-17** `.env` SHALL be written atomically.

**REQ-18** `.env` SHALL be written with restricted permissions (0600 POSIX, restricted ACL Windows).

**REQ-19** `.env` SHALL be deterministic (sorted keys, canonical quoting).

**REQ-20** `.env` SHALL never be committed.

**Acceptance:**

* Re-running materialize produces identical `.env`.
* `.env` appears in `.gitignore`.
* Pre-commit hook blocks `.env` if staged.

---

# 8. Fileless Execution Mode

**REQ-21** Tool SHALL provide:

```
tool run --env <env> -- <command>
```

**REQ-22** `run` SHALL inject secrets as process environment variables without writing files.

**REQ-23** `run` SHALL propagate child exit code.

**REQ-24** `run` SHALL support:

* `--no-prompt`
* `--clear-env`
* `--pass VAR1,VAR2`

**REQ-25** `run --env prod` SHALL require production barrier.

**Acceptance:**

* No plaintext files created during `run`.
* Child process receives expected environment variables.

---

# 9. AWS SSM Backend (Optional)

## 9.1 Backend Selection

**REQ-26** Environment policy SHALL define backend: `vault` or `ssm`.

**REQ-27** In `ssm` mode, repo SHALL store references, not values.

---

## 9.2 SSM Operations

**REQ-28** Tool SHALL provide:

* `ssm pull`
* `ssm diff`
* `ssm set`
* `ssm push`

**REQ-29** SSM writes SHALL require production barrier.

**REQ-30** SSM diff SHALL not reveal secret values unless `--reveal`.

**Acceptance:**

* `ssm pull` retrieves SecureString parameters.
* `ssm diff` reports differences without exposing values.

---

# 10. Git Integration

**REQ-31** Tool SHALL provide `harden` command.

`harden` SHALL:

* Add `.env` and `.secrets/plain/**` to `.gitignore`
* Provide pre-commit hook
* Provide pre-push drift check

**REQ-32** Tool SHALL provide `status --fail-if-dirty`.

**Acceptance:**

* Committing plaintext secrets fails when hooks enabled.
* CI fails when drift detected.

---

# 11. Merge Optimization

**REQ-33** Tool SHALL NOT centralize all secrets into a single encrypted blob.

**REQ-34** Tool SHALL provide optional merge driver for `.env`.

**REQ-35** Structured encryption SHALL minimize diff noise.

**Acceptance:**

* Two agents editing different keys merge without conflict.
* Same-key edits produce conflict markers.

---

# 12. Key Management

**REQ-36** Tool SHALL support multiple recipients.

**REQ-37** Tool SHALL support recipient add/remove.

**REQ-38** Tool SHALL support rotation.

**REQ-39** Tool SHALL integrate with OS keyring (macOS, Windows, Linux).

**Acceptance:**

* Removing recipient prevents future decrypt.
* Keyring save/status/delete works cross-platform.

---

# 13. Security Requirements

**REQ-40** Tool SHALL fail closed on any decryption error.

**REQ-41** Tool SHALL never print secret values unless explicitly requested.

**REQ-42** Tool SHALL prevent path traversal on writes.

**REQ-43** Writes SHALL be atomic.

**REQ-44** Status checks SHALL not require decryption unless necessary.

---

# 14. CLI & Automation

**REQ-45** All commands SHALL support `--json`.

**REQ-46** All commands SHALL support `--no-prompt`.

**REQ-47** Exit codes SHALL be stable and documented.

---

# 15. CI/CD Compatibility

**REQ-48** Tool SHALL support fully non-interactive CI usage.

**REQ-49** Tool SHALL support role-based AWS auth (profile/role ARN).

**REQ-50** Tool SHALL provide `--check` mode for preflight validation.

---

# 16. Performance

**REQ-51** Encryption/decryption SHALL be streaming-capable.

**REQ-52** Operations SHALL scale linearly with number of files.

**REQ-53** Status SHALL not decrypt all files unnecessarily.

---

# 17. Testing Matrix

Tool SHALL be tested on:

* macOS
* Linux
* Windows

Scenarios SHALL include:

* Multiple worktrees
* Parallel edits
* Merge conflicts
* CI run mode
* Production barrier enforcement
* SSM integration
* Key rotation
* Drift detection

---

# 18. Release & Integrity

**REQ-54** Tool SHALL provide signed release artifacts.

**REQ-55** Tool SHALL provide deterministic format versioning.

---

# 19. Validation Summary

This specification guarantees:

* No plaintext secrets in Git
* Root-level `.env` compatibility
* Fileless deployment mode
* Production safety barriers
* Multi-agent parallel workflow safety
* Deterministic merges
* Optional SSM production backend
* Cross-platform behavior
* Strict failure modes
* CI compatibility

There are no overlapping requirements:

* Encryption concerns are isolated (Section 3).
* File handling isolated (Section 7).
* Execution mode isolated (Section 8).
* Backend isolated (Section 9).
* Git integration isolated (Section 10).
* Security centralized (Section 13).

