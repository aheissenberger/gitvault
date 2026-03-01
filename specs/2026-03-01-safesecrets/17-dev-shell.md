---
id: "S-20260301-017"
title: "NFR: interactive developer sandbox shell"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["xtask/**"]
  touch: ["xtask/src/main.rs", "xtask/Cargo.toml"]
  avoid: ["src/**", "target/**"]
acceptance:
  - id: "AC1"
    text: "cargo xtask dev-shell builds the current debug binary, creates an isolated temp git repo containing sample secret files, opens an interactive shell with gitvault resolvable on PATH, and removes the temp directory on exit."
  - id: "AC2"
    text: "The shell environment provides GITVAULT_IDENTITY pointing to a generated age identity key so that encrypt/decrypt commands work without additional setup."
  - id: "AC3"
    text: "The sandbox directory is unconditionally removed after the shell exits, regardless of exit code."
  - id: "AC4"
    text: "dev-shell is listed in cargo xtask help output."
verification:
  commands:
    - "cargo build --manifest-path xtask/Cargo.toml"
    - "cargo test --manifest-path xtask/Cargo.toml"
risk:
  level: "low"
links:
  issue: ""
  pr: ""
---

## Context
Developers need a fast, repeatable way to exercise the `gitvault` CLI end-to-end without polluting
their working repository. Without a dedicated sandbox, each manual test requires manual setup and
teardown of a git repo, sample files, and age keys, which is error-prone and slows iteration.

## Goal
Provide a single `cargo xtask dev-shell` command that gives any contributor an immediately usable,
isolated environment for testing all `gitvault` subcommands against the current build.

## Non-goals
- Automated integration testing (covered by `cargo test`).
- Persistent named environments or shared sandboxes.
- Windows-native shell support (cmd.exe / PowerShell); `$SHELL` fallback to `bash` is sufficient.

## Constraints
- Must not modify the host repository or working tree.
- Sandbox is ephemeral: created in `$TMPDIR` and removed unconditionally on exit.
- The `gitvault` binary on PATH must be the current debug build, not any previously installed version.
- No internet access or cloud credentials are required for the sandbox to be functional.

## Requirement Coverage
- NFR: Developer experience — fast local CLI testing loop.
- NFR: Sandbox isolation — no side-effects to host repo.
- NFR: Reproducibility — consistent initial state on every invocation.
- NFR: Discoverability — welcome banner documents available commands and pre-configured values.

## Acceptance Criteria
- AC1: Running `cargo xtask dev-shell` results in a shell opened inside a git-initialised temp
  directory containing `.env.plain` and `db.secrets.json`; `gitvault --help` succeeds inside it.
- AC2: `$GITVAULT_IDENTITY` is set to a valid age identity file path; `gitvault encrypt .env.plain
  --recipient <pubkey>` succeeds without extra flags.
- AC3: After the user types `exit`, the temp directory no longer exists on disk.
- AC4: `cargo xtask help` (or `cargo xtask --help`) lists `dev-shell` with a description.

## Test Plan
- Build check: `cargo build --manifest-path xtask/Cargo.toml` must succeed with no errors.
- Unit: existing xtask unit tests (`from_args_*`) continue to pass.
- Manual smoke test:
  1. `cargo xtask dev-shell`
  2. Inside shell: `gitvault harden && gitvault encrypt .env.plain --recipient $PUBKEY`
     (where `$PUBKEY` is shown in the welcome banner)
  3. `gitvault status` exits 0.
  4. `exit` — confirm temp dir is gone: `ls /tmp/gitvault-sandbox-*` returns no results.

## Notes
- The shell is launched via `$SHELL --rcfile <init-script>` so that the welcome banner is shown
  and PATH is configured before the user prompt appears.
- `GITVAULT_IDENTITY` is also set in the environment so `gitvault materialize` and `gitvault
  decrypt` work without passing `--identity` explicitly.
- The generated age identity and public key are printed in the banner for copy-paste convenience.
- Cleanup uses `fs::remove_dir_all`; a warning is printed (but the task still exits 0) if removal
  fails (e.g. permissions issue in CI).
