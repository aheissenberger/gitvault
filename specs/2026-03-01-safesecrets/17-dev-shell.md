---
id: "S-20260301-017"
title: "NFR: interactive developer sandbox shell"
status: "InProgress"
owners: ["@aheissenberger"]
mode: ["cli"]
scope:
  repoAreas: ["xtask/**"]
  touch: ["xtask/src/main.rs", "xtask/Cargo.toml"]
  avoid: ["src/**", "target/**"]
acceptance:
  - id: "AC1"
    text: "cargo xtask dev-shell builds the current debug binary, creates an isolated temp folder, creates a workspace-root symlink named dev-shell-folder to that temp folder, creates a second workspace-root symlink named dev-shell-folder-git to client/.git, creates client and server.git folders, initializes server.git with git init --bare, initializes client with git init, configures origin to ../server.git, and opens an interactive shell in the client folder with gitvault resolvable on PATH."
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
- A symlink named `dev-shell-folder` is created in the workspace root and points to the temp folder for VS Code access while the shell is active.
- A second symlink named `dev-shell-folder-git` is created in the workspace root and points to `client/.git` for VS Code access while the shell is active.
- The `gitvault` binary on PATH must be the current debug build, not any previously installed version.
- No internet access or cloud credentials are required for the sandbox to be functional.

## Requirement Coverage
- NFR: Developer experience — fast local CLI testing loop.
- NFR: Sandbox isolation — no side-effects to host repo.
- NFR: Reproducibility — consistent initial state on every invocation.
- NFR: Discoverability — welcome banner documents available commands and pre-configured values.

## Acceptance Criteria
- AC1: Running `cargo xtask dev-shell` builds the current debug binary, creates a temp folder, creates `dev-shell-folder` symlink in
  workspace root, creates `dev-shell-folder-git` symlink to `client/.git` in workspace root,
  creates `client/` and `server.git/`, runs `git init --bare` in `server.git`, runs `git init` in
  `client`, configures `git remote add origin ../server.git`, and sets upstream with `git push -u
  origin main`.
- AC2: The `client/` folder contains this sample structure with sample data, including at least 1–2
  secret-like fields (for example `Password`, `AccessToken`) across files:
  ```
  .env
  conf/
    dbsecrets.json
    serverless.yaml
    mail/
      acount.toml
  ```
- AC3: `gitvault` is resolvable on PATH inside the launched shell and `$GITVAULT_IDENTITY` points to
  a generated valid age identity key for encrypt/decrypt flows.
- AC4: After the user types `exit`, the temp directory is removed unconditionally regardless of
  shell exit code, and `cargo xtask help` (or `cargo xtask --help`) lists `dev-shell`.

## Test Plan
- Build check: `cargo build --manifest-path xtask/Cargo.toml` must succeed with no errors.
- Unit: existing xtask unit tests (`from_args_*`) continue to pass.
- Manual smoke test:
  1. `cargo xtask dev-shell`
  2. Verify symlinks exist in workspace root:
    - `ls -l dev-shell-folder` points to the temp folder.
    - `ls -l dev-shell-folder-git` points to `dev-shell-folder/client/.git`.
  3. Inside shell, verify repo layout:
    - `ls` shows `client` and `server.git`
    - `git -C server.git rev-parse --is-bare-repository` returns `true`
    - `git -C client remote -v` includes `origin ../server.git`
  4. Inside `client`, verify sample files exist and include secret-like fields (`Password`,
    `AccessToken`) and run `gitvault --help`.
  5. Optional flow check in `client`: `gitvault encrypt .env --recipient $PUBKEY` succeeds.
  6. `exit` — confirm temp dir is gone and both symlinks are removed or no longer point to an
    existing target.

## Notes
- The shell is launched via `$SHELL --rcfile <init-script>` so that the welcome banner is shown
  and PATH is configured before the user prompt appears.
- Workspace-root symlink name is fixed to `dev-shell-folder` for quick navigation in VS Code.
- Workspace-root git metadata symlink name is fixed to `dev-shell-folder-git` and points to
  `client/.git` for quick navigation in VS Code.
- `GITVAULT_IDENTITY` is also set in the environment so `gitvault materialize` and `gitvault
  decrypt` work without passing `--identity` explicitly.
- The generated age identity and public key are printed in the banner for copy-paste convenience.
- Cleanup removes the temp directory unconditionally after shell exit; cleanup should also remove
  the workspace symlinks created for this session.

## Current Verification Status
Requirement updated to reflect new sandbox topology (`client` + `server.git`) and workspace symlink
flow. Implementation and verification status pending against updated acceptance criteria.
