---
id: "S-20260303-028"
title: "AI CLI command group: skill/context print"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-ui", "vscode-bg"]
scope:
  repoAreas: ["src/**", "tests/**", "specs/**", "README.md", "docs/ai/**"]
  touch: ["src/cli.rs", "src/dispatch.rs", "src/commands/**", "tests/cli_integration.rs", "README.md", "specs/**", "docs/ai/cli-help.json"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "Adds top-level `ai` command group with `skill print` and `context print` subcommands and no skill-name argument in MVP."
  - id: "AC2"
    text: "Both commands reuse global flags (`--json`, `--no-prompt`, `--identity-selector`, AWS flags) with behavior consistent with REQ-45/REQ-46 automation contracts."
  - id: "AC3"
    text: "`--json` output for both print commands follows a stable MCP-style envelope with deterministic keys for success and error cases."
  - id: "AC4"
    text: "Command/help documentation and generated CLI help index are updated to include all new command paths."
verification:
  commands:
    - "cargo xtask spec-verify"
    - "cargo test --all-targets --all-features"
    - "cargo xtask cli-help"
risk:
  level: "medium"
links:
  issue: ""
  pr: ""
---

## Context
`gitvault` users need a lightweight, deterministic way to bootstrap AI tooling workflows directly from CLI output. For low-frequency usage, a command-based approach avoids the operational overhead of an MCP server while still enabling consistent Copilot setup.

## Goal
Introduce minimal AI-oriented print commands that provide canonical skill and context artifacts in human-readable and machine-readable forms.

## Non-goals
- Building or shipping an MCP server.
- Adding dynamic skill discovery or external network-backed AI commands.
- Introducing additional `ai` subcommands beyond `skill print` and `context print` in this scope.

## Constraints
- Existing command behavior and exit-code contracts remain backward compatible.
- JSON schema keys for AI print commands are deterministic and test-covered.
- No interactive fallback is introduced for these commands.
- Help text regeneration remains mandatory when command surface changes.

## Requirement Coverage
- REQ-69.
- REQ-45, REQ-46, REQ-47 (automation compatibility and stable behavior).

## Acceptance Criteria
- AC1: `gitvault ai skill print` and `gitvault ai context print` are available and functional.
- AC2: Global automation flags behave consistently.
- AC3: JSON envelope shape is stable and validated in tests.
- AC4: `README.md` CLI reference and `docs/ai/cli-help.json` include the new commands.

## Test Plan
- Add CLI integration tests for human and JSON outputs of both commands.
- Validate non-interactive behavior under `--no-prompt`.
- Run `cargo xtask cli-help` and verify new command paths are captured.
- Run `cargo xtask spec-verify` and `cargo test --all-targets --all-features`.

## Notes
This spec intentionally keeps the AI command surface minimal. Future expansions (e.g., template export variants or MCP bridge tooling) should be introduced via additive requirement specs.
