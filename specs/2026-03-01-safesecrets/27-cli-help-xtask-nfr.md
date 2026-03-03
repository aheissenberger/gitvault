---
id: "S-20260303-027"
title: "NFR: CLI help index xtask (cargo xtask cli-help)"
status: "done"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-ui", "vscode-bg"]
scope:
  repoAreas: ["xtask/**", "docs/ai/**", ".copilot/**", "docs/**"]
  touch: ["xtask/src/main.rs", "docs/ai/cli-help.json", ".copilot/context.md", ".copilot/instructions.*.md", "docs/releasing.md"]
  avoid: ["src/**", "tests/**"]
acceptance:
  - id: "AC1"
    text: "`cargo xtask cli-help` builds the gitvault binary, walks every command and sub-command, and writes structured JSON to `docs/ai/cli-help.json` without error."
  - id: "AC2"
    text: "`docs/ai/cli-help.json` contains one entry per CLI path (top-level and all sub-commands) with the full `--help` text for each."
  - id: "AC3"
    text: "All `.copilot/instructions.*.md` files and `.copilot/context.md` instruct agents to run `cargo xtask cli-help` and read `docs/ai/cli-help.json` before updating README.md."
  - id: "AC4"
    text: "`cargo xtask instructions-lint` enforces AC3 and fails if the phrase is missing from `context.md`."
  - id: "AC5"
    text: "`docs/releasing.md` includes a step to regenerate `docs/ai/cli-help.json` when CLI commands change before tagging a release."
verification:
  commands:
    - "cargo xtask cli-help"
    - "cargo xtask instructions-lint"
    - "cargo xtask spec-verify"
risk:
  level: "low"
links:
  issue: ""
  pr: ""
---

## Context

AI agents updating `README.md` or writing CLI documentation need an accurate, machine-readable description of all gitvault commands and their options. Without a single authoritative source, agents hallucinate flags or miss newly added sub-commands.

## Goal

Provide `cargo xtask cli-help` as a zero-config developer task that produces `docs/ai/cli-help.json` — a structured snapshot of every `--help` output in the CLI hierarchy. Embed awareness of this task in all agent instruction files so it becomes the standard pre-step for any README or CLI documentation work.

## Non-goals

- Replacing `README.md` with generated content.
- Parsing help text into a semantic AST; raw text per command path is sufficient.
- Running as part of `cargo xtask verify` (it would rebuild the binary unnecessarily on every CI pass).

## Constraints

- `docs/ai/cli-help.json` is a committed artifact; it must be regenerated and committed whenever CLI commands change.
- The xtask must remain side-effect-free beyond writing the JSON file.

## Acceptance Criteria

- AC1: `cargo xtask cli-help` succeeds and writes `docs/ai/cli-help.json`.
- AC2: JSON contains one entry per CLI path with full `--help` text.
- AC3: All four agent instruction files reference `cargo xtask cli-help` for README work.
- AC4: `cargo xtask instructions-lint` enforces the phrase in `context.md`.
- AC5: `docs/releasing.md` includes the regeneration step.

## Test Plan

```bash
cargo xtask cli-help          # must exit 0 and print "commands captured: 22"
cargo xtask instructions-lint # must exit 0
cargo xtask spec-verify       # must report 98 files verified
cat docs/ai/cli-help.json | grep '"path"' | wc -l  # must be ≥ 22
```

## Notes

- `docs/ai/cli-help.json` should be committed to the repository so agents can read it without building first.
- The xtask uses `find_gitvault_bin()` (shared with the `dev-shell` task) to locate the binary after build.
- Sub-command discovery is driven by parsing the `Commands:` section of `--help` output; the `help` pseudo-command is filtered out automatically.
