---
id: "S-20260302-025"
title: "Plan: .gitvault/config.toml — canonical project config and hook-adapter selection"
status: "draft"
owners: ["@aheissenberger"]
mode: ["cli", "vscode-ui", "vscode-bg"]
scope:
  repoAreas: ["src/**", "specs/**", "README.md"]
  touch: ["src/repo/**", "src/commands/admin.rs", "src/config.rs", "README.md", "specs/**"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "REQ-67: .gitvault/config.toml [hooks] adapter selects the external adapter; absent/empty means built-in default."
  - id: "AC2"
    text: "REQ-67: Adapter binary gitvault-<name> is resolved from PATH; missing binary follows CI/--no-prompt error contract."
  - id: "AC3"
    text: "REQ-67: Unknown adapter name in config produces a Usage error immediately."
verification:
  commands:
    - "cargo xtask spec-verify"
    - "cargo test --all-targets --all-features"
risk:
  level: "low"
links:
  issue: ""
  pr: ""
---

## Context
REQ-64..66 define three external hook-manager adapters. REQ-67 specifies that adapter selection uses `.gitvault/config.toml` — a new canonical TOML config file for gitvault project-level settings. This is extensible for future keys without touching existing behaviour.

## Goal
Introduce `src/config.rs` to parse `.gitvault/config.toml`, expose `[hooks] adapter`, and integrate adapter selection into `cmd_harden`.

## Non-goals
- Auto-detecting hook managers from their own config files.
- Writing or modifying hook-manager config files.

## Design

### File location and format
`.gitvault/config.toml` at the repository root:

```toml
[hooks]
adapter = "husky"   # "husky" | "pre-commit" | "lefthook"
```

### New module: `src/config.rs`

```rust
pub struct GitvaultConfig {
    pub hooks: HooksConfig,
}

pub struct HooksConfig {
    pub adapter: Option<HookAdapter>,
}

pub enum HookAdapter { Husky, PreCommit, Lefthook }

pub fn load_config(repo_root: &Path) -> Result<GitvaultConfig, GitvaultError>;
```

`load_config` returns default (no adapter) when file is absent. Returns `GitvaultError::Usage` for unknown adapter names.

### Adapter resolution in `cmd_harden`
```
adapter = load_config(repo_root)?.hooks.adapter
None    → install_git_hooks only
Some(a) → binary = "gitvault-" + a.as_str()
          which(binary) → found → exec binary "harden"
                       → not found + no_prompt → error
                       → not found + interactive → warn, fall back
```

## Requirement Coverage
- REQ-67.

## Acceptance Criteria
- AC1: No `.gitvault/config.toml` → built-in only, no error.
- AC2: Valid adapter + binary on PATH → adapter invoked.
- AC3: Unknown adapter name → immediate Usage error.

## Test Plan
- Unit tests in `src/config.rs` for TOML parsing edge cases.
- Integration tests covering: absent file, valid adapter with mock binary, no `[hooks]` section, unknown name, missing binary + `--no-prompt`.

## Implementation-facing Acceptance Scenarios
- Scenario A1 (absent file): No `.gitvault/config.toml` → `harden` installs built-in hooks, exits 0.
- Scenario A2 (valid + adapter present): `[hooks] adapter = "husky"`, `gitvault-husky` on PATH → adapter invoked with `harden`.
- Scenario A3 (no hooks section): File exists with other keys, no `[hooks]` → built-in adapter, no error.
- Scenario A4 (unknown name): `adapter = "unknown"` → `GitvaultError::Usage`, non-zero exit.
- Scenario A5 (valid + adapter missing + CI): `adapter = "lefthook"`, binary absent, `--no-prompt` → non-zero exit with actionable message.
