---
id: "S-20260304-NFR002"
title: "Global Engineering NFR — Subprocess Wrapper Extraction and Crate Selection"
status: "implemented"
owners: ["@aheissenberger"]
mode: ["cli"]
platforms: ["Linux", "macOS", "Windows"]
scope:
  repoAreas: ["src/**"]
  touch: ["src/git.rs", "src/ssh.rs", "src/repo/plugin.rs", "src/identity.rs", "src/fs_util.rs", "src/repo/paths.rs"]
  avoid: ["target/**"]
acceptance:
  - id: "AC1"
    text: "A subprocess wrapper module is introduced whenever three or more distinct production call sites invoke the same external binary (git, ssh-add, ssh-keygen) with overlapping boilerplate (env sanitization, error conversion, output parsing)."
  - id: "AC2"
    text: "Wrapper modules (`src/git.rs`, `src/ssh.rs`) are the sole entry point for their respective binaries in production code. Direct `Command::new(\"git\")` / `Command::new(\"ssh-add\")` / `Command::new(\"ssh-keygen\")` in non-test production code are forbidden after the corresponding wrapper module exists."
  - id: "AC3"
    text: "User-command execution (`run.rs`) is never routed through git/ssh/plugin wrappers. It has a distinct security model (user intent, pass-through env) and must remain a dedicated path."
  - id: "AC4"
    text: "Platform-specific binary resolution (PATH scanning, PATHEXT on Windows) uses the `which` crate rather than a hand-rolled implementation. The `which` crate is the accepted standard for this problem domain."
  - id: "AC5"
    text: "Home directory resolution uses the `dirs` crate (`dirs::home_dir()`) rather than reading the `HOME` environment variable directly. `HOME` is absent on Windows; `dirs` uses the platform-appropriate API (`USERPROFILE` / `SHGetKnownFolderPath`)."
  - id: "AC6"
    text: "A crate is adopted when it: (a) eliminates a class of correctness bugs on at least one supported platform, (b) has fewer than 50 transitive dependencies when added, (c) is in the top-1000 most downloaded crates on crates.io or is maintained by the Rust project. Crates that do not meet all three criteria require explicit justification in the spec."
  - id: "AC7"
    text: "Wrapper extraction is **not** applied to: OS-level permission calls (`icacls`, `chmod`), user-command pass-through (`run.rs`), or test-only subprocess setups. These have distinct security models or are too call-site-specific to benefit from centralization."
  - id: "AC8"
    text: "Every wrapper function documents: the binary it wraps, the security defaults applied (env vars stripped, prompts suppressed), and any platform-specific behavior differences."
verification:
  commands:
    - "cargo fmt --all -- --check"
    - "cargo clippy --all-targets -- -D warnings"
    - "cargo test --all"
    - "grep -rn 'Command::new(\"git\")' src/ --include='*.rs' | grep -v '#\\[cfg(test)\\]\\|mod tests\\|test_helpers'"
    - "grep -rn 'Command::new(\"ssh-add\")\\|Command::new(\"ssh-keygen\")' src/ --include='*.rs' | grep -v '#\\[cfg(test)\\]\\|mod tests'"
risk:
  level: "low"
links:
  issue: ""
  pr: ""
---

## Purpose

This NFR defines the criteria and rules for extracting subprocess wrappers and selecting third-party crates in the `gitvault` codebase. It prevents the recurrence of the REQ-90 class of issues (where inconsistent env sanitization across 12+ scattered call sites led to security gaps) by mandating centralization before the pattern spreads.

## Background

The 2026-03-04 security hardening work (NFR-001, REQ-87–97) identified that:

1. **Scattered subprocess calls accumulate security debt**: 30 `Command::new("git")` calls spread across 8 files meant REQ-90 env sanitization had to be applied (or was missed) at each site individually. A single centralized `src/git.rs` wrapper reduced this to one enforced location.

2. **Hand-rolled platform utilities have correctness gaps**: The `which_binary()` function in `plugin.rs` handled Windows `PATHEXT` expansion but missed UNC path quoting and other edge cases that the `which` crate handles. Similarly, `std::env::var("HOME")` fails silently on Windows where `USERPROFILE` is the correct variable.

3. **Not every subprocess needs a wrapper**: `run.rs` executes arbitrary user commands with intentional full env inheritance — wrapping it would violate its security model. `permissions.rs` calls `icacls` once, with no pattern repetition — wrapping adds complexity with no benefit.

## Wrapper Extraction Criteria

Extract a wrapper module when **all three** of the following are true:

| Criterion | Description |
|-----------|-------------|
| **Repetition** | ≥ 3 distinct production call sites invoke the same binary |
| **Shared boilerplate** | Call sites share ≥ 2 of: env sanitization, error type conversion, stdout parsing, platform branching |
| **Divergence risk** | A future call site that omits the boilerplate would create a security or correctness bug |

Do **not** extract when:
- The call site has unique security model requirements (user pass-through, privilege escalation)
- The binary is called exactly once in the entire codebase
- The wrapper would obscure meaningful call-site-specific error context

## Crate Adoption Criteria

Adopt a crate when **all three** are satisfied:

| Criterion | Threshold |
|-----------|-----------|
| **Correctness benefit** | Eliminates a class of bugs on ≥ 1 supported platform (Linux, macOS, Windows) |
| **Dependency weight** | Adds ≤ 50 transitive dependencies |
| **Ecosystem standing** | Top-1000 downloads on crates.io **or** maintained by the Rust project / domain authority |

### Approved adoptions (this NFR)

| Crate | Replaces | Benefit |
|-------|----------|---------|
| `dirs` | `std::env::var("HOME")` | Works on Windows (`USERPROFILE`/`SHGetKnownFolderPath`); handles edge cases like NixOS and container environments |
| `which` | `which_binary()` in `plugin.rs` | Correct PATHEXT handling, UNC path quoting, symlink resolution on all platforms |

### Explicitly deferred

| Pattern | Reason |
|---------|--------|
| `icacls` in `permissions.rs` | Called once; native Windows ACL crates add complexity without benefit unless finer ACL semantics are needed |
| `run.rs` subprocess execution | Intentional full-env pass-through; wrapping violates security model |

## Wrapper Module Contracts

### `src/git.rs` (implemented — REQ-90)
- Strips: `GIT_DIR`, `GIT_CONFIG`, `GIT_CONFIG_GLOBAL`
- Sets: `GIT_TERMINAL_PROMPT=0`
- Functions: `git_output`, `git_output_raw`, `git_run`, `git_output_async`

### `src/ssh.rs` (implemented — REQ-98)
- Strips: none required (SSH agent uses socket, not env injection)
- Sets: `SSH_ASKPASS_REQUIRE=never` to suppress password prompts in non-interactive contexts
- Functions: `ssh_add_list_keys`, `ssh_keygen_fingerprint`
- Platform note: binary is `ssh-add` / `ssh-keygen` on all platforms; OpenSSH for Windows ships these since Windows 10 1809.

### `src/repo/paths.rs::SystemGitRunner::show_toplevel` (migrated — git wrapper complete)
- The last production `Command::new("git")` call outside `src/git.rs` was in `SystemGitRunner::show_toplevel`.
- It has been migrated to use `crate::git::git_output_raw`, completing the git wrapper migration.
- AC2 of this NFR (no bare `Command::new("git")` in non-test production code) is now fully satisfied.

## Filesystem Utility Wrappers (REQ-107–109)

NFR-002 scope has been extended to cover filesystem utility wrappers in addition to subprocess
wrappers. The same centralization rationale applies: duplicated call sites accumulate divergent
error handling and correctness gaps (e.g., non-atomic writes, missing path context in errors).

### `src/fs_util.rs` (implemented)

| REQ | Function | Status | Replaces |
|-----|----------|--------|---------|
| REQ-107 | `atomic_write(path, data)` | Implemented | Inline `NamedTempFile` + rename at each call site |
| REQ-108 | `read_text(path)` | Partial (utility done; gradual adoption) | `std::fs::read_to_string` (~76 call sites) |
| REQ-109 | `ensure_dir(path)` | Partial (utility done; selective adoption) | `std::fs::create_dir_all` (~78 call sites) |

**REQ-107** (`atomic_write`): All non-excepted write sites must use this function. Exception
sites (those requiring a permission step between write and rename, e.g. `barrier.rs`) must
carry a `// fs_util::atomic_write not used here: <reason>` comment. See `req-107.md`.

**REQ-108** (`read_text`): New code must use this wrapper; existing sites migrate incrementally.
Includes the file path in every error message for diagnostics. See `req-108.md`.

**REQ-109** (`ensure_dir`): New code must use this wrapper; existing sites migrate incrementally.
`src/commands/init.rs` and `src/ssm/refs.rs` are already migrated. See `req-109.md`.

## REQ Mapping

| REQ | Title | Status |
|-----|-------|--------|
| REQ-98 | Centralized SSH Subprocess Wrapper (`src/ssh.rs`) | Implemented |
| REQ-99 | Use `dirs` Crate for Home Directory Resolution | Implemented |
| REQ-100 | Use `which` Crate for Binary PATH Resolution | Implemented |
| REQ-107 | Atomic File Write Utility (`fs_util::atomic_write`) | Implemented |
| REQ-108 | Contextual File Read Utility (`fs_util::read_text`) | Partial |
| REQ-109 | Contextual Directory Creation Utility (`fs_util::ensure_dir`) | Partial |

## Future Guidance

When adding a new external binary call, ask:
1. Does a wrapper for this binary already exist in `src/`? → Use it.
2. Will this be the 3rd+ call site for this binary? → Extract a wrapper first, then call it.
3. Is there a crate that solves the platform problem correctly? → Evaluate against the three criteria above.
4. Does this call have unique env/security requirements? → Document the exception explicitly in code.
