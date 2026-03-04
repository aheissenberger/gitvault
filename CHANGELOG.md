# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.4.8] - 2026-03-01

### Security
- Replace `serde_yml 0.0.12` (unsound/unmaintained, RUSTSEC-2025-0068) with `serde_yaml 0.9` for YAML field-level encryption
- Add `audit.toml` to document accepted risk for `rsa` RUSTSEC-2023-0071 (Marvin Attack, no upstream fix available; transitive via `age`, not network-exposed)

### CI
- Switch `cargo-audit` installation to `taiki-e/install-action` (pre-built binary, avoids 3-min compile time)

## [v0.4.7] - 2026-03-01

- Regenerated AI docs, fixed stale CLI help paths
- Expanded and restructured documentation (recipient guide, Quick Start, CLI reference, macOS app-signing guide)

## [v0.4.5] - 2025-01-01

- Boosted test coverage to 95.46% to satisfy CI threshold

## [v0.4.4] - 2025-01-01

- Fixed CLI DX round 4: prod flag clarity, passphrase safety hint, TTL format

## [v0.4.3] - 2025-01-01

- Fixed CLI DX round 3: doc accuracy and help consistency improvements

## [v0.4.2] - 2025-01-01

- Added Global Options group, `-H` flag, and stdout support to CLI help

## [v0.4.1] - 2025-01-01

- CLI DX improvements: consistent flags, environment variable bindings, cleaner help output

## [v0.4.0] - 2025-01-01

- Security hardening (SEC-001–007): git env sanitization, SSH path traversal fix, atomic writes via `fs_util`, env key validation, env file size limits
- Extracted `fs_util` helpers and completed git/SSH wrapper migration

## [v0.3.6] - 2025-01-01

- Comprehensive security hardening addressing SEC-001–007

## [v0.3.5] - 2025-01-01

- Extracted `fs_util` helpers and finished git/SSH wrapper migration

## [v0.3.4] - 2025-01-01

- Implemented REQ-101–105 security hardening
- Added SSH wrapper, `dirs`/`which` crates; centralized git subprocess calls in `src/git.rs`

## [v0.3.3] - 2025-01-01

- Implemented REQ-87–97 security hardening NFR

## [v0.3.2] - 2025-01-01

- Implemented REQ-73–86 security hardening (multiple security improvements across the codebase)

## [v0.3.1] - 2025-01-01

- Fixed test isolation on Windows (use tempdir for fields tests)

## [v0.3.0] - 2025-01-01

- Added SSH passphrase support for age and SSH identities
- Implemented Option A directory layout
- Added `gitvault init` onboarding command (REQ-71)
- Added `gitvault harden` file import with glob, encrypt, and gitignore support (REQ-70)
- Added recipient management: directory-based per-person recipient files, `add-self`, `--add-recipient` flag (REQ-72)
- Added `identity pubkey` subcommand and `rekey` command (replacing `rotate`)
- Added Apache and MIT license files

## [v0.2.30] - 2025-01-01

- Added config file support with `[env]`, `[barrier]`, `[paths]`, and `[keyring]` sections
- Extracted hardcoded defaults to `src/defaults.rs`
- Added `--env` flag to `gitvault encrypt`
- Renamed `SECRETS_ENV` to `GITVAULT_ENV`

## [v0.2.29] - 2025-01-01

- Added `gitvault ai skill` and `gitvault ai context` print commands
- Removed spec IDs from README and `--help` text

## [v0.2.28] - 2025-01-01

- Streamlined release verification flow

[Unreleased]: https://github.com/aheissenberger/gitvault/compare/v0.4.6...HEAD
[v0.4.6]: https://github.com/aheissenberger/gitvault/compare/v0.4.5...v0.4.6
[v0.4.5]: https://github.com/aheissenberger/gitvault/compare/v0.4.4...v0.4.5
[v0.4.4]: https://github.com/aheissenberger/gitvault/compare/v0.4.3...v0.4.4
[v0.4.3]: https://github.com/aheissenberger/gitvault/compare/v0.4.2...v0.4.3
[v0.4.2]: https://github.com/aheissenberger/gitvault/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/aheissenberger/gitvault/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/aheissenberger/gitvault/compare/v0.3.6...v0.4.0
[v0.3.6]: https://github.com/aheissenberger/gitvault/compare/v0.3.5...v0.3.6
[v0.3.5]: https://github.com/aheissenberger/gitvault/compare/v0.3.4...v0.3.5
[v0.3.4]: https://github.com/aheissenberger/gitvault/compare/v0.3.3...v0.3.4
[v0.3.3]: https://github.com/aheissenberger/gitvault/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/aheissenberger/gitvault/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/aheissenberger/gitvault/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/aheissenberger/gitvault/compare/v0.2.30...v0.3.0
[v0.2.30]: https://github.com/aheissenberger/gitvault/compare/v0.2.29...v0.2.30
[v0.2.29]: https://github.com/aheissenberger/gitvault/compare/v0.2.28...v0.2.29
[v0.2.28]: https://github.com/aheissenberger/gitvault/compare/v0.2.27...v0.2.28
