# Skill: Deploy with semantic version prompt

Use this skill when the user asks to deploy or release.

Rust coding conventions: see [`.github/instructions/rust.instructions.md`](../../.github/instructions/rust.instructions.md).

## Required first question

Ask exactly this before doing any release mutation:

`Which semantic version upgrade should I apply: major, minor, or patch?`

If the user does not choose one of `major|minor|patch`, ask again with only these options.

## Execution flow

After the user chooses a bump type:

1. Read current version from `Cargo.toml` (`[package].version`).
2. Compute next version:
   - `major`: `X+1.0.0`
   - `minor`: `X.Y+1.0`
   - `patch`: `X.Y.Z+1`
3. Update `Cargo.toml` version.
4. Run verification:
   - `cargo verify`
   - Verify required coverage by running the CLI:
     - `cargo llvm-cov --workspace --all-features --fail-under-lines 95`
5. Commit with message:
   - `chore(release): v<new-version>`
6. Create annotated tag:
   - `git tag -a v<new-version> -m "v<new-version>"`
7. Run release gate:
   - `cargo xtask release-check`
8. Push commit and tag:
   - `git push origin main`
   - `git push origin v<new-version>`

## Safety rules

- Abort if working tree is dirty before version bump and show the blocking files.
- Abort if verification fails; do not tag or push.
- Never create lightweight tags.
- Never skip `cargo xtask release-check`.

## Output contract

Report:

- selected bump type,
- old version -> new version,
- verification result,
- created commit hash,
- created tag,
- push result.