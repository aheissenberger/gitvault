# Repo context

## Core rules
- Keep diffs minimal and aligned with existing patterns.
- Do not edit generated/vendor files unless the spec explicitly allows it.
- Add or update tests for changed behavior.
- Rust coding conventions: see [`.github/instructions/rust.instructions.md`](../.github/instructions/rust.instructions.md).
- Run required verification commands from spec frontmatter.
- Always run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.

## Spec workflow
- One task per worktree; do not broaden scope.
- Update `specs/<id>/04-progress.md` after task completion.
- Use `cargo xtask`/aliases for spec/worktree actions: `spec-init`, `spec-verify`, `wt-*`.
- Do not add or use shell wrappers for spec/worktree flows.
- Run `cargo xtask cli-help` to regenerate `docs/ai/cli-help.json` before updating README.md.

## Collaboration
- Keep commits small and reviewable.
- Reference spec/AC ids in commits (e.g., `S-... / AC1`).
- Link the spec path in PRs.
- Treat `.cargo-home/` as local cache (untracked).

## Skills
- Deploy/release workflow: `.copilot/skills/deploy-semver.md`