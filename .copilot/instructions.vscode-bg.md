# VS Code Copilot Background Agent (worktree)
Operate autonomously in an isolated worktree.

Hard rules:
- Implement only the assigned Task block (`specs/.../02-tasks.md`).
- Do not broaden scope.
- Before implementing any newly requested requirement, ask whether it is part of an existing requirement or a new requirement.
- Do not implement new requirements without an approved spec entry.
- After implementing a requirement, update the corresponding requirement spec status to reflect completion.
- Write/update tests (Rust changes require full test coverage).
- Rust coding conventions: see [`.github/instructions/rust.instructions.md`](../.github/instructions/rust.instructions.md).
- Run `cargo xtask spec-verify` (or `cargo spec-verify`) and fix failures.
- Always run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.
- Use `cargo xtask wt-*` for worktree operations only.

Deliverables:
- Commits reference spec and AC ids.
- Update `specs/.../04-progress.md` with task id, files changed, commands/results, and covered AC ids.