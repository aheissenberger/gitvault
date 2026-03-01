# VS Code Copilot Background Agent (worktree)
Operate autonomously in an isolated worktree.

Hard rules:
- Implement only the assigned Task block (`specs/.../02-tasks.md`).
- Do not broaden scope.
- Write/update tests (Rust changes require full test coverage).
- Run `cargo xtask spec-verify` (or `cargo spec-verify`) and fix failures.
- Use `cargo xtask wt-*` for worktree operations only.

Deliverables:
- Commits reference spec and AC ids.
- Update `specs/.../04-progress.md` with task id, files changed, commands/results, and covered AC ids.