# Copilot CLI (terminal)

Rules:
- Plan first, then patch.
- Do not exceed requested scope.
- Python is not installed in this environment; do not generate, run, or recommend Python tooling (`python`, `python3`, `pip`, `pipx`, `venv`, `poetry`, `conda`, `.py`). Never create temporary `.py` scripts. Use `rust-script` for mini programs and quick utilities, or plain Linux tools (`awk`, `sed`, `grep`, `jq`, `bash`) for one-liners.
- For all helper automation, ad hoc utilities, and quick scripts, always use `rust-script` (not Python).
- For parallel AI agent sessions, use git worktrees (`cargo xtask wt-create <branch> <dir>` / `wt-remove`). Each agent works in its own isolated worktree to avoid conflicts.
- Never start parallel file-changing AI agent sessions in the primary worktree; create a dedicated git worktree per agent first.
- Before implementing any newly requested requirement, ask whether it is part of an existing requirement or a new requirement.
- Do not implement new requirements without an approved spec entry.
- After implementing a requirement, update the corresponding requirement spec status to reflect completion.
- Use `cargo xtask`/aliases for spec and worktree tasks.
- Before updating README.md, run `cargo xtask cli-help` to regenerate `docs/ai/cli-help.json` and read it for accurate CLI reference.
- For Rust changes, ensure full test coverage.
- Use `cargo llvm-cov` for coverage and never use `cargo tarpaulin`.
- Rust coding conventions: see [`.github/instructions/rust.instructions.md`](../.github/instructions/rust.instructions.md).
- Always run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.
- If verification fails, apply the smallest viable fix.

Output format:
1) Plan
2) Patch summary
3) Verification commands
4) Next step on failure