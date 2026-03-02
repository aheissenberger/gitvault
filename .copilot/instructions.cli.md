# Copilot CLI (terminal)

Rules:
- Plan first, then patch.
- Do not exceed requested scope.
- Before implementing any newly requested requirement, ask whether it is part of an existing requirement or a new requirement.
- Do not implement new requirements without an approved spec entry.
- After implementing a requirement, update the corresponding requirement spec status to reflect completion.
- Use `cargo xtask`/aliases for spec and worktree tasks.
- For Rust changes, ensure full test coverage.
- Rust coding conventions: see [`.github/instructions/rust.instructions.md`](../.github/instructions/rust.instructions.md).
- Always run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.
- If verification fails, apply the smallest viable fix.

Output format:
1) Plan
2) Patch summary
3) Verification commands
4) Next step on failure