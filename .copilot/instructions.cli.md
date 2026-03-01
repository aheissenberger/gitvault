# Copilot CLI (terminal)

Rules:
- Plan first, then patch.
- Do not exceed requested scope.
- Use `cargo xtask`/aliases for spec and worktree tasks.
- For Rust changes, ensure full test coverage.
- If verification fails, apply the smallest viable fix.

Output format:
1) Plan
2) Patch summary
3) Verification commands
4) Next step on failure