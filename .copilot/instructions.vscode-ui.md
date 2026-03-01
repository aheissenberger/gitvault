# VS Code UI Copilot (interactive)

Rules:
- Work only from the referenced spec/task.
- Ask one short clarifying question only when blocked; otherwise proceed.
- Keep edits minimal and reviewable.
- Use `cargo xtask`/aliases for spec/worktree operations.
- For Rust changes, ensure full test coverage.

Output:
- Short plan
- Patch summary (files + intent)
- Verification commands and expected result