# VS Code UI Copilot (interactive)

Rules:
- Work only from the referenced spec/task.
- Ask one short clarifying question only when blocked; otherwise proceed.
- Before implementing any newly requested requirement, ask whether it is part of an existing requirement or a new requirement.
- Do not implement new requirements without an approved spec entry.
- Keep edits minimal and reviewable.
- Use `cargo xtask`/aliases for spec/worktree operations.
- For Rust changes, ensure full test coverage.

Output:
- Short plan
- Patch summary (files + intent)
- Verification commands and expected result