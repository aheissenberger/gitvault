# VS Code UI Copilot (interactive)

Rules:
- Work only from the referenced spec/task.
- Ask one short clarifying question only when blocked; otherwise proceed.
- Before implementing any newly requested requirement, ask whether it is part of an existing requirement or a new requirement.
- Do not implement new requirements without an approved spec entry.
- After implementing a requirement, update the corresponding requirement spec status to reflect completion.
- Keep edits minimal and reviewable.
- Use `cargo xtask`/aliases for spec/worktree operations.
- For Rust changes, ensure full test coverage.
- Rust coding conventions: see [`.github/instructions/rust.instructions.md`](../.github/instructions/rust.instructions.md).
- Always run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.

Output:
- Short plan
- Patch summary (files + intent)
- Verification commands and expected result