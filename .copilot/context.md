# Repo context (read-only)
- Prefer smallest diff
- Follow existing patterns
- Do not touch generated/vendor files unless spec explicitly allows it
- Always update/add tests when behavior changes
- Always run verification commands from spec frontmatter if present

## Worktree discipline
- One task = one worktree
- Never broaden scope
- Keep commits small and reviewable
- Update specs/<id>/04-progress.md after completing a task

## Conventions
- Commit messages should reference spec id and AC ids: (S-... / AC1)
- PRs must link the spec folder path