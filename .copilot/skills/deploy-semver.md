# Skill: Deploy with semantic version prompt

Use this skill when the user asks to deploy or release.

Rust coding conventions: see [`.github/instructions/rust.instructions.md`](../../.github/instructions/rust.instructions.md).

## Determine bump type first

Before doing any release mutation, detect whether the user prompt already specifies one of these bump types: `patch`, `minor`, or `major`.

- If the prompt includes exactly one valid bump type, use it directly and do not ask a follow-up question.
- If the prompt includes none, ask using VS Code Copilot Chat UI question elements (quick-pick / single-select), not plain free text.
- Use this exact prompt text in the UI question:

`Which semantic version upgrade should I apply: patch, minor, or major?`

- Present exactly these options in the UI picker: `patch`, `minor`, `major`.
- If the user response is not one of `patch|minor|major`, ask again using the same UI picker with only those options.

### Implementation hint (Copilot Chat UI)

When asking for bump type, use `ask_questions` with one single-select question and three options.

Example structure:

```json
{
   "questions": [
      {
         "header": "Semver",
         "question": "Which semantic version upgrade should I apply: patch, minor, or major?",
         "multiSelect": false,
         "options": [
            { "label": "patch" },
            { "label": "minor" },
            { "label": "major" }
         ]
      }
   ]
}
```

## Execution flow

After the bump type is known:

1. Read current version from `Cargo.toml` (`[package].version`).
2. Require a clean tree before verification:
   - `git status --short` must be empty before continuing.
3. Run verification:
   - `cargo verify > /dev/null 2>&1`
   - Verify required coverage by running the CLI:
     - `cargo llvm-cov --workspace --all-features --ignore-filename-regex "aws_config\.rs|ssm/backend\.rs" --fail-under-lines 95 > /dev/null 2>&1`
4. Require a clean tree after verification:
   - `git status --short` must be empty before continuing.
5. Compute next version:
   - `patch`: `X.Y.Z+1`
   - `minor`: `X.Y+1.0`
   - `major`: `X+1.0.0`
6. Update `Cargo.toml` version.
7. Commit with message:
   - `chore(release): v<new-version>`
8. Create annotated tag:
   - `git tag -a v<new-version> -m "v<new-version>"`
9. Require clean tree before release gate:
   - `git status --short` must be empty.
10. Run release gate:
   - `cargo xtask release-check`
11. Push commit and tag:
   - `git push origin main`
   - `git push origin v<new-version>`

## Safety rules

- Abort if working tree is dirty before verification and show the blocking files.
- Abort if verification fails; do not tag or push.
- Abort if the tree is dirty after verification; do not auto-restore files during release.
- Never create lightweight tags.
- Never skip `cargo xtask release-check`.

## Output contract

Report:

- selected bump type,
- old version -> new version,
- verification result,
- created commit hash,
- created tag,
- push result.