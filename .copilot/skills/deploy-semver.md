# Skill: Deploy with semantic version prompt

Use this skill when the user asks to deploy or release.

Rust coding conventions: see [`.github/instructions/rust.instructions.md`](../../.github/instructions/rust.instructions.md).

## Determine bump type first

Before doing any release mutation, detect whether the user prompt already specifies one of these bump types: `major`, `minor`, or `patch`.

- If the prompt includes exactly one valid bump type, use it directly and do not ask a follow-up question.
- If the prompt includes none, ask using VS Code Copilot Chat UI question elements (quick-pick / single-select), not plain free text.
- Use this exact prompt text in the UI question:

`Which semantic version upgrade should I apply: major, minor, or patch?`

- Present exactly these options in the UI picker: `major`, `minor`, `patch`.
- If the user response is not one of `major|minor|patch`, ask again using the same UI picker with only those options.

### Implementation hint (Copilot Chat UI)

When asking for bump type, use `ask_questions` with one single-select question and three options.

Example structure:

```json
{
   "questions": [
      {
         "header": "Semver",
         "question": "Which semantic version upgrade should I apply: major, minor, or patch?",
         "multiSelect": false,
         "options": [
            { "label": "major" },
            { "label": "minor" },
            { "label": "patch" }
         ]
      }
   ]
}
```

## Execution flow

After the bump type is known:

1. Read current version from `Cargo.toml` (`[package].version`).
2. Compute next version:
   - `major`: `X+1.0.0`
   - `minor`: `X.Y+1.0`
   - `patch`: `X.Y.Z+1`
3. Update `Cargo.toml` version.
4. Run verification:
   - `cargo verify`
   - Verify required coverage by running the CLI:
     - `cargo llvm-cov --workspace --all-features --ignore-filename-regex "aws_config\.rs|ssm/backend\.rs" --fail-under-lines 95 > /dev/null 2>&1`
5. Commit with message:
   - `chore(release): v<new-version>`
6. Create annotated tag:
   - `git tag -a v<new-version> -m "v<new-version>"`
7. Run release gate:
   - `cargo xtask release-check`
8. Push commit and tag:
   - `git push origin main`
   - `git push origin v<new-version>`

## Safety rules

- Abort if working tree is dirty before version bump and show the blocking files.
- Abort if verification fails; do not tag or push.
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