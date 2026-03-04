//! AI tooling helpers: `gitvault ai skill print` and `gitvault ai context print`.
//!
//! Both content blobs are embedded at compile time via [`include_str!`]; no
//! filesystem access is performed at runtime, so the commands work correctly
//! from any working directory and in any deployment (installed binary, CI, etc.).

use crate::cli::AiAction;
use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;

/// Canonical gitvault skill content for Copilot / AI agent usage.
///
/// Embedded at compile time from `docs/ai/skill.md`.
const SKILL_CONTENT: &str = include_str!("../../docs/ai/skill.md");

/// Concise project AI context for agent onboarding.
///
/// Embedded at compile time from `docs/ai/AGENT_START.md`.
const CONTEXT_CONTENT: &str = include_str!("../../docs/ai/AGENT_START.md");

/// Dispatch `gitvault ai …` sub-commands.
///
/// # Errors
///
/// Returns [`GitvaultError::Other`] if JSON serialization fails unexpectedly.
pub fn cmd_ai(action: AiAction, json: bool) -> Result<CommandOutcome, GitvaultError> {
    match action {
        AiAction::Skill => print_content(SKILL_CONTENT, json),
        AiAction::Context => print_content(CONTEXT_CONTENT, json),
    }
}

/// Print `content` in human or JSON mode.
///
/// JSON mode uses the stable MCP-style envelope:
/// `{"protocol":"gitvault-ai/1","tool":"gitvault","success":true,"payload":{...}}`.
fn print_content(content: &str, json: bool) -> Result<CommandOutcome, GitvaultError> {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "protocol": "gitvault-ai/1",
                "tool": "gitvault",
                "success": true,
                "payload": {
                    "content": content,
                    "format": "markdown"
                }
            })
        );
    } else {
        println!("{content}");
    }

    Ok(CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::AiAction;

    #[test]
    fn test_ai_skill_print_human_succeeds() {
        let result = cmd_ai(AiAction::Skill, false);
        assert_eq!(
            result.expect("skill print human should succeed"),
            CommandOutcome::Success
        );
    }

    #[test]
    fn test_ai_context_print_human_succeeds() {
        let result = cmd_ai(AiAction::Context, false);
        assert_eq!(
            result.expect("context print human should succeed"),
            CommandOutcome::Success
        );
    }

    #[test]
    fn test_ai_skill_print_json_succeeds() {
        let result = cmd_ai(AiAction::Skill, true);
        assert_eq!(
            result.expect("skill print json should succeed"),
            CommandOutcome::Success
        );
    }

    #[test]
    fn test_ai_context_print_json_succeeds() {
        let result = cmd_ai(AiAction::Context, true);
        assert_eq!(
            result.expect("context print json should succeed"),
            CommandOutcome::Success
        );
    }

    #[test]
    fn test_skill_content_is_non_empty() {
        assert!(
            !SKILL_CONTENT.is_empty(),
            "embedded skill content must not be empty"
        );
    }

    #[test]
    fn test_context_content_is_non_empty() {
        assert!(
            !CONTEXT_CONTENT.is_empty(),
            "embedded context content must not be empty"
        );
    }

    #[test]
    fn test_skill_content_contains_expected_keywords() {
        let lower = SKILL_CONTENT.to_lowercase();
        assert!(
            lower.contains("gitvault"),
            "skill content should mention 'gitvault'"
        );
        assert!(
            lower.contains("encrypt"),
            "skill content should mention encryption"
        );
        assert!(
            lower.contains("identity"),
            "skill content should mention identity"
        );
    }

    #[test]
    fn test_context_content_contains_expected_keywords() {
        let lower = CONTEXT_CONTENT.to_lowercase();
        assert!(
            lower.contains("gitvault"),
            "context content should mention 'gitvault'"
        );
        assert!(
            lower.contains("agent"),
            "context content should mention 'agent'"
        );
    }

    #[test]
    fn test_ai_json_envelope_has_correct_fields() {
        // Verify the JSON structure matches the documented MCP-style envelope format.
        // We build the same envelope the production code uses and validate its shape.
        let json = serde_json::json!({
            "protocol": "gitvault-ai/1",
            "tool": "gitvault",
            "success": true,
            "payload": {
                "content": SKILL_CONTENT,
                "format": "markdown"
            }
        });

        assert_eq!(
            json["protocol"].as_str(),
            Some("gitvault-ai/1"),
            "JSON envelope must carry the correct protocol field"
        );
        assert_eq!(
            json["tool"].as_str(),
            Some("gitvault"),
            "JSON envelope must identify the tool as 'gitvault'"
        );
        assert_eq!(
            json["success"].as_bool(),
            Some(true),
            "JSON envelope success field must be true"
        );
        assert_eq!(
            json["payload"]["format"].as_str(),
            Some("markdown"),
            "JSON envelope payload must declare markdown format"
        );
        assert!(
            !json["payload"]["content"].as_str().unwrap_or("").is_empty(),
            "JSON envelope payload content must not be empty"
        );
    }
}
