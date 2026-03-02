//! Output formatting utilities.

/// Print a success message. If `json` is true, emits `{"status":"ok","message":"..."}` to stdout.
pub(crate) fn output_success(message: &str, json: bool) {
    if json {
        println!("{}", serde_json::json!({"status": "ok", "message": message}));
    } else {
        println!("{message}");
    }
}

/// Return true if the CI env var is set to a truthy value (1/true/yes).
pub(crate) fn ci_is_non_interactive() -> bool {
    matches!(
        std::env::var("CI").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Return the effective no_prompt setting — always true in CI.
pub(crate) fn resolve_no_prompt(no_prompt: bool) -> bool {
    no_prompt || ci_is_non_interactive()
}
