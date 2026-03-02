//! Output formatting utilities.

/// Print a success message. If `json` is true, emits `{"status":"ok","message":"..."}` to stdout.
pub fn output_success(message: &str, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"status": "ok", "message": message})
        );
    } else {
        println!("{message}");
    }
}

/// Return true if the CI env var is set to a truthy value (1/true/yes).
pub fn ci_is_non_interactive() -> bool {
    matches!(std::env::var("CI").as_deref(), Ok("1" | "true" | "yes"))
}

/// Return the effective `no_prompt` setting — always true in CI.
pub fn resolve_no_prompt(no_prompt: bool) -> bool {
    no_prompt || ci_is_non_interactive()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialise all env-var mutations in this module so tests don't race.
    static CI_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn output_success_plain_does_not_panic() {
        output_success("plain message", false);
    }

    #[test]
    fn output_success_json_does_not_panic() {
        output_success("json message", true);
    }

    #[test]
    fn ci_is_non_interactive_with_ci_1() {
        let _g = CI_LOCK.lock().unwrap();
        // SAFETY: CI_LOCK held; single-threaded access to this env var.
        unsafe { std::env::set_var("CI", "1") };
        assert!(ci_is_non_interactive());
        unsafe { std::env::remove_var("CI") };
    }

    #[test]
    fn ci_is_non_interactive_with_ci_true() {
        let _g = CI_LOCK.lock().unwrap();
        unsafe { std::env::set_var("CI", "true") };
        assert!(ci_is_non_interactive());
        unsafe { std::env::remove_var("CI") };
    }

    #[test]
    fn ci_is_non_interactive_with_ci_yes() {
        let _g = CI_LOCK.lock().unwrap();
        unsafe { std::env::set_var("CI", "yes") };
        assert!(ci_is_non_interactive());
        unsafe { std::env::remove_var("CI") };
    }

    #[test]
    fn ci_is_non_interactive_when_unset_returns_false() {
        let _g = CI_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("CI") };
        assert!(!ci_is_non_interactive());
    }

    #[test]
    fn ci_is_non_interactive_with_falsy_value_returns_false() {
        let _g = CI_LOCK.lock().unwrap();
        unsafe { std::env::set_var("CI", "false") };
        assert!(!ci_is_non_interactive());
        unsafe { std::env::remove_var("CI") };
    }

    #[test]
    fn resolve_no_prompt_true_when_flag_set() {
        let _g = CI_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("CI") };
        assert!(resolve_no_prompt(true));
    }

    #[test]
    fn resolve_no_prompt_false_when_no_flag_and_no_ci() {
        let _g = CI_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("CI") };
        assert!(!resolve_no_prompt(false));
    }

    #[test]
    fn resolve_no_prompt_true_when_ci_env_set() {
        let _g = CI_LOCK.lock().unwrap();
        unsafe { std::env::set_var("CI", "1") };
        assert!(resolve_no_prompt(false));
        unsafe { std::env::remove_var("CI") };
    }
}
