//! Fileless run mode: inject secrets into a child process environment.
//!
//! REQ-21: `gitvault run --env <env> -- <command> [args]`
//! REQ-22: inject secrets as env vars; no plaintext files written.
//! REQ-23: propagate child exit code exactly.
//! REQ-24: support --clear-env, --pass VAR1,VAR2.
//! REQ-25: --env prod requires production barrier (enforced in main.rs, not here).

use std::process::Command;

use crate::error::GitvaultError;

/// Execute `cmd` with `args`, injecting `secrets` into its environment.
///
/// - `clear_env`: if true, start with an empty environment (only secrets + pass-through vars).
/// - `pass_vars`: names of variables to forward from the current process environment when
///   `clear_env` is true.  Ignored when `clear_env` is false (all current vars pass through).
///
/// Returns the child process exit code. REQ-23.
pub fn run_command(
    secrets: &[(String, String)],
    cmd: &str,
    args: &[String],
    clear_env: bool,
    pass_vars: &[String],
) -> Result<i32, GitvaultError> {
    let mut command = Command::new(cmd);
    command.args(args);

    if clear_env {
        // REQ-24 --clear-env: start with empty environment
        command.env_clear();

        // Re-add explicitly requested pass-through variables
        for var in pass_vars {
            if let Ok(val) = std::env::var(var) {
                command.env(var, val);
            }
        }
    }
    // (When clear_env is false the child inherits the full current environment by default.)

    // REQ-22: inject secrets — overrides any inherited value with the same name
    for (key, value) in secrets {
        command.env(key, value);
    }

    let status = command
        .status()
        .map_err(|e| GitvaultError::Other(format!("Failed to execute '{cmd}': {e}")))?;

    // REQ-23: propagate exit code
    Ok(status.code().unwrap_or(1))
}

/// Parse a comma-separated list of variable names (used for --pass).
pub fn parse_pass_vars(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_exit_code_zero() {
        let code = run_command(&[], "true", &[], false, &[]).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_run_exit_code_nonzero() {
        let code = run_command(&[], "false", &[], false, &[]).unwrap();
        assert_ne!(code, 0);
    }

    #[test]
    fn test_run_propagates_specific_exit_code() {
        // Use sh -c 'exit N' to get a specific code
        let code = run_command(
            &[],
            "sh",
            &["-c".to_string(), "exit 42".to_string()],
            false,
            &[],
        )
        .unwrap();
        assert_eq!(code, 42);
    }

    #[test]
    fn test_secrets_injected_into_env() {
        let secrets = vec![
            ("GITVAULT_TEST_KEY".to_string(), "injected_value".to_string()),
        ];
        // sh -c 'test "$VAR" = "value"' exits 0 on match, 1 on mismatch
        let code = run_command(
            &secrets,
            "sh",
            &[
                "-c".to_string(),
                r#"test "$GITVAULT_TEST_KEY" = "injected_value""#.to_string(),
            ],
            false,
            &[],
        )
        .unwrap();
        assert_eq!(code, 0, "secret should be visible in child environment");
    }

    #[test]
    fn test_clear_env_removes_parent_vars() {
        // Set a var in the current process, verify child does NOT see it with --clear-env
        unsafe { std::env::set_var("GITVAULT_SHOULD_NOT_PASS", "nope"); }

        let code = run_command(
            &[],
            "sh",
            &[
                "-c".to_string(),
                r#"test -z "$GITVAULT_SHOULD_NOT_PASS""#.to_string(),
            ],
            true,  // clear_env
            &[],   // no pass-through
        )
        .unwrap();

        unsafe { std::env::remove_var("GITVAULT_SHOULD_NOT_PASS"); }
        assert_eq!(code, 0, "cleared env should not contain parent var");
    }

    #[test]
    fn test_pass_vars_forwarded_with_clear_env() {
        unsafe { std::env::set_var("GITVAULT_PASS_ME", "hello"); }

        let code = run_command(
            &[],
            "sh",
            &[
                "-c".to_string(),
                r#"test "$GITVAULT_PASS_ME" = "hello""#.to_string(),
            ],
            true,
            &["GITVAULT_PASS_ME".to_string()],
        )
        .unwrap();

        unsafe { std::env::remove_var("GITVAULT_PASS_ME"); }
        assert_eq!(code, 0, "passed-through var should be visible in child");
    }

    #[test]
    fn test_secrets_override_inherited_vars() {
        unsafe { std::env::set_var("GITVAULT_OVERRIDE_TEST", "original"); }

        let secrets = vec![
            ("GITVAULT_OVERRIDE_TEST".to_string(), "overridden".to_string()),
        ];
        let code = run_command(
            &secrets,
            "sh",
            &[
                "-c".to_string(),
                r#"test "$GITVAULT_OVERRIDE_TEST" = "overridden""#.to_string(),
            ],
            false,
            &[],
        )
        .unwrap();

        unsafe { std::env::remove_var("GITVAULT_OVERRIDE_TEST"); }
        assert_eq!(code, 0, "secret should override inherited env var");
    }

    #[test]
    fn test_parse_pass_vars() {
        assert_eq!(
            parse_pass_vars("HOME,PATH,USER"),
            vec!["HOME", "PATH", "USER"]
        );
        assert_eq!(parse_pass_vars("  A , B "), vec!["A", "B"]);
        assert_eq!(parse_pass_vars(""), Vec::<String>::new());
        assert_eq!(parse_pass_vars("SINGLE"), vec!["SINGLE"]);
    }

    #[test]
    fn test_invalid_command_returns_error() {
        let result = run_command(&[], "this-binary-does-not-exist-gitvault", &[], false, &[]);
        assert!(result.is_err());
    }
}
