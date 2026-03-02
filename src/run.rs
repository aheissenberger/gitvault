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

    // REQ-23: propagate exit code; on Unix, signal-killed processes return 128 + signal number.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(128 + sig);
        }
    }
    Ok(status.code().unwrap_or(crate::error::EXIT_ERROR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

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
        let secrets = vec![(
            "GITVAULT_TEST_KEY".to_string(),
            "injected_value".to_string(),
        )];
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
        let _guard = env_lock().lock().unwrap();
        // Set a var in the current process, verify child does NOT see it with --clear-env
        unsafe {
            std::env::set_var("GITVAULT_SHOULD_NOT_PASS", "nope");
        }

        let code = run_command(
            &[],
            "sh",
            &[
                "-c".to_string(),
                r#"test -z "$GITVAULT_SHOULD_NOT_PASS""#.to_string(),
            ],
            true, // clear_env
            &[],  // no pass-through
        )
        .unwrap();

        unsafe {
            std::env::remove_var("GITVAULT_SHOULD_NOT_PASS");
        }
        assert_eq!(code, 0, "cleared env should not contain parent var");
    }

    #[test]
    fn test_pass_vars_forwarded_with_clear_env() {
        let _guard = env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("GITVAULT_PASS_ME", "hello");
        }

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

        unsafe {
            std::env::remove_var("GITVAULT_PASS_ME");
        }
        assert_eq!(code, 0, "passed-through var should be visible in child");
    }

    #[test]
    fn test_secrets_override_inherited_vars() {
        let _guard = env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("GITVAULT_OVERRIDE_TEST", "original");
        }

        let secrets = vec![(
            "GITVAULT_OVERRIDE_TEST".to_string(),
            "overridden".to_string(),
        )];
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

        unsafe {
            std::env::remove_var("GITVAULT_OVERRIDE_TEST");
        }
        assert_eq!(code, 0, "secret should override inherited env var");
    }

    #[test]
    fn test_invalid_command_returns_error() {
        let result = run_command(&[], "this-binary-does-not-exist-gitvault", &[], false, &[]);
        assert!(result.is_err());
    }

    /// REQ-23: a process killed by a signal must return 128 + signal_number, not EXIT_ERROR(1).
    #[cfg(unix)]
    #[test]
    fn test_signal_killed_process_returns_128_plus_signal() {
        // SIGTERM = 15; `/bin/sh -c 'kill -TERM $$'` sends SIGTERM to the shell itself.
        let result = run_command(
            &[],
            "sh",
            &["-c".to_string(), "kill -TERM $$".to_string()],
            false,
            &[],
        );
        // SIGTERM is signal 15, so expect 128 + 15 = 143.
        let code = result.expect("run_command should succeed even for signal-killed child");
        assert_eq!(
            code,
            128 + 15,
            "signal-killed process should return 128 + signal"
        );
    }
}
