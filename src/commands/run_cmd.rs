//! `gitvault run` command implementation.

use crate::commands::effects::{CommandOutcome, execute_effects};
use crate::error::GitvaultError;
use crate::fhsm;

/// Options for the [`cmd_run`] command.
pub struct RunOptions {
    /// Environment override (e.g. `"dev"`, `"prod"`).
    pub env: Option<String>,
    /// Path to an age identity file.
    pub identity: Option<String>,
    /// Assert production environment (REQ-13 barrier).
    pub prod: bool,
    /// Clear inherited env before injecting secrets.
    pub clear_env: bool,
    /// Raw password for password-encrypted identity files.
    pub pass_raw: Option<String>,
    /// Command and arguments to execute.
    pub command: Vec<String>,
    /// Suppress interactive prompts.
    pub no_prompt: bool,
    /// Identity selector for SSH-agent key disambiguation (REQ-39/46).
    pub selector: Option<String>,
}

/// Run a command with secrets injected as environment variables (REQ-21..25)
///
/// # Errors
///
/// Returns [`GitvaultError`] if the FHSM transition fails or any effect in the
/// execution chain fails (barrier check, identity load, decryption, subprocess).
pub fn cmd_run(opts: RunOptions) -> Result<CommandOutcome, GitvaultError> {
    let event = fhsm::Event::Run {
        env: opts.env,
        identity: opts.identity,
        prod: opts.prod,
        no_prompt: opts.no_prompt,
        clear_env: opts.clear_env,
        pass_raw: opts.pass_raw,
        command: opts.command,
    };
    let effects = fhsm::transition(&event)?;
    execute_effects(effects, opts.selector.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use tempfile::TempDir;

    #[test]
    fn test_cmd_run_empty_command_is_usage_error() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let err = cmd_run(RunOptions {
            env: None,
            identity: None,
            prod: false,
            clear_env: false,
            pass_raw: None,
            command: vec![],
            no_prompt: true,
            selector: None,
        })
        .expect_err("empty command should fail");

        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_run_fail_closed_on_invalid_ciphertext() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let env_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&env_dir).unwrap();
        std::fs::write(env_dir.join("broken.env.age"), b"not-age-data").unwrap();

        let err = cmd_run(RunOptions {
            env: Some("dev".to_string()),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            prod: false,
            clear_env: false,
            pass_raw: None,
            command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
            no_prompt: true,
            selector: None,
        })
        .expect_err("run should fail closed on decrypt error");

        assert!(matches!(err, GitvaultError::Decryption(_)));
    }

    #[test]
    fn test_cmd_run_clear_env_strips_parent_env() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Write a minimal encrypted env file so the decrypt step succeeds.
        write_encrypted_env_file(dir.path(), "dev", "dummy.env.age", &identity, "DUMMY=1\n");

        // Set a unique sentinel var in the parent; it must NOT reach the child when
        // --clear-env is active.
        let outcome = with_env_var(
            "GITVAULT_CLEAR_ENV_SENTINEL_5x7z",
            Some("parent_value"),
            || {
                cmd_run(RunOptions {
                    env: Some("dev".to_string()),
                    identity: Some(identity_file.path().to_string_lossy().to_string()),
                    prod: false,
                    clear_env: true,
                    pass_raw: None,
                    // Exit 0 if the sentinel is absent/empty, non-zero otherwise.
                    command: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        r#"test -z "$GITVAULT_CLEAR_ENV_SENTINEL_5x7z""#.to_string(),
                    ],
                    no_prompt: true,
                    selector: None,
                })
                .expect("child process should launch successfully")
            },
        );

        assert_eq!(
            outcome,
            CommandOutcome::Exit(0),
            "--clear-env should prevent parent env vars from reaching the child"
        );
    }

    #[test]
    fn test_cmd_run_clear_env_with_pass_raw_preserves_path() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        write_encrypted_env_file(dir.path(), "dev", "dummy.env.age", &identity, "DUMMY=1\n");

        // With --clear-env + --keep-vars PATH, the child must see a non-empty PATH.
        let outcome = cmd_run(RunOptions {
            env: Some("dev".to_string()),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            prod: false,
            clear_env: true,
            pass_raw: Some("PATH".to_string()),
            // Exit 0 if PATH is set and non-empty.
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                r#"test -n "$PATH""#.to_string(),
            ],
            no_prompt: true,
            selector: None,
        })
        .expect("child process should launch successfully");

        assert_eq!(
            outcome,
            CommandOutcome::Exit(0),
            "--keep-vars PATH should preserve PATH even with --clear-env"
        );
    }

    #[test]
    fn test_cmd_run_secrets_injected_as_env_vars() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Encrypt a secret that the child process will verify.
        write_encrypted_env_file(
            dir.path(),
            "dev",
            "app.env.age",
            &identity,
            "MY_SECRET=injected_value\n",
        );

        let outcome = cmd_run(RunOptions {
            env: Some("dev".to_string()),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            prod: false,
            clear_env: false,
            pass_raw: None,
            // Exit 0 if MY_SECRET has the expected value.
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                r#"test "$MY_SECRET" = "injected_value""#.to_string(),
            ],
            no_prompt: true,
            selector: None,
        })
        .expect("run should succeed");

        assert_eq!(
            outcome,
            CommandOutcome::Exit(0),
            "secrets should be injected as environment variables into the child process"
        );
    }

    #[test]
    fn test_cmd_run_nonexistent_identity_returns_meaningful_error() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Point identity at a path that will never exist.
        let err = cmd_run(RunOptions {
            env: Some("dev".to_string()),
            identity: Some("/nonexistent/identity/file.age".to_string()),
            prod: false,
            clear_env: false,
            pass_raw: None,
            command: vec!["true".to_string()],
            no_prompt: true,
            selector: None,
        })
        .expect_err("should fail when identity file does not exist");

        // Must be a structured error, not a panic. Accept any I/O-related or usage variant.
        assert!(
            matches!(
                err,
                GitvaultError::Io(_)
                    | GitvaultError::Other(_)
                    | GitvaultError::Decryption(_)
                    | GitvaultError::Usage(_)
            ),
            "expected a meaningful Io/Other/Decryption/Usage error, got: {err:?}"
        );
    }
}
