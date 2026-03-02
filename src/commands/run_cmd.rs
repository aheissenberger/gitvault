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
}

/// Run a command with secrets injected as environment variables (REQ-21..25)
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
    execute_effects(effects)
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

        let env_dir = dir.path().join("secrets/dev");
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
        })
        .expect_err("run should fail closed on decrypt error");

        assert!(matches!(err, GitvaultError::Decryption(_)));
    }
}
