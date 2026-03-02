//! `gitvault run` command implementation.

use crate::commands::effects::{CommandOutcome, execute_effects};
use crate::error::GitvaultError;
use crate::fhsm;

/// Run a command with secrets injected as environment variables (REQ-21..25)
#[allow(clippy::too_many_arguments)]
pub fn cmd_run(
    env_override: Option<String>,
    identity_path: Option<String>,
    prod: bool,
    clear_env: bool,
    pass_raw: Option<String>,
    command: Vec<String>,
    _json: bool,
    no_prompt: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let event = fhsm::Event::Run {
        env: env_override,
        identity: identity_path,
        prod,
        no_prompt,
        clear_env,
        pass_raw,
        command,
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

        let err = cmd_run(None, None, false, false, None, vec![], false, true)
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

        let err = cmd_run(
            Some("dev".to_string()),
            Some(identity_file.path().to_string_lossy().to_string()),
            false,
            false,
            None,
            vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
            true,
            true,
        )
        .expect_err("run should fail closed on decrypt error");

        assert!(matches!(err, GitvaultError::Decryption(_)));
    }
}
