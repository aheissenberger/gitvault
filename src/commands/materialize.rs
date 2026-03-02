//! `gitvault materialize` command implementation.

use crate::commands::effects::execute_effects;
use crate::error::GitvaultError;
use crate::fhsm;

/// Materialize secrets to root .env
pub(crate) fn cmd_materialize(
    env_override: Option<String>,
    identity_path: Option<String>,
    prod: bool,
    json: bool,
    no_prompt: bool,
) -> Result<(), GitvaultError> {
    let event = fhsm::Event::Materialize {
        env: env_override,
        identity: identity_path,
        prod,
        no_prompt,
    };
    let effects = fhsm::transition(&event).map_err(|e| GitvaultError::Usage(e.to_string()))?;
    execute_effects(effects)?;
    crate::output::output_success("Materialized secrets to .env", json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use crate::error::GitvaultError;
    use tempfile::TempDir;

    #[test]
    fn test_cmd_materialize_and_rotate_env_scoped() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        write_encrypted_env_file(
            dir.path(),
            "dev",
            "app.env.age",
            &identity,
            "API_KEY=abc123\n",
        );

        with_identity_env(identity_file.path(), || {
            cmd_materialize(None, None, false, false, true)
                .expect("materialize should decrypt env-scoped secrets");
            crate::commands::recipients::cmd_rotate(None, true)
                .expect("rotate should process env-scoped files");
        });

        let materialized =
            std::fs::read_to_string(dir.path().join(".env")).expect(".env should be created");
        assert!(materialized.contains("API_KEY=\"abc123\""));
    }

    #[test]
    fn test_cmd_materialize_fail_closed_on_invalid_ciphertext() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let env_dir = dir.path().join("secrets/dev");
        std::fs::create_dir_all(&env_dir).unwrap();
        let bad_file = env_dir.join("broken.env.age");
        std::fs::write(&bad_file, b"not-age-data").unwrap();

        let err = cmd_materialize(
            Some("dev".to_string()),
            Some(identity_file.path().to_string_lossy().to_string()),
            false,
            true,
            true,
        )
        .expect_err("invalid ciphertext must fail closed");

        match err {
            GitvaultError::Decryption(message) => {
                assert!(message.contains("Failed to decrypt"));
            }
            other => panic!("expected decryption error, got: {other:?}"),
        }
    }
}
