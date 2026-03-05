//! `gitvault encrypt` command implementation.

use std::path::PathBuf;

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::resolve_recipient_keys;
use crate::{crypto, env, repo, store};

/// Encrypt a file and write the .age output under `.gitvault/store/<env>/`,
/// mirroring the source file's path relative to the repository root.
///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root cannot be found, the input
/// file cannot be read, no valid recipients are resolved, or encryption fails.
// String params are intentionally owned: public API called from CLI dispatch
// where values are moved out of the parsed command struct.
#[allow(clippy::needless_pass_by_value)]
pub fn cmd_encrypt(
    file: String,
    recipient_keys: Vec<String>,
    env_override: Option<String>,
    json: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let cfg = crate::config::effective_config(&repo_root)?;
    let input_path = PathBuf::from(&file);

    // REQ-33: each source file maps to exactly one .age artifact
    if input_path.extension().and_then(|e| e.to_str()) == Some("age") {
        return Err(GitvaultError::Usage(
            "Cannot encrypt an already-encrypted .age file (REQ-33: no mega-blob)".to_string(),
        ));
    }

    let recipient_keys = resolve_recipient_keys(&repo_root, recipient_keys)?;

    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r = crypto::parse_recipient(k)?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let active_env = env_override.unwrap_or_else(|| env::resolve_env(&repo_root, &cfg.env));

    repo::ensure_dirs(&repo_root, &active_env)?;
    let out_path = store::compute_store_path(&input_path, &active_env, &repo_root)?;

    // REQ-42: prevent path traversal
    repo::validate_write_path(&repo_root, &out_path)?;

    if let Some(parent) = out_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(GitvaultError::Io)?;
    }

    // REQ-51: streaming encryption — no full-file buffer
    let tmp = tempfile::NamedTempFile::new_in(
        out_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    )?;
    {
        let mut in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::encrypt_stream(recipients, &mut in_file, &mut out_file)?;
    }
    tmp.persist(&out_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    crate::output::output_success(&format!("Encrypted to {}", out_path.display()), json);
    Ok(CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use tempfile::TempDir;

    #[test]
    fn test_cmd_encrypt_rejects_age_input_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let in_path = dir.path().join("already.age");
        std::fs::write(&in_path, b"x").unwrap();

        let err = cmd_encrypt(in_path.to_string_lossy().to_string(), vec![], None, true)
            .expect_err("encrypting .age input should fail");

        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_encrypt_invalid_recipient_in_normal_path_errors() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let plain_file = dir.path().join("data.txt");
        std::fs::write(&plain_file, "VALUE=123\n").unwrap();

        let bad_recipient = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let err = cmd_encrypt(
            plain_file.to_string_lossy().to_string(),
            vec![bad_recipient.to_string()],
            None,
            false,
        )
        .expect_err("invalid recipient should fail encrypt");
        assert!(
            matches!(err, GitvaultError::Encryption(_)),
            "expected Encryption error from bad recipient, got: {err:?}"
        );
    }

    #[test]
    fn test_cmd_encrypt_no_filename_in_path_errors() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let recipient = identity.to_public().to_string();

        with_identity_env(identity_file.path(), || {
            let err = cmd_encrypt("/".to_string(), vec![recipient], None, false)
                .expect_err("root path should fail with no filename");
            assert!(
                matches!(err, GitvaultError::Usage(_) | GitvaultError::Io(_)),
                "expected Usage or Io error for root path, got: {err:?}"
            );
        });
    }

    #[test]
    fn test_cmd_encrypt_writes_mirrored_output() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let nested = dir.path().join("app/platform/service/config");
        std::fs::create_dir_all(&nested).unwrap();
        let plain_file = nested.join("service.env");
        std::fs::write(&plain_file, "TOKEN=abc\n").unwrap();

        with_identity_env(identity_file.path(), || {
            cmd_encrypt(
                plain_file.to_string_lossy().to_string(),
                vec![identity.to_public().to_string()],
                None,
                false,
            )
            .expect("encrypt should succeed with mirrored output");
        });

        assert!(
            dir.path()
                .join(".gitvault/store/dev/app/platform/service/config/service.env.age")
                .exists(),
            "mirrored store path should exist"
        );
    }

    #[test]
    fn test_cmd_encrypt_env_override_writes_to_named_env() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let plain_file = dir.path().join("app.env");
        std::fs::write(&plain_file, "KEY=value\n").unwrap();

        with_identity_env(identity_file.path(), || {
            cmd_encrypt(
                plain_file.to_string_lossy().to_string(),
                vec![identity.to_public().to_string()],
                Some("staging".to_string()),
                false,
            )
            .expect("encrypt with --env staging should succeed");
        });

        assert!(
            dir.path()
                .join(".gitvault/store/staging/app.env.age")
                .exists(),
            "output should be under .gitvault/store/staging/"
        );
        assert!(
            !dir.path().join(".gitvault/store/dev/app.env.age").exists(),
            "output must NOT fall back to the default dev env"
        );
    }
}
