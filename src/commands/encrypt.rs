//! `gitvault encrypt` command implementation.

use std::path::PathBuf;

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::{load_identity, resolve_recipient_keys};
use crate::{crypto, env, repo, structured};

/// Encrypt a file and write the .age output under secrets/
pub fn cmd_encrypt(
    file: String,
    recipient_keys: Vec<String>,
    fields: Option<String>,
    value_only: bool,
    json: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let input_path = PathBuf::from(&file);

    // REQ-33: each source file maps to exactly one .age artifact
    if input_path.extension().and_then(|e| e.to_str()) == Some("age") {
        return Err(GitvaultError::Usage(
            "Cannot encrypt an already-encrypted .age file (REQ-33: no mega-blob)".to_string(),
        ));
    }

    let recipient_keys = resolve_recipient_keys(&repo_root, recipient_keys)?;

    // REQ-4: field-level encryption for JSON/YAML/TOML
    if let Some(fields_str) = &fields {
        let fields: Vec<&str> = fields_str.split(',').map(str::trim).collect();
        let identity_str = load_identity(None)?;
        let identity = crypto::parse_identity(&identity_str)?;
        // REQ-42: prevent path traversal for in-place field writes
        repo::validate_write_path(&repo_root, &input_path)?;
        structured::encrypt_fields(&input_path, &fields, &identity, &recipient_keys)
            .map_err(|e| GitvaultError::Encryption(e.to_string()))?;
        crate::output::output_success(
            &format!(
                "Encrypted fields [{fields_str}] in {}",
                input_path.display()
            ),
            json,
        );
        return Ok(CommandOutcome::Success);
    }

    // REQ-6: .env value-only mode
    let ext = input_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if value_only
        && (ext == "env"
            || input_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .starts_with(".env"))
    {
        let identity_str = load_identity(None)?;
        let identity = crypto::parse_identity(&identity_str)?;
        let content = std::fs::read_to_string(&input_path)?;
        let encrypted = structured::encrypt_env_values(&content, &identity, &recipient_keys)
            .map_err(|e| GitvaultError::Encryption(e.to_string()))?;
        // REQ-42: prevent path traversal for in-place value-only writes
        repo::validate_write_path(&repo_root, &input_path)?;
        // REQ-43: atomic write
        let tmp = tempfile::NamedTempFile::new_in(
            input_path.parent().unwrap_or(std::path::Path::new(".")),
        )?;
        std::fs::write(tmp.path(), encrypted)?;
        tmp.persist(&input_path)
            .map_err(|e| GitvaultError::Io(e.error))?;
        crate::output::output_success(
            &format!("Encrypted .env values in {}", input_path.display()),
            json,
        );
        return Ok(CommandOutcome::Success);
    }

    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r = crypto::parse_recipient(k)?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let filename = input_path
        .file_name()
        .ok_or_else(|| GitvaultError::Usage("Invalid file path".to_string()))?
        .to_string_lossy();
    let out_name = format!("{filename}.age");
    let active_env = env::resolve_env(&repo_root);

    repo::ensure_dirs(&repo_root, &active_env)?;
    let out_path = repo::get_env_encrypted_path(&repo_root, &active_env, &out_name);

    // REQ-42: prevent path traversal
    repo::validate_write_path(&repo_root, &out_path)?;

    // REQ-51: streaming encryption — no full-file buffer
    let tmp =
        tempfile::NamedTempFile::new_in(out_path.parent().unwrap_or(std::path::Path::new(".")))?;
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

        let err = cmd_encrypt(
            in_path.to_string_lossy().to_string(),
            vec![],
            None,
            false,
            true,
        )
        .expect_err("encrypting .age input should fail");

        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_encrypt_value_only_writes_in_place() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let recipient = identity.to_public().to_string();

        let env_file = dir.path().join(".env.local");
        std::fs::write(&env_file, "API_KEY=secret\n").unwrap();

        with_identity_env(identity_file.path(), || {
            cmd_encrypt(
                env_file.to_string_lossy().to_string(),
                vec![recipient],
                None,
                true,
                true,
            )
            .expect("value-only encryption should succeed");
        });

        let updated = std::fs::read_to_string(&env_file).unwrap();
        assert!(updated.contains("API_KEY=age:"));
    }

    #[test]
    fn test_cmd_encrypt_then_decrypt_fields_roundtrip() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let recipient = identity.to_public().to_string();

        let json_file = dir.path().join("config.json");
        std::fs::write(&json_file, r#"{"secret":"abc","name":"demo"}"#).unwrap();

        with_identity_env(identity_file.path(), || {
            cmd_encrypt(
                json_file.to_string_lossy().to_string(),
                vec![recipient.clone()],
                Some("secret".to_string()),
                false,
                true,
            )
            .expect("field encryption should succeed");

            crate::commands::decrypt::cmd_decrypt(
                json_file.to_string_lossy().to_string(),
                None,
                None,
                Some("secret".to_string()),
                false,
                true,
                true,
            )
            .expect("field decryption should succeed");
        });

        let content = std::fs::read_to_string(&json_file).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(value["secret"], "abc");
        assert_eq!(value["name"], "demo");
    }

    #[test]
    fn test_cmd_encrypt_fields_on_nonexistent_file_propagates_error() {
        // Covers the `|e| GitvaultError::Encryption(e.to_string())` closure in the fields branch.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let recipient = identity.to_public().to_string();

        // A non-existent JSON file causes encrypt_fields to return an error.
        let nonexistent = dir.path().join("no_such_file.json");

        with_identity_env(identity_file.path(), || {
            let err = cmd_encrypt(
                nonexistent.to_string_lossy().to_string(),
                vec![recipient],
                Some("field".to_string()),
                false,
                false,
            )
            .expect_err("encrypt fields on nonexistent file should fail");
            assert!(
                matches!(err, GitvaultError::Encryption(_)),
                "expected Encryption error, got: {err:?}"
            );
        });
    }

    #[test]
    fn test_cmd_encrypt_invalid_recipient_in_normal_path_errors() {
        // Covers the error branch of the recipient-map closure in the normal encrypt path.
        // The key passes resolve_recipient_keys (returned as-is) but fails parse_recipient.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let plain_file = dir.path().join("data.txt");
        std::fs::write(&plain_file, "VALUE=123\n").unwrap();

        // A syntactically-valid age1 key that fails the actual bech32 parse.
        let bad_recipient = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let err = cmd_encrypt(
            plain_file.to_string_lossy().to_string(),
            vec![bad_recipient.to_string()],
            None,
            false,
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
        // Covers the ok_or_else("Invalid file path") branch when input_path has no filename.
        // A path ending in "/" or "." has no file_name component.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let recipient = identity.to_public().to_string();

        // The path "." has no meaningful filename (file_name() returns Some(".")).
        // Use "/" which has no file_name().
        with_identity_env(identity_file.path(), || {
            let err = cmd_encrypt(
                "/".to_string(),
                vec![recipient],
                None,
                false,
                false,
            )
            .expect_err("root path should fail with no filename");
            // Either Usage (no filename) or Io (can't read /) is acceptable.
            assert!(
                matches!(err, GitvaultError::Usage(_) | GitvaultError::Io(_)),
                "expected Usage or Io error for root path, got: {err:?}"
            );
        });
    }
}
