//! `gitvault encrypt` command implementation.

use std::path::{Path, PathBuf};

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::{load_identity, resolve_recipient_keys};
use crate::{crypto, env, repo, structured};

/// Compute the output `.age` path for `input_path` under the encrypted secrets directory.
///
/// When `keep_path` is set the relative directory structure of `input_path` (relative
/// to `repo_root`) is replicated under the per-env secrets directory.
fn compute_output_path(
    repo_root: &Path,
    input_path: &Path,
    active_env: &str,
    keep_path: bool,
) -> Result<PathBuf, GitvaultError> {
    if keep_path {
        let resolved_input = if input_path.is_absolute() {
            input_path.to_path_buf()
        } else {
            std::env::current_dir()?.join(input_path)
        };

        let canonical_repo_root = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf());
        let canonical_input = resolved_input
            .canonicalize()
            .unwrap_or_else(|_| resolved_input.clone());

        let rel_input = canonical_input
            .strip_prefix(&canonical_repo_root)
            .or_else(|_| resolved_input.strip_prefix(repo_root))
            .map_err(|_| {
                GitvaultError::Usage(format!(
                    "--keep-path requires input under repository root: {}",
                    input_path.display()
                ))
            })?;

        let rel_name = rel_input
            .file_name()
            .ok_or_else(|| GitvaultError::Usage("Invalid file path".to_string()))?
            .to_string_lossy();
        let out_name = format!("{rel_name}.age");

        let mut out_dir = repo::get_env_encrypted_dir(repo_root, active_env);
        if let Some(rel_parent) = rel_input.parent()
            && !rel_parent.as_os_str().is_empty()
        {
            out_dir = out_dir.join(rel_parent);
        }
        Ok(out_dir.join(out_name))
    } else {
        let filename = input_path
            .file_name()
            .ok_or_else(|| GitvaultError::Usage("Invalid file path".to_string()))?
            .to_string_lossy();
        let out_name = format!("{filename}.age");
        Ok(repo::get_env_encrypted_path(
            repo_root, active_env, &out_name,
        ))
    }
}

/// Encrypt a file and write the .age output under secrets/
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
    keep_path: bool,
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
            input_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
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

    let active_env = env_override.unwrap_or_else(|| env::resolve_env(&repo_root));

    repo::ensure_dirs(&repo_root, &active_env)?;
    let out_path = compute_output_path(&repo_root, &input_path, &active_env, keep_path)?;

    // REQ-42: prevent path traversal
    repo::validate_write_path(&repo_root, &out_path)?;

    if let Some(parent) = out_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
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

        let err = cmd_encrypt(
            in_path.to_string_lossy().to_string(),
            vec![],
            None,
            false,
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
                false,
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
                None,
                false,
                Some("secret".to_string()),
                false,
                true,
            )
            .expect("field encryption should succeed");

            crate::commands::decrypt::cmd_decrypt(crate::commands::decrypt::DecryptOptions {
                file: json_file.to_string_lossy().to_string(),
                identity: None,
                output: None,
                fields: Some("secret".to_string()),
                reveal: false,
                value_only: false,
                json: true,
                no_prompt: true,
                selector: None,
            })
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
                None,
                false,
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

    #[test]
    fn test_cmd_encrypt_keep_path_outside_repo_errors() {
        // When --keep-path is used with an input file outside the repo root,
        // strip_prefix fails and we get a Usage error.
        // Covers lines 28-32 (the strip_prefix error branch in compute_output_path).
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Create a file outside the repo root (in a sibling temp dir)
        let outside_dir = TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("secret.env");
        std::fs::write(&outside_file, "TOKEN=abc\n").unwrap();

        with_identity_env(identity_file.path(), || {
            let err = cmd_encrypt(
                outside_file.to_string_lossy().to_string(),
                vec![identity.to_public().to_string()],
                None,
                true, // --keep-path
                None,
                false,
                false,
            )
            .expect_err("input outside repo with --keep-path should fail");
            assert!(
                matches!(err, GitvaultError::Usage(_)),
                "expected Usage error for file outside repo, got: {err:?}"
            );
            let msg = err.to_string();
            assert!(
                msg.contains("repository root"),
                "error should mention repository root: {msg}"
            );
        });
    }

    #[test]
    fn test_cmd_encrypt_keep_path_writes_nested_output() {
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
                true,
                None,
                false,
                false,
            )
            .expect("encrypt with --keep-path should succeed");
        });

        assert!(
            dir.path()
                .join("secrets/dev/app/platform/service/config/service.env.age")
                .exists()
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
                None,
                false,
                false,
            )
            .expect("encrypt with --env staging should succeed");
        });

        assert!(
            dir.path().join("secrets/staging/app.env.age").exists(),
            "output should be under secrets/staging/"
        );
        assert!(
            !dir.path().join("secrets/dev/app.env.age").exists(),
            "output must NOT fall back to the default dev env"
        );
    }
}
