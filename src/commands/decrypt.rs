//! `gitvault decrypt` command implementation.

use std::path::PathBuf;

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::{load_identity, load_identity_from_source};
use crate::{crypto, fhsm, repo, structured};

/// Decrypt a .age file and write plaintext
#[allow(clippy::too_many_arguments)]
pub fn cmd_decrypt(
    file: String,
    identity_path: Option<String>,
    output: Option<String>,
    fields: Option<String>,
    reveal: bool,
    value_only: bool,
    json: bool,
    no_prompt: bool,
) -> Result<CommandOutcome, GitvaultError> {
    // Use FHSM to resolve the identity source; file I/O remains here.
    let event = fhsm::Event::Decrypt {
        file: file.clone(),
        identity: identity_path,
        no_prompt,
        output: output.clone(),
    };
    let effects = fhsm::transition(&event)?;
    let identity_str = effects
        .iter()
        .find_map(|e| {
            if let fhsm::Effect::ResolveIdentity { source } = e {
                Some(load_identity_from_source(source))
            } else {
                None
            }
        })
        .unwrap_or_else(|| load_identity(None))?;

    let input_path = PathBuf::from(&file);
    let identity = crypto::parse_identity(&identity_str)?;
    let repo_root = crate::repo::find_repo_root()?;

    // REQ-6: value-only mode: decrypt each VALUE in a .env file individually
    if value_only {
        use crate::structured::decrypt_env_values;
        let content = std::fs::read_to_string(&input_path).map_err(GitvaultError::Io)?;
        let decrypted = decrypt_env_values(&content, &identity)?;
        if reveal {
            print!("{decrypted}");
            return Ok(CommandOutcome::Success);
        }
        let out_path = match &output {
            Some(p) => std::path::PathBuf::from(p),
            None => input_path.clone(),
        };
        repo::validate_write_path(&repo_root, &out_path)?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".gitvault-tmp-")
            .tempfile_in(out_path.parent().unwrap_or(std::path::Path::new(".")))?;
        use std::io::Write;
        tmp.write_all(decrypted.as_bytes())?;
        tmp.persist(&out_path)
            .map_err(|e| GitvaultError::Io(e.error))?;
        crate::output::output_success(&format!("Decrypted values in {}", out_path.display()), json);
        return Ok(CommandOutcome::Success);
    }

    // REQ-4: field-level decryption for JSON/YAML/TOML
    if let Some(fields_str) = &fields {
        let fields: Vec<&str> = fields_str.split(',').map(str::trim).collect();
        // REQ-42: prevent path traversal for in-place field writes
        repo::validate_write_path(&repo_root, &input_path)?;
        structured::decrypt_fields(&input_path, &fields, &identity)
            .map_err(|e| GitvaultError::Decryption(e.to_string()))?;
        crate::output::output_success(
            &format!(
                "Decrypted fields [{fields_str}] in {}",
                input_path.display()
            ),
            json,
        );
        return Ok(CommandOutcome::Success);
    }

    // REQ-41: if --reveal, print to stdout and never write to file
    if reveal {
        let in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut stdout = std::io::BufWriter::new(std::io::stdout());
        crypto::decrypt_stream(&identity, in_file, &mut stdout)?;
        return Ok(CommandOutcome::Success);
    }

    let out_path = if let Some(out) = output {
        PathBuf::from(out)
    } else {
        let name = input_path
            .file_name()
            .ok_or_else(|| {
                GitvaultError::Usage(format!("path has no file name: {}", input_path.display()))
            })?
            .to_string_lossy();
        let out_name = name.strip_suffix(".age").unwrap_or(&name).to_string();
        input_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(out_name)
    };

    // REQ-42: prevent path traversal
    repo::validate_write_path(&repo_root, &out_path)?;

    // REQ-51: streaming decryption
    let tmp =
        tempfile::NamedTempFile::new_in(out_path.parent().unwrap_or(std::path::Path::new(".")))?;
    {
        let in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::decrypt_stream(&identity, in_file, &mut out_file)?;
    }
    tmp.persist(&out_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    crate::output::output_success(&format!("Decrypted to {}", out_path.display()), json);
    Ok(CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use tempfile::TempDir;

    #[test]
    fn test_cmd_decrypt_reveal_succeeds() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(identity.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext = crypto::encrypt(recipients, b"TOP_SECRET=1\n").unwrap();
        let encrypted_file = dir.path().join("secret.env.age");
        std::fs::write(&encrypted_file, ciphertext).unwrap();

        cmd_decrypt(
            encrypted_file.to_string_lossy().to_string(),
            Some(identity_file.path().to_string_lossy().to_string()),
            None,
            None,
            true,
            false,
            true,
            true,
        )
        .expect("reveal mode should decrypt to stdout without error");
    }

    #[test]
    fn test_cmd_decrypt_default_output_path_writes_plaintext() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(identity.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext = crypto::encrypt(recipients, b"X=42\n").unwrap();
        let encrypted_file = dir.path().join("app.env.age");
        std::fs::write(&encrypted_file, ciphertext).unwrap();

        cmd_decrypt(
            encrypted_file.to_string_lossy().to_string(),
            Some(identity_file.path().to_string_lossy().to_string()),
            None,
            None,
            false,
            false,
            true,
            true,
        )
        .expect("default output decrypt should succeed");

        let plain = std::fs::read_to_string(dir.path().join("app.env")).unwrap();
        assert!(plain.contains("X=42"));
    }

    #[test]
    fn test_cmd_decrypt_fields_wrong_identity_propagates_error() {
        // Covers the `|e| GitvaultError::Decryption(e.to_string())` closure in the fields branch.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let (wrong_identity_file, _) = setup_identity_file();

        // Encrypt a field to `identity`.
        let json_file = dir.path().join("config.json");
        std::fs::write(&json_file, r#"{"secret":"abc","name":"demo"}"#).unwrap();
        with_identity_env(identity_file.path(), || {
            crate::commands::encrypt::cmd_encrypt(
                json_file.to_string_lossy().to_string(),
                vec![identity.to_public().to_string()],
                Some("secret".to_string()),
                false,
                false,
            )
            .expect("field encrypt should succeed");
        });

        // Try to decrypt with the wrong identity → map_err closure fires.
        let err = with_identity_env(wrong_identity_file.path(), || {
            cmd_decrypt(
                json_file.to_string_lossy().to_string(),
                None,
                None,
                Some("secret".to_string()),
                false,
                false,
                false,
                true,
            )
        })
        .expect_err("field decrypt with wrong identity should fail");

        assert!(
            matches!(err, GitvaultError::Decryption(_)),
            "expected Decryption error, got: {err:?}"
        );
    }

    #[test]
    fn test_cmd_decrypt_value_only_roundtrip() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Create a plain .env file
        let env_file = dir.path().join("app.env");
        std::fs::write(&env_file, "API_KEY=mysecret\nDB_HOST=localhost\n").unwrap();

        // Encrypt with --value-only
        with_identity_env(identity_file.path(), || {
            crate::commands::encrypt::cmd_encrypt(
                env_file.to_string_lossy().to_string(),
                vec![identity.to_public().to_string()],
                None,
                true, // value_only
                false,
            )
            .expect("value-only encrypt should succeed");
        });

        // Verify values are encrypted in-place
        let encrypted_content = std::fs::read_to_string(&env_file).unwrap();
        assert!(
            encrypted_content.contains("API_KEY=age:"),
            "API_KEY value should be encrypted"
        );
        assert!(
            encrypted_content.contains("DB_HOST=age:"),
            "DB_HOST value should be encrypted"
        );

        // Decrypt with --value-only
        cmd_decrypt(
            env_file.to_string_lossy().to_string(),
            Some(identity_file.path().to_string_lossy().to_string()),
            None,
            None,
            false,
            true, // value_only
            false,
            true,
        )
        .expect("value-only decrypt should succeed");

        // Verify values are restored
        let decrypted_content = std::fs::read_to_string(&env_file).unwrap();
        assert_eq!(
            decrypted_content, "API_KEY=mysecret\nDB_HOST=localhost\n",
            "decrypted content should match original"
        );
    }
}
