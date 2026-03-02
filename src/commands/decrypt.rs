//! `gitvault decrypt` command implementation.

use std::path::PathBuf;

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::{load_identity, load_identity_from_source};
use crate::{crypto, fhsm, repo, structured};

/// Options for the [`cmd_decrypt`] command.
// Each bool field maps directly to a CLI flag; suppressing `struct_excessive_bools`
// is intentional for CLI option structs.
#[allow(clippy::struct_excessive_bools)]
pub struct DecryptOptions {
    /// Path to the encrypted `.age` file.
    pub file: String,
    /// Path to an age identity file.
    pub identity: Option<String>,
    /// Output path (defaults to the input path with `.age` stripped).
    pub output: Option<String>,
    /// Comma-separated field paths to decrypt in structured files.
    pub fields: Option<String>,
    /// Print decrypted value to stdout instead of writing to file.
    pub reveal: bool,
    /// Decrypt each VALUE in a `.env` file individually (REQ-6).
    pub value_only: bool,
    /// Emit JSON output.
    pub json: bool,
    /// Suppress interactive prompts.
    pub no_prompt: bool,
}

/// Decrypt a .age file and write plaintext
pub fn cmd_decrypt(opts: DecryptOptions) -> Result<CommandOutcome, GitvaultError> {
    // Use FHSM to resolve the identity source; file I/O remains here.
    let event = fhsm::Event::Decrypt {
        file: opts.file.clone(),
        identity: opts.identity,
        no_prompt: opts.no_prompt,
        output: opts.output.clone(),
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

    let input_path = PathBuf::from(&opts.file);
    let identity = crypto::parse_identity(&identity_str)?;
    let repo_root = crate::repo::find_repo_root()?;

    // REQ-6: value-only mode: decrypt each VALUE in a .env file individually
    if opts.value_only {
        use crate::structured::decrypt_env_values;
        use std::io::Write;
        let content = std::fs::read_to_string(&input_path).map_err(GitvaultError::Io)?;
        let decrypted = decrypt_env_values(&content, &identity)?;
        if opts.reveal {
            print!("{decrypted}");
            return Ok(CommandOutcome::Success);
        }
        let out_path = match &opts.output {
            Some(p) => std::path::PathBuf::from(p),
            None => input_path,
        };
        repo::validate_write_path(&repo_root, &out_path)?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".gitvault-tmp-")
            .tempfile_in(
                out_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new(".")),
            )?;
        tmp.write_all(decrypted.as_bytes())?;
        tmp.persist(&out_path)
            .map_err(|e| GitvaultError::Io(e.error))?;
        crate::output::output_success(
            &format!("Decrypted values in {}", out_path.display()),
            opts.json,
        );
        return Ok(CommandOutcome::Success);
    }

    // REQ-4: field-level decryption for JSON/YAML/TOML
    if let Some(fields_str) = &opts.fields {
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
            opts.json,
        );
        return Ok(CommandOutcome::Success);
    }

    // REQ-41: if --reveal, print to stdout and never write to file
    if opts.reveal {
        let in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut stdout = std::io::BufWriter::new(std::io::stdout());
        crypto::decrypt_stream(&identity, in_file, &mut stdout)?;
        return Ok(CommandOutcome::Success);
    }

    let out_path = if let Some(out) = opts.output {
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
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(out_name)
    };

    // REQ-42: prevent path traversal
    repo::validate_write_path(&repo_root, &out_path)?;

    // REQ-51: streaming decryption
    let tmp = tempfile::NamedTempFile::new_in(
        out_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    )?;
    {
        let in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::decrypt_stream(&identity, in_file, &mut out_file)?;
    }
    tmp.persist(&out_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    crate::output::output_success(&format!("Decrypted to {}", out_path.display()), opts.json);
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

        cmd_decrypt(DecryptOptions {
            file: encrypted_file.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: None,
            fields: None,
            reveal: true,
            value_only: false,
            json: true,
            no_prompt: true,
        })
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

        cmd_decrypt(DecryptOptions {
            file: encrypted_file.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: None,
            fields: None,
            reveal: false,
            value_only: false,
            json: true,
            no_prompt: true,
        })
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
            cmd_decrypt(DecryptOptions {
                file: json_file.to_string_lossy().to_string(),
                identity: None,
                output: None,
                fields: Some("secret".to_string()),
                reveal: false,
                value_only: false,
                json: false,
                no_prompt: true,
            })
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
        cmd_decrypt(DecryptOptions {
            file: env_file.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: None,
            fields: None,
            reveal: false,
            value_only: true,
            json: false,
            no_prompt: true,
        })
        .expect("value-only decrypt should succeed");

        // Verify values are restored
        let decrypted_content = std::fs::read_to_string(&env_file).unwrap();
        assert_eq!(
            decrypted_content, "API_KEY=mysecret\nDB_HOST=localhost\n",
            "decrypted content should match original"
        );
    }

    /// Covers lines 51-52: `reveal=true` with `value_only=true` prints decrypted values to stdout
    /// and returns early without writing to disk.
    #[test]
    fn test_cmd_decrypt_value_only_reveal_prints_to_stdout() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Create a plain .env file with one encrypted value
        let env_file = dir.path().join("reveal.env");
        std::fs::write(&env_file, "TOKEN=supersecret\n").unwrap();
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

        // --reveal + --value-only: must succeed without writing to disk
        let outcome = cmd_decrypt(DecryptOptions {
            file: env_file.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: None,
            fields: None,
            reveal: true,
            value_only: true,
            json: false,
            no_prompt: true,
        })
        .expect("reveal + value_only should succeed");
        assert!(matches!(outcome, CommandOutcome::Success));
    }

    /// Covers line 55: `value_only=true` with an explicit `output` path.
    #[test]
    fn test_cmd_decrypt_value_only_with_explicit_output_path() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Create and value-only-encrypt the source file
        let env_file = dir.path().join("source.env");
        std::fs::write(&env_file, "DB_PASS=hunter2\n").unwrap();
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

        // Decrypt into a separate output file (explicit output path)
        let out_file = dir.path().join("dest.env");
        cmd_decrypt(DecryptOptions {
            file: env_file.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: Some(out_file.to_string_lossy().to_string()),
            fields: None,
            reveal: false,
            value_only: true,
            json: false,
            no_prompt: true,
        })
        .expect("value_only decrypt to explicit output should succeed");

        let content = std::fs::read_to_string(&out_file).unwrap();
        assert_eq!(
            content, "DB_PASS=hunter2\n",
            "decrypted output should match original"
        );
    }
}
