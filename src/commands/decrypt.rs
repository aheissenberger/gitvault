//! `gitvault decrypt` command implementation.

use std::path::PathBuf;

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::{load_identity_from_source_with_selector, load_identity_with_selector};
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
    /// Identity selector to narrow the identity source.
    pub selector: Option<String>,
}

/// Decrypt a .age file and write plaintext
///
/// # Errors
///
/// Returns [`GitvaultError`] if the identity cannot be loaded, the input file cannot
/// be read, decryption fails, or the output path is outside the repository root.
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
                Some(load_identity_from_source_with_selector(
                    source,
                    opts.selector.as_deref(),
                ))
            } else {
                None
            }
        })
        .unwrap_or_else(|| load_identity_with_selector(None, opts.selector.as_deref()))?;

    let input_path = PathBuf::from(&opts.file);
    let any_identity = crypto::parse_identity_any(&identity_str)?;
    let identity = any_identity.as_identity();
    let repo_root = crate::repo::find_repo_root()?;

    // REQ-6: value-only mode: decrypt each VALUE in a .env file individually
    if opts.value_only {
        use crate::structured::decrypt_env_values;
        use std::io::Write;
        let content = std::fs::read_to_string(&input_path).map_err(GitvaultError::Io)?;
        let decrypted = decrypt_env_values(&content, identity)?;
        if opts.reveal {
            print!("{decrypted}");
            return Ok(CommandOutcome::Success);
        }
        let out_path = resolve_output_path(&repo_root, &input_path, opts.output.as_deref())?;
        repo::validate_write_path(&repo_root, &out_path)?;
        if let Some(parent) = out_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
        }
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
        structured::decrypt_fields(&input_path, &fields, identity)
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
        crypto::decrypt_stream(identity, in_file, &mut stdout)?;
        return Ok(CommandOutcome::Success);
    }

    let out_path = resolve_output_path(&repo_root, &input_path, opts.output.as_deref())?;

    // REQ-42: prevent path traversal
    repo::validate_write_path(&repo_root, &out_path)?;

    if let Some(parent) = out_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }

    // REQ-51: streaming decryption
    let tmp = tempfile::NamedTempFile::new_in(
        out_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    )?;
    {
        let in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::decrypt_stream(identity, in_file, &mut out_file)?;
    }
    tmp.persist(&out_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    crate::output::output_success(&format!("Decrypted to {}", out_path.display()), opts.json);
    Ok(CommandOutcome::Success)
}

fn resolve_output_path(
    repo_root: &std::path::Path,
    input_path: &std::path::Path,
    output: Option<&str>,
) -> Result<PathBuf, GitvaultError> {
    match output {
        Some(crate::cli::OUTPUT_KEEP_PATH_SENTINEL) => {
            let abs_input = if input_path.is_absolute() {
                input_path.to_path_buf()
            } else {
                std::env::current_dir()?.join(input_path)
            };

            let canonical_repo_root = repo_root
                .canonicalize()
                .unwrap_or_else(|_| repo_root.to_path_buf());
            let canonical_input = abs_input
                .canonicalize()
                .unwrap_or_else(|_| abs_input.clone());

            let rel_input = canonical_input
                .strip_prefix(&canonical_repo_root)
                .or_else(|_| abs_input.strip_prefix(repo_root))
                .map_err(|_| {
                    GitvaultError::Usage(format!(
                        "--output without value requires encrypted input under repository root: {}",
                        input_path.display()
                    ))
                })?;

            let mut components = rel_input.components();
            let first = components
                .next()
                .and_then(|c| c.as_os_str().to_str())
                .unwrap_or_default();
            let _env = components
                .next()
                .and_then(|c| c.as_os_str().to_str())
                .unwrap_or_default();
            if first != "secrets" {
                return Err(GitvaultError::Usage(
                    "--output without value expects encrypted input under secrets/<env>/..."
                        .to_string(),
                ));
            }

            let rest = components.collect::<PathBuf>();
            let name = rest.file_name().ok_or_else(|| {
                GitvaultError::Usage(format!("path has no file name: {}", input_path.display()))
            })?;
            let name = name.to_string_lossy();
            let out_name = name.strip_suffix(".age").unwrap_or(&name).to_string();

            let mut out_path = repo_root.to_path_buf();
            if let Some(parent) = rest.parent()
                && !parent.as_os_str().is_empty()
            {
                out_path = out_path.join(parent);
            }
            Ok(out_path.join(out_name))
        }
        Some(out) => Ok(PathBuf::from(out)),
        None => {
            let name = input_path
                .file_name()
                .ok_or_else(|| {
                    GitvaultError::Usage(format!("path has no file name: {}", input_path.display()))
                })?
                .to_string_lossy();
            let out_name = name.strip_suffix(".age").unwrap_or(&name).to_string();
            Ok(input_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(out_name))
        }
    }
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
            selector: None,
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
            selector: None,
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
                None,
                false,
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
                selector: None,
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
                false,
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
            selector: None,
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
                false,
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
            selector: None,
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
                false,
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
            selector: None,
        })
        .expect("value_only decrypt to explicit output should succeed");

        let content = std::fs::read_to_string(&out_file).unwrap();
        assert_eq!(
            content, "DB_PASS=hunter2\n",
            "decrypted output should match original"
        );
    }

    #[test]
    fn test_cmd_decrypt_bare_output_restores_repo_relative_path() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let nested = dir.path().join("service/api/v1/config");
        std::fs::create_dir_all(&nested).unwrap();
        let plain_file = nested.join("app.env");
        std::fs::write(&plain_file, "KEY=VALUE\n").unwrap();

        with_identity_env(identity_file.path(), || {
            crate::commands::encrypt::cmd_encrypt(
                plain_file.to_string_lossy().to_string(),
                vec![identity.to_public().to_string()],
                None,
                true,
                None,
                false,
                false,
            )
            .expect("keep-path encrypt should succeed");
        });

        std::fs::remove_file(&plain_file).unwrap();
        let encrypted = dir
            .path()
            .join("secrets/dev/service/api/v1/config/app.env.age");

        cmd_decrypt(DecryptOptions {
            file: encrypted.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: Some(crate::cli::OUTPUT_KEEP_PATH_SENTINEL.to_string()),
            fields: None,
            reveal: false,
            value_only: false,
            json: false,
            no_prompt: true,
            selector: None,
        })
        .expect("decrypt with bare --output should succeed");

        let restored =
            std::fs::read_to_string(dir.path().join("service/api/v1/config/app.env")).unwrap();
        assert!(restored.contains("KEY=VALUE"));
    }

    /// Covers lines 170-174: `strip_prefix` error when encrypted file is outside the repo.
    #[test]
    fn test_resolve_output_path_sentinel_outside_repo_errors() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Encrypt a file that's outside the repo root (use absolute path of /tmp/...)
        let outside = tempfile::NamedTempFile::new().unwrap();
        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(identity.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext = crate::crypto::encrypt(recipients, b"secret\n").unwrap();
        std::fs::write(outside.path(), ciphertext).unwrap();

        // --output without value (sentinel) requires input to be under repo root → error.
        let err = cmd_decrypt(DecryptOptions {
            file: outside.path().to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: Some(crate::cli::OUTPUT_KEEP_PATH_SENTINEL.to_string()),
            fields: None,
            reveal: false,
            value_only: false,
            json: false,
            no_prompt: true,
            selector: None,
        })
        .expect_err("decrypt with sentinel outside repo should fail");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error for out-of-repo input, got: {err:?}"
        );
    }

    /// Covers lines 186-189: first component != "secrets" with sentinel output.
    #[test]
    fn test_resolve_output_path_sentinel_not_under_secrets_errors() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Put an encrypted file directly under the repo root (not under secrets/).
        let enc_file = dir.path().join("myfile.age");
        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(identity.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext = crate::crypto::encrypt(recipients, b"data\n").unwrap();
        std::fs::write(&enc_file, ciphertext).unwrap();

        // --output without value with input NOT under secrets/<env>/ → error
        let err = cmd_decrypt(DecryptOptions {
            file: enc_file.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: Some(crate::cli::OUTPUT_KEEP_PATH_SENTINEL.to_string()),
            fields: None,
            reveal: false,
            value_only: false,
            json: false,
            no_prompt: true,
            selector: None,
        })
        .expect_err("decrypt with sentinel outside secrets/ should fail");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error for non-secrets input path, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("secrets"),
            "error should mention secrets/<env>/: {msg}"
        );
    }

    /// Covers line 84: `create_dir_all(parent)` when `value_only` output path parent doesn't exist.
    #[test]
    fn test_cmd_decrypt_value_only_output_creates_missing_parent_dir() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Create and value-only-encrypt the source file
        let env_file = dir.path().join("values.env");
        std::fs::write(&env_file, "SECRET=abc\n").unwrap();
        with_identity_env(identity_file.path(), || {
            crate::commands::encrypt::cmd_encrypt(
                env_file.to_string_lossy().to_string(),
                vec![identity.to_public().to_string()],
                None,
                false,
                None,
                true, // value_only
                false,
            )
            .expect("value-only encrypt should succeed");
        });

        // Output to a non-existent subdirectory; cmd_decrypt must create it
        let out_file = dir.path().join("newsubdir/decrypted.env");
        cmd_decrypt(DecryptOptions {
            file: env_file.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            output: Some(out_file.to_string_lossy().to_string()),
            fields: None,
            reveal: false,
            value_only: true,
            json: false,
            no_prompt: true,
            selector: None,
        })
        .expect("value_only decrypt to new subdir should succeed");

        assert!(out_file.exists(), "output file should be created");
        let content = std::fs::read_to_string(&out_file).unwrap();
        assert_eq!(content, "SECRET=abc\n");
    }
}
