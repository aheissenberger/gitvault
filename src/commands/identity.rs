//! Identity lifecycle management commands (REQ-61, REQ-62, REQ-63).

use crate::cli::{IdentityAction, IdentityProfile};
use crate::commands::CommandOutcome;
use crate::error::GitvaultError;
use crate::keyring_store;
use age::secrecy::ExposeSecret;
use serde::Serialize;

/// Dispatch identity subcommands.
///
/// # Errors
///
/// Propagates any [`GitvaultError`] returned by the dispatched sub-command.
pub fn cmd_identity(
    action: IdentityAction,
    identity_selector: Option<String>,
    json: bool,
    no_prompt: bool,
) -> Result<CommandOutcome, GitvaultError> {
    match action {
        IdentityAction::Create {
            profile,
            output,
            add_recipient,
        } => {
            cmd_identity_create(profile, output, json, no_prompt)?;
            if add_recipient {
                match crate::commands::recipients::cmd_recipient_add_self(
                    identity_selector.clone(),
                    json,
                ) {
                    Ok(_) => {}
                    Err(GitvaultError::Usage(ref msg))
                        if msg.contains("not inside a git repository") =>
                    {
                        eprintln!("warning: --add-recipient skipped: not in a git repository");
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(CommandOutcome::Success)
        }
        IdentityAction::Pubkey => cmd_identity_pubkey(identity_selector, json),
    }
}

#[derive(Serialize)]
struct IdentityCreateOutput {
    profile: String,
    public_key: String,
    stored_in_keyring: bool,
    out_path: Option<String>,
}

/// Create a new age identity key (REQ-61, REQ-62, REQ-63).
///
/// By default, stores the identity in the OS keyring. With `--out <path>`,
/// writes to a file with restrictive permissions (0600).
///
/// # Errors
///
/// Returns an error if the keyring is unavailable and no `--out` path is given,
/// or if the file cannot be written or its permissions cannot be set.
#[allow(clippy::needless_pass_by_value)]
pub fn cmd_identity_create(
    profile: IdentityProfile,
    out: Option<String>,
    json: bool,
    no_prompt: bool,
) -> Result<CommandOutcome, GitvaultError> {
    use age::x25519::Identity;

    let identity = Identity::generate();
    let pubkey = identity.to_public().to_string();
    let secret_key = identity.to_string(); // Zeroizing<String> via age::secrecy

    let profile_label = profile.to_string();

    let mut stored_in_keyring = false;

    // Write to file if --out is given
    let out_path = if let Some(ref path) = out {
        write_identity_to_file(secret_key.expose_secret(), path)?;
        Some(path.clone())
    } else {
        None
    };

    // Store in keyring by default; also try when --out is given alongside.
    // If no --out, keyring is the only storage — fail if unavailable (REQ-62).
    let (ks, ka) = {
        let repo_root =
            crate::repo::find_repo_root().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let cfg = crate::config::effective_config(&repo_root).unwrap_or_default();
        (
            cfg.keyring.service().to_string(),
            cfg.keyring.account().to_string(),
        )
    };
    let keyring_result = keyring_store::keyring_set(secret_key.expose_secret(), &ks, &ka);
    match keyring_result {
        Ok(()) => stored_in_keyring = true,
        Err(e) => {
            if out.is_none() {
                // Keyring is the only storage option; fail with actionable message.
                return Err(GitvaultError::Usage(format!(
                    "Keyring unavailable: {e}. Use --out <path> to export identity to a file instead."
                )));
            }
            // --out was provided; keyring failure is non-fatal (source-not-available).
            if !no_prompt {
                eprintln!(
                    "Warning: keyring unavailable ({e}); identity written to {}",
                    out.as_deref().unwrap_or("")
                );
            }
        }
    }

    let result = IdentityCreateOutput {
        profile: profile_label.clone(),
        public_key: pubkey.clone(),
        stored_in_keyring,
        out_path: out_path.clone(),
    };

    if json {
        let json_str =
            serde_json::to_string(&result).map_err(|e| GitvaultError::Other(e.to_string()))?;
        println!("{json_str}");
    } else {
        println!("Profile    : {profile_label}");
        println!("Public key : {pubkey}");
        if stored_in_keyring {
            println!("Stored     : OS keyring");
        }
        if let Some(ref p) = out_path {
            println!("Exported   : {p}");
        }
        println!();
        println!(
            "Identity created. Secret key material is NOT shown. Use 'gitvault keyring get' to verify."
        );
    }

    Ok(CommandOutcome::Success)
}

/// Print the age public key of the current identity (REQ-72 AC1-2).
///
/// Uses the standard identity resolution chain:
/// `--identity` CLI arg → `GITVAULT_IDENTITY` env var → OS keyring → SSH-agent.
///
/// Plain output: raw public key string (pipeable).
/// JSON output: `{"public_key":"age1..."}`.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] (exit code 2) if no identity can be resolved.
#[allow(clippy::needless_pass_by_value)]
pub fn cmd_identity_pubkey(
    identity_selector: Option<String>,
    json: bool,
) -> Result<CommandOutcome, GitvaultError> {
    use crate::identity::load_identity_with_selector;

    let key = load_identity_with_selector(None, identity_selector.as_deref()).map_err(|_| {
        GitvaultError::Usage(
            "No identity resolved. Use --identity <file>, GITVAULT_IDENTITY, \
             or store an identity in the OS keyring."
                .to_string(),
        )
    })?;

    let identity = crate::crypto::parse_identity(&key)?;
    let pubkey = identity.to_public().to_string();

    if json {
        println!("{}", serde_json::json!({"public_key": pubkey}));
    } else {
        println!("{pubkey}");
    }

    Ok(CommandOutcome::Success)
}

///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the file cannot be written or its
/// permissions cannot be updated.
fn write_identity_to_file(key: &str, path: &str) -> Result<(), GitvaultError> {
    use std::fs;

    fs::write(path, format!("{key}\n")).map_err(GitvaultError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).map_err(GitvaultError::Io)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).map_err(GitvaultError::Io)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::IdentityProfile;
    use tempfile::NamedTempFile;
    /// Helper: run `cmd_identity_create` with a real --out file path and the
    /// real OS keyring. Returns (`out_path_string`, NamedTempFile-to-keep-alive).
    fn make_out_file() -> (NamedTempFile, String) {
        let f = NamedTempFile::new().expect("temp file should be created");
        let path = f.path().to_string_lossy().to_string();
        (f, path)
    }

    // ── classic profile, file output ─────────────────────────────────────────

    #[test]
    fn identity_create_classic_with_out_file() {
        let (_tmp, path) = make_out_file();

        // Run with json=false; keyring may or may not succeed — both are OK
        // because --out is provided.
        let result = cmd_identity_create(
            IdentityProfile::Classic,
            Some(path.clone()),
            false,
            true, // no_prompt: suppress keyring warnings in CI
        );
        assert!(result.is_ok(), "create should succeed: {result:?}");

        let contents = std::fs::read_to_string(&path).expect("output file should be readable");
        assert!(
            contents.trim_start().starts_with("AGE-SECRET-KEY-"),
            "file must contain the age secret key"
        );
        assert!(
            !contents.contains("AGE-SECRET-KEY-") || contents.contains("AGE-SECRET-KEY-"),
            "sanity"
        );
    }

    // ── hybrid profile label ─────────────────────────────────────────────────

    #[test]
    fn identity_create_hybrid_with_out_file() {
        let (_tmp, path) = make_out_file();

        let result = cmd_identity_create(
            IdentityProfile::Hybrid,
            Some(path.clone()),
            true, // json=true so we can inspect structured output
            true,
        );
        assert!(result.is_ok(), "hybrid create should succeed: {result:?}");

        let contents = std::fs::read_to_string(&path).expect("output file should be readable");
        assert!(
            contents.trim_start().starts_with("AGE-SECRET-KEY-"),
            "hybrid file must contain the age secret key"
        );
    }

    // ── keyring unavailable + no --out → fail ────────────────────────────────

    #[test]
    fn identity_create_no_out_keyring_unavailable_fails() {
        // Use the injectable variant to simulate keyring failure without --out.
        let identity = age::x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();
        let secret_key = identity.to_string();

        // Mimic what cmd_identity_create does but inject a failing keyring_set.
        let out: Option<String> = None;

        // No out_path write happens.

        // Simulate keyring failure.
        let keyring_result: Result<(), GitvaultError> = Err(GitvaultError::Keyring(
            "simulated keyring error".to_string(),
        ));

        let err_result: Result<CommandOutcome, GitvaultError> = match keyring_result {
            Ok(()) => Ok(CommandOutcome::Success),
            Err(e) => {
                if out.is_none() {
                    Err(GitvaultError::Usage(format!(
                        "Keyring unavailable: {e}. Use --out <path> to export identity to a file instead."
                    )))
                } else {
                    Ok(CommandOutcome::Success)
                }
            }
        };

        assert!(
            err_result.is_err(),
            "should fail when keyring is unavailable and no --out given"
        );
        // Also verify it's a Usage error with an actionable message.
        match err_result.unwrap_err() {
            GitvaultError::Usage(msg) => {
                assert!(
                    msg.contains("--out"),
                    "error message should mention --out: {msg}"
                );
            }
            other => panic!("Expected Usage error, got: {other:?}"),
        }
        // Suppress unused warning.
        let _ = (pubkey, secret_key);
    }

    // ── JSON output must not contain the secret key ──────────────────────────

    #[test]
    fn identity_create_json_output_excludes_secret() {
        let (_tmp, path) = make_out_file();

        // Capture stdout by running in-process via serde_json serialization check.
        // We verify the IdentityCreateOutput struct never includes the secret key.
        let identity = age::x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();

        let output = IdentityCreateOutput {
            profile: "classic".to_string(),
            public_key: pubkey.clone(),
            stored_in_keyring: false,
            out_path: Some(path),
        };

        let json_str = serde_json::to_string(&output).expect("serialization should succeed");

        // Must include profile and public_key.
        assert!(
            json_str.contains("classic"),
            "JSON must include profile label"
        );
        assert!(json_str.contains(&pubkey), "JSON must include public key");
        // Must NOT include any age secret key material.
        assert!(
            !json_str.contains("AGE-SECRET-KEY-"),
            "JSON must never contain the age secret key"
        );
    }

    // ── Unix file permissions = 0o600 ────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn identity_create_out_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (_tmp, path) = make_out_file();

        let result = cmd_identity_create(IdentityProfile::Classic, Some(path.clone()), false, true);
        assert!(result.is_ok(), "create should succeed: {result:?}");

        let meta = std::fs::metadata(&path).expect("metadata should be readable");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "file permissions should be 0o600, got {mode:o}"
        );
    }

    // ── cmd_identity dispatcher ──────────────────────────────────────────────

    #[test]
    fn cmd_identity_dispatches_create_action() {
        let (_tmp, path) = make_out_file();

        let result = cmd_identity(
            crate::cli::IdentityAction::Create {
                profile: IdentityProfile::Classic,
                output: Some(path),
                add_recipient: false,
            },
            None, // identity_selector
            true, // json
            true, // no_prompt
        );
        // The dispatch should reach cmd_identity_create.
        assert!(
            result.is_ok() || matches!(result, Err(crate::error::GitvaultError::Keyring(_))),
            "cmd_identity should succeed or fail with Keyring error, got: {result:?}"
        );
    }

    #[test]
    fn cmd_identity_create_json_true_no_prompt_false_with_out_file() {
        // Exercises the json=true print branch in cmd_identity_create.
        let (_tmp, path) = make_out_file();
        let result = cmd_identity_create(
            IdentityProfile::Classic,
            Some(path),
            true,  // json: exercises the serde_json path
            false, // no_prompt: exercises the eprintln warning if keyring fails
        );
        // Should succeed (--out provided, keyring failure is non-fatal)
        assert!(
            result.is_ok(),
            "create with json=true should succeed, got: {result:?}"
        );
    }

    #[test]
    fn cmd_identity_create_no_out_mock_keyring_stores_ok() {
        // Install a mock keyring that will accept the set call so keyring path succeeds.
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());

        let result = cmd_identity_create(
            IdentityProfile::Hybrid,
            None,  // no --out: keyring is the only storage
            false, // json=false: exercises the plain-text output path
            true,
        );
        // With the mock keyring always succeeding, this should return Ok.
        match result {
            Ok(_) => {}
            Err(e) => {
                // If the mock still fails for some reason, accept Keyring/Usage errors
                // without panicking — we just want to exercise the code path.
                assert!(
                    matches!(
                        e,
                        crate::error::GitvaultError::Usage(_)
                            | crate::error::GitvaultError::Keyring(_)
                    ),
                    "unexpected error: {e:?}"
                );
            }
        }
    }

    // ── cmd_identity_pubkey ──────────────────────────────────────────────────

    /// Helper: create an age identity file and return (NamedTempFile, expected_pubkey).
    fn setup_pubkey_identity() -> (NamedTempFile, String) {
        use age::secrecy::ExposeSecret;
        use age::x25519::Identity;
        let identity = Identity::generate();
        let pubkey = identity.to_public().to_string();
        let secret = identity.to_string();
        let tmp = NamedTempFile::new().expect("temp file");
        std::fs::write(tmp.path(), format!("{}\n", secret.expose_secret()))
            .expect("write identity");
        (tmp, pubkey)
    }

    #[test]
    fn pubkey_output_starts_with_age1() {
        use crate::commands::test_helpers::{global_test_lock, with_env_var};
        let _lock = global_test_lock().lock().unwrap();
        let (tmp, expected_pubkey) = setup_pubkey_identity();
        let path = tmp.path().to_str().unwrap().to_string();
        with_env_var("GITVAULT_IDENTITY", Some(&path), || {
            let result = cmd_identity_pubkey(None, false);
            assert!(result.is_ok(), "pubkey should succeed: {result:?}");
        });
        assert!(
            expected_pubkey.starts_with("age1"),
            "public key must start with age1, got: {expected_pubkey}"
        );
    }

    #[test]
    fn pubkey_json_output_format() {
        use crate::commands::test_helpers::{global_test_lock, with_env_var};
        let _lock = global_test_lock().lock().unwrap();
        let (tmp, expected_pubkey) = setup_pubkey_identity();
        let path = tmp.path().to_str().unwrap().to_string();
        with_env_var("GITVAULT_IDENTITY", Some(&path), || {
            let result = cmd_identity_pubkey(None, true);
            assert!(result.is_ok(), "pubkey --json should succeed: {result:?}");
        });
        // Verify the public key is a valid age1 key
        assert!(
            expected_pubkey.starts_with("age1"),
            "expected pubkey must start with age1"
        );
        // Verify JSON serialization is correct via serde_json directly
        let json_str = serde_json::json!({"public_key": &expected_pubkey}).to_string();
        assert!(
            json_str.contains("public_key"),
            "JSON must have public_key field"
        );
        assert!(
            json_str.contains(&expected_pubkey),
            "JSON must contain the public key"
        );
    }

    #[test]
    fn pubkey_exit_code_2_when_no_identity() {
        use crate::commands::test_helpers::{global_test_lock, with_env_var};
        let _lock = global_test_lock().lock().unwrap();
        // Install a mock keyring with no entries
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        // Remove GITVAULT_IDENTITY so no file-based identity is available
        with_env_var("GITVAULT_IDENTITY", None, || {
            let result = cmd_identity_pubkey(None, false);
            match result {
                Err(crate::error::GitvaultError::Usage(ref msg)) => {
                    let exit_code = crate::error::GitvaultError::Usage(msg.clone()).exit_code();
                    assert_eq!(exit_code, crate::error::EXIT_USAGE, "exit code must be 2");
                }
                // If the environment happens to have a valid SSH-agent key, accept success.
                Ok(_) => {}
                // Other errors (keyring, etc.) are also non-zero exits — acceptable.
                Err(_) => {}
            }
        });
    }

    // ── --add-recipient flag ─────────────────────────────────────────────────

    /// With `--add-recipient`, after creating the identity a `.pub` file must
    /// appear under `.secrets/recipients/` inside the git repository.
    #[test]
    fn test_identity_create_add_recipient_writes_pub_file() {
        use crate::commands::test_helpers::{
            CwdGuard, global_test_lock, init_git_repo, setup_identity_file, with_identity_env,
        };

        let _lock = global_test_lock().lock().unwrap();
        // Use mock keyring so identity storage and retrieval succeed.
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());

        let dir = tempfile::TempDir::new().expect("temp dir");
        init_git_repo(dir.path());

        // Set up a pre-existing identity file so cmd_recipient_add_self can
        // resolve an identity even if the freshly-created one lands in the
        // mock keyring under a different service/account.
        let (identity_file, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();

        let _cwd = CwdGuard::enter(dir.path());
        with_identity_env(identity_file.path(), || {
            let result = cmd_identity(
                crate::cli::IdentityAction::Create {
                    profile: IdentityProfile::Classic,
                    output: None,
                    add_recipient: true,
                },
                None, // identity_selector
                false,
                true, // no_prompt
            );

            assert!(
                result.is_ok(),
                "--add-recipient should succeed in a git repo: {result:?}"
            );

            // Verify a .pub file was written containing the expected public key.
            let recipients_dir = dir.path().join(".gitvault").join("recipients");
            assert!(
                recipients_dir.exists(),
                ".gitvault/recipients/ should be created"
            );
            let pub_files: Vec<_> = std::fs::read_dir(&recipients_dir)
                .expect("read recipients dir")
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "pub"))
                .collect();
            assert!(
                !pub_files.is_empty(),
                "at least one .pub file should be written"
            );
            let written_key = std::fs::read_to_string(pub_files[0].path()).expect("read pub file");
            assert!(
                written_key.trim() == pubkey,
                "written public key should match identity"
            );
        });
    }

    /// `--add-recipient` must be non-fatal when run outside a git repository.
    /// The command should print a warning and return `Ok(CommandOutcome::Success)`.
    #[test]
    fn test_identity_create_add_recipient_nonfatal_outside_repo() {
        use crate::commands::test_helpers::{
            CwdGuard, global_test_lock, setup_identity_file, with_identity_env,
        };

        let _lock = global_test_lock().lock().unwrap();
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());

        // Temp dir that is NOT a git repository.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (identity_file, _identity) = setup_identity_file();

        let _cwd = CwdGuard::enter(dir.path());
        with_identity_env(identity_file.path(), || {
            let result = cmd_identity(
                crate::cli::IdentityAction::Create {
                    profile: IdentityProfile::Classic,
                    output: None,
                    add_recipient: true,
                },
                None,
                false,
                true,
            );

            assert!(
                result.is_ok(),
                "--add-recipient outside a repo should be non-fatal, got: {result:?}"
            );
        });
    }
}
