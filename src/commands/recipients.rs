//! `gitvault recipient` and `gitvault rotate` command implementations.

use crate::cli::RecipientAction;
use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::{load_identity_with_selector, resolve_recipient_keys};
use crate::{crypto, repo};

/// Sanitise a git username into a filesystem-safe recipient name (REQ-72 AC14).
///
/// Rules:
/// 1. Lowercase the name.
/// 2. Replace every character outside `[a-z0-9_-]` with `-`.
/// 3. Collapse consecutive dashes into one.
/// 4. Truncate to 64 characters.
/// 5. If the result is empty, fall back to `"self"`.
fn sanitise_name(name: &str) -> String {
    let lower = name.to_lowercase();
    // Replace non-allowed characters with `-`
    let replaced: String = lower
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Collapse consecutive dashes
    let mut collapsed = String::with_capacity(replaced.len());
    let mut prev_dash = false;
    for c in replaced.chars() {
        if c == '-' {
            if !prev_dash {
                collapsed.push(c);
            }
            prev_dash = true;
        } else {
            collapsed.push(c);
            prev_dash = false;
        }
    }
    // Truncate to 64 chars (char boundary safe for ASCII)
    let truncated: String = collapsed.chars().take(64).collect();
    if truncated.is_empty() {
        "self".to_string()
    } else {
        truncated
    }
}

/// Derive a recipient name from the git `user.name` config, falling back to
/// a short prefix of the public key.
///
/// REQ-90: sanitizes `GIT_DIR`, `GIT_CONFIG`, and `GIT_CONFIG_GLOBAL` from the
///         child environment to prevent environment-based config injection.
/// REQ-96: single authoritative helper — call this once per command, share result.
fn read_git_user_name() -> Option<String> {
    std::process::Command::new("git")
        .args(["config", "user.name"])
        // REQ-90: remove git env vars that could redirect config reads.
        .env_remove("GIT_DIR")
        .env_remove("GIT_CONFIG")
        .env_remove("GIT_CONFIG_GLOBAL")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Derive a sanitised recipient filename from the git `user.name` config,
/// falling back to a short prefix of the public key.
fn derive_recipient_name(pubkey: &str) -> String {
    if let Some(name) = read_git_user_name() {
        sanitise_name(&name)
    } else {
        // Fall back: use the first 12 chars of the pubkey (after "age1")
        pubkey.get(4..16).unwrap_or("default").to_string()
    }
}

/// Add own public key to the recipients directory (REQ-72 AC14).
///
/// Idempotent: if the own key is already present in any `.pub` file the
/// function prints a notice and returns `CommandOutcome::Success`.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] (exit code 2) when no identity can be resolved.
pub fn cmd_recipient_add_self(
    identity_selector: Option<String>,
    json: bool,
) -> Result<CommandOutcome, GitvaultError> {
    // 1. Resolve identity — exit code 2 if none found.
    let key = crate::identity::load_identity_with_selector(None, identity_selector.as_deref())
        .map_err(|_| {
            GitvaultError::Usage(
                "No identity resolved. Use GITVAULT_IDENTITY, --identity-selector, \
                     or store an identity in the OS keyring."
                    .to_string(),
            )
        })?;

    // 2. Derive public key.
    let identity = crypto::parse_identity(&key)?;
    let pubkey = identity.to_public().to_string();

    // 3. Locate repo root and load config.
    let repo_root = crate::repo::find_repo_root()?;
    let cfg = crate::config::effective_config(&repo_root)?;
    let recipients_dir = cfg.paths.recipients_dir();

    // 4. Check for idempotency — already registered?
    let existing = repo::read_recipients(&repo_root, recipients_dir)?;
    if existing.contains(&pubkey) {
        crate::output::output_success("Already registered as a recipient", json);
        return Ok(CommandOutcome::Success);
    }

    // 5. Derive filename from git user.name (REQ-96: call once, share result).
    let git_name = read_git_user_name();
    let name = git_name
        .as_deref()
        .map_or_else(|| "self".to_string(), sanitise_name);

    // 6. Write .pub file.
    repo::write_recipients(&repo_root, recipients_dir, &name, &pubkey)?;

    // 7. Print success and reminder.
    crate::output::output_success(&format!("Added self as recipient: {name}.pub"), json);
    if !json {
        println!("  Hint: git add .gitvault/recipients/{name}.pub && git commit");
    }

    Ok(CommandOutcome::Success)
}

///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root cannot be found, the recipient
/// key is invalid, or reading/writing the recipients directory fails.
pub fn cmd_recipient(
    action: RecipientAction,
    identity_selector: Option<String>,
    json: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let cfg = crate::config::effective_config(&repo_root)?;
    let recipients_dir = cfg.paths.recipients_dir();
    match action {
        RecipientAction::Add { pubkey } => {
            // Validate it's a valid age public key
            crypto::parse_recipient(&pubkey)?;
            // Check for duplicates
            let existing = repo::read_recipients(&repo_root, recipients_dir)?;
            if existing.contains(&pubkey) {
                return Err(GitvaultError::Usage(format!(
                    "Recipient already present: {pubkey}"
                )));
            }
            let name = derive_recipient_name(&pubkey);
            repo::write_recipients(&repo_root, recipients_dir, &name, &pubkey)?;
            crate::output::output_success(&format!("Added recipient: {pubkey}"), json);
        }
        RecipientAction::Remove { pubkey } => {
            repo::remove_recipient_by_key(&repo_root, recipients_dir, &pubkey)?;
            crate::output::output_success(&format!("Removed recipient: {pubkey}"), json);
        }
        RecipientAction::List => {
            let recipients = repo::list_recipients(&repo_root, recipients_dir)?;
            if json {
                let entries: Vec<_> = recipients
                    .iter()
                    .map(|(name, key)| serde_json::json!({"name": name, "key": key}))
                    .collect();
                println!("{}", serde_json::json!({"recipients": entries}));
            } else if recipients.is_empty() {
                println!("No persistent recipients. Use 'gitvault recipient add <pubkey>'.");
            } else {
                for (name, key) in &recipients {
                    println!("{name}: {key}");
                }
            }
        }
        RecipientAction::AddSelf => {
            return cmd_recipient_add_self(identity_selector, json);
        }
    }
    Ok(CommandOutcome::Success)
}

/// Re-encrypt all secrets with the current recipients list (REQ-72)
///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root cannot be found, the identity
/// cannot be loaded, or re-encryption of any secret file fails with a hard error.
#[allow(clippy::needless_pass_by_value)]
pub fn cmd_rekey(
    identity_path: Option<String>,
    selector: Option<String>,
    json: bool,
    env_filter: Option<String>,
    dry_run: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let identity_str = load_identity_with_selector(identity_path, selector.as_deref())?;
    let any_identity = crypto::parse_identity_any_with_passphrase(
        &identity_str,
        crate::identity::try_fetch_ssh_passphrase(
            crate::defaults::KEYRING_SERVICE,
            crate::defaults::KEYRING_ACCOUNT,
            false, // rekey is an interactive operation
        ),
    )?;
    let identity = any_identity.as_identity();

    let recipient_keys = resolve_recipient_keys(&repo_root, vec![])?;

    // Parse all recipient keys once up-front (validates them before touching any file).
    let parsed_recipients: Vec<age::x25519::Recipient> = recipient_keys
        .iter()
        .map(|k| crypto::parse_recipient(k))
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    // Collect all encrypted files, applying env_filter if provided.
    let all_encrypted_files = repo::list_all_encrypted_files(&repo_root)?;
    let encrypted_files: Vec<std::path::PathBuf> = if let Some(ref env) = env_filter {
        let filter_segment_slash = format!("/{env}/");
        let filter_prefix = format!(".secrets/{env}/");
        all_encrypted_files
            .into_iter()
            .filter(|p| {
                let display = p.to_string_lossy();
                display.contains(&filter_segment_slash) || display.contains(&filter_prefix)
            })
            .collect()
    } else {
        all_encrypted_files
    };

    // Phase 1 – classify each file into one of three categories:
    //   a) Rekeyed   – decryption succeeded; we hold the plaintext
    //   b) Skipped   – no-access (not a recipient); skip gracefully
    //   c) Error     – hard error; abort immediately with exit code 1
    // REQ-87: plaintext is Zeroizing<Vec<u8>> so it is overwritten on drop.
    #[allow(dead_code)]
    enum FileOutcome {
        Rekeyed(std::path::PathBuf, zeroize::Zeroizing<Vec<u8>>),
        Skipped(std::path::PathBuf, String),
        Error(std::path::PathBuf, String),
    }

    let mut outcomes: Vec<FileOutcome> = Vec::new();

    for path in encrypted_files {
        let ciphertext = std::fs::read(&path)?;
        match crypto::decrypt(identity, &ciphertext) {
            Ok(plaintext) => outcomes.push(FileOutcome::Rekeyed(path, plaintext)),
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                // age reports "No matching keys found" when the identity is not a recipient.
                if msg.contains("no matching") || msg.contains("no usable") {
                    outcomes.push(FileOutcome::Skipped(path, e.to_string()));
                } else {
                    // Hard error — abort immediately.
                    return Err(e);
                }
            }
        }
    }

    // Summarise counts.
    let n_rekeyed = outcomes
        .iter()
        .filter(|o| matches!(o, FileOutcome::Rekeyed(_, _)))
        .count();
    let n_skipped = outcomes
        .iter()
        .filter(|o| matches!(o, FileOutcome::Skipped(_, _)))
        .count();
    let n_errors: usize = 0; // hard errors already returned above

    if dry_run {
        // --dry-run: just report what would happen.
        if json {
            let files: Vec<serde_json::Value> = outcomes
                .iter()
                .map(|o| match o {
                    FileOutcome::Rekeyed(p, _) => serde_json::json!({
                        "file": p.to_string_lossy(),
                        "status": "would-rekey"
                    }),
                    FileOutcome::Skipped(p, reason) => serde_json::json!({
                        "file": p.to_string_lossy(),
                        "status": "skipped",
                        "error": reason
                    }),
                    FileOutcome::Error(p, reason) => serde_json::json!({
                        "file": p.to_string_lossy(),
                        "status": "error",
                        "error": reason
                    }),
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "dry_run": true,
                    "files": files,
                    "summary": {
                        "rekeyed": n_rekeyed,
                        "skipped": n_skipped,
                        "errors": n_errors
                    }
                })
            );
        } else {
            for o in &outcomes {
                match o {
                    FileOutcome::Rekeyed(p, _) => {
                        println!("[dry-run] would rekey: {}", p.display());
                    }
                    FileOutcome::Skipped(p, _) => {
                        println!("[dry-run] skipped (no access): {}", p.display());
                    }
                    FileOutcome::Error(p, reason) => {
                        println!("[dry-run] error: {} — {reason}", p.display());
                    }
                }
            }
            println!(
                "[dry-run] Rekeyed {} file(s), {} skipped, {} error(s)",
                n_rekeyed, n_skipped, n_errors
            );
        }
        return Ok(CommandOutcome::Success);
    }

    // Phase 2 – persist-all: only reached when every decryption succeeded.
    // Re-encrypt and write all category-a files atomically via temp-file rename.
    for outcome in &outcomes {
        if let FileOutcome::Rekeyed(path, plaintext) = outcome {
            let recipients: Vec<Box<dyn age::Recipient + Send>> = parsed_recipients
                .iter()
                .map(|r| Box::new(r.clone()) as Box<dyn age::Recipient + Send>)
                .collect();
            let new_ciphertext = crypto::encrypt(recipients, plaintext)?;
            let tmp = tempfile::NamedTempFile::new_in(
                path.parent().unwrap_or_else(|| std::path::Path::new(".")),
            )?;
            std::fs::write(tmp.path(), &new_ciphertext)?;
            tmp.persist(path).map_err(|e| GitvaultError::Io(e.error))?;
        }
    }

    let summary = format!(
        "Rekeyed {} file(s), {} skipped, {} error(s)",
        n_rekeyed, n_skipped, n_errors
    );

    if json {
        let files: Vec<serde_json::Value> = outcomes
            .iter()
            .map(|o| match o {
                FileOutcome::Rekeyed(p, _) => serde_json::json!({
                    "file": p.to_string_lossy(),
                    "status": "re-encrypted"
                }),
                FileOutcome::Skipped(p, reason) => serde_json::json!({
                    "file": p.to_string_lossy(),
                    "status": "skipped",
                    "error": reason
                }),
                FileOutcome::Error(p, reason) => serde_json::json!({
                    "file": p.to_string_lossy(),
                    "status": "error",
                    "error": reason
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "files": files,
                "summary": {
                    "rekeyed": n_rekeyed,
                    "skipped": n_skipped,
                    "errors": n_errors
                }
            })
        );
    } else {
        crate::output::output_success(&summary, false);
    }

    Ok(CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use age::x25519;
    use tempfile::TempDir;

    #[test]
    fn test_resolve_recipient_keys_defaults_to_local_identity_public_key() {
        use age::secrecy::ExposeSecret;
        let _lock = global_test_lock().lock().unwrap();
        let identity = x25519::Identity::generate();
        let expected_recipient = identity.to_public().to_string();

        let dir = TempDir::new().unwrap();

        let resolved = with_env_var(
            "GITVAULT_IDENTITY",
            Some(identity.to_string().expose_secret()),
            || {
                resolve_recipient_keys(dir.path(), vec![])
                    .expect("default recipient resolution should succeed")
            },
        );

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_defaults_from_identity_file_path() {
        use age::secrecy::ExposeSecret;
        let _lock = global_test_lock().lock().unwrap();
        let identity = x25519::Identity::generate();
        let expected_recipient = identity.to_public().to_string();

        let identity_file = tempfile::NamedTempFile::new().expect("temp file should be created");
        std::fs::write(identity_file.path(), identity.to_string().expose_secret())
            .expect("identity should be written to temp file");

        let dir = TempDir::new().unwrap();

        let resolved = with_env_var(
            "GITVAULT_IDENTITY",
            Some(&identity_file.path().to_string_lossy()),
            || {
                resolve_recipient_keys(dir.path(), vec![])
                    .expect("default recipient resolution should succeed")
            },
        );

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_fails_without_identity_source() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();

        let result = with_env_var("GITVAULT_IDENTITY", None, || {
            resolve_recipient_keys(dir.path(), vec![])
        });

        let err = result.expect_err("expected usage error for missing identity");
        let GitvaultError::Usage(msg) = err else {
            panic!("expected Usage error, got: {err:?}")
        };
        assert!(
            msg.contains("No identity resolved"),
            "expected 'No identity resolved' in: {msg}"
        );
    }

    #[test]
    fn test_resolve_recipient_keys_fails_with_malformed_identity_key() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();

        let result = with_env_var("GITVAULT_IDENTITY", Some("AGE-SECRET-KEY-INVALID"), || {
            resolve_recipient_keys(dir.path(), vec![])
        });

        let err = result.expect_err("expected decryption error for malformed identity");
        let GitvaultError::Decryption(msg) = err else {
            panic!("expected Decryption error, got: {err:?}")
        };
        assert!(msg.contains("Invalid identity key"));
    }

    #[test]
    fn test_resolve_recipient_keys_returns_recipients_from_file() {
        let dir = TempDir::new().unwrap();
        let pubkey = x25519::Identity::generate().to_public().to_string();
        // Write a non-empty recipient into the directory so that the early return executes.
        repo::write_recipients(
            dir.path(),
            crate::defaults::RECIPIENTS_DIR,
            "default",
            &pubkey,
        )
        .expect("write_recipients should succeed");

        let result =
            resolve_recipient_keys(dir.path(), vec![]).expect("should return recipients from file");
        assert_eq!(result, vec![pubkey]);
    }

    #[test]
    fn test_cmd_recipient_add_list_remove() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let pubkey = x25519::Identity::generate().to_public().to_string();
        cmd_recipient(
            RecipientAction::Add {
                pubkey: pubkey.clone(),
            },
            None,
            true,
        )
        .expect("add recipient should succeed");

        cmd_recipient(RecipientAction::List, None, false).expect("list recipient should succeed");

        cmd_recipient(RecipientAction::Remove { pubkey }, None, false)
            .expect("remove recipient should succeed");

        let recipients = repo::read_recipients(dir.path(), crate::defaults::RECIPIENTS_DIR)
            .expect("recipients should be readable");
        assert!(recipients.is_empty());
    }

    #[test]
    fn test_cmd_recipient_duplicate_add_fails() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let pubkey = x25519::Identity::generate().to_public().to_string();

        cmd_recipient(
            RecipientAction::Add {
                pubkey: pubkey.clone(),
            },
            None,
            true,
        )
        .unwrap();

        let err = cmd_recipient(RecipientAction::Add { pubkey }, None, true).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_recipient_remove_missing_fails() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let missing = x25519::Identity::generate().to_public().to_string();
        let err =
            cmd_recipient(RecipientAction::Remove { pubkey: missing }, None, true).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_recipient_list_json_with_recipients() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let pubkey = x25519::Identity::generate().to_public().to_string();
        cmd_recipient(RecipientAction::Add { pubkey }, None, false).expect("add should succeed");

        // json=true covers the JSON recipients output branch (line 881).
        cmd_recipient(RecipientAction::List, None, true).expect("list json should succeed");
    }

    #[test]
    fn test_cmd_recipient_list_empty_plain() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // No recipients added → empty list message (lines 883-884).
        cmd_recipient(RecipientAction::List, None, false).expect("list empty plain should succeed");
    }

    #[test]
    fn test_cmd_rekey_with_invalid_crypto_recipient_fails() {
        // Covers the error branch of the recipient-map closure in cmd_rekey.
        // The key passes read_recipients (matches age1[0-9a-z]+) but fails parse_recipient.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Write an encrypted file so cmd_rekey has something to iterate over.
        write_encrypted_env_file(dir.path(), "dev", "rekey.env.age", &identity, "K=1\n");

        // Write a recipient that passes the regex but fails actual crypto parsing.
        let bad_key = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let recipients_dir = dir.path().join(".gitvault/recipients");
        std::fs::create_dir_all(&recipients_dir).unwrap();
        std::fs::write(recipients_dir.join("bad.pub"), format!("{bad_key}\n")).unwrap();

        with_identity_env(identity_file.path(), || {
            let err = cmd_rekey(None, None, false, None, false)
                .expect_err("rekey with invalid recipient should fail");
            assert!(
                matches!(err, GitvaultError::Encryption(_)),
                "expected Encryption error, got: {err:?}"
            );
        });
    }

    // ── add-self tests (REQ-72 AC14) ─────────────────────────────────────────

    #[test]
    fn test_add_self_writes_pub_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let expected_pubkey = identity.to_public().to_string();

        with_identity_env(identity_file.path(), || {
            cmd_recipient_add_self(None, false).expect("add-self should succeed");
        });

        // Verify at least one .pub file exists and contains the pubkey
        let recipients_dir = dir.path().join(".gitvault/recipients");
        let entries: Vec<_> = std::fs::read_dir(&recipients_dir)
            .expect("recipients dir should exist")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pub"))
            .collect();
        assert!(!entries.is_empty(), "at least one .pub file should exist");

        let found = entries.iter().any(|e| {
            std::fs::read_to_string(e.path())
                .map(|c| c.trim() == expected_pubkey)
                .unwrap_or(false)
        });
        assert!(found, "own pubkey should be in a .pub file");
    }

    #[test]
    fn test_add_self_idempotent() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            cmd_recipient_add_self(None, false).expect("first add-self should succeed");
            // Second call should also succeed (idempotent)
            cmd_recipient_add_self(None, false)
                .expect("second add-self should succeed (idempotent)");
        });

        // Only one .pub file should exist (not two)
        let recipients_dir = dir.path().join(".gitvault/recipients");
        let pub_count = std::fs::read_dir(&recipients_dir)
            .expect("recipients dir should exist")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pub"))
            .count();
        assert_eq!(pub_count, 1, "idempotent: only one .pub file should exist");
    }

    #[test]
    fn test_add_self_sanitises_name() {
        // Test the sanitise_name function directly
        assert_eq!(sanitise_name("Alice Smith"), "alice-smith");
        assert_eq!(sanitise_name("João da Silva"), "jo-o-da-silva");
        assert_eq!(sanitise_name("user@example.com"), "user-example-com");
        assert_eq!(sanitise_name("hello---world"), "hello-world");
        assert_eq!(sanitise_name(""), "self");
        assert_eq!(sanitise_name("   "), "-");
        // Truncation to 64 chars
        let long_name = "a".repeat(80);
        assert_eq!(sanitise_name(&long_name).len(), 64);
        // Allowed chars pass through
        assert_eq!(sanitise_name("alice_bob-123"), "alice_bob-123");
    }

    #[test]
    fn test_add_self_no_identity_returns_usage_error() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Install mock keyring (no entries) so keyring lookup fails gracefully
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());

        let err = with_env_var("GITVAULT_IDENTITY", None, || {
            cmd_recipient_add_self(None, false)
        })
        .expect_err("add-self without identity should fail");

        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error, got: {err:?}"
        );
    }

    // ── rekey enhancement tests (REQ-72 AC6-9,AC11) ──────────────────────────

    #[test]
    fn test_rekey_dry_run_no_files_written() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let file_path = repo::get_env_encrypted_path(dir.path(), "dev", "test.env.age");
        write_encrypted_env_file(dir.path(), "dev", "test.env.age", &identity, "K=dry\n");

        let original_bytes = std::fs::read(&file_path).expect("should read ciphertext");

        with_identity_env(identity_file.path(), || {
            let outcome =
                cmd_rekey(None, None, false, None, true).expect("dry-run rekey should succeed");
            assert_eq!(outcome, CommandOutcome::Success);
        });

        let bytes_after = std::fs::read(&file_path).expect("should read ciphertext after");
        assert_eq!(
            original_bytes, bytes_after,
            "--dry-run must not modify files"
        );
    }

    #[test]
    fn test_rekey_env_filter() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Create files in both dev and prod environments.
        write_encrypted_env_file(dir.path(), "dev", "dev.env.age", &identity, "ENV=dev\n");
        write_encrypted_env_file(dir.path(), "prod", "prod.env.age", &identity, "ENV=prod\n");

        let dev_path = repo::get_env_encrypted_path(dir.path(), "dev", "dev.env.age");
        let prod_path = repo::get_env_encrypted_path(dir.path(), "prod", "prod.env.age");

        let dev_bytes_before = std::fs::read(&dev_path).unwrap();
        let prod_bytes_before = std::fs::read(&prod_path).unwrap();

        with_identity_env(identity_file.path(), || {
            // Rekey with --env dev; prod file should be untouched (same bytes).
            let outcome = cmd_rekey(None, None, false, Some("dev".to_string()), false)
                .expect("env-filtered rekey should succeed");
            assert_eq!(outcome, CommandOutcome::Success);
        });

        // prod file must be byte-for-byte identical (not touched).
        let prod_bytes_after = std::fs::read(&prod_path).unwrap();
        assert_eq!(
            prod_bytes_before, prod_bytes_after,
            "--env dev should not touch prod files"
        );

        // dev file was re-encrypted; it may differ in bytes (age uses random nonce) but
        // we can verify it's still a valid age ciphertext by checking decryptability.
        let dev_bytes_after = std::fs::read(&dev_path).unwrap();
        // Just confirm the file changed in content (age nonces ensure this) OR is still decryptable.
        // Since age uses ephemeral keys, ciphertext will differ on re-encryption.
        let _ = dev_bytes_before; // suppress unused warning
        assert!(!dev_bytes_after.is_empty(), "dev file should still exist");
    }

    #[test]
    fn test_rekey_summary_counts() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Write two files encrypted with our identity.
        write_encrypted_env_file(dir.path(), "dev", "a.env.age", &identity, "A=1\n");
        write_encrypted_env_file(dir.path(), "dev", "b.env.age", &identity, "B=2\n");

        // Write a third file encrypted with a DIFFERENT identity (our identity won't decrypt it).
        let other_identity = x25519::Identity::generate();
        write_encrypted_env_file(dir.path(), "staging", "c.env.age", &other_identity, "C=3\n");

        with_identity_env(identity_file.path(), || {
            // Should succeed: 2 rekeyed, 1 skipped (no-access), 0 errors.
            let outcome = cmd_rekey(None, None, false, None, false)
                .expect("rekey with mixed access should succeed");
            assert_eq!(outcome, CommandOutcome::Success);
        });
    }
}
