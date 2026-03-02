//! `gitvault recipient` and `gitvault rotate` command implementations.

use crate::cli::RecipientAction;
use crate::error::GitvaultError;
use crate::identity::{load_identity, resolve_recipient_keys};
use crate::{crypto, repo};

/// Manage persistent recipients (REQ-37)
pub(crate) fn cmd_recipient(action: RecipientAction, json: bool) -> Result<(), GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    match action {
        RecipientAction::Add { pubkey } => {
            // Validate it's a valid age public key
            crypto::parse_recipient(&pubkey)?;
            let mut recipients = repo::read_recipients(&repo_root)?;
            if recipients.contains(&pubkey) {
                return Err(GitvaultError::Usage(format!(
                    "Recipient already present: {pubkey}"
                )));
            }
            recipients.push(pubkey.clone());
            repo::write_recipients(&repo_root, &recipients)?;
            crate::output::output_success(&format!("Added recipient: {pubkey}"), json);
        }
        RecipientAction::Remove { pubkey } => {
            let mut recipients = repo::read_recipients(&repo_root)?;
            let before = recipients.len();
            recipients.retain(|r| r != &pubkey);
            if recipients.len() == before {
                return Err(GitvaultError::Usage(format!(
                    "Recipient not found: {pubkey}"
                )));
            }
            repo::write_recipients(&repo_root, &recipients)?;
            crate::output::output_success(&format!("Removed recipient: {pubkey}"), json);
        }
        RecipientAction::List => {
            let recipients = repo::read_recipients(&repo_root)?;
            if json {
                println!("{}", serde_json::json!({"recipients": recipients}));
            } else if recipients.is_empty() {
                println!("No persistent recipients. Use 'gitvault recipient add <pubkey>'.");
            } else {
                for r in &recipients {
                    println!("{r}");
                }
            }
        }
    }
    Ok(())
}

/// Re-encrypt all secrets with the current recipients list (REQ-38)
pub(crate) fn cmd_rotate(identity_path: Option<String>, json: bool) -> Result<(), GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let identity_str = load_identity(identity_path)?;
    let identity = crypto::parse_identity(&identity_str)?;

    let recipient_keys = resolve_recipient_keys(&repo_root, vec![])?;
    let mut rotated = 0usize;

    let encrypted_files = repo::list_all_encrypted_files(&repo_root)?;
    for path in encrypted_files {
        let ciphertext = std::fs::read(&path)?;
        let plaintext = crypto::decrypt(&identity, &ciphertext)?;
        let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
            .iter()
            .map(|k| Ok(Box::new(crypto::parse_recipient(k)?) as Box<dyn age::Recipient + Send>))
            .collect::<Result<Vec<_>, GitvaultError>>()?;
        let new_ciphertext = crypto::encrypt(recipients, &plaintext)?;
        let tmp =
            tempfile::NamedTempFile::new_in(path.parent().unwrap_or(std::path::Path::new(".")))?;
        std::fs::write(tmp.path(), &new_ciphertext)?;
        tmp.persist(&path).map_err(|e| GitvaultError::Io(e.error))?;
        rotated += 1;
    }
    crate::output::output_success(
        &format!(
            "Rotated {rotated} secret(s) to {} recipient(s)",
            recipient_keys.len()
        ),
        json,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use age::x25519;
    use tempfile::TempDir;

    #[test]
    fn test_resolve_recipient_keys_defaults_to_local_identity_public_key() {
        let _lock = global_test_lock().lock().unwrap();
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let expected_recipient = identity.to_public().to_string();

        use age::secrecy::ExposeSecret;
        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe {
            std::env::set_var("GITVAULT_IDENTITY", identity_secret.expose_secret());
        }

        let resolved = resolve_recipient_keys(dir.path(), vec![])
            .expect("default recipient resolution should succeed");

        match previous {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_IDENTITY", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_IDENTITY");
            },
        }

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_defaults_from_identity_file_path() {
        let _lock = global_test_lock().lock().unwrap();
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let expected_recipient = identity.to_public().to_string();

        use age::secrecy::ExposeSecret;
        let identity_file = tempfile::NamedTempFile::new().expect("temp file should be created");
        std::fs::write(identity_file.path(), identity_secret.expose_secret())
            .expect("identity should be written to temp file");

        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe {
            std::env::set_var(
                "GITVAULT_IDENTITY",
                identity_file.path().to_string_lossy().to_string(),
            );
        }

        let resolved = resolve_recipient_keys(dir.path(), vec![])
            .expect("default recipient resolution should succeed");

        match previous {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_IDENTITY", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_IDENTITY");
            },
        }

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_fails_without_identity_source() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        let previous_keyring = std::env::var("GITVAULT_KEYRING").ok();
        unsafe {
            std::env::remove_var("GITVAULT_IDENTITY");
            std::env::remove_var("GITVAULT_KEYRING");
        }

        let result = resolve_recipient_keys(dir.path(), vec![]);

        match previous {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_IDENTITY", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_IDENTITY");
            },
        }
        match previous_keyring {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_KEYRING", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_KEYRING");
            },
        }

        match result {
            Err(GitvaultError::Usage(message)) => {
                assert!(message.contains("No identity provided"));
            }
            other => panic!("expected usage error for missing identity, got: {other:?}"),
        }
    }

    #[test]
    fn test_resolve_recipient_keys_fails_with_malformed_identity_key() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe {
            std::env::set_var("GITVAULT_IDENTITY", "AGE-SECRET-KEY-INVALID");
        }

        let result = resolve_recipient_keys(dir.path(), vec![]);

        match previous {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_IDENTITY", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_IDENTITY");
            },
        }

        match result {
            Err(GitvaultError::Decryption(message)) => {
                assert!(message.contains("Invalid identity key"));
            }
            other => panic!("expected decryption error for malformed identity, got: {other:?}"),
        }
    }

    #[test]
    fn test_resolve_recipient_keys_returns_recipients_from_file() {
        let dir = TempDir::new().unwrap();
        let pubkey = x25519::Identity::generate().to_public().to_string();
        // Write a non-empty recipients file so that line 330 (early return) executes.
        repo::write_recipients(dir.path(), std::slice::from_ref(&pubkey))
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
            true,
        )
        .expect("add recipient should succeed");

        cmd_recipient(RecipientAction::List, false).expect("list recipient should succeed");

        cmd_recipient(
            RecipientAction::Remove {
                pubkey: pubkey.clone(),
            },
            false,
        )
        .expect("remove recipient should succeed");

        let recipients = repo::read_recipients(dir.path()).expect("recipients should be readable");
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
            true,
        )
        .unwrap();

        let err = cmd_recipient(RecipientAction::Add { pubkey }, true).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_recipient_remove_missing_fails() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let missing = x25519::Identity::generate().to_public().to_string();
        let err = cmd_recipient(RecipientAction::Remove { pubkey: missing }, true).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_recipient_list_json_with_recipients() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let pubkey = x25519::Identity::generate().to_public().to_string();
        cmd_recipient(
            RecipientAction::Add {
                pubkey: pubkey.clone(),
            },
            false,
        )
        .expect("add should succeed");

        // json=true covers the JSON recipients output branch (line 881).
        cmd_recipient(RecipientAction::List, true).expect("list json should succeed");
    }

    #[test]
    fn test_cmd_recipient_list_empty_plain() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // No recipients added → empty list message (lines 883-884).
        cmd_recipient(RecipientAction::List, false).expect("list empty plain should succeed");
    }
}
