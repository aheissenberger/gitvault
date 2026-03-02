//! `gitvault keyring` command implementation.

use crate::cli::KeyringAction;
use crate::error::GitvaultError;
use crate::identity::load_identity;
use crate::{crypto, keyring_store};

/// Manage identity key in OS keyring (REQ-39)
pub(crate) fn cmd_keyring(action: KeyringAction, json: bool) -> Result<(), GitvaultError> {
    cmd_keyring_with_ops(
        action,
        json,
        keyring_store::keyring_set,
        keyring_store::keyring_get,
        keyring_store::keyring_delete,
    )
}

pub(crate) fn cmd_keyring_with_ops<SetFn, GetFn, DeleteFn>(
    action: KeyringAction,
    json: bool,
    keyring_set_fn: SetFn,
    keyring_get_fn: GetFn,
    keyring_delete_fn: DeleteFn,
) -> Result<(), GitvaultError>
where
    SetFn: Fn(&str) -> Result<(), GitvaultError>,
    GetFn: Fn() -> Result<String, GitvaultError>,
    DeleteFn: Fn() -> Result<(), GitvaultError>,
{
    match action {
        KeyringAction::Set { identity } => {
            let key = load_identity(identity)?;
            keyring_set_fn(&key)?;
            crate::output::output_success("Identity stored in OS keyring.", json);
        }
        KeyringAction::Get => {
            let key = keyring_get_fn()?;
            let identity = crypto::parse_identity(&key)?;
            let pubkey = identity.to_public().to_string();
            if json {
                println!("{}", serde_json::json!({"public_key": pubkey}));
            } else {
                println!("Public key: {pubkey}");
            }
        }
        KeyringAction::Delete => {
            keyring_delete_fn()?;
            crate::output::output_success("Identity removed from OS keyring.", json);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use tempfile::TempDir;

    #[test]
    fn test_cmd_keyring_with_ops_success_paths() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        use age::secrecy::ExposeSecret;
        let key = identity.to_string().expose_secret().to_string();

        cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(identity_file.path().to_string_lossy().to_string()),
            },
            true,
            |_value| Ok(()),
            || Ok(key.clone()),
            || Ok(()),
        )
        .unwrap();

        cmd_keyring_with_ops(
            KeyringAction::Get,
            true,
            |_value| Ok(()),
            || Ok(key.clone()),
            || Ok(()),
        )
        .unwrap();

        cmd_keyring_with_ops(
            KeyringAction::Delete,
            true,
            |_value| Ok(()),
            || Ok(key.clone()),
            || Ok(()),
        )
        .unwrap();
    }

    #[test]
    fn test_cmd_keyring_with_ops_error_paths() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let set_err = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(identity_file.path().to_string_lossy().to_string()),
            },
            true,
            |_value| Err(GitvaultError::Keyring("set-failed".to_string())),
            || Ok("unused".to_string()),
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(set_err, GitvaultError::Keyring(_)));

        let get_err = cmd_keyring_with_ops(
            KeyringAction::Get,
            true,
            |_value| Ok(()),
            || Err(GitvaultError::Keyring("get-failed".to_string())),
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(get_err, GitvaultError::Keyring(_)));

        let delete_err = cmd_keyring_with_ops(
            KeyringAction::Delete,
            true,
            |_value| Ok(()),
            || Ok("unused".to_string()),
            || Err(GitvaultError::Keyring("delete-failed".to_string())),
        )
        .unwrap_err();
        assert!(matches!(delete_err, GitvaultError::Keyring(_)));
    }

    #[test]
    fn test_cmd_keyring_set_stores_key() {
        let (tmp_file, _) = setup_identity_file();
        let stored = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let stored_clone = stored.clone();
        let result = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(tmp_file.path().to_string_lossy().to_string()),
            },
            false,
            move |key: &str| {
                *stored_clone.lock().unwrap() = key.to_string();
                Ok(())
            },
            || Err(GitvaultError::Keyring("not used".to_string())),
            || Err(GitvaultError::Keyring("not used".to_string())),
        );
        assert!(result.is_ok());
        assert!(stored.lock().unwrap().starts_with("AGE-SECRET-KEY-"));
    }

    #[test]
    fn test_cmd_keyring_get_returns_public_key() {
        let (_, identity) = setup_identity_file();
        use age::secrecy::ExposeSecret;
        let key_str = identity.to_string().expose_secret().to_string();
        let result = cmd_keyring_with_ops(
            KeyringAction::Get,
            false,
            |_| Err(GitvaultError::Keyring("not used".to_string())),
            move || Ok(key_str.clone()),
            || Err(GitvaultError::Keyring("not used".to_string())),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_keyring_delete_calls_delete_fn() {
        let called = std::sync::Arc::new(std::sync::Mutex::new(false));
        let called_clone = called.clone();
        let result = cmd_keyring_with_ops(
            KeyringAction::Delete,
            false,
            |_| Err(GitvaultError::Keyring("not used".to_string())),
            || Err(GitvaultError::Keyring("not used".to_string())),
            move || {
                *called_clone.lock().unwrap() = true;
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_cmd_keyring_set_propagates_store_error() {
        let (tmp_file, _) = setup_identity_file();
        let result = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(tmp_file.path().to_string_lossy().to_string()),
            },
            false,
            |_| Err(GitvaultError::Keyring("store failed".to_string())),
            || Err(GitvaultError::Keyring("not used".to_string())),
            || Err(GitvaultError::Keyring("not used".to_string())),
        );
        assert!(matches!(result, Err(GitvaultError::Keyring(_))));
    }

    /// Cover the `crypto::parse_identity` Err-branch in the Get arm by returning
    /// an invalid key string from the injected getter.
    #[test]
    fn test_cmd_keyring_get_invalid_key_errors() {
        let result = cmd_keyring_with_ops(
            KeyringAction::Get,
            false,
            |_| Err(GitvaultError::Keyring("not used".to_string())),
            || Ok("not-a-valid-age-secret-key".to_string()),
            || Err(GitvaultError::Keyring("not used".to_string())),
        );
        assert!(result.is_err());
    }

    /// Cover the `load_identity` Err-branch in the Set arm by pointing to a
    /// path that does not exist.
    #[test]
    fn test_cmd_keyring_set_identity_load_failure() {
        let result = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some("/nonexistent/path/identity.txt".to_string()),
            },
            false,
            |_| Ok(()),
            || Err(GitvaultError::Keyring("not used".to_string())),
            || Err(GitvaultError::Keyring("not used".to_string())),
        );
        assert!(result.is_err());
    }

    /// json=true path for Get via cmd_keyring_with_ops (already covered, kept for clarity).
    #[test]
    fn test_cmd_keyring_get_json_output() {
        let (_, identity) = setup_identity_file();
        use age::secrecy::ExposeSecret;
        let key_str = identity.to_string().expose_secret().to_string();
        let result = cmd_keyring_with_ops(
            KeyringAction::Get,
            true, // json = true
            |_| Err(GitvaultError::Keyring("not used".to_string())),
            move || Ok(key_str.clone()),
            || Err(GitvaultError::Keyring("not used".to_string())),
        );
        assert!(result.is_ok());
    }

    /// Smoke-test the real `cmd_keyring` wrapper (not injectable).
    /// On macOS this hits the OS keychain; on other platforms it returns a "not
    /// supported" error from the platform stub.  Either way the wrapper code
    /// (lines 9-17) is exercised.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_cmd_keyring_real_wrapper_non_macos() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _) = setup_identity_file();

        // Set: load_identity succeeds but keyring_store::keyring_set returns
        // "not supported" → the error propagates through cmd_keyring.
        let err = cmd_keyring(
            KeyringAction::Set {
                identity: Some(identity_file.path().to_string_lossy().to_string()),
            },
            false,
        )
        .unwrap_err();
        assert!(matches!(err, GitvaultError::Keyring(_)));

        // Get: keyring_store::keyring_get returns "not supported" immediately.
        let err = cmd_keyring(KeyringAction::Get, false).unwrap_err();
        assert!(matches!(err, GitvaultError::Keyring(_)));

        // Delete: keyring_store::keyring_delete returns "not supported".
        let err = cmd_keyring(KeyringAction::Delete, false).unwrap_err();
        assert!(matches!(err, GitvaultError::Keyring(_)));
    }
}
