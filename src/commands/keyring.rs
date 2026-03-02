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
    SetFn: Fn(&str) -> Result<(), String>,
    GetFn: Fn() -> Result<String, String>,
    DeleteFn: Fn() -> Result<(), String>,
{
    match action {
        KeyringAction::Set { identity } => {
            let key = load_identity(identity)?;
            keyring_set_fn(&key)
                .map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")))?;
            crate::output_success("Identity stored in OS keyring.", json);
        }
        KeyringAction::Get => {
            let key = keyring_get_fn()
                .map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")))?;
            let identity = crypto::parse_identity(&key)?;
            let pubkey = identity.to_public().to_string();
            if json {
                println!("{}", serde_json::json!({"public_key": pubkey}));
            } else {
                println!("Public key: {pubkey}");
            }
        }
        KeyringAction::Delete => {
            keyring_delete_fn().map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")))?;
            crate::output_success("Identity removed from OS keyring.", json);
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
            |_value| Err("set-failed".to_string()),
            || Ok("unused".to_string()),
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(set_err, GitvaultError::Other(_)));

        let get_err = cmd_keyring_with_ops(
            KeyringAction::Get,
            true,
            |_value| Ok(()),
            || Err("get-failed".to_string()),
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(get_err, GitvaultError::Other(_)));

        let delete_err = cmd_keyring_with_ops(
            KeyringAction::Delete,
            true,
            |_value| Ok(()),
            || Ok("unused".to_string()),
            || Err("delete-failed".to_string()),
        )
        .unwrap_err();
        assert!(matches!(delete_err, GitvaultError::Other(_)));
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
            || Err("not used".to_string()),
            || Err("not used".to_string()),
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
            |_| Err("not used".to_string()),
            move || Ok(key_str.clone()),
            || Err("not used".to_string()),
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
            |_| Err("not used".to_string()),
            || Err("not used".to_string()),
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
            |_| Err("store failed".to_string()),
            || Err("not used".to_string()),
            || Err("not used".to_string()),
        );
        assert!(matches!(result, Err(GitvaultError::Other(_))));
    }
}
