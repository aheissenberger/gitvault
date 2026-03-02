//! `gitvault keyring` command implementation.

use crate::cli::KeyringAction;
use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::load_identity;
use crate::{crypto, keyring_store};
use zeroize::Zeroizing;

/// Manage identity key in OS keyring (REQ-39)
pub fn cmd_keyring(action: KeyringAction, json: bool) -> Result<CommandOutcome, GitvaultError> {
    cmd_keyring_with_ops(
        action,
        json,
        keyring_store::keyring_set,
        keyring_store::keyring_get,
        keyring_store::keyring_delete,
    )
}

/// Dependency-injected variant of [`cmd_keyring`] that accepts explicit keyring
/// operation functions instead of calling the real OS keyring backend.
///
/// This is the core implementation; [`cmd_keyring`] is a thin wrapper that
/// forwards the three real [`keyring_store`](crate::keyring_store) functions.
///
/// # Parameters
///
/// - `action` – the keyring sub-command to execute ([`KeyringAction::Set`],
///   [`KeyringAction::Get`], or [`KeyringAction::Delete`]).
/// - `json` – when `true`, successful output is emitted as JSON; otherwise
///   human-readable text is printed.
/// - `keyring_set_fn` (`SetFn`) – called with the raw age secret-key string
///   when `action` is `Set`.  Signature: `Fn(&str) -> Result<(), GitvaultError>`.
/// - `keyring_get_fn` (`GetFn`) – called with no arguments when `action` is
///   `Get`; must return the stored age secret-key string wrapped in
///   [`Zeroizing`].  Signature: `Fn() -> Result<Zeroizing<String>, GitvaultError>`.
/// - `keyring_delete_fn` (`DeleteFn`) – called with no arguments when `action`
///   is `Delete`.  Signature: `Fn() -> Result<(), GitvaultError>`.
///
/// # When to use
///
/// Prefer this function in tests so you can inject lightweight mock closures
/// (or named helper functions) in place of the real OS keyring, keeping tests
/// hermetic and fast.  Production callers should use [`cmd_keyring`] instead.
pub fn cmd_keyring_with_ops<SetFn, GetFn, DeleteFn>(
    action: KeyringAction,
    json: bool,
    set_fn: SetFn,
    get_fn: GetFn,
    delete_fn: DeleteFn,
) -> Result<CommandOutcome, GitvaultError>
where
    SetFn: Fn(&str) -> Result<(), GitvaultError>,
    GetFn: Fn() -> Result<Zeroizing<String>, GitvaultError>,
    DeleteFn: Fn() -> Result<(), GitvaultError>,
{
    match action {
        KeyringAction::Set { identity } => {
            let key = load_identity(identity)?;
            set_fn(&key)?;
            crate::output::output_success("Identity stored in OS keyring.", json);
        }
        KeyringAction::Get => {
            let key = get_fn()?;
            let identity = crypto::parse_identity(&key)?;
            let pubkey = identity.to_public().to_string();
            if json {
                println!("{}", serde_json::json!({"public_key": pubkey}));
            } else {
                println!("Public key: {pubkey}");
            }
        }
        KeyringAction::Delete => {
            delete_fn()?;
            crate::output::output_success("Identity removed from OS keyring.", json);
        }
    }
    Ok(CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use tempfile::TempDir;

    // ── Shared named helpers ────────────────────────────────────────────────
    // Using named functions (not inline closures) means each function body is
    // instrumented once and counts as covered whenever ANY test calls it.
    // This eliminates dead-closure coverage gaps caused by passing a function
    // as an "unused" parameter to the wrong action arm.

    /// Succeeds silently – used as a stand-in set_fn in Get / Delete tests.
    // Must return Result to match SetFn: Fn(&str) -> Result<(), _> bound.
    #[allow(clippy::unnecessary_wraps)]
    fn set_ok(_key: &str) -> Result<(), GitvaultError> {
        Ok(())
    }

    /// Succeeds silently – used as a stand-in delete_fn in Set / Get tests.
    // Must return Result to match DeleteFn: Fn() -> Result<(), _> bound.
    #[allow(clippy::unnecessary_wraps)]
    fn delete_ok() -> Result<(), GitvaultError> {
        Ok(())
    }

    /// Generates a fresh age identity string – used as a stand-in get_fn in
    /// Set / Delete tests, and as the real get_fn in Get tests (so the body
    /// is actually executed and covered during Get-action tests).
    // Must return Result to match GetFn: Fn() -> Result<Zeroizing<String>, _> bound.
    #[allow(clippy::unnecessary_wraps)]
    fn gen_get() -> Result<Zeroizing<String>, GitvaultError> {
        use age::secrecy::ExposeSecret;
        Ok(Zeroizing::new(
            age::x25519::Identity::generate()
                .to_string()
                .expose_secret()
                .clone(),
        ))
    }

    /// Returns an error – used as the active set_fn in Set-error tests.
    fn set_err(_key: &str) -> Result<(), GitvaultError> {
        Err(GitvaultError::Keyring("set-failed".to_string()))
    }

    /// Returns an error – used as the active get_fn in Get-error tests.
    fn get_err() -> Result<Zeroizing<String>, GitvaultError> {
        Err(GitvaultError::Keyring("get-failed".to_string()))
    }

    /// Returns an error – used as the active delete_fn in Delete-error tests.
    fn delete_err() -> Result<(), GitvaultError> {
        Err(GitvaultError::Keyring("delete-failed".to_string()))
    }

    // ── Success-path tests ──────────────────────────────────────────────────

    #[test]
    fn test_cmd_keyring_with_ops_success_paths() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        // Set – only set_ok is called; gen_get / delete_ok are not called here
        // but their bodies ARE covered by the Get / Delete sub-tests below.
        cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(identity_file.path().to_string_lossy().to_string()),
            },
            true,
            set_ok,
            gen_get,
            delete_ok,
        )
        .unwrap();

        // Get – gen_get IS called here, set_ok / delete_ok not called here.
        cmd_keyring_with_ops(KeyringAction::Get, true, set_ok, gen_get, delete_ok).unwrap();

        // Delete – delete_ok IS called here, set_ok / gen_get not called here.
        cmd_keyring_with_ops(KeyringAction::Delete, true, set_ok, gen_get, delete_ok).unwrap();
    }

    // ── Error-path tests ────────────────────────────────────────────────────

    #[test]
    fn test_cmd_keyring_with_ops_error_paths() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        // Set error – set_err IS called; gen_get / delete_ok are not called.
        let err = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(identity_file.path().to_string_lossy().to_string()),
            },
            true,
            set_err,
            gen_get,
            delete_ok,
        )
        .unwrap_err();
        assert!(matches!(err, GitvaultError::Keyring(_)));

        // Get error – get_err IS called; set_ok / delete_ok are not called.
        let err =
            cmd_keyring_with_ops(KeyringAction::Get, true, set_ok, get_err, delete_ok).unwrap_err();
        assert!(matches!(err, GitvaultError::Keyring(_)));

        // Delete error – delete_err IS called; set_ok / gen_get are not called.
        let err = cmd_keyring_with_ops(KeyringAction::Delete, true, set_ok, gen_get, delete_err)
            .unwrap_err();
        assert!(matches!(err, GitvaultError::Keyring(_)));
    }

    // ── Focused unit tests ──────────────────────────────────────────────────

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
            // gen_get / delete_ok bodies covered by other tests.
            gen_get,
            delete_ok,
        );
        assert!(result.is_ok());
        assert!(stored.lock().unwrap().starts_with("AGE-SECRET-KEY-"));
    }

    #[test]
    fn test_cmd_keyring_get_returns_public_key() {
        use age::secrecy::ExposeSecret;
        let (_, identity) = setup_identity_file();
        let key_str = identity.to_string().expose_secret().clone();
        // set_ok / delete_ok bodies covered by other tests.
        let result = cmd_keyring_with_ops(
            KeyringAction::Get,
            false,
            set_ok,
            move || Ok(Zeroizing::new(key_str.clone())),
            delete_ok,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_keyring_delete_calls_delete_fn() {
        let called = std::sync::Arc::new(std::sync::Mutex::new(false));
        let called_clone = called.clone();
        // set_ok / gen_get bodies covered by other tests.
        let result =
            cmd_keyring_with_ops(KeyringAction::Delete, false, set_ok, gen_get, move || {
                *called_clone.lock().unwrap() = true;
                Ok(())
            });
        assert!(result.is_ok());
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_cmd_keyring_set_propagates_store_error() {
        let (tmp_file, _) = setup_identity_file();
        // set_err IS called; gen_get / delete_ok bodies covered elsewhere.
        let result = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(tmp_file.path().to_string_lossy().to_string()),
            },
            false,
            set_err,
            gen_get,
            delete_ok,
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
            set_ok,
            || Ok(Zeroizing::new("not-a-valid-age-secret-key".to_string())),
            delete_ok,
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
            set_ok,
            gen_get,
            delete_ok,
        );
        assert!(result.is_err());
    }

    /// json=true path for Get via cmd_keyring_with_ops.
    #[test]
    fn test_cmd_keyring_get_json_output() {
        use age::secrecy::ExposeSecret;
        let (_, identity) = setup_identity_file();
        let key_str = identity.to_string().expose_secret().clone();
        let result = cmd_keyring_with_ops(
            KeyringAction::Get,
            true,
            set_ok,
            move || Ok(Zeroizing::new(key_str.clone())),
            delete_ok,
        );
        assert!(result.is_ok());
    }

    /// Smoke-test the real `cmd_keyring` wrapper (not injectable) on all platforms.
    ///
    /// Uses the in-memory mock backend so `Set` always succeeds and the `Ok(_)` dispatch
    /// branch is reliably covered in CI.  The mock has no cross-Entry persistence, so
    /// `Get` and `Delete` return `NoEntry`; we only care that the dispatch logic runs.
    #[test]
    fn test_cmd_keyring_real_wrapper_exercises_delegate() {
        // Install the mock backend so Entry::new() always succeeds → Set always returns Ok.
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());

        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _) = setup_identity_file();

        let set_result = cmd_keyring(
            KeyringAction::Set {
                identity: Some(identity_file.path().to_string_lossy().to_string()),
            },
            false,
        );

        // With the mock backend, Set always succeeds; exercise Get / Delete dispatch paths.
        // The mock has no cross-Entry persistence so Get returns NoEntry — that is fine.
        match set_result {
            Ok(_) => {
                let _ = cmd_keyring(KeyringAction::Get, false);
                let _ = cmd_keyring(KeyringAction::Delete, false);
            }
            Err(GitvaultError::Keyring(_)) => {}
            Err(other) => panic!("Unexpected error from cmd_keyring Set: {other:?}"),
        }
    }
}
