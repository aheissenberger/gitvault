//! Production barrier enforcement.
//!
//! REQ-13: accessing prod requires --prod flag AND (valid allow token OR interactive confirmation).
//! REQ-14: allow token expires automatically (default TTL: 3600 seconds).
//! REQ-15: fail closed — any unmet condition returns BarrierNotSatisfied.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::GitvaultError;
use crate::permissions;

/// Default token TTL in seconds (1 hour).
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;

/// Path of the allow token relative to repo root.
const TOKEN_PATH: &str = ".secrets/.prod-token";

/// Check the production barrier for the given environment.
///
/// REQ-13: if `env` == "prod", requires:
///   - `prod_flag` == true   (explicit --prod opt-in), AND
///   - valid unexpired allow token OR interactive confirmation (blocked when no_prompt)
///
/// REQ-15: fails closed — returns Err(BarrierNotSatisfied) if any condition is unmet.
/// Non-prod environments pass immediately.
pub fn check_prod_barrier(
    repo_root: &Path,
    env: &str,
    prod_flag: bool,
    no_prompt: bool,
) -> Result<(), GitvaultError> {
    check_prod_barrier_with_confirm(
        repo_root,
        env,
        prod_flag,
        no_prompt,
        prompt_prod_confirmation,
    )
}

fn check_prod_barrier_with_confirm<F>(
    repo_root: &Path,
    env: &str,
    prod_flag: bool,
    no_prompt: bool,
    confirm: F,
) -> Result<(), GitvaultError>
where
    F: FnOnce() -> Result<bool, GitvaultError>,
{
    if env != "prod" {
        return Ok(());
    }

    // REQ-13: explicit --prod flag required
    if !prod_flag {
        return Err(GitvaultError::BarrierNotSatisfied(
            "add --prod to confirm production access".to_string(),
        ));
    }

    // REQ-13 + REQ-14: check for a valid (unexpired) allow token
    if has_valid_token(repo_root) {
        return Ok(());
    }

    // REQ-13: fall back to interactive confirmation
    if no_prompt {
        return Err(GitvaultError::BarrierNotSatisfied(
            "no valid prod allow token and --no-prompt is set; run `gitvault allow-prod` first"
                .to_string(),
        ));
    }

    if confirm()? {
        Ok(())
    } else {
        Err(GitvaultError::BarrierNotSatisfied(
            "production access denied by user".to_string(),
        ))
    }
}

fn prompt_prod_confirmation() -> Result<bool, GitvaultError> {
    #[cfg(not(test))]
    {
        eprint!("⚠️  You are about to access PRODUCTION secrets. Confirm? [y/N] ");
        let mut stdin = std::io::stdin().lock();
        read_confirmation_from(&mut stdin)
    }

    #[cfg(test)]
    {
        let response = std::env::var("GITVAULT_TEST_CONFIRM").unwrap_or_else(|_| "n".to_string());
        let mut input = std::io::Cursor::new(format!("{response}\n").into_bytes());
        read_confirmation_from(&mut input)
    }
}

fn read_confirmation_from(reader: &mut impl std::io::BufRead) -> Result<bool, GitvaultError> {
    let mut input = String::new();
    reader.read_line(&mut input).map_err(GitvaultError::Io)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

/// Write a timed allow token to `.secrets/.prod-token`. REQ-14.
///
/// The token contains the Unix timestamp at which it expires.
pub fn allow_prod(repo_root: &Path, ttl_secs: u64) -> Result<u64, GitvaultError> {
    let expiry = now_secs()
        .checked_add(ttl_secs)
        .ok_or_else(|| GitvaultError::Other("timestamp overflow".to_string()))?;

    let token_path = repo_root.join(TOKEN_PATH);
    if let Some(parent) = token_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let token_parent = token_path.parent().unwrap_or(repo_root);
    let tmp = tempfile::NamedTempFile::new_in(token_parent)?;
    fs::write(tmp.path(), expiry.to_string())?;
    tmp.persist(&token_path)
        .map_err(|e| GitvaultError::Io(e.error))?;
    enforce_restricted_token_permissions(&token_path)?;

    Ok(expiry)
}

fn enforce_restricted_token_permissions(path: &Path) -> Result<(), GitvaultError> {
    permissions::enforce_owner_rw(path, "production token")
}

/// Revoke the allow token by removing the token file.
pub fn revoke_prod(repo_root: &Path) -> Result<(), GitvaultError> {
    let token_path = repo_root.join(TOKEN_PATH);
    if token_path.exists() {
        fs::remove_file(&token_path)?;
    }
    Ok(())
}

/// Returns true if a valid (unexpired) allow token exists. REQ-14.
fn has_valid_token(repo_root: &Path) -> bool {
    let token_path = repo_root.join(TOKEN_PATH);
    let Ok(content) = fs::read_to_string(&token_path) else {
        return false;
    };
    let Ok(expiry) = content.trim().parse::<u64>() else {
        return false;
    };
    now_secs() < expiry
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static CONFIRM_LOCK: Mutex<()> = Mutex::new(());

    fn root() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn non_prod_env_always_passes() {
        let dir = root();
        assert!(check_prod_barrier(dir.path(), "dev", false, true).is_ok());
        assert!(check_prod_barrier(dir.path(), "staging", false, true).is_ok());
    }

    #[test]
    fn prod_without_prod_flag_fails() {
        let dir = root();
        let err = check_prod_barrier(dir.path(), "prod", false, true).unwrap_err();
        assert!(matches!(err, GitvaultError::BarrierNotSatisfied(_)));
    }

    #[test]
    fn prod_with_prod_flag_no_token_no_prompt_fails() {
        let dir = root();
        let err = check_prod_barrier(dir.path(), "prod", true, true).unwrap_err();
        assert!(matches!(err, GitvaultError::BarrierNotSatisfied(_)));
    }

    #[test]
    fn prod_with_valid_token_passes() {
        let dir = root();
        allow_prod(dir.path(), 3600).unwrap();
        assert!(check_prod_barrier(dir.path(), "prod", true, true).is_ok());
    }

    #[test]
    fn prod_with_expired_token_fails() {
        let dir = root();
        // Write an already-expired token (expiry = 1 second past epoch)
        let token_path = dir.path().join(".secrets/.prod-token");
        std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        std::fs::write(&token_path, "1").unwrap(); // expired in 1970

        let err = check_prod_barrier(dir.path(), "prod", true, true).unwrap_err();
        assert!(matches!(err, GitvaultError::BarrierNotSatisfied(_)));
    }

    #[test]
    fn allow_prod_writes_future_expiry() {
        let dir = root();
        let expiry = allow_prod(dir.path(), 3600).unwrap();
        assert!(expiry > now_secs());
        assert!(has_valid_token(dir.path()));
    }

    #[test]
    fn revoke_prod_removes_token() {
        let dir = root();
        allow_prod(dir.path(), 3600).unwrap();
        assert!(has_valid_token(dir.path()));
        revoke_prod(dir.path()).unwrap();
        assert!(!has_valid_token(dir.path()));
    }

    #[test]
    fn allow_token_token_path_is_gitignored_after_ensure() {
        // The token path itself: just verify the constant is sane
        assert!(TOKEN_PATH.starts_with(".secrets/"));
    }

    #[test]
    fn prod_with_interactive_confirm_yes_passes() {
        let dir = root();
        let result = check_prod_barrier_with_confirm(dir.path(), "prod", true, false, || Ok(true));
        assert!(result.is_ok());
    }

    #[test]
    fn prod_with_interactive_confirm_no_fails() {
        let dir = root();
        let result = check_prod_barrier_with_confirm(dir.path(), "prod", true, false, || Ok(false));
        assert!(matches!(result, Err(GitvaultError::BarrierNotSatisfied(_))));
    }

    #[test]
    fn prod_confirmation_error_is_propagated() {
        let dir = root();
        let result = check_prod_barrier_with_confirm(dir.path(), "prod", true, false, || {
            Err(GitvaultError::Io(std::io::Error::other("read failed")))
        });
        assert!(matches!(result, Err(GitvaultError::Io(_))));
    }

    #[test]
    fn read_confirmation_from_accepts_yes_case_insensitive() {
        let mut input = Cursor::new(b"Y\n".to_vec());
        let accepted = read_confirmation_from(&mut input).unwrap();
        assert!(accepted);
    }

    #[test]
    fn read_confirmation_from_rejects_other_values() {
        let mut input = Cursor::new(b"n\n".to_vec());
        let accepted = read_confirmation_from(&mut input).unwrap();
        assert!(!accepted);
    }

    #[test]
    fn check_prod_barrier_interactive_yes_via_prompt_helper() {
        let dir = root();
        let _guard = CONFIRM_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("GITVAULT_TEST_CONFIRM", "y");
        }
        let result = check_prod_barrier(dir.path(), "prod", true, false);
        unsafe {
            std::env::remove_var("GITVAULT_TEST_CONFIRM");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn check_prod_barrier_interactive_no_via_prompt_helper() {
        let dir = root();
        let _guard = CONFIRM_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("GITVAULT_TEST_CONFIRM", "n");
        }
        let result = check_prod_barrier(dir.path(), "prod", true, false);
        unsafe {
            std::env::remove_var("GITVAULT_TEST_CONFIRM");
        }
        assert!(matches!(result, Err(GitvaultError::BarrierNotSatisfied(_))));
    }

    #[test]
    fn malformed_token_content_is_treated_as_invalid() {
        let dir = root();
        let token_path = dir.path().join(".secrets/.prod-token");
        std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        std::fs::write(&token_path, "not-a-timestamp").unwrap();

        assert!(!has_valid_token(dir.path()));
    }
}
