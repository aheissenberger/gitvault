use std::path::Path;

use crate::error::GitvaultError;

/// Restrict `path` to owner-read/write only (mode `0600` on Unix, restricted ACL on Windows).
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading file metadata or setting permissions fails.
/// On Windows, returns [`GitvaultError::Usage`] if the current username cannot be
/// determined, or [`GitvaultError::Io`] if `icacls` cannot be spawned or reports failure.
pub fn enforce_owner_rw(path: &Path, resource: &str) -> Result<(), GitvaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    #[cfg(windows)]
    enforce_windows_acl_with(path, resource, |p, grant| {
        std::process::Command::new("icacls")
            .arg(p)
            .args(["/inheritance:r", "/grant:r", grant])
            .status()
            .map(|s| s.success())
    })?;

    #[cfg(not(windows))]
    {
        let _ = resource;
    }

    Ok(())
}

/// Windows ACL logic with an injectable command runner — available in test builds on all
/// platforms so the USERNAME-missing and icacls-failure branches can be unit-tested on Linux/macOS.
///
/// `run_acl(path, grant)` must return `Ok(true)` when the ACL was applied successfully,
/// `Ok(false)` when the command ran but reported failure, or `Err(_)` when it could not be spawned.
#[cfg(windows)]
pub(crate) fn enforce_windows_acl_with<F>(
    path: &Path,
    resource: &str,
    run_acl: F,
) -> Result<(), GitvaultError>
where
    F: FnOnce(&Path, &str) -> Result<bool, std::io::Error>,
{
    let user = std::env::var("USERNAME")
        .map_err(|_| GitvaultError::Other("USERNAME is not set".to_string()))?;
    enforce_windows_acl_with_user(path, resource, Some(&user), run_acl)
}

#[cfg(any(windows, test))]
fn enforce_windows_acl_with_user<F>(
    path: &Path,
    resource: &str,
    user: Option<&str>,
    run_acl: F,
) -> Result<(), GitvaultError>
where
    F: FnOnce(&Path, &str) -> Result<bool, std::io::Error>,
{
    let user = user.ok_or_else(|| GitvaultError::Other("USERNAME is not set".to_string()))?;
    let grant = windows_grant_for_user(user);
    if !run_acl(path, &grant)? {
        return Err(restricted_acl_error(resource));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn windows_grant_for_user(user: &str) -> String {
    format!("{user}:F")
}

#[cfg(any(windows, test))]
fn restricted_acl_error(resource: &str) -> GitvaultError {
    GitvaultError::Other(format!("Failed to apply restricted ACL to {resource}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn windows_grant_format_is_stable() {
        assert_eq!(windows_grant_for_user("alice"), "alice:F");
    }

    #[test]
    fn acl_error_message_mentions_resource() {
        let err = restricted_acl_error(".env");
        assert!(err.to_string().contains(".env"));
    }

    #[test]
    #[cfg(unix)]
    fn enforce_owner_rw_sets_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"secret").unwrap();

        enforce_owner_rw(tmp.path(), "test file").unwrap();

        let mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // ── enforce_windows_acl_with — cross-platform tests ──────────────────────
    // These tests use the injectable `enforce_windows_acl_with` to verify the
    // Windows ACL logic (USERNAME resolution, grant formatting, error handling)
    // on any platform — no real `icacls` binary required.

    #[test]
    fn enforce_windows_acl_with_missing_username_returns_error() {
        let tmp = NamedTempFile::new().unwrap();

        let result = enforce_windows_acl_with_user(tmp.path(), "secret.age", None, |_, _| Ok(true));

        assert!(
            matches!(&result, Err(GitvaultError::Other(m)) if m.contains("USERNAME")),
            "expected USERNAME error, got: {result:?}"
        );
    }

    #[test]
    fn enforce_windows_acl_with_acl_failure_returns_error() {
        let tmp = NamedTempFile::new().unwrap();

        // Simulate icacls returning a non-zero exit code (failure).
        let result =
            enforce_windows_acl_with_user(tmp.path(), "secret.env", Some("testuser"), |_, _| {
                Ok(false)
            });

        assert!(
            matches!(&result, Err(GitvaultError::Other(m)) if m.contains("secret.env")),
            "expected ACL-failure error, got: {result:?}"
        );
    }

    #[test]
    fn enforce_windows_acl_with_success_passes_correct_grant() {
        let tmp = NamedTempFile::new().unwrap();

        let mut received_grant = String::new();
        let result =
            enforce_windows_acl_with_user(tmp.path(), "secret.age", Some("alice"), |_, grant| {
                received_grant = grant.to_string();
                Ok(true)
            });

        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(received_grant, "alice:F", "grant should be '<user>:F'");
    }

    #[test]
    fn enforce_windows_acl_with_io_error_propagates() {
        let tmp = NamedTempFile::new().unwrap();

        // Simulate icacls failing to spawn (IO error).
        let result =
            enforce_windows_acl_with_user(tmp.path(), "secret.age", Some("alice"), |_, _| {
                Err(std::io::Error::other("spawn failed"))
            });

        assert!(
            matches!(result, Err(GitvaultError::Io(_))),
            "expected Io error, got: {result:?}"
        );
    }
}
