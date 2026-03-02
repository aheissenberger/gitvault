use std::path::Path;

use crate::error::GitvaultError;

pub fn enforce_owner_rw(path: &Path, resource: &str) -> Result<(), GitvaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME")
            .map_err(|_| GitvaultError::Other("USERNAME is not set".to_string()))?;
        let grant = windows_grant_for_user(&user);
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", grant.as_str()])
            .status()?;
        if !status.success() {
            return Err(restricted_acl_error(resource));
        }
    }

    #[cfg(not(windows))]
    {
        let _ = resource;
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
}
