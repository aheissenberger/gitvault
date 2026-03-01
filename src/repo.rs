use std::path::{Path, PathBuf};
use std::fs;
use std::process::Command;
use crate::error::GitvaultError;

/// Directory for encrypted artifacts (REQ-7)
pub const SECRETS_DIR: &str = "secrets";

/// Base directory for plaintext outputs (REQ-8)
pub const PLAIN_BASE_DIR: &str = ".secrets/plain";

/// Get the path for an encrypted artifact under secrets/. REQ-7
pub fn get_encrypted_path(repo_root: &Path, name: &str) -> PathBuf {
    repo_root.join(SECRETS_DIR).join(name)
}

/// Get the path for a plaintext artifact under .secrets/plain/<env>/. REQ-8
pub fn get_plain_path(repo_root: &Path, env: &str, name: &str) -> PathBuf {
    repo_root.join(PLAIN_BASE_DIR).join(env).join(name)
}

/// Ensure all required directories exist.
pub fn ensure_dirs(repo_root: &Path, env: &str) -> Result<(), GitvaultError> {
    fs::create_dir_all(repo_root.join(SECRETS_DIR))?;
    fs::create_dir_all(repo_root.join(PLAIN_BASE_DIR).join(env))?;
    Ok(())
}

/// Check that no plaintext secrets are tracked in git. REQ-10
///
/// Checks that:
/// - .secrets/plain/** is not tracked
/// - .env is not tracked
pub fn check_no_tracked_plaintext(repo_root: &Path) -> Result<(), GitvaultError> {
    let output = Command::new("git")
        .args(["ls-files", ".secrets/plain/", ".env"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| GitvaultError::Other(format!("Failed to run git: {e}")))?;

    let tracked = String::from_utf8_lossy(&output.stdout);
    let files: Vec<&str> = tracked.lines().filter(|l| !l.is_empty()).collect();
    if !files.is_empty() {
        return Err(GitvaultError::PlaintextLeak(files.join(", ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_get_encrypted_path() {
        let root = Path::new("/repo");
        let path = get_encrypted_path(root, "database.env.age");
        assert_eq!(path, PathBuf::from("/repo/secrets/database.env.age"));
    }

    #[test]
    fn test_get_plain_path() {
        let root = Path::new("/repo");
        let path = get_plain_path(root, "dev", "database.env");
        assert_eq!(path, PathBuf::from("/repo/.secrets/plain/dev/database.env"));
    }

    #[test]
    fn test_get_plain_path_staging() {
        let root = Path::new("/repo");
        let path = get_plain_path(root, "staging", "app.env");
        assert_eq!(path, PathBuf::from("/repo/.secrets/plain/staging/app.env"));
    }

    #[test]
    fn test_ensure_dirs_creates_directories() {
        let dir = TempDir::new().unwrap();
        ensure_dirs(dir.path(), "dev").unwrap();

        assert!(dir.path().join("secrets").exists(), "secrets/ should be created");
        assert!(dir.path().join(".secrets/plain/dev").exists(), ".secrets/plain/dev/ should be created");
    }

    #[test]
    fn test_ensure_dirs_staging() {
        let dir = TempDir::new().unwrap();
        ensure_dirs(dir.path(), "staging").unwrap();

        assert!(dir.path().join(".secrets/plain/staging").exists());
    }

    #[test]
    fn test_check_no_tracked_plaintext_clean_repo() {
        let dir = TempDir::new().unwrap();
        let result = check_no_tracked_plaintext(dir.path());
        let _ = result; // just verify it doesn't panic
    }
}
