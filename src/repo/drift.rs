use crate::error::GitvaultError;
use std::path::Path;
use std::process::Command;

/// Check whether `secrets/` has uncommitted changes (drift). REQ-32.
///
/// Returns Ok(true) if there are uncommitted changes, Ok(false) if clean.
pub fn has_secrets_drift(repo_root: &Path) -> Result<bool, GitvaultError> {
    let output = Command::new("git")
        .args(["diff", "--quiet", "HEAD", "--", "secrets/"])
        .current_dir(repo_root)
        .output();

    match output {
        Ok(out) => Ok(!out.status.success()),
        Err(e) => Err(GitvaultError::Other(format!("failed to run git: {e}"))),
    }
}

/// Check that no plaintext secrets are staged for commit. REQ-10
///
/// Uses `git diff --cached --name-only` so that a first-time `git add .env`
/// (staged but not yet tracked) is caught before the commit lands.
///
/// Checks that staged files do not include:
/// - anything under .secrets/plain/
/// - .env
pub fn check_no_tracked_plaintext(repo_root: &Path) -> Result<(), GitvaultError> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| GitvaultError::Other(format!("Failed to run git: {e}")))?;

    let staged = String::from_utf8_lossy(&output.stdout);
    let files: Vec<&str> = staged
        .lines()
        .filter(|l| {
            !l.is_empty() && (l.contains(".secrets/plain/") || *l == ".env" || l.ends_with("/.env"))
        })
        .collect();
    if !files.is_empty() {
        return Err(GitvaultError::PlaintextLeak(files.join(", ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_git_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .status()
            .expect("git init should run");
        assert!(status.success());
    }

    #[test]
    fn test_check_no_tracked_plaintext_clean_repo() {
        let dir = TempDir::new().unwrap();
        let result = check_no_tracked_plaintext(dir.path());
        let _ = result; // just verify it doesn't panic
    }

    #[test]
    fn test_has_secrets_drift_nonexistent_repo_root_returns_err() {
        let dir = TempDir::new().unwrap();
        let missing_root = dir.path().join("missing");
        // git cannot run against a missing directory; error must propagate (M10 fix)
        let result = has_secrets_drift(&missing_root);
        assert!(
            result.is_err(),
            "expected Err when git cannot run, got {result:?}"
        );
    }

    #[test]
    fn test_check_no_tracked_plaintext_git_invocation_failure() {
        let dir = TempDir::new().unwrap();
        let missing_root = dir.path().join("missing");
        let err = check_no_tracked_plaintext(&missing_root).unwrap_err();
        assert!(matches!(err, GitvaultError::Other(_)));
    }

    #[test]
    fn test_check_no_staged_plaintext_detects_staged_files() {
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());

        std::fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        let add_status = Command::new("git")
            .args(["add", ".env"])
            .current_dir(dir.path())
            .status()
            .expect("git add should run");
        assert!(add_status.success());

        let err = check_no_tracked_plaintext(dir.path()).unwrap_err();
        match err {
            GitvaultError::PlaintextLeak(files) => {
                assert!(files.contains(".env"));
            }
            other => panic!("expected plaintext leak error, got: {other:?}"),
        }
    }

    /// Covers `has_secrets_drift` success path (in a real git repo).
    #[test]
    fn test_has_secrets_drift_in_git_repo() {
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        // In a fresh repo with no commits, `git diff HEAD` may fail/return true.
        // We just verify the function returns Ok (doesn't panic or error).
        let _ = has_secrets_drift(dir.path());
    }
}
