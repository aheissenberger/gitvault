use crate::defaults::{HISTORY_SCAN_LIMIT, PLAIN_BASE_DIR};
use crate::error::GitvaultError;
use crate::git::{git_output, git_output_raw};
use std::path::Path;

/// Check whether `secrets/` has uncommitted changes (drift). REQ-32.
///
/// Returns Ok(true) if there are uncommitted changes, Ok(false) if clean.
///
/// # Errors
///
/// Returns [`GitvaultError::Other`] if `git diff` cannot be spawned.
pub fn has_secrets_drift(repo_root: &Path) -> Result<bool, GitvaultError> {
    // `git diff --quiet` exits 1 when there are differences — not an error.
    let out = git_output_raw(
        &[
            "diff",
            "--quiet",
            "HEAD",
            "--",
            crate::defaults::SECRETS_DIR,
        ],
        repo_root,
    )?;
    Ok(!out.status.success())
}

/// Check that no plaintext secrets are staged for commit. REQ-10
///
/// Uses `git diff --cached --name-only` so that a first-time `git add .env`
/// (staged but not yet tracked) is caught before the commit lands.
///
/// Checks that staged files do not include:
/// - anything under .secrets/plain/
/// - .env
///
/// # Errors
///
/// Returns [`GitvaultError::Other`] if `git diff --cached` cannot be spawned.
/// Returns [`GitvaultError::PlaintextLeak`] if plaintext secrets are staged.
pub fn check_no_tracked_plaintext(repo_root: &Path) -> Result<(), GitvaultError> {
    let raw = git_output(&["diff", "--cached", "--name-only"], repo_root)?;
    let staged = String::from_utf8_lossy(&raw);
    let files: Vec<&str> = staged
        .lines()
        .filter(|l| {
            !l.is_empty()
                && (l.contains(crate::defaults::PLAIN_BASE_DIR)
                    || *l == ".env"
                    || l.ends_with("/.env"))
        })
        .collect();
    if !files.is_empty() {
        return Err(GitvaultError::PlaintextLeak(files.join(", ")));
    }
    Ok(())
}

/// Check committed history for plaintext secret files. REQ-81.
///
/// Scans up to [`HISTORY_SCAN_LIMIT`] commits in `git log --all` for files that
/// match the plain output directory or `.env` paths. Returns a list of paths
/// found in committed history, or an empty vec if none are found.
///
/// REQ-95: uses `--diff-filter=AR` (Added and Renamed) so that secrets renamed
/// into sensitive paths are also detected, not only newly added files.
///
/// Callers should treat a non-empty result as a [`GitvaultError::PlaintextLeak`].
///
/// # Errors
///
/// Returns [`GitvaultError::Other`] if `git log` cannot be spawned.
pub fn find_history_plaintext_leaks(repo_root: &Path) -> Result<Vec<String>, GitvaultError> {
    let max = format!("--max-count={HISTORY_SCAN_LIMIT}");
    let raw = git_output(
        &[
            "log",
            "--all",
            "--diff-filter=AR", // REQ-95: include renames in addition to adds.
            "--name-only",
            "--format=",
            &max,
        ],
        repo_root,
    )?;
    let stdout = String::from_utf8_lossy(&raw);
    let leaks: Vec<String> = stdout
        .lines()
        .filter(|l| {
            !l.is_empty() && (l.contains(PLAIN_BASE_DIR) || *l == ".env" || l.ends_with("/.env"))
        })
        .map(str::to_string)
        .collect();

    Ok(leaks)
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
        let _ = result;
    }

    #[test]
    fn test_has_secrets_drift_nonexistent_repo_root_returns_err() {
        let dir = TempDir::new().unwrap();
        let missing_root = dir.path().join("missing");
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
        let _ = has_secrets_drift(dir.path());
    }

    /// REQ-81: find_history_plaintext_leaks returns Ok on a repo with no history.
    #[test]
    fn test_find_history_plaintext_leaks_empty_repo() {
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let leaks = find_history_plaintext_leaks(dir.path()).unwrap();
        assert!(leaks.is_empty());
    }

    /// REQ-81: find_history_plaintext_leaks returns Err when git cannot run.
    #[test]
    fn test_find_history_plaintext_leaks_git_failure() {
        let dir = TempDir::new().unwrap();
        let missing_root = dir.path().join("missing");
        let result = find_history_plaintext_leaks(&missing_root);
        assert!(matches!(result, Err(GitvaultError::Other(_))));
    }

    /// REQ-81: find_history_plaintext_leaks detects a committed .env file.
    #[test]
    fn test_find_history_plaintext_leaks_detects_committed_env() {
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());

        // Configure git identity for commits
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir.path())
            .status()
            .unwrap();

        std::fs::write(dir.path().join(".env"), "SECRET=plaintext\n").unwrap();
        Command::new("git")
            .args(["add", ".env"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "add .env"])
            .current_dir(dir.path())
            .status()
            .unwrap();

        let leaks = find_history_plaintext_leaks(dir.path()).unwrap();
        assert!(
            leaks.iter().any(|l| l == ".env"),
            "expected .env in leaks, got: {leaks:?}"
        );
    }
}
