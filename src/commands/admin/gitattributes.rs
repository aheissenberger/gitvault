//! `.gitattributes` management — merge-driver registration.
//!
//! Handles the local git-config entry that wires up the `gitvault-env` custom
//! merge driver so that `*.env.age` files use it during `git merge`.

use std::path::Path;

use crate::error::GitvaultError;
use crate::git::{git_output_raw, git_run};

/// Local git-config key for the gitvault merge driver.
pub(crate) const MERGE_DRIVER_CONFIG_KEY: &str = "merge.gitvault-env.driver";

/// Command template stored in git config for the merge driver.
pub(crate) const MERGE_DRIVER_CONFIG_VALUE: &str = "gitvault merge-driver %O %A %B";

/// Ensure the `merge.gitvault-env.driver` git-config entry exists in the
/// repository's local config.
///
/// If the key is already set (by any value), this is a no-op so that
/// user-customised driver commands are preserved.
pub(super) fn ensure_merge_driver_git_config(repo_root: &Path) -> Result<(), GitvaultError> {
    // `git config --get` exits 1 when the key is absent — not an error.
    let get_output = git_output_raw(
        &["config", "--local", "--get", MERGE_DRIVER_CONFIG_KEY],
        repo_root,
    )?;

    if get_output.status.success() {
        return Ok(());
    }

    if get_output.status.code() != Some(1) {
        let stderr = String::from_utf8_lossy(&get_output.stderr);
        return Err(GitvaultError::Other(format!(
            "git config --get {MERGE_DRIVER_CONFIG_KEY} failed: {stderr}"
        )));
    }

    git_run(
        &[
            "config",
            "--local",
            MERGE_DRIVER_CONFIG_KEY,
            MERGE_DRIVER_CONFIG_VALUE,
        ],
        repo_root,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    /// Calling `ensure_merge_driver_git_config` in a directory that is **not** a
    /// git repository causes `git config --local --get` to exit with code 128.
    /// That exit code is neither 0 nor 1, so the function must return an error.
    /// Covers the `status.code() != Some(1)` error branch (lines 34-37).
    #[test]
    fn test_ensure_merge_driver_git_config_errors_on_nongit_dir() {
        let dir = TempDir::new().unwrap();
        // No `git init` — this is intentionally not a git repository.
        let result = ensure_merge_driver_git_config(dir.path());
        assert!(
            result.is_err(),
            "should fail in a non-git directory (exit code 128)"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains(MERGE_DRIVER_CONFIG_KEY),
            "error should mention the config key: {msg}"
        );
    }

    /// Calling `ensure_merge_driver_git_config` with a directory that does not
    /// exist causes `git_output_raw` to fail when spawning the process (because
    /// `current_dir` is invalid). This covers the `?` error-propagation at line
    /// 27 (the error arm of `git_output_raw(...)?`).
    #[test]
    fn test_ensure_merge_driver_git_config_errors_on_nonexistent_dir() {
        let nonexistent = std::path::PathBuf::from(
            "/tmp/__gitvault_test_nonexistent_dir_that_should_never_exist__",
        );
        let result = ensure_merge_driver_git_config(&nonexistent);
        assert!(
            result.is_err(),
            "should fail when the directory does not exist"
        );
    }
}
