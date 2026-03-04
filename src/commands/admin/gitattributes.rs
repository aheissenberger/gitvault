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
