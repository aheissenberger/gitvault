//! Hook-manager adapter plugin support.
//!
//! This module handles discovery and invocation of external hook-manager
//! adapter binaries (e.g. `gitvault-husky`, `gitvault-pre-commit`,
//! `gitvault-lefthook`).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::HookAdapter;
use crate::error::GitvaultError;

// ---------------------------------------------------------------------------
// AdapterLookup
// ---------------------------------------------------------------------------

/// Result of attempting to find an adapter binary on `PATH`.
pub enum AdapterLookup {
    /// The binary was found at the given path.
    Found(PathBuf),
    /// The binary was not found on `PATH`.
    NotFound {
        /// The binary name that was searched for.
        binary: String,
    },
}

// ---------------------------------------------------------------------------
// find_adapter_binary
// ---------------------------------------------------------------------------

/// Look up `adapter.binary_name()` on `PATH`.
///
/// Uses the same search strategy as the OS shell: walks every directory in
/// `PATH` and returns the first executable match.
#[must_use]
pub fn find_adapter_binary(adapter: &HookAdapter) -> AdapterLookup {
    let binary = adapter.binary_name();
    if let Ok(path) = which_binary(binary) {
        AdapterLookup::Found(path)
    } else {
        AdapterLookup::NotFound {
            binary: binary.to_string(),
        }
    }
}

/// Resolve a binary name to its full path by searching `PATH`, mirroring
/// the behaviour of the `which` shell built-in without pulling in an external
/// crate.
fn which_binary(name: &str) -> Result<PathBuf, ()> {
    let path_var = std::env::var_os("PATH").ok_or(())?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            // Check execute permission on Unix.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = std::fs::metadata(&candidate).map_err(|_| ())?;
                if meta.permissions().mode() & 0o111 != 0 {
                    return Ok(candidate);
                }
            }
            #[cfg(not(unix))]
            {
                return Ok(candidate);
            }
        }
    }
    Err(())
}

// ---------------------------------------------------------------------------
// invoke_adapter_harden
// ---------------------------------------------------------------------------

/// Invoke the adapter binary with the `harden` subcommand in `repo_root`.
///
/// Returns `Ok(())` if the adapter exits with status code 0.
///
/// # Errors
///
/// Returns [`GitvaultError::Other`] if the process cannot be spawned.
/// Returns [`GitvaultError::Usage`] if the adapter exits with a non-zero
/// status code.
pub fn invoke_adapter_harden(adapter_path: &Path, repo_root: &Path) -> Result<(), GitvaultError> {
    let status = Command::new(adapter_path)
        .arg("harden")
        .current_dir(repo_root)
        .status()
        .map_err(|e| {
            GitvaultError::Other(format!(
                "failed to spawn adapter {}: {e}",
                adapter_path.display()
            ))
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(GitvaultError::Usage(format!(
            "hook adapter {} exited with status {status}",
            adapter_path.display()
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HookAdapter;
    use std::str::FromStr;

    #[test]
    fn test_find_adapter_binary_not_on_path() {
        // Use a name that is guaranteed not to be on PATH.
        let fake = HookAdapter::from_str("husky").unwrap();
        // Override PATH so the real gitvault-husky (if any) won't be found.
        let original_path = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("PATH", "/tmp/__no_such_dir_gitvault_test__");
        }
        let result = find_adapter_binary(&fake);
        // Restore PATH.
        match original_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }

        assert!(
            matches!(result, AdapterLookup::NotFound { binary } if binary == "gitvault-husky")
        );
    }

    #[test]
    fn test_adapter_lookup_found_for_real_binary() {
        // `echo` is always present on Unix systems.  We can't use HookAdapter
        // directly because its binary names are `gitvault-*`, so we test the
        // underlying `which_binary` helper instead.
        let result = which_binary("echo");
        assert!(result.is_ok(), "echo should be found on PATH");
        let path = result.unwrap();
        assert!(path.is_absolute());
    }

    #[test]
    fn test_which_binary_not_found_returns_err() {
        let original_path = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("PATH", "/tmp/__no_such_dir_gitvault_test__");
        }
        let result = which_binary("gitvault-fake-binary-xyz");
        match original_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        assert!(result.is_err());
    }
}
