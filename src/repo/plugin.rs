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
/// Uses the [`which`] crate for cross-platform binary resolution (REQ-100).
/// Handles `PATHEXT` expansion on Windows, UNC paths, and symlink resolution.
#[must_use]
pub fn find_adapter_binary(adapter: &HookAdapter) -> AdapterLookup {
    let binary = adapter.binary_name();
    which::which(binary).map_or_else(
        |_| AdapterLookup::NotFound {
            binary: binary.to_string(),
        },
        AdapterLookup::Found,
    )
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
    use crate::commands::test_helpers::global_test_lock;
    use crate::config::HookAdapter;
    use std::str::FromStr;

    #[test]
    fn test_find_adapter_binary_not_on_path() {
        let _lock = global_test_lock().lock().unwrap();
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

        assert!(matches!(result, AdapterLookup::NotFound { binary } if binary == "gitvault-husky"));
    }

    #[test]
    fn test_adapter_lookup_found_for_real_binary() {
        #[cfg(windows)]
        let probe = "cmd";
        #[cfg(not(windows))]
        let probe = "echo";

        // Verify that which::which resolves a known binary.
        let result = which::which(probe);
        assert!(result.is_ok(), "{probe} should be found on PATH");
        let path = result.unwrap();
        assert!(path.is_absolute());
    }

    #[test]
    fn test_which_binary_not_found_returns_err() {
        let result = which::which("gitvault-fake-binary-xyz-that-does-not-exist");
        assert!(result.is_err());
    }

    // ── invoke_adapter_harden ─────────────────────────────────────────────────

    #[test]
    fn test_invoke_adapter_harden_success_with_true_command() {
        // /usr/bin/true always exits 0 regardless of arguments.
        let true_path = std::path::Path::new("/usr/bin/true");
        if !true_path.exists() {
            return; // Skip on platforms without /usr/bin/true
        }
        let result = invoke_adapter_harden(true_path, std::path::Path::new("/tmp"));
        assert!(
            result.is_ok(),
            "invoke_adapter_harden with /usr/bin/true should succeed"
        );
    }

    #[test]
    fn test_invoke_adapter_harden_failure_with_false_command() {
        // /usr/bin/false always exits 1 regardless of arguments.
        let false_path = std::path::Path::new("/usr/bin/false");
        if !false_path.exists() {
            return; // Skip on platforms without /usr/bin/false
        }
        let result = invoke_adapter_harden(false_path, std::path::Path::new("/tmp"));
        assert!(
            matches!(result, Err(GitvaultError::Usage(_))),
            "invoke_adapter_harden with /usr/bin/false should return Usage error, got: {result:?}"
        );
    }

    #[test]
    fn test_invoke_adapter_harden_nonexistent_binary_fails() {
        let result = invoke_adapter_harden(
            std::path::Path::new("/no/such/binary/gitvault-adapter"),
            std::path::Path::new("/tmp"),
        );
        assert!(
            matches!(result, Err(GitvaultError::Other(_))),
            "nonexistent binary should return Other error, got: {result:?}"
        );
    }

    #[test]
    fn test_find_adapter_binary_found_when_on_path() {
        let _lock = global_test_lock().lock().unwrap();
        // Create a temp directory with a fake gitvault-husky script, then prepend
        // that directory to PATH so find_adapter_binary returns Found.
        let tmp = tempfile::TempDir::new().expect("temp dir");
        #[cfg(windows)]
        let bin_name = "gitvault-husky.cmd";
        #[cfg(not(windows))]
        let bin_name = "gitvault-husky";
        let binary_path = tmp.path().join(bin_name);
        #[cfg(windows)]
        std::fs::write(&binary_path, "@echo off\r\nexit /b 0\r\n").expect("write script");
        #[cfg(not(windows))]
        std::fs::write(&binary_path, "#!/bin/sh\nexit 0\n").expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&binary_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&binary_path, perms).unwrap();
        }

        let original_path = std::env::var_os("PATH").unwrap_or_default();
        let mut entries = Vec::new();
        entries.push(tmp.path().to_path_buf());
        entries.extend(std::env::split_paths(&original_path));
        let new_path = std::env::join_paths(entries).expect("join PATH entries should succeed");
        unsafe {
            std::env::set_var("PATH", &new_path);
        }

        let adapter = HookAdapter::from_str("husky").unwrap();
        let result = find_adapter_binary(&adapter);

        unsafe {
            std::env::set_var("PATH", original_path);
        }

        assert!(
            matches!(result, AdapterLookup::Found(_)),
            "find_adapter_binary should find the binary when it's on PATH"
        );
    }
}
