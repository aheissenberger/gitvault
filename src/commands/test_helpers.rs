//! Shared test utilities for commands module tests.
//!
//! Import with `use crate::commands::test_helpers::*;` inside any `#[cfg(test)]` block.

use age::secrecy::ExposeSecret;
use age::x25519;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use tempfile::NamedTempFile;

use crate::crypto;
use crate::repo;

pub fn global_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub struct CwdGuard {
    pub previous: std::path::PathBuf,
}

impl CwdGuard {
    /// # Panics
    ///
    /// Panics if the current directory cannot be read or if switching to `path` fails.
    pub fn enter(path: &Path) -> Self {
        let previous = std::env::current_dir().expect("current dir should be readable");
        std::env::set_current_dir(path).expect("should switch cwd");
        Self { previous }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.previous);
    }
}

/// # Panics
///
/// Panics if `git init` cannot be run or exits with a non-zero status.
pub fn init_git_repo(path: &Path) {
    let status = Command::new("git")
        .args(["init", "-q"])
        .current_dir(path)
        .status()
        .expect("git init should run");
    assert!(status.success());
}

/// # Panics
///
/// Panics if a temporary file cannot be created or the identity cannot be written to it.
pub fn setup_identity_file() -> (NamedTempFile, x25519::Identity) {
    let identity = x25519::Identity::generate();
    let identity_file = NamedTempFile::new().expect("temp file should be created");
    std::fs::write(identity_file.path(), identity.to_string().expose_secret())
        .expect("identity should be written");
    (identity_file, identity)
}

pub fn with_identity_env<T>(identity_path: &Path, f: impl FnOnce() -> T) -> T {
    with_env_var(
        "GITVAULT_IDENTITY",
        Some(identity_path.to_string_lossy().as_ref()),
        f,
    )
}

pub fn with_env_var<T>(name: &str, value: Option<&str>, f: impl FnOnce() -> T) -> T {
    let previous = std::env::var(name).ok();
    match value {
        Some(v) => unsafe {
            std::env::set_var(name, v);
        },
        None => unsafe {
            std::env::remove_var(name);
        },
    }

    let out = f();

    match previous {
        Some(v) => unsafe {
            std::env::set_var(name, v);
        },
        None => unsafe {
            std::env::remove_var(name);
        },
    }

    out
}

/// # Panics
///
/// Panics if encryption fails, if the output path has no parent directory, or if
/// any file I/O operation fails.
pub fn write_encrypted_env_file(
    repo_root: &Path,
    env_name: &str,
    file_name: &str,
    identity: &x25519::Identity,
    plaintext: &str,
) {
    let recipients: Vec<Box<dyn age::Recipient + Send>> =
        vec![Box::new(identity.to_public()) as Box<dyn age::Recipient + Send>];
    let ciphertext =
        crypto::encrypt(recipients, plaintext.as_bytes()).expect("encryption should succeed");
    let out_path = repo::get_env_encrypted_path(repo_root, env_name, file_name);
    std::fs::create_dir_all(
        out_path
            .parent()
            .expect("encrypted output should have parent directory"),
    )
    .expect("env secrets directory should be created");
    std::fs::write(out_path, ciphertext).expect("ciphertext should be written");
}
