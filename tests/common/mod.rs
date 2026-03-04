//! Shared helpers for integration tests.
//!
//! Each test file that needs these helpers should declare:
//!   `mod common;`
//! at the top of the file.

#![allow(dead_code)]

use age::secrecy::ExposeSecret;
use age::x25519;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Return a [`Command`] pointing at the compiled `gitvault` binary.
pub fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gitvault"))
}

/// Run `git init -q` in `path`.
pub fn init_git_repo(path: &Path) {
    let status = Command::new("git")
        .args(["init", "-q"])
        .current_dir(path)
        .status()
        .expect("git init should run");
    assert!(status.success());
}

/// Configure a local git identity so commits work in tests.
pub fn configure_git_identity(path: &Path) {
    let set_email = Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(path)
        .status()
        .expect("git config user.email should run");
    assert!(set_email.success());

    let set_name = Command::new("git")
        .args(["config", "user.name", "Gitvault Test"])
        .current_dir(path)
        .status()
        .expect("git config user.name should run");
    assert!(set_name.success());
}

/// Return a `PATH` string that prepends the directory containing the gitvault
/// binary, so that git hooks that call `gitvault` can find it.
pub fn gitvault_path_env() -> String {
    let bin = std::path::Path::new(env!("CARGO_BIN_EXE_gitvault"));
    let bin_dir = bin
        .parent()
        .expect("gitvault binary should have a parent directory");
    let current_path = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", bin_dir.display(), current_path)
}

/// Read a single git config value from the local repo config.
pub fn git_config_local(path: &Path, key: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["config", "--local", "--get", key])
        .current_dir(path)
        .output()
        .expect("git config should run");

    if !out.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Generate a fresh age x25519 identity, write it to a temp file, and return
/// `(TempDir, identity_file_path, public_key_string)`.
///
/// The `TempDir` must be kept alive for the duration of the test.
pub fn write_identity_file() -> (TempDir, String, String) {
    let tmp = TempDir::new().expect("temp dir should be created");
    let identity = x25519::Identity::generate();
    let secret = identity.to_string();
    let public = identity.to_public().to_string();
    let path = tmp.path().join("identity.agekey");
    std::fs::write(&path, secret.expose_secret()).expect("identity should be written");
    (tmp, path.to_string_lossy().to_string(), public)
}
