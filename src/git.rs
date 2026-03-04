//! Centralised git subprocess helpers.
//!
//! Every production git call goes through one of the three functions here so
//! that security-relevant defaults are applied in one place (REQ-90):
//!
//! * `GIT_CONFIG` and `GIT_CONFIG_GLOBAL` are always stripped — prevents an
//!   attacker-controlled config file from redirecting operations.
//! * `GIT_DIR` is always stripped — prevents re-pointing git at a foreign repo.
//! * `GIT_TERMINAL_PROMPT=0` is always set — git never blocks waiting for
//!   interactive credentials in a non-interactive CLI.
//!
//! Callers pass a `current_dir` (required) so the working directory is always
//! explicit rather than inherited from the process environment.

use std::path::Path;
use std::process::Command;

use crate::error::GitvaultError;

/// Apply the standard security env to a [`Command`] builder (REQ-90).
fn sanitize(cmd: &mut Command) -> &mut Command {
    cmd.env_remove("GIT_DIR")
        .env_remove("GIT_CONFIG")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env("GIT_TERMINAL_PROMPT", "0")
}

/// Run `git <args>` in `dir`, returning stdout on success.
///
/// Returns [`GitvaultError::Other`] if the process cannot be spawned or exits
/// with a non-zero status.
///
/// # Errors
///
/// Returns an error when git cannot be spawned or exits non-zero.
pub fn git_output(args: &[&str], dir: &Path) -> Result<Vec<u8>, GitvaultError> {
    let mut cmd = Command::new("git");
    sanitize(&mut cmd);
    let out = cmd
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| GitvaultError::Other(format!("failed to spawn git: {e}")))?;

    if out.status.success() {
        Ok(out.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(GitvaultError::Other(format!(
            "git {} failed: {stderr}",
            args.join(" ")
        )))
    }
}

/// Run `git <args>` in `dir`, returning stdout even when git exits non-zero.
///
/// Use this for commands where non-zero exit is a meaningful signal (e.g.
/// `git diff --quiet` exits 1 when there are differences). The full
/// [`std::process::Output`] is returned so the caller can inspect `.status`.
///
/// # Errors
///
/// Returns an error only when git cannot be spawned.
pub fn git_output_raw(args: &[&str], dir: &Path) -> Result<std::process::Output, GitvaultError> {
    let mut cmd = Command::new("git");
    sanitize(&mut cmd);
    cmd.args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| GitvaultError::Other(format!("failed to spawn git: {e}")))
}

/// Run `git <args>` in `dir`, returning `()` on success.
///
/// # Errors
///
/// Returns an error when git cannot be spawned or exits non-zero.
pub fn git_run(args: &[&str], dir: &Path) -> Result<(), GitvaultError> {
    let mut cmd = Command::new("git");
    sanitize(&mut cmd);
    let status = cmd
        .args(args)
        .current_dir(dir)
        .status()
        .map_err(|e| GitvaultError::Other(format!("failed to spawn git: {e}")))?;

    if status.success() {
        Ok(())
    } else {
        Err(GitvaultError::Other(format!(
            "git {} exited with status {status}",
            args.join(" ")
        )))
    }
}

/// Async variant of [`git_output`] for `tokio` contexts (e.g. SSM commands).
///
/// # Errors
///
/// Returns an error when git cannot be spawned or exits non-zero.
#[cfg(feature = "ssm")]
pub async fn git_output_async(args: &[&str], dir: &Path) -> Result<Vec<u8>, GitvaultError> {
    #[cfg(feature = "ssm")]
    use tokio::process::Command as TokioCommand;

    let mut cmd = TokioCommand::new("git");
    cmd.env_remove("GIT_DIR")
        .env_remove("GIT_CONFIG")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env("GIT_TERMINAL_PROMPT", "0");
    let out = cmd
        .args(args)
        .current_dir(dir)
        .output()
        .await
        .map_err(|e| GitvaultError::Other(format!("failed to spawn git: {e}")))?;

    if out.status.success() {
        Ok(out.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(GitvaultError::Other(format!(
            "git {} failed: {stderr}",
            args.join(" ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn init_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        dir
    }

    #[test]
    fn git_output_returns_stdout() {
        let dir = init_repo();
        let out = git_output(&["rev-parse", "--git-dir"], dir.path()).unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn git_output_errors_on_bad_command() {
        let dir = init_repo();
        let result = git_output(&["no-such-subcommand-xyz"], dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn git_output_raw_returns_on_nonzero_exit() {
        let dir = init_repo();
        // `git diff --quiet` exits 0 when clean; no staged changes here.
        let out = git_output_raw(&["diff", "--quiet"], dir.path()).unwrap();
        assert!(out.status.success());
    }

    #[test]
    fn git_run_succeeds() {
        let dir = init_repo();
        git_run(&["config", "core.autocrlf", "false"], dir.path()).unwrap();
    }

    #[test]
    fn git_run_errors_on_bad_command() {
        let dir = init_repo();
        let result = git_run(&["no-such-subcommand-xyz"], dir.path());
        assert!(result.is_err());
    }
}
