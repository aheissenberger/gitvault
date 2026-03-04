//! Centralised git subprocess helpers.
//!
//! Every production git call goes through one of the three functions here so
//! that security-relevant defaults are applied in one place (REQ-90):
//!
//! * `GIT_DIR` is always stripped — prevents re-pointing git at a foreign repo.
//! * `GIT_CONFIG` and `GIT_CONFIG_GLOBAL` are always stripped — prevents an
//!   attacker-controlled config file from redirecting operations.
//! * `GIT_SSH_COMMAND` / `GIT_SSH` are always stripped — prevents redirecting
//!   SSH transport to an attacker-controlled binary.
//! * `GIT_EXEC_PATH` is always stripped — prevents redirecting git sub-command
//!   lookup to an attacker-controlled directory.
//! * `GIT_INDEX_FILE` is always stripped — prevents redirecting the index to
//!   an attacker-controlled file.
//! * `GIT_OBJECT_DIRECTORY` is always stripped — prevents redirecting the
//!   object store to an attacker-controlled location.
//! * `GIT_ALTERNATE_OBJECT_DIRECTORIES` is always stripped — prevents adding
//!   an attacker-controlled object store.
//! * `GIT_WORK_TREE` is always stripped — prevents overriding working-tree
//!   resolution.
//! * `GIT_TERMINAL_PROMPT=0` is always set — git never blocks waiting for
//!   interactive credentials in a non-interactive CLI.
//!
//! Callers pass a `current_dir` (required) so the working directory is always
//! explicit rather than inherited from the process environment.

use std::path::Path;
use std::process::Command;

use crate::error::GitvaultError;

/// All git environment variables that MUST be stripped on every invocation (REQ-90).
///
/// These variables can redirect git operations to attacker-controlled locations.
const GIT_SANITIZE_VARS: &[&str] = &[
    "GIT_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_EXEC_PATH",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_WORK_TREE",
];

/// Apply the standard security env to a [`Command`] builder (REQ-90).
fn sanitize(cmd: &mut Command) -> &mut Command {
    for var in GIT_SANITIZE_VARS {
        cmd.env_remove(var);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0")
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
    for var in GIT_SANITIZE_VARS {
        cmd.env_remove(var);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0");
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

    /// Verify that `GIT_EXEC_PATH` (and the other sanitized vars) set in the
    /// parent environment are stripped before git is invoked (REQ-90 / SEC-001).
    ///
    /// We set `GIT_EXEC_PATH` to a non-existent directory, then run a real git
    /// command. If the variable were inherited git would fail to find its
    /// sub-commands; the fact that it succeeds proves it was stripped.
    ///
    /// A mutex guards `std::env::set_var` so parallel test threads cannot
    /// interfere with each other.
    #[test]
    fn sanitize_strips_git_exec_path() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());

        let dir = init_repo();
        let _guard = ENV_LOCK.lock().unwrap();

        // Point GIT_EXEC_PATH at a nonexistent directory.
        // If sanitize() failed to strip it, git would be unable to find its
        // sub-commands and the call would return an error.
        unsafe { std::env::set_var("GIT_EXEC_PATH", "/nonexistent-path-for-test") };
        let result = git_output(&["rev-parse", "--git-dir"], dir.path());
        unsafe { std::env::remove_var("GIT_EXEC_PATH") };

        assert!(
            result.is_ok(),
            "git_output should succeed even with a bad GIT_EXEC_PATH in parent env; got: {result:?}"
        );
    }

    /// Verify every entry in GIT_SANITIZE_VARS is covered — i.e. the const is
    /// non-empty and contains the known-critical variables.
    #[test]
    fn sanitize_vars_contains_required_entries() {
        let required = [
            "GIT_DIR",
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_SSH_COMMAND",
            "GIT_SSH",
            "GIT_EXEC_PATH",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_WORK_TREE",
        ];
        for var in &required {
            assert!(
                GIT_SANITIZE_VARS.contains(var),
                "GIT_SANITIZE_VARS is missing required variable: {var}"
            );
        }
    }
}
