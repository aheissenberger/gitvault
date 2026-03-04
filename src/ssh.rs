//! Centralised SSH subprocess helpers (REQ-98).
//!
//! Every production call to `ssh-add` or `ssh-keygen` goes through one of the
//! functions here so that security-relevant defaults are applied in one place:
//!
//! * `SSH_ASKPASS_REQUIRE=never` is always set — prevents `ssh-add`/`ssh-keygen`
//!   from blocking on an interactive passphrase prompt in CI or non-terminal
//!   contexts.  Without this, `ssh-keygen -l` on a passphrase-protected key can
//!   hang indefinitely.
//!
//! Platform note: `ssh-add` and `ssh-keygen` are part of OpenSSH, which ships
//! on Linux, macOS, and Windows (since Windows 10 1809 / Server 2019). The
//! binary names are identical on all three platforms.

use std::path::Path;
use std::process::Command;

/// Error type for SSH agent / keygen operations.
#[derive(Debug)]
pub enum SshError {
    /// The binary (`ssh-add` or `ssh-keygen`) could not be spawned.
    NotAvailable(String),
    /// The binary ran but exited with a non-zero status.
    Failed(String),
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable(msg) => write!(f, "SSH tool not available: {msg}"),
            Self::Failed(msg) => write!(f, "SSH tool failed: {msg}"),
        }
    }
}

/// Apply the standard security env to an SSH [`Command`] builder (REQ-98).
fn sanitize(cmd: &mut Command) -> &mut Command {
    // SSH_ASKPASS_REQUIRE=never: never block waiting for interactive input.
    cmd.env("SSH_ASKPASS_REQUIRE", "never")
}

/// Run `ssh-add -l -E sha256` and return raw stdout bytes.
///
/// Returns [`SshError::NotAvailable`] when `ssh-add` cannot be spawned (binary
/// absent or no `SSH_AUTH_SOCK`). Callers are responsible for parsing the output.
///
/// # Errors
///
/// Returns an error when `ssh-add` cannot be spawned.
pub fn ssh_add_list_keys() -> Result<Vec<u8>, SshError> {
    let mut cmd = Command::new("ssh-add");
    sanitize(&mut cmd);
    cmd.args(["-l", "-E", "sha256"])
        .output()
        .map(|o| o.stdout)
        .map_err(|e| SshError::NotAvailable(format!("ssh-add not available: {e}")))
}

/// Run `ssh-keygen -l -E sha256 -f <path>` and return the output line.
///
/// Returns `None` when `ssh-keygen` cannot be spawned, exits non-zero, or the
/// output is empty. The returned string is the raw first line of stdout, which
/// contains the fingerprint (e.g. `"256 SHA256:abc… comment (ED25519)"`).
///
/// Note: this function intentionally does not error — callers use it as a
/// predicate (does this file's fingerprint match?) so `None` is the natural
/// "no match / unavailable" signal.
pub fn ssh_keygen_fingerprint(path: &Path) -> Option<String> {
    let mut cmd = Command::new("ssh-keygen");
    sanitize(&mut cmd);
    cmd.args(["-l", "-E", "sha256", "-f"])
        .arg(path)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_add_list_keys_returns_bytes_or_err() {
        // Either Ok (agent running) or Err::NotAvailable (no agent in CI).
        // We only verify the function doesn't panic.
        let _ = ssh_add_list_keys();
    }

    #[test]
    fn ssh_keygen_fingerprint_nonexistent_path_returns_none() {
        let result = ssh_keygen_fingerprint(Path::new("/no/such/key/file.pem"));
        assert!(result.is_none());
    }

    #[test]
    fn ssh_keygen_fingerprint_directory_returns_none() {
        // A directory is not a valid key file.
        let result = ssh_keygen_fingerprint(Path::new("/tmp"));
        assert!(result.is_none());
    }

    #[test]
    fn ssh_error_display_not_available_contains_context() {
        let err = SshError::NotAvailable("missing binary".to_string());
        let rendered = err.to_string();
        assert!(rendered.contains("SSH tool not available"));
        assert!(rendered.contains("missing binary"));
    }

    #[test]
    fn ssh_error_display_failed_contains_context() {
        let err = SshError::Failed("non-zero exit".to_string());
        let rendered = err.to_string();
        assert!(rendered.contains("SSH tool failed"));
        assert!(rendered.contains("non-zero exit"));
    }

    #[test]
    fn ssh_error_debug_includes_variant_name() {
        let err = SshError::Failed("boom".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Failed"));
    }
}
