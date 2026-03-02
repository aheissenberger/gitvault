use thiserror::Error;

use crate::fhsm::FhsmError;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PLAINTEXT_LEAK: i32 = 3;
pub const EXIT_DECRYPT_ERROR: i32 = 4;
pub const EXIT_BARRIER: i32 = 5;
/// Exit code for drift: files have changed since encryption (distinct from plaintext leak).
pub const EXIT_DRIFT: i32 = 6;

#[derive(Error, Debug)]
pub enum GitvaultError {
    /// Wraps a standard I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// An error occurred during encryption of secret material.
    #[error("Encryption error: {0}")]
    Encryption(String),
    /// An error occurred during decryption of secret material.
    #[error("Decryption error: {0}")]
    Decryption(String),
    /// A plaintext secret was detected in a git-tracked file.
    #[error("Plaintext secret detected in tracked files: {0}")]
    PlaintextLeak(String),
    /// The caller supplied an invalid argument or flag combination.
    #[error("Invalid argument: {0}")]
    Usage(String),
    /// A catch-all error variant for miscellaneous failures.
    #[error("{0}")]
    Other(String),
    /// The production barrier condition was not met.
    #[error("Production barrier not satisfied: {0}")]
    BarrierNotSatisfied(String),
    /// An error occurred while accessing the system keyring.
    #[error("Keyring error: {0}")]
    Keyring(String),
    /// A drift between encrypted and plaintext secrets was detected.
    #[error("Drift detected: {0}")]
    Drift(String),
}

impl GitvaultError {
    /// Map the error variant to a POSIX exit code for the CLI process.
    ///
    /// Callers use this to propagate structured exit codes to the shell so
    /// scripts can distinguish encryption failures from permission errors, etc.
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Decryption(_) => EXIT_DECRYPT_ERROR,
            Self::PlaintextLeak(_) => EXIT_PLAINTEXT_LEAK,
            Self::Usage(_) => EXIT_USAGE,
            Self::BarrierNotSatisfied(_) => EXIT_BARRIER,
            Self::Drift(_) => EXIT_DRIFT,
            Self::Io(_) | Self::Encryption(_) | Self::Other(_) | Self::Keyring(_) => EXIT_ERROR,
        }
    }
}

impl From<FhsmError> for GitvaultError {
    fn from(e: FhsmError) -> Self {
        Self::Usage(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_map_correctly() {
        let io_err = GitvaultError::Io(std::io::Error::other("io"));
        let enc_err = GitvaultError::Encryption("enc".to_string());
        let dec_err = GitvaultError::Decryption("dec".to_string());
        let leak_err = GitvaultError::PlaintextLeak(".env".to_string());
        let usage_err = GitvaultError::Usage("usage".to_string());
        let other_err = GitvaultError::Other("other".to_string());
        let barrier_err = GitvaultError::BarrierNotSatisfied("barrier".to_string());
        let keyring_err = GitvaultError::Keyring("keyring".to_string());
        let drift_err = GitvaultError::Drift("drift".to_string());

        assert_eq!(io_err.exit_code(), EXIT_ERROR);
        assert_eq!(enc_err.exit_code(), EXIT_ERROR);
        assert_eq!(dec_err.exit_code(), EXIT_DECRYPT_ERROR);
        assert_eq!(leak_err.exit_code(), EXIT_PLAINTEXT_LEAK);
        assert_eq!(usage_err.exit_code(), EXIT_USAGE);
        assert_eq!(other_err.exit_code(), EXIT_ERROR);
        assert_eq!(barrier_err.exit_code(), EXIT_BARRIER);
        assert_eq!(keyring_err.exit_code(), EXIT_ERROR);
        assert_eq!(drift_err.exit_code(), EXIT_DRIFT);
    }

    #[test]
    fn display_messages_include_context() {
        assert!(
            GitvaultError::Usage("bad arg".to_string())
                .to_string()
                .contains("Invalid argument")
        );
        assert!(
            GitvaultError::BarrierNotSatisfied("missing token".to_string())
                .to_string()
                .contains("Production barrier not satisfied")
        );
    }
}
