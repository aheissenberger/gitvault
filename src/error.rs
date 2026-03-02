use thiserror::Error;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PLAINTEXT_LEAK: i32 = 3;
pub const EXIT_DECRYPT_ERROR: i32 = 4;
pub const EXIT_BARRIER: i32 = 5;

#[derive(Error, Debug)]
pub enum GitvaultError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Plaintext secret detected in tracked files: {0}")]
    PlaintextLeak(String),
    #[error("Invalid argument: {0}")]
    Usage(String),
    #[error("{0}")]
    Other(String),
    #[error("Production barrier not satisfied: {0}")]
    BarrierNotSatisfied(String),
}

impl GitvaultError {
    pub fn exit_code(&self) -> i32 {
        match self {
            GitvaultError::Io(_) => EXIT_ERROR,
            GitvaultError::Encryption(_) => EXIT_ERROR,
            GitvaultError::Decryption(_) => EXIT_DECRYPT_ERROR,
            GitvaultError::PlaintextLeak(_) => EXIT_PLAINTEXT_LEAK,
            GitvaultError::Usage(_) => EXIT_USAGE,
            GitvaultError::Other(_) => EXIT_ERROR,
            GitvaultError::BarrierNotSatisfied(_) => EXIT_BARRIER,
        }
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

        assert_eq!(io_err.exit_code(), EXIT_ERROR);
        assert_eq!(enc_err.exit_code(), EXIT_ERROR);
        assert_eq!(dec_err.exit_code(), EXIT_DECRYPT_ERROR);
        assert_eq!(leak_err.exit_code(), EXIT_PLAINTEXT_LEAK);
        assert_eq!(usage_err.exit_code(), EXIT_USAGE);
        assert_eq!(other_err.exit_code(), EXIT_ERROR);
        assert_eq!(barrier_err.exit_code(), EXIT_BARRIER);
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
