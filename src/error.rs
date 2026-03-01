use thiserror::Error;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PLAINTEXT_LEAK: i32 = 3;
pub const EXIT_DECRYPT_ERROR: i32 = 4;

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
        }
    }
}
