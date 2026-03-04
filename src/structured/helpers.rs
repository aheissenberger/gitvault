use crate::error::GitvaultError;
use std::path::Path;

pub(super) const AGE_ARMOR_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
/// Prefix used for single-line encrypted values in .env value-only mode.
pub(super) const ENV_ENC_PREFIX: &str = "age:";

pub fn is_age_armor(value: &str) -> bool {
    value.trim_start().starts_with(AGE_ARMOR_HEADER)
}

pub(super) fn is_env_encrypted(value: &str) -> bool {
    value.starts_with(ENV_ENC_PREFIX)
}

/// Write bytes to file atomically using a temp file + rename.
/// Delegates to [`crate::fs_util::atomic_write`] — the canonical implementation.
pub(super) fn atomic_write(path: &Path, data: &[u8]) -> Result<(), GitvaultError> {
    crate::fs_util::atomic_write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_is_age_armor_true() {
        assert!(is_age_armor("-----BEGIN AGE ENCRYPTED FILE-----\nrest"));
    }

    #[test]
    fn test_is_age_armor_false() {
        assert!(!is_age_armor("plain text"));
    }

    #[test]
    fn test_is_env_encrypted_true() {
        assert!(is_env_encrypted("age:some_ciphertext"));
    }

    #[test]
    fn test_is_env_encrypted_false() {
        assert!(!is_env_encrypted("plain_value"));
    }

    #[test]
    fn test_atomic_write_roundtrip() {
        let tmp = NamedTempFile::with_suffix(".dat").unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp); // delete the file so atomic_write can create it fresh

        atomic_write(&path, b"hello world").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
    }

    #[test]
    fn test_atomic_write_new_in_fails_for_missing_dir() {
        // Passing a path whose parent directory does not exist forces
        // NamedTempFile::new_in to fail, covering the ? error branch.
        let bad_path = std::path::Path::new("/nonexistent_dir_abc123/file.txt");
        let err = atomic_write(bad_path, b"data").unwrap_err();
        // The error should be an IO error (directory not found)
        assert!(
            matches!(err, GitvaultError::Io(_)),
            "expected Io error, got: {err}"
        );
    }
}
