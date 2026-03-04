//! File-system utility helpers used throughout gitvault.
//!
//! These helpers encode the canonical patterns for safe file I/O:
//! atomic writes via temp-file-then-rename, contextual read errors, and
//! idempotent directory creation.
//!
//! # Adoption notes
//! - [`atomic_write`] and [`ensure_dir`] are actively used at new call sites.
//! - [`read_text`] is available for gradual adoption; existing call sites are
//!   migrated incrementally. // Gradually adopted: see NFR-002 for migration plan

use std::path::Path;

use crate::error::GitvaultError;

/// Atomically write `data` to `path` using a temp file + rename in the same directory.
///
/// This is the canonical pattern used throughout gitvault for safe file writes.
/// The rename is atomic on POSIX systems and best-effort on Windows, so readers
/// never see a partially written file.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the temp file cannot be created, the data
/// cannot be written, or the rename fails.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), GitvaultError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(GitvaultError::Io)?;
    use std::io::Write;
    tmp.write_all(data).map_err(GitvaultError::Io)?;
    tmp.persist(path).map_err(|e| GitvaultError::Io(e.error))?;
    Ok(())
}

/// Read a file to a UTF-8 string with a contextual error message including the path.
///
/// Wraps [`std::fs::read_to_string`] and decorates the error with the file path
/// so callers get actionable messages without having to add context themselves.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the file cannot be opened or is not valid
/// UTF-8, with the file path included in the error message.
///
/// # Adoption
///
/// Gradually adopted: see NFR-002 for migration plan.
pub fn read_text(path: &Path) -> Result<String, GitvaultError> {
    std::fs::read_to_string(path).map_err(|e| {
        GitvaultError::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        ))
    })
}

/// Create a directory and all parents; idempotent (succeeds if already exists).
///
/// Wraps [`std::fs::create_dir_all`] with a contextual error message that
/// includes the path, so callers get actionable messages without adding context.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the directory (or any parent) cannot be
/// created, with the target path included in the error message.
pub fn ensure_dir(path: &Path) -> Result<(), GitvaultError> {
    std::fs::create_dir_all(path).map_err(|e| {
        GitvaultError::Io(std::io::Error::new(
            e.kind(),
            format!("create_dir_all {}: {e}", path.display()),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{NamedTempFile, TempDir};

    // ── atomic_write ──────────────────────────────────────────────────────────

    #[test]
    fn atomic_write_roundtrip() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp); // remove the file so atomic_write creates it fresh

        atomic_write(&path, b"hello world").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);

        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_missing_parent_returns_io_error() {
        let bad = std::path::Path::new("/nonexistent_dir_abc123/file.txt");
        let err = atomic_write(bad, b"data").unwrap_err();
        assert!(
            matches!(err, GitvaultError::Io(_)),
            "expected Io error, got: {err}"
        );
    }

    // ── read_text ─────────────────────────────────────────────────────────────

    #[test]
    fn read_text_returns_file_contents() {
        let mut tmp = NamedTempFile::new().unwrap();
        use std::io::Write;
        tmp.write_all(b"hello\nworld").unwrap();
        let path = tmp.path().to_path_buf();
        assert_eq!(read_text(&path).unwrap(), "hello\nworld");
    }

    #[test]
    fn read_text_missing_file_includes_path_in_error() {
        let path = std::path::Path::new("/no/such/file.txt");
        let err = read_text(path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/no/such/file.txt"),
            "error should include path, got: {msg}"
        );
    }

    // ── ensure_dir ────────────────────────────────────────────────────────────

    #[test]
    fn ensure_dir_creates_nested_dirs() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("a").join("b").join("c");
        ensure_dir(&target).unwrap();
        assert!(target.is_dir());
    }

    #[test]
    fn ensure_dir_is_idempotent() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("x");
        ensure_dir(&target).unwrap();
        ensure_dir(&target).unwrap(); // second call must not fail
        assert!(target.is_dir());
    }

    #[test]
    fn ensure_dir_error_includes_path() {
        // On Linux a file cannot have children, so this forces a failure.
        let tmp = NamedTempFile::new().unwrap();
        let impossible = tmp.path().join("child");
        let err = ensure_dir(&impossible).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("create_dir_all"),
            "error should include context, got: {msg}"
        );
    }
}
