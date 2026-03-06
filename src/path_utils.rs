//! Shared path utilities for gitvault.
//!
//! Centralises path normalisation and repo-relative path computation so that
//! all modules (`store`, `commands::decrypt`, …) behave identically.
//!
//! ## Design
//!
//! Two distinct normalisation strategies are provided:
//!
//! - [`lexical_normalize`] — resolves `.` and `..` components **without**
//!   any filesystem access.  Used for *output* path construction where
//!   following symlinks or resolving short names is undesirable.
//!
//! - [`normalize_for_comparison`] — resolves the path via
//!   [`dunce::canonicalize`] (which expands short names on Windows and
//!   strips the `\\?\` UNC prefix) when the path exists on disk, falling
//!   back to the parent-directory or lexical strategy when it does not.
//!   Used for *prefix comparisons* that must be stable across different
//!   representations of the same path (e.g. `RUNNER~1` vs `runneradmin`
//!   on Windows CI).
//!
//! - [`make_repo_relative`] — converts an absolute path to its
//!   repo-relative form using [`normalize_for_comparison`] for the
//!   strip-prefix check.

use std::path::{Component, Path, PathBuf};

/// Lexically normalise a path by resolving `.` and `..` components without
/// any filesystem access (`canonicalize` is **not** called).
///
/// On Windows this also normalises path separators (both `/` and `\` are
/// accepted as input via [`Path::components`]; output uses the OS-native
/// separator via [`PathBuf::push`]).
///
/// # Examples
///
/// ```ignore
/// let p = Path::new("/repo/./svc/../svc/config.json");
/// assert_eq!(lexical_normalize(p), PathBuf::from("/repo/svc/config.json"));
/// ```
pub(crate) fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match result.components().next_back() {
                Some(Component::Normal(_)) => {
                    result.pop();
                }
                _ => {
                    result.push(component);
                }
            },
            c => result.push(c),
        }
    }
    result
}

/// Canonicalise a path for prefix comparison, resolving short names and
/// mixed separators without leaving the `\\?\` UNC prefix on Windows.
///
/// Strategy (in order):
/// 1. Try [`dunce::canonicalize`] on `path` itself (succeeds when the full
///    path exists on disk — covers both file and directory targets).
/// 2. Walk up the path tree until an existing ancestor is found, canonicalize
///    that ancestor, then reattach the non-existing suffix.  This handles
///    deeply nested paths that don't exist yet (e.g. an encrypted artifact
///    several directories deep that hasn't been created yet), resolving any
///    short names (`RUNNER~1` → `runneradmin`) in the existing portion.
/// 3. Last resort: fall back to [`lexical_normalize`].
///
/// On Unix the function is essentially a thin wrapper around
/// [`dunce::canonicalize`] with the same fallback logic; there are no short
/// names so the result is identical to what `canonicalize` would produce.
pub(crate) fn normalize_for_comparison(path: &Path) -> PathBuf {
    if let Ok(canonical) = dunce::canonicalize(path) {
        return canonical;
    }
    // Walk up the directory tree to find the deepest existing ancestor, then
    // reattach the non-existing suffix so short-name components in the
    // existing part are resolved (e.g. RUNNER~1 → runneradmin on Windows CI).
    let mut current = path.to_path_buf();
    let mut suffix = PathBuf::new();
    loop {
        let Some(parent) = current.parent().filter(|p| *p != current) else {
            break;
        };
        let file_name = match current.file_name() {
            Some(n) => PathBuf::from(n),
            None => break,
        };
        suffix = if suffix.as_os_str().is_empty() {
            file_name
        } else {
            file_name.join(&suffix)
        };
        current = parent.to_path_buf();
        if let Ok(canonical) = dunce::canonicalize(&current) {
            return canonical.join(&suffix);
        }
    }
    lexical_normalize(path)
}

/// Convert `input` to a path relative to `repo_root`.
///
/// - If `input` is **absolute**, both `input` and `repo_root` are normalised
///   via [`normalize_for_comparison`] before stripping the prefix.  If the
///   strip fails (i.e. `input` is genuinely outside `repo_root`), `input` is
///   returned unchanged as an absolute path.
/// - If `input` is **relative**, it is returned as-is.
pub(crate) fn make_repo_relative(input: &Path, repo_root: &Path) -> PathBuf {
    if input.is_absolute() {
        let norm_input = normalize_for_comparison(input);
        let norm_root = normalize_for_comparison(repo_root);
        norm_input
            .strip_prefix(&norm_root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| input.to_path_buf())
    } else {
        input.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── lexical_normalize ─────────────────────────────────────────────────────

    #[test]
    fn lexical_normalize_strips_cur_dir() {
        let p = Path::new("a/./b/./c.txt");
        assert_eq!(lexical_normalize(p), PathBuf::from("a/b/c.txt"));
    }

    #[test]
    fn lexical_normalize_resolves_parent_dir() {
        let p = Path::new("a/b/../c.txt");
        assert_eq!(lexical_normalize(p), PathBuf::from("a/c.txt"));
    }

    #[test]
    fn lexical_normalize_parent_dir_at_root_preserved() {
        // A leading `..` on a relative path cannot be collapsed further.
        let p = Path::new("../outside/file.txt");
        assert_eq!(lexical_normalize(p), PathBuf::from("../outside/file.txt"));
    }

    // ── make_repo_relative ────────────────────────────────────────────────────

    /// Relative path is returned unchanged.
    #[test]
    fn make_repo_relative_relative_path_unchanged() {
        let repo = Path::new("/some/repo");
        let input = Path::new("svc/config.json");
        assert_eq!(
            make_repo_relative(input, repo),
            PathBuf::from("svc/config.json")
        );
    }

    /// Absolute path inside the repo → stripped to repo-relative form.
    ///
    /// Uses real temp directories so that `normalize_for_comparison` can call
    /// `dunce::canonicalize` successfully.
    #[test]
    fn make_repo_relative_absolute_inside_repo() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        let nested = repo.join("svc").join("config.json");
        // Create the parent dir so canonicalize can resolve the parent.
        std::fs::create_dir_all(repo.join("svc")).unwrap();
        let result = make_repo_relative(&nested, repo);
        // The result must be the 2-component relative path.
        assert_eq!(
            result.components().count(),
            2,
            "expected 2 components, got: {result:?}"
        );
        assert_eq!(result, PathBuf::from("svc").join("config.json"));
    }

    /// Absolute path **outside** the repo → returned as-is (absolute fallback).
    #[test]
    fn make_repo_relative_absolute_outside_repo_fallback() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let repo = dir1.path();
        let outside = dir2.path().join("file.txt");
        let result = make_repo_relative(&outside, repo);
        // Cannot strip → should return the original absolute path unchanged.
        assert!(
            result.is_absolute(),
            "should return absolute fallback, got: {result:?}"
        );
    }

    // ── normalize_for_comparison ──────────────────────────────────────────────

    #[test]
    fn normalize_for_comparison_existing_dir_resolves() {
        let dir = TempDir::new().unwrap();
        // The temp dir definitely exists; normalize_for_comparison must resolve it.
        let result = normalize_for_comparison(dir.path());
        // Result must be absolute.
        assert!(
            result.is_absolute(),
            "expected absolute path, got: {result:?}"
        );
    }

    #[test]
    fn normalize_for_comparison_nonexistent_file_uses_parent() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("does_not_exist.txt");
        // File doesn't exist; the parent (TempDir) does.
        let result = normalize_for_comparison(&file);
        assert!(
            result.is_absolute(),
            "expected absolute path, got: {result:?}"
        );
        assert_eq!(result.file_name().unwrap(), "does_not_exist.txt");
    }
}
