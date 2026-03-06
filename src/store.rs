//! Store path computation for `.gitvault/store/` layout.
//!
//! This module provides [`compute_store_path`], which maps a source file path
//! to its canonical encrypted artifact path under `.gitvault/store/<env>/`,
//! mirroring the source's directory structure relative to the repository root.

use std::path::{Component, Path, PathBuf};

use crate::error::GitvaultError;
use crate::path_utils::{make_repo_relative, normalize_for_comparison};

/// Compute the store path for `source` under `.gitvault/store/<env>/`.
///
/// Returns `<repo_root>/.gitvault/store/<env>/<relative-source-path>.age`,
/// where `<relative-source-path>` is the path of `source` relative to
/// `repo_root`.
///
/// Path normalization is **lexical** — `.` and `..` components are resolved
/// using [`Path::components`] without any filesystem access.
/// [`std::fs::canonicalize`] is **not** used.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if the (lexically normalized) path of
/// `source` is outside `repo_root` (i.e. the relative path would start with
/// `..`).
pub fn compute_store_path(
    source: &Path,
    env: &str,
    repo_root: &Path,
) -> Result<PathBuf, GitvaultError> {
    // Make source absolute if relative (using current working directory).
    let abs_source = if source.is_absolute() {
        source.to_path_buf()
    } else {
        std::env::current_dir()?.join(source)
    };

    // Use normalize_for_comparison so that Windows short names (RUNNER~1 ↔
    // runneradmin) and mixed path separators are resolved before comparison.
    let norm_source = normalize_for_comparison(&abs_source);
    let norm_root = normalize_for_comparison(repo_root);

    let rel = norm_source.strip_prefix(&norm_root).map_err(|_| {
        GitvaultError::Usage(format!(
            "source file '{}' is outside the repository root; path must be within the repo for store mirroring.",
            source.display()
        ))
    })?;

    // Guard: after strip_prefix the relative path must not escape the root.
    if rel.components().next() == Some(Component::ParentDir) {
        return Err(GitvaultError::Usage(format!(
            "source file '{}' is outside the repository root; path must be within the repo for store mirroring.",
            source.display()
        )));
    }

    let filename = rel
        .file_name()
        .ok_or_else(|| GitvaultError::Usage("Invalid file path".to_string()))?
        .to_string_lossy();
    let out_name = format!("{filename}.age");

    let store_base = normalize_for_comparison(repo_root).join(".gitvault").join("store").join(env);

    match rel.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            Ok(store_base.join(parent).join(out_name))
        }
        _ => Ok(store_base.join(out_name)),
    }
}

/// Resolve an input `<FILE>` argument to an absolute `.age` store path.
///
/// Applies the two-part explicit-store-path check (REQ-114 AC2):
/// - If `input` has the `.age` extension **and** its repo-relative path begins
///   with `.gitvault/store/`, it is treated as an explicit store path and
///   returned directly (made absolute relative to `repo_root` if needed).
/// - Otherwise, `input` is treated as a source path: [`compute_store_path`] is
///   called to derive the mirrored store path, and the result is verified to
///   exist on disk.
///
/// All path operations use canonicalisation for comparisons and lexical
/// normalisation for output path construction.
///
/// # Errors
///
/// Returns [`GitvaultError::NotFound`] with the AC5 message when the derived
/// store path does not exist on disk.
/// Returns [`GitvaultError::Usage`] (via [`compute_store_path`]) if the source
/// path escapes the repository root.
pub fn resolve_store_path(
    input: &Path,
    env: &str,
    repo_root: &Path,
) -> Result<PathBuf, GitvaultError> {
    // Compute the repo-relative form of `input` for the two-part check.
    // For absolute paths: strip the repo root prefix (canonicalised).
    // For relative paths: use as-is.
    let repo_relative: PathBuf = make_repo_relative(input, repo_root);

    let has_age_ext = repo_relative.extension().is_some_and(|e| e == "age");
    let under_store = repo_relative.starts_with(".gitvault/store/");

    if has_age_ext && under_store {
        // Explicit store path: return absolute form.
        let abs = if input.is_absolute() {
            input.to_path_buf()
        } else {
            repo_root.join(input)
        };
        return Ok(abs);
    }

    // Source path: compute and verify.
    let derived = compute_store_path(input, env, repo_root)?;
    if !derived.exists() {
        return Err(GitvaultError::NotFound(format!(
            "No encrypted archive found for '{}' in environment '{}'. Run 'gitvault encrypt {} --env {}' to create it.",
            input.display(),
            env,
            input.display(),
            env,
        )));
    }
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_compute_store_path_flat_file() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let source = repo_root.join("app.env");

        let result = compute_store_path(&source, "dev", repo_root).unwrap();

        assert_eq!(result, repo_root.join(".gitvault/store/dev/app.env.age"));
    }

    #[test]
    fn test_compute_store_path_nested_file() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let source = repo_root.join("services/auth/config.json");

        let result = compute_store_path(&source, "prod", repo_root).unwrap();

        assert_eq!(
            result,
            repo_root.join(".gitvault/store/prod/services/auth/config.json.age")
        );
    }

    #[test]
    fn test_compute_store_path_outside_repo_errors() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let outside = TempDir::new().unwrap();
        let source = outside.path().join("secret.env");

        let err = compute_store_path(&source, "dev", repo_root)
            .expect_err("outside-repo path should fail");

        assert!(matches!(err, GitvaultError::Usage(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("outside the repository root"),
            "error should mention repository root: {msg}"
        );
    }

    #[test]
    fn test_compute_store_path_dotdot_relative_outside_repo_errors() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path().join("subrepo");
        // source is lexically above repo_root via ".."
        let source = repo_root.join("../../outside.txt");

        let err = compute_store_path(&source, "dev", &repo_root)
            .expect_err("path escaping via .. should fail");

        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_compute_store_path_mirrored_env() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let source = repo_root.join("infra/k8s/deployment.yaml");

        let result = compute_store_path(&source, "staging", repo_root).unwrap();

        assert_eq!(
            result,
            repo_root.join(".gitvault/store/staging/infra/k8s/deployment.yaml.age")
        );
    }

    // ── resolve_store_path tests (AC10) ───────────────────────────────────────

    #[test]
    fn test_resolve_store_path_source_path_maps_to_correct_age_path() {
        // AC10: source-path resolution → correct mirrored .age store path
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        // Create the expected store file so the exists-check passes.
        let store_dir = repo_root.join(".gitvault/store/prod/services/auth");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::write(store_dir.join("config.json.age"), b"").unwrap();

        let source = repo_root.join("services/auth/config.json");
        let result = resolve_store_path(&source, "prod", repo_root).unwrap();

        assert_eq!(
            result,
            repo_root.join(".gitvault/store/prod/services/auth/config.json.age")
        );
    }

    #[test]
    fn test_resolve_store_path_absolute_age_store_path_is_explicit() {
        // AC10: absolute .age store path under repo root → recognised as explicit store path
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let store_path = repo_root.join(".gitvault/store/dev/app.env.age");

        // The explicit store path is returned as-is (absolute), without an existence check.
        let result = resolve_store_path(&store_path, "dev", repo_root).unwrap();
        assert_eq!(result, store_path);
    }

    #[test]
    fn test_resolve_store_path_source_not_found_returns_not_found_error() {
        // AC5: derived path doesn't exist → NotFound error with correct message
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let source = repo_root.join("missing.env");

        let err = resolve_store_path(&source, "dev", repo_root)
            .expect_err("missing store path should produce NotFound");

        assert!(
            matches!(err, GitvaultError::NotFound(_)),
            "expected NotFound, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("No encrypted archive found"),
            "error should mention AC5 message: {msg}"
        );
        assert!(
            msg.contains("gitvault encrypt"),
            "error should suggest encrypt command: {msg}"
        );
    }

    #[test]
    fn test_resolve_store_path_relative_age_path_not_under_store_is_source() {
        // An .age file that does NOT start with .gitvault/store/ is treated as source path.
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        // Absolute path inside the repo that has .age extension but is NOT under .gitvault/store/
        // → source path resolution → store file doesn't exist → NotFound.
        let source = repo_root.join("backup/config.json.age");
        let err = resolve_store_path(&source, "dev", repo_root)
            .expect_err("non-store .age path should be treated as source and fail");

        assert!(
            matches!(err, GitvaultError::NotFound(_)),
            "expected NotFound, got: {err:?}"
        );
    }

    // ── lexical_normalize: CurDir branch (line 17) ───────────────────────────

    #[test]
    fn test_compute_store_path_with_curdur_component_is_stripped() {
        // A source path containing a `.` (CurDir) component — lexical_normalize must
        // strip it so the path resolves correctly.  PathBuf::join does NOT normalise,
        // so repo_root.join("./file.txt") really keeps the `.` component.
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        // repo_root.join("./file.txt") → absolute path with a CurDir component.
        // lexical_normalize strips it → same as repo_root.join("file.txt").
        let source = repo_root.join("./file.txt");
        let result = compute_store_path(&source, "dev", repo_root).unwrap();
        assert_eq!(result, repo_root.join(".gitvault/store/dev/file.txt.age"));
    }

    #[test]
    fn test_compute_store_path_nested_curdur_components_are_stripped() {
        // Multiple CurDir components interspersed with Normal components.
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let source = repo_root.join("./sub/./dir/./file.txt");
        let result = compute_store_path(&source, "prod", repo_root).unwrap();
        assert_eq!(
            result,
            repo_root.join(".gitvault/store/prod/sub/dir/file.txt.age")
        );
    }

    // ── lexical_normalize: ParentDir at non-Normal boundary (lines 25-27) ────

    #[test]
    fn test_compute_store_path_parentdir_immediately_after_root_errors() {
        // An absolute path whose first component after the root prefix is `..`
        // (e.g. `/../subdir/file.txt`) cannot be stripped by any sane repo root,
        // so `strip_prefix` fails and `compute_store_path` returns Usage error.
        // During normalisation the `..` after root triggers lines 25-27 in
        // `lexical_normalize` (ParentDir with no preceding Normal component to pop).
        let repo_root = std::path::Path::new("/tmp/gitvault_parentdir_test");
        let source = std::path::Path::new("/../tmp/gitvault_parentdir_test/file.txt");
        // `lexical_normalize` runs lines 25-27 for the `..` after `/`.
        // The normalised path then fails strip_prefix → Usage error.
        let err = compute_store_path(source, "dev", repo_root)
            .expect_err("path with .. immediately after root should error");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error, got: {err:?}"
        );
    }

    // ── resolve_store_path: relative explicit .age path (line 142) ──────────

    #[test]
    fn test_resolve_store_path_relative_explicit_age_path_returns_joined() {
        // A *relative* .age path that starts with `.gitvault/store/` is treated as an
        // explicit store path.  Because it is NOT absolute, line 142 executes:
        //   `repo_root.join(input)`.
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        // Relative input: not absolute, has .age extension, under .gitvault/store/.
        let input = std::path::Path::new(".gitvault/store/staging/app.env.age");
        let result = resolve_store_path(input, "staging", repo_root).unwrap();
        assert_eq!(
            result,
            repo_root.join(".gitvault/store/staging/app.env.age"),
            "relative explicit store path should be joined with repo_root"
        );
    }
}
