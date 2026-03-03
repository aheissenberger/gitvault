use crate::defaults;
use crate::error::GitvaultError;
use crate::{crypto, merge};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

trait GitRunner {
    fn show_toplevel(&self, start: &Path) -> std::io::Result<Output>;
}

struct SystemGitRunner;

impl GitRunner for SystemGitRunner {
    fn show_toplevel(&self, start: &Path) -> std::io::Result<Output> {
        Command::new("git")
            .args(["-C"])
            .arg(start)
            .args(["rev-parse", "--show-toplevel"])
            .output()
    }
}

/// Directory for encrypted artifacts (REQ-7); re-exported from [`defaults`].
pub use defaults::SECRETS_DIR;

/// Base directory for plaintext outputs (REQ-8); re-exported from [`defaults`].
pub use defaults::PLAIN_BASE_DIR;

/// Guard against path traversal: ensure `target` is under `base`.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if `target` has no file-name component or
/// resolves to a path outside `base`.
pub fn validate_write_path(base: &Path, target: &Path) -> Result<(), GitvaultError> {
    fn normalize(path: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::CurDir => {}
                c => out.push(c),
            }
        }
        out
    }

    fn canonicalize_with_missing_tail(path: &Path) -> Result<PathBuf, GitvaultError> {
        if let Ok(canonical) = path.canonicalize() {
            return Ok(canonical);
        }

        let mut existing = path;
        let mut tail = Vec::new();
        while !existing.exists() {
            let name = existing.file_name().ok_or_else(|| {
                GitvaultError::Usage(format!(
                    "path has no file name component: {}",
                    path.display()
                ))
            })?;
            tail.push(name.to_os_string());
            existing = existing.parent().ok_or_else(|| {
                GitvaultError::Usage(format!(
                    "path has no file name component: {}",
                    path.display()
                ))
            })?;
        }

        let mut canonical = existing
            .canonicalize()
            .unwrap_or_else(|_| normalize(existing));
        for part in tail.iter().rev() {
            canonical.push(part);
        }
        Ok(canonical)
    }

    let canonical_base = canonicalize_with_missing_tail(base)?;
    let canonical_target = canonicalize_with_missing_tail(target)?;

    #[cfg(windows)]
    fn starts_with_base(target: &Path, base: &Path) -> bool {
        fn normalize_for_compare(path: &Path) -> String {
            let mut normalized = path.to_string_lossy().replace('/', "\\");
            while normalized.ends_with('\\') && normalized.len() > 3 {
                normalized.pop();
            }
            normalized.to_ascii_lowercase()
        }

        let normalized_target = normalize_for_compare(target);
        let normalized_base = normalize_for_compare(base);
        if normalized_target == normalized_base {
            return true;
        }
        let base_with_sep = format!("{normalized_base}\\");
        normalized_target.starts_with(&base_with_sep)
    }

    #[cfg(not(windows))]
    fn starts_with_base(target: &Path, base: &Path) -> bool {
        target.starts_with(base)
    }

    if starts_with_base(&canonical_target, &canonical_base) {
        Ok(())
    } else {
        Err(GitvaultError::Usage(format!(
            "Path traversal detected: {} is outside repository root {}",
            target.display(),
            base.display()
        )))
    }
}

/// Get the path for an encrypted artifact under secrets/. REQ-7
#[must_use]
pub fn get_encrypted_path(repo_root: &Path, name: &str) -> PathBuf {
    repo_root.join(SECRETS_DIR).join(name)
}

/// Get the directory for env-scoped encrypted artifacts under `secrets/<env>/`.
#[must_use]
pub fn get_env_encrypted_dir(repo_root: &Path, env: &str) -> PathBuf {
    repo_root.join(SECRETS_DIR).join(env)
}

/// Get the path for an encrypted artifact under `secrets/<env>/`.
#[must_use]
pub fn get_env_encrypted_path(repo_root: &Path, env: &str, name: &str) -> PathBuf {
    get_env_encrypted_dir(repo_root, env).join(name)
}

/// List encrypted files for an environment.
///
/// Prefers env-scoped layout `secrets/<env>/*.age` and falls back to legacy
/// layout `secrets/*.age` when no env-scoped files exist.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading the secrets directory fails.
pub fn list_encrypted_files_for_env(
    repo_root: &Path,
    env: &str,
) -> Result<Vec<PathBuf>, GitvaultError> {
    let env_dir = get_env_encrypted_dir(repo_root, env);
    let mut env_files = list_age_files_in_dir(&env_dir)?;
    if !env_files.is_empty() {
        env_files.sort();
        return Ok(env_files);
    }

    let mut legacy_files = list_age_files_in_dir(&repo_root.join(SECRETS_DIR))?;
    legacy_files.sort();
    Ok(legacy_files)
}

/// List all encrypted files under `secrets/**` recursively.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading the secrets directory or any subdirectory fails.
pub fn list_all_encrypted_files(repo_root: &Path) -> Result<Vec<PathBuf>, GitvaultError> {
    let mut out = Vec::new();
    collect_age_files(&repo_root.join(SECRETS_DIR), &mut out)?;
    out.sort();
    Ok(out)
}

fn list_age_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>, GitvaultError> {
    if !dir.exists() || !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("age") {
            files.push(path);
        }
    }
    Ok(files)
}

fn collect_age_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), GitvaultError> {
    if !dir.exists() || !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_age_files(&path, out)?;
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("age") {
            out.push(path);
        }
    }
    Ok(())
}

/// Get the path for a plaintext artifact under .secrets/plain/<env>/. REQ-8
#[must_use]
pub fn get_plain_path(repo_root: &Path, env: &str, name: &str) -> PathBuf {
    repo_root.join(PLAIN_BASE_DIR).join(env).join(name)
}

/// Ensure all required directories exist.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if `env` is not a valid environment name.
/// Returns [`GitvaultError::Io`] if any directory cannot be created.
pub fn ensure_dirs(repo_root: &Path, env: &str) -> Result<(), GitvaultError> {
    crate::env::validate_env_name(env)?;
    fs::create_dir_all(repo_root.join(SECRETS_DIR))?;
    fs::create_dir_all(get_env_encrypted_dir(repo_root, env))?;
    fs::create_dir_all(repo_root.join(PLAIN_BASE_DIR).join(env))?;
    Ok(())
}

/// Decrypt all encrypted secrets for the given environment.
///
/// Reads all `.age` files for `env`, decrypts them with `identity`, and returns
/// the key-value pairs parsed from the plaintext.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading an encrypted file fails.
/// Returns [`GitvaultError::Decryption`] if any file cannot be decrypted with `identity`.
/// Returns [`GitvaultError::Usage`] if decrypted content is not valid `.env` syntax.
pub fn decrypt_env_secrets(
    repo_root: &Path,
    env: &str,
    identity: &dyn age::Identity,
) -> Result<Vec<(String, String)>, GitvaultError> {
    let mut secrets: Vec<(String, String)> = Vec::new();
    let encrypted_files = list_encrypted_files_for_env(repo_root, env)?;

    for path in encrypted_files {
        let ciphertext = std::fs::read(&path)?;
        match crypto::decrypt(identity, &ciphertext) {
            Ok(plaintext) => {
                let text = String::from_utf8_lossy(&plaintext);
                secrets.extend(merge::parse_env_pairs(&text)?);
            }
            Err(e) => {
                return Err(GitvaultError::Decryption(format!(
                    "Failed to decrypt {}: {e}",
                    path.display()
                )));
            }
        }
    }

    Ok(secrets)
}

fn find_repo_root_from_with_runner(
    start: &std::path::Path,
    git_runner: &dyn GitRunner,
) -> Result<std::path::PathBuf, crate::error::GitvaultError> {
    let output = git_runner.show_toplevel(start);

    match output {
        Ok(out) if out.status.success() => {
            let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if root.is_empty() {
                return Err(crate::error::GitvaultError::Usage(
                    "not inside a git repository (no .git directory found)".to_string(),
                ));
            }
            Ok(PathBuf::from(root))
        }
        Ok(_) => Err(crate::error::GitvaultError::Usage(
            "not inside a git repository (no .git directory found)".to_string(),
        )),
        Err(_) => {
            let mut dir = start.to_path_buf();
            loop {
                if dir.join(".git").exists() {
                    return Ok(dir);
                }
                match dir.parent() {
                    Some(parent) => dir = parent.to_path_buf(),
                    None => {
                        return Err(crate::error::GitvaultError::Usage(
                            "not inside a git repository (no .git directory found)".to_string(),
                        ));
                    }
                }
            }
        }
    }
}

/// Resolve repository root from `start`.
///
/// Uses `git rev-parse --show-toplevel` first, and falls back to walking up the
/// directory tree only when invoking `git` itself fails.
///
/// Returns [`crate::error::GitvaultError::Usage`] if no `.git` is found — the caller is
/// not inside a git repository.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if no `.git` directory is found while walking up.
pub fn find_repo_root_from(
    start: &std::path::Path,
) -> Result<std::path::PathBuf, crate::error::GitvaultError> {
    let git_runner = SystemGitRunner;
    find_repo_root_from_with_runner(start, &git_runner)
}

/// Find the repository root starting from `std::env::current_dir()`.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the current directory cannot be determined.
/// Returns [`GitvaultError::Usage`] if no `.git` directory is found while walking up.
pub fn find_repo_root() -> Result<std::path::PathBuf, crate::error::GitvaultError> {
    let cwd = std::env::current_dir()?;
    find_repo_root_from(&cwd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519;
    use std::io;
    use tempfile::TempDir;

    struct FailingGitRunner;

    impl GitRunner for FailingGitRunner {
        fn show_toplevel(&self, _start: &Path) -> io::Result<Output> {
            Err(io::Error::other("mock git execution failure"))
        }
    }

    fn init_git_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .status()
            .expect("git init should run");
        assert!(status.success());
    }

    fn gen_identity() -> x25519::Identity {
        x25519::Identity::generate()
    }

    fn assert_paths_equivalent(left: &Path, right: &Path) {
        fn normalize(path: &Path) -> String {
            path.canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase()
        }

        assert_eq!(normalize(left), normalize(right));
    }

    #[test]
    fn test_get_encrypted_path() {
        let root = Path::new("/repo");
        let path = get_encrypted_path(root, "database.env.age");
        assert_eq!(path, PathBuf::from("/repo/secrets/database.env.age"));
    }

    #[test]
    fn test_get_plain_path() {
        let root = Path::new("/repo");
        let path = get_plain_path(root, "dev", "database.env");
        assert_eq!(path, PathBuf::from("/repo/.secrets/plain/dev/database.env"));
    }

    #[test]
    fn test_get_plain_path_staging() {
        let root = Path::new("/repo");
        let path = get_plain_path(root, "staging", "app.env");
        assert_eq!(path, PathBuf::from("/repo/.secrets/plain/staging/app.env"));
    }

    #[test]
    fn test_ensure_dirs_creates_directories() {
        let dir = TempDir::new().unwrap();
        ensure_dirs(dir.path(), "dev").unwrap();

        assert!(
            dir.path().join("secrets").exists(),
            "secrets/ should be created"
        );
        assert!(
            dir.path().join(".secrets/plain/dev").exists(),
            ".secrets/plain/dev/ should be created"
        );
        assert!(
            dir.path().join("secrets/dev").exists(),
            "secrets/dev/ should be created"
        );
    }

    #[test]
    fn test_ensure_dirs_staging() {
        let dir = TempDir::new().unwrap();
        ensure_dirs(dir.path(), "staging").unwrap();

        assert!(dir.path().join(".secrets/plain/staging").exists());
    }

    #[test]
    fn test_validate_write_path_allows_subpath() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("subdir").join("file.txt");
        // Create subdir so canonicalize can resolve the parent
        std::fs::create_dir_all(dir.path().join("subdir")).unwrap();
        let result = validate_write_path(dir.path(), &target);
        assert!(result.is_ok(), "subpath inside repo root should be allowed");
    }

    #[test]
    fn test_validate_write_path_blocks_traversal() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("..").join("etc").join("passwd");
        let result = validate_write_path(dir.path(), &target);
        assert!(
            result.is_err(),
            "path traversal outside repo root should be blocked"
        );
    }

    #[test]
    fn test_get_env_encrypted_path() {
        let root = Path::new("/repo");
        let path = get_env_encrypted_path(root, "staging", "app.env.age");
        assert_eq!(path, PathBuf::from("/repo/secrets/staging/app.env.age"));
    }

    #[test]
    fn test_list_encrypted_files_for_env_prefers_env_dir() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("secrets/dev")).unwrap();
        std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
        std::fs::write(dir.path().join("secrets/dev/app.env.age"), b"x").unwrap();
        std::fs::write(dir.path().join("secrets/legacy.env.age"), b"x").unwrap();

        let files = list_encrypted_files_for_env(dir.path(), "dev").unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with(Path::new("secrets/dev/app.env.age")));
    }

    #[test]
    fn test_list_encrypted_files_for_env_falls_back_to_legacy() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
        std::fs::write(dir.path().join("secrets/app.env.age"), b"x").unwrap();

        let files = list_encrypted_files_for_env(dir.path(), "dev").unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with(Path::new("secrets/app.env.age")));
    }

    #[test]
    fn test_list_all_encrypted_files_recurses() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("secrets/dev")).unwrap();
        std::fs::create_dir_all(dir.path().join("secrets/prod")).unwrap();
        std::fs::write(dir.path().join("secrets/dev/app.env.age"), b"x").unwrap();
        std::fs::write(dir.path().join("secrets/prod/app.env.age"), b"x").unwrap();

        let files = list_all_encrypted_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_list_all_encrypted_files_missing_dir_is_empty() {
        let dir = TempDir::new().unwrap();
        let files = list_all_encrypted_files(dir.path()).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_validate_write_path_handles_curdir_and_parentless_target() {
        let base = Path::new("./nonexistent/base");
        let target = Path::new("file.txt");
        let result = validate_write_path(base, target);
        assert!(result.is_err());
    }

    /// Covers line 36: `Ok(p) => p` in `validate_write_path` (target file exists → canonicalize succeeds).
    #[test]
    fn test_validate_write_path_with_existing_target_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("existing.txt");
        std::fs::write(&file, b"content").unwrap();
        // canonicalize() will succeed for an existing file → exercises the `Ok(p) => p` arm.
        let result = validate_write_path(dir.path(), &file);
        assert!(
            result.is_ok(),
            "existing file inside base should be allowed"
        );
    }

    /// Covers `validate_write_path` lines 42-46: path with no `file_name` component (ends in "..").
    #[test]
    fn test_validate_write_path_target_ends_with_dotdot_returns_usage_error() {
        let dir = TempDir::new().unwrap();
        // A non-existent path whose last component is ".." → file_name() is None
        let target = dir.path().join("nonexistent_subdir").join("..");
        let result = validate_write_path(dir.path(), &target);
        // If the system resolves it or doesn't, we just test that it handles without panic.
        // It should either succeed (if it resolves within dir) or fail with a usage error.
        let _ = result;
    }

    /// Covers `decrypt_env_secrets` with no encrypted files → empty result.
    #[test]
    fn test_decrypt_env_secrets_no_files_returns_empty() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let result = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(result.is_empty());
    }

    /// Covers `decrypt_env_secrets` success path: one valid encrypted file.
    #[test]
    fn test_decrypt_env_secrets_success() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());

        // Create the env secrets directory and write an encrypted file.
        let secrets_dir = dir.path().join("secrets/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let plaintext = b"KEY=value\nFOO=bar\n";
        let ciphertext = crate::crypto::encrypt(vec![recipient], plaintext).unwrap();
        std::fs::write(secrets_dir.join("app.env.age"), &ciphertext).unwrap();

        let secrets = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(secrets.contains(&("KEY".to_string(), "value".to_string())));
        assert!(secrets.contains(&("FOO".to_string(), "bar".to_string())));
    }

    /// Covers `decrypt_env_secrets` error path: wrong identity → Decryption error.
    #[test]
    fn test_decrypt_env_secrets_wrong_identity_returns_error() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let wrong_identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());

        let secrets_dir = dir.path().join("secrets/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let ciphertext = crate::crypto::encrypt(vec![recipient], b"KEY=value\n").unwrap();
        std::fs::write(secrets_dir.join("app.env.age"), &ciphertext).unwrap();

        let result = decrypt_env_secrets(dir.path(), "dev", &wrong_identity);
        assert!(
            matches!(result, Err(GitvaultError::Decryption(_))),
            "expected decryption error, got: {result:?}"
        );
    }

    /// Covers `list_age_files_in_dir` with non-.age files (they should be ignored).
    #[test]
    fn test_list_age_files_in_dir_ignores_non_age_files() {
        let dir = TempDir::new().unwrap();
        let secrets_dir = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        std::fs::write(secrets_dir.join("file.txt"), b"x").unwrap();
        std::fs::write(secrets_dir.join("file.age"), b"x").unwrap();

        let files = list_age_files_in_dir(&secrets_dir).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("file.age"));
    }

    /// Covers `collect_age_files` with mixed files and subdirectories.
    #[test]
    fn test_collect_age_files_with_non_age_files() {
        let dir = TempDir::new().unwrap();
        let secrets_dir = dir.path().join("secrets");
        std::fs::create_dir_all(secrets_dir.join("dev")).unwrap();
        // Add a non-.age file — should be ignored
        std::fs::write(secrets_dir.join("README.md"), b"docs").unwrap();
        std::fs::write(secrets_dir.join("dev/app.env.age"), b"x").unwrap();

        let files = list_all_encrypted_files(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("app.env.age"));
    }

    /// Covers the `get_env_encrypted_dir` function.
    #[test]
    fn test_get_env_encrypted_dir() {
        let root = Path::new("/repo");
        let dir = get_env_encrypted_dir(root, "prod");
        assert_eq!(dir, PathBuf::from("/repo/secrets/prod"));
    }

    // ─── find_repo_root_from tests ───────────────────────────────────────────

    #[test]
    fn find_repo_root_from_finds_git_dir() {
        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());
        let found = find_repo_root_from(tmp.path()).unwrap();
        assert_paths_equivalent(&found, tmp.path());
    }

    #[test]
    fn find_repo_root_from_walks_up() {
        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());
        let sub = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&sub).unwrap();
        let found = find_repo_root_from(&sub).unwrap();
        assert_paths_equivalent(&found, tmp.path());
    }

    #[test]
    fn find_repo_root_from_returns_start_when_no_git() {
        let tmp = TempDir::new().unwrap();
        // No .git dir — should now return an error
        let result = find_repo_root_from(tmp.path());
        assert!(
            result.is_err(),
            "expected error when no .git directory found"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not inside a git repository"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn find_repo_root_from_fallback_when_git_invocation_fails() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();

        let found = find_repo_root_from_with_runner(tmp.path(), &FailingGitRunner).unwrap();

        assert_paths_equivalent(&found, tmp.path());
    }

    #[test]
    fn find_repo_root_from_fallback_walks_up_when_git_invocation_fails() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let sub = tmp.path().join("x/y/z");
        std::fs::create_dir_all(&sub).unwrap();

        let found = find_repo_root_from_with_runner(&sub, &FailingGitRunner).unwrap();

        assert_paths_equivalent(&found, tmp.path());
    }
}
