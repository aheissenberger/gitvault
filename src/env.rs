use crate::config::EnvConfig;
use crate::error::GitvaultError;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

/// Resolve the active environment for a given worktree root.
///
/// Priority (REQ-11):
/// 1. `GITVAULT_ENV` environment variable
/// 2. `defaults::ENV_FILE` (`.git/gitvault/env`) file in the worktree root
/// 3. Default: `cfg.default_env()` (default: `"dev"`)
///
/// Each worktree resolves independently (REQ-12) because resolution
/// is relative to the passed `worktree_root` path.
#[must_use]
pub fn resolve_env(worktree_root: &Path, cfg: &EnvConfig) -> String {
    // Priority 1: GITVAULT_ENV env var
    if let Ok(env) = std::env::var("GITVAULT_ENV") {
        let env = env.trim().to_string();
        if !env.is_empty() && env.len() <= crate::defaults::MAX_ENV_NAME_BYTES {
            return env;
        }
    }

    // Priority 2: env file (fixed path: defaults::ENV_FILE)
    let env_file = worktree_root.join(crate::defaults::ENV_FILE);
    if let Ok(content) = fs::read_to_string(&env_file) {
        let env = content.trim().to_string();
        // REQ-111: reject suspiciously long env names (>255 bytes) to avoid memory abuse.
        if !env.is_empty() && env.len() <= crate::defaults::MAX_ENV_NAME_BYTES {
            return env;
        }
        // Too long or empty — fall through to default
    }

    // Priority 3: configured default (or built-in "dev")
    cfg.default_env().to_string()
}

/// Validate that an environment name is safe to use as a path component.
///
/// Only allows `[A-Za-z0-9_-]+` so that values like `../../etc` cannot
/// escape the repository root when used in `repo_root.join(env)` calls.
/// Returns [`GitvaultError::Usage`] if the name is invalid.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if `env` contains characters outside `[A-Za-z0-9_-]`.
///
/// # Panics
///
/// Never panics in practice; the regex literal `^[A-Za-z0-9_-]+$` always compiles.
pub fn validate_env_name(env: &str) -> Result<(), GitvaultError> {
    static ENV_RE: OnceLock<Regex> = OnceLock::new();
    let re = ENV_RE
        .get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("env name regex must compile"));
    if re.is_match(env) {
        Ok(())
    } else {
        Err(GitvaultError::Usage(format!(
            "invalid environment name {env:?}: must match ^[A-Za-z0-9_-]+$"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_default_env_is_dev() {
        let _guard = env_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }
        let env = resolve_env(dir.path(), &Default::default());
        assert_eq!(env, "dev");
    }

    #[test]
    fn test_env_file_takes_priority_over_default() {
        let _guard = env_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }

        fs::create_dir_all(dir.path().join(".git/gitvault")).unwrap();
        fs::write(dir.path().join(".git/gitvault").join("env"), "staging").unwrap();

        let env = resolve_env(dir.path(), &Default::default());
        assert_eq!(env, "staging");
    }

    #[test]
    fn test_secrets_env_var_overrides_file() {
        let _guard = env_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();

        fs::create_dir_all(dir.path().join(".git/gitvault")).unwrap();
        fs::write(dir.path().join(".git/gitvault").join("env"), "staging").unwrap();

        unsafe {
            std::env::set_var("GITVAULT_ENV", "prod");
        }
        let env = resolve_env(dir.path(), &Default::default());
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }

        assert_eq!(env, "prod");
    }

    #[test]
    fn test_worktree_independence() {
        let _guard = env_lock().lock().unwrap();
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }

        fs::create_dir_all(dir1.path().join(".git/gitvault")).unwrap();
        fs::write(dir1.path().join(".git/gitvault").join("env"), "staging").unwrap();

        fs::create_dir_all(dir2.path().join(".git/gitvault")).unwrap();
        fs::write(dir2.path().join(".git/gitvault").join("env"), "dev").unwrap();

        assert_eq!(resolve_env(dir1.path(), &Default::default()), "staging");
        assert_eq!(resolve_env(dir2.path(), &Default::default()), "dev");
    }

    #[test]
    fn test_whitespace_env_var_falls_back_to_file() {
        let _guard = env_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".git/gitvault")).unwrap();
        fs::write(dir.path().join(".git/gitvault").join("env"), "staging").unwrap();

        unsafe {
            std::env::set_var("GITVAULT_ENV", "   ");
        }
        let env = resolve_env(dir.path(), &Default::default());
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }

        assert_eq!(env, "staging");
    }

    #[test]
    fn test_whitespace_env_file_falls_back_to_dev() {
        let _guard = env_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }
        fs::create_dir_all(dir.path().join(".git/gitvault")).unwrap();
        fs::write(dir.path().join(".git/gitvault").join("env"), "  \n").unwrap();

        let env = resolve_env(dir.path(), &Default::default());
        assert_eq!(env, "dev");
    }

    #[test]
    fn test_validate_env_name_accepts_valid() {
        assert!(validate_env_name("dev").is_ok());
        assert!(validate_env_name("prod").is_ok());
        assert!(validate_env_name("staging-1").is_ok());
        assert!(validate_env_name("my_env").is_ok());
        assert!(validate_env_name("Env-2024").is_ok());
    }

    #[test]
    fn test_validate_env_name_rejects_path_traversal() {
        assert!(validate_env_name("../../etc").is_err());
        assert!(validate_env_name("../prod").is_err());
        assert!(validate_env_name("prod/subdir").is_err());
        assert!(validate_env_name(".hidden").is_err());
    }

    #[test]
    fn test_validate_env_name_rejects_empty() {
        assert!(validate_env_name("").is_err());
    }

    #[test]
    fn test_validate_env_name_rejects_spaces_and_specials() {
        assert!(validate_env_name("my env").is_err());
        assert!(validate_env_name("prod;rm -rf /").is_err());
        assert!(validate_env_name("prod\n").is_err());
    }

    // ── SEC-007: size limit on env name sources ───────────────────────────────

    #[test]
    fn test_env_var_longer_than_255_bytes_falls_through_to_default() {
        let _guard = env_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }
        let long_env = "a".repeat(256);
        unsafe {
            std::env::set_var("GITVAULT_ENV", &long_env);
        }
        let env = resolve_env(dir.path(), &Default::default());
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }
        assert_eq!(env, "dev", "oversized env var should fall through to default");
    }

    #[test]
    fn test_env_file_longer_than_255_bytes_falls_through_to_default() {
        let _guard = env_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_ENV");
        }
        fs::create_dir_all(dir.path().join(".git/gitvault")).unwrap();
        let long_env = "b".repeat(256);
        fs::write(dir.path().join(".git/gitvault").join("env"), &long_env).unwrap();

        let env = resolve_env(dir.path(), &Default::default());
        assert_eq!(
            env, "dev",
            "oversized env file content should fall through to default"
        );
    }
}
