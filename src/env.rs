use std::fs;
use std::path::Path;

/// Resolve the active environment for a given worktree root.
///
/// Priority (REQ-11):
/// 1. `SECRETS_ENV` environment variable
/// 2. `.secrets/env` file in the worktree root
/// 3. Default: "dev"
///
/// Each worktree resolves independently (REQ-12) because resolution
/// is relative to the passed `worktree_root` path.
pub fn resolve_env(worktree_root: &Path) -> String {
    // Priority 1: SECRETS_ENV env var
    if let Ok(env) = std::env::var("SECRETS_ENV") {
        let env = env.trim().to_string();
        if !env.is_empty() {
            return env;
        }
    }

    // Priority 2: .secrets/env file
    let env_file = worktree_root.join(".secrets").join("env");
    if let Ok(content) = fs::read_to_string(&env_file) {
        let env = content.trim().to_string();
        if !env.is_empty() {
            return env;
        }
    }

    // Priority 3: default
    "dev".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_default_env_is_dev() {
        let dir = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("SECRETS_ENV");
        }
        let env = resolve_env(dir.path());
        assert_eq!(env, "dev");
    }

    #[test]
    fn test_env_file_takes_priority_over_default() {
        let dir = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("SECRETS_ENV");
        }

        fs::create_dir_all(dir.path().join(".secrets")).unwrap();
        fs::write(dir.path().join(".secrets").join("env"), "staging").unwrap();

        let env = resolve_env(dir.path());
        assert_eq!(env, "staging");
    }

    #[test]
    fn test_secrets_env_var_overrides_file() {
        let dir = TempDir::new().unwrap();

        fs::create_dir_all(dir.path().join(".secrets")).unwrap();
        fs::write(dir.path().join(".secrets").join("env"), "staging").unwrap();

        unsafe {
            std::env::set_var("SECRETS_ENV", "prod");
        }
        let env = resolve_env(dir.path());
        unsafe {
            std::env::remove_var("SECRETS_ENV");
        }

        assert_eq!(env, "prod");
    }

    #[test]
    fn test_worktree_independence() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        unsafe {
            std::env::remove_var("SECRETS_ENV");
        }

        fs::create_dir_all(dir1.path().join(".secrets")).unwrap();
        fs::write(dir1.path().join(".secrets").join("env"), "staging").unwrap();

        fs::create_dir_all(dir2.path().join(".secrets")).unwrap();
        fs::write(dir2.path().join(".secrets").join("env"), "dev").unwrap();

        assert_eq!(resolve_env(dir1.path()), "staging");
        assert_eq!(resolve_env(dir2.path()), "dev");
    }
}
