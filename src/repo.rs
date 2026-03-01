use crate::error::GitvaultError;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Directory for encrypted artifacts (REQ-7)
pub const SECRETS_DIR: &str = "secrets";

/// Base directory for plaintext outputs (REQ-8)
pub const PLAIN_BASE_DIR: &str = ".secrets/plain";

/// File storing persistent recipient public keys (REQ-36)
pub const RECIPIENTS_FILE: &str = ".secrets/recipients";

/// Guard against path traversal: ensure `target` is under `base`.
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

    let canonical_base = base.canonicalize().unwrap_or_else(|_| normalize(base));
    let canonical_target = target.canonicalize().unwrap_or_else(|_| {
        // For not-yet-existing files, canonicalize the parent then re-attach filename
        if let Some(parent) = target.parent() {
            let canon_parent = parent.canonicalize().unwrap_or_else(|_| normalize(parent));
            canon_parent.join(target.file_name().unwrap_or_default())
        } else {
            normalize(target)
        }
    });
    if canonical_target.starts_with(&canonical_base) {
        Ok(())
    } else {
        Err(GitvaultError::Usage(format!(
            "Path traversal detected: {} is outside repository root {}",
            target.display(),
            base.display()
        )))
    }
}

/// Read persistent recipients from .secrets/recipients (one pubkey per line).
pub fn read_recipients(repo_root: &Path) -> Result<Vec<String>, GitvaultError> {
    let path = repo_root.join(RECIPIENTS_FILE);
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

/// Write recipients to .secrets/recipients atomically.
pub fn write_recipients(repo_root: &Path, recipients: &[String]) -> Result<(), GitvaultError> {
    let path = repo_root.join(RECIPIENTS_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = recipients.join("\n") + "\n";
    let tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    std::fs::write(tmp.path(), content)?;
    tmp.persist(&path).map_err(|e| GitvaultError::Io(e.error))?;
    Ok(())
}

/// Get the path for an encrypted artifact under secrets/. REQ-7
pub fn get_encrypted_path(repo_root: &Path, name: &str) -> PathBuf {
    repo_root.join(SECRETS_DIR).join(name)
}

/// Get the path for a plaintext artifact under .secrets/plain/<env>/. REQ-8
#[allow(dead_code)]
pub fn get_plain_path(repo_root: &Path, env: &str, name: &str) -> PathBuf {
    repo_root.join(PLAIN_BASE_DIR).join(env).join(name)
}

/// Ensure all required directories exist.
pub fn ensure_dirs(repo_root: &Path, env: &str) -> Result<(), GitvaultError> {
    fs::create_dir_all(repo_root.join(SECRETS_DIR))?;
    fs::create_dir_all(repo_root.join(PLAIN_BASE_DIR).join(env))?;
    Ok(())
}

/// Install gitvault git hooks into `.git/hooks/`. REQ-31.
///
/// Installs:
/// - `pre-commit`: blocks commits if plaintext secrets are staged.
/// - `pre-push`: runs status check before push.
///
/// Hooks are idempotent: existing hooks that already call gitvault are left unchanged;
/// otherwise the script is written (or overwritten with the gitvault block).
pub fn install_git_hooks(repo_root: &Path) -> Result<(), GitvaultError> {
    let hooks_dir = repo_root.join(".git").join("hooks");
    if !hooks_dir.exists() {
        // Not a git repo (or bare repo) — skip silently
        return Ok(());
    }

    install_hook(&hooks_dir.join("pre-commit"), PRE_COMMIT_HOOK)?;
    install_hook(&hooks_dir.join("pre-push"), PRE_PUSH_HOOK)?;

    Ok(())
}

const PRE_COMMIT_HOOK: &str = r#"#!/usr/bin/env sh
# gitvault: block commits if plaintext secrets are staged
set -e
if command -v gitvault >/dev/null 2>&1; then
  gitvault status --no-prompt
fi
"#;

const PRE_PUSH_HOOK: &str = r#"#!/usr/bin/env sh
# gitvault: run safety check before push
set -e
if command -v gitvault >/dev/null 2>&1; then
  gitvault status --no-prompt
fi
"#;

fn install_hook(hook_path: &Path, script: &str) -> Result<(), GitvaultError> {
    // If hook already exists and already contains a gitvault block, skip
    if hook_path.exists() {
        let existing = fs::read_to_string(hook_path)?;
        if existing.contains("gitvault") {
            return Ok(());
        }
        // Append gitvault block after existing content
        let mut content = existing;
        if !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str("\n# --- gitvault ---\n");
        // Append just the gitvault invocation lines (skip shebang)
        let body: String = script
            .lines()
            .skip(1) // skip #!/usr/bin/env sh
            .collect::<Vec<_>>()
            .join("\n");
        content.push_str(&body);
        content.push('\n');
        fs::write(hook_path, &content)?;
    } else {
        fs::write(hook_path, script)?;
    }

    // Make executable (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(hook_path, perms)?;
    }

    Ok(())
}

/// Check whether `secrets/` has uncommitted changes (drift). REQ-32.
///
/// Returns Ok(true) if there are uncommitted changes, Ok(false) if clean.
pub fn has_secrets_drift(repo_root: &Path) -> Result<bool, GitvaultError> {
    let output = Command::new("git")
        .args(["diff", "--quiet", "HEAD", "--", "secrets/"])
        .current_dir(repo_root)
        .output();

    match output {
        Ok(out) => Ok(!out.status.success()),
        Err(_) => Ok(false), // not a git repo or git unavailable — treat as clean
    }
}

/// Check that no plaintext secrets are tracked in git. REQ-10
///
/// Checks that:
/// - .secrets/plain/** is not tracked
/// - .env is not tracked
pub fn check_no_tracked_plaintext(repo_root: &Path) -> Result<(), GitvaultError> {
    let output = Command::new("git")
        .args(["ls-files", ".secrets/plain/", ".env"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| GitvaultError::Other(format!("Failed to run git: {e}")))?;

    let tracked = String::from_utf8_lossy(&output.stdout);
    let files: Vec<&str> = tracked.lines().filter(|l| !l.is_empty()).collect();
    if !files.is_empty() {
        return Err(GitvaultError::PlaintextLeak(files.join(", ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
    }

    #[test]
    fn test_ensure_dirs_staging() {
        let dir = TempDir::new().unwrap();
        ensure_dirs(dir.path(), "staging").unwrap();

        assert!(dir.path().join(".secrets/plain/staging").exists());
    }

    #[test]
    fn test_check_no_tracked_plaintext_clean_repo() {
        let dir = TempDir::new().unwrap();
        let result = check_no_tracked_plaintext(dir.path());
        let _ = result; // just verify it doesn't panic
    }

    #[test]
    fn test_install_git_hooks_in_non_git_dir() {
        // Should silently succeed when .git/hooks doesn't exist
        let dir = TempDir::new().unwrap();
        let result = install_git_hooks(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_install_git_hooks_creates_scripts() {
        let dir = TempDir::new().unwrap();
        // Create a fake .git/hooks directory
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();

        install_git_hooks(dir.path()).unwrap();

        let pre_commit = dir.path().join(".git/hooks/pre-commit");
        let pre_push = dir.path().join(".git/hooks/pre-push");

        assert!(pre_commit.exists(), "pre-commit hook should be created");
        assert!(pre_push.exists(), "pre-push hook should be created");

        let content = std::fs::read_to_string(&pre_commit).unwrap();
        assert!(
            content.contains("gitvault"),
            "hook should reference gitvault"
        );
    }

    #[test]
    fn test_install_git_hooks_idempotent() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();

        // Install twice
        install_git_hooks(dir.path()).unwrap();
        install_git_hooks(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join(".git/hooks/pre-commit")).unwrap();
        // Should only contain one gitvault block (not duplicated)
        assert_eq!(content.matches("# gitvault:").count(), 1);
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
    fn test_read_write_recipients() {
        let dir = TempDir::new().unwrap();
        let keys = vec![
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string(),
            "age1z6j0we5lvscfzxqlqtpfwkf6p4amhjw6hv6h0x3n7lkdmkdwkjnq9x5x5v".to_string(),
        ];
        write_recipients(dir.path(), &keys).unwrap();
        let read_back = read_recipients(dir.path()).unwrap();
        assert_eq!(read_back, keys);
    }

    #[test]
    fn test_recipients_dedup_on_add() {
        let dir = TempDir::new().unwrap();
        let pubkey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string();

        // Write once
        write_recipients(dir.path(), std::slice::from_ref(&pubkey)).unwrap();

        // Simulate cmd_recipient Add logic (check contains before adding)
        let mut recipients = read_recipients(dir.path()).unwrap();
        if !recipients.contains(&pubkey) {
            recipients.push(pubkey.clone());
            write_recipients(dir.path(), &recipients).unwrap();
        }

        let read_back = read_recipients(dir.path()).unwrap();
        assert_eq!(
            read_back.iter().filter(|r| r.as_str() == pubkey).count(),
            1,
            "duplicate recipient should not be added"
        );
    }

    #[test]
    fn test_read_recipients_empty_when_no_file() {
        let dir = TempDir::new().unwrap();
        let recipients = read_recipients(dir.path()).unwrap();
        assert!(recipients.is_empty());
    }

    #[test]
    fn test_install_hook_appends_to_existing() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        let hook_path = dir.path().join(".git/hooks/pre-commit");

        // Write an existing hook without gitvault
        std::fs::write(&hook_path, "#!/usr/bin/env sh\necho 'existing hook'\n").unwrap();

        install_git_hooks(dir.path()).unwrap();

        let content = std::fs::read_to_string(&hook_path).unwrap();
        assert!(
            content.contains("existing hook"),
            "original content preserved"
        );
        assert!(content.contains("gitvault"), "gitvault block appended");
    }
}
