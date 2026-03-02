use crate::error::GitvaultError;
use std::fs;
use std::io::Write as _;
use std::path::Path;

const PRE_COMMIT_HOOK: &str = r#"#!/usr/bin/env sh
# gitvault: block commits if plaintext secrets are staged
set -e
staged=$(git diff --cached --name-only 2>/dev/null | grep -E '(^|/)\.secrets/plain/|^\.env$' || true)
if [ -n "$staged" ]; then
    echo "gitvault: refusing commit – plaintext secrets staged for commit: $staged" >&2
    exit 1
fi
if command -v gitvault >/dev/null 2>&1; then
  gitvault status --no-prompt
fi
"#;

const PRE_PUSH_HOOK: &str = r"#!/usr/bin/env sh
# gitvault: run safety check before push
set -e
if command -v gitvault >/dev/null 2>&1; then
    gitvault status --no-prompt --fail-if-dirty
fi
";

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), GitvaultError> {
    let mut tmp = tempfile::Builder::new()
        .prefix(".gitvault-tmp-")
        .tempfile_in(path.parent().unwrap_or_else(|| Path::new(".")))?;
    tmp.write_all(content)?;
    tmp.persist(path).map_err(|e| GitvaultError::Io(e.error))?;
    Ok(())
}

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
        atomic_write(hook_path, content.as_bytes())?;
    } else {
        atomic_write(hook_path, script.as_bytes())?;
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

/// Install gitvault git hooks into `.git/hooks/`. REQ-31.
///
/// Installs:
/// - `pre-commit`: blocks commits if plaintext secrets are staged.
/// - `pre-push`: runs status check before push.
///
/// Hooks are idempotent: existing hooks that already call gitvault are left unchanged;
/// otherwise the script is written (or overwritten with the gitvault block).
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if a hook file cannot be read, written, or made executable.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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

        let pre_push_content = std::fs::read_to_string(&pre_push).unwrap();
        assert!(
            pre_push_content.contains("--fail-if-dirty"),
            "pre-push hook should enforce drift checks"
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

    /// Covers lines 550-551 in test_recipients_dedup_on_add by taking the
    /// `!recipients.contains()` branch (recipient not yet present).
    #[test]
    fn test_install_hook_appends_when_no_trailing_newline() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        let hook_path = dir.path().join(".git/hooks/pre-commit");

        // Write existing hook content WITHOUT a trailing newline.
        std::fs::write(&hook_path, "#!/usr/bin/env sh\necho hello").unwrap();

        install_git_hooks(dir.path()).unwrap();

        let content = std::fs::read_to_string(&hook_path).unwrap();
        assert!(
            content.contains("echo hello"),
            "original content must be preserved"
        );
        assert!(
            content.contains("gitvault"),
            "gitvault block must be appended"
        );
    }
}
