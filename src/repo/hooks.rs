use crate::error::GitvaultError;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const MANAGED_BLOCK_BEGIN: &str = "# --- gitvault managed begin ---";
const MANAGED_BLOCK_END: &str = "# --- gitvault managed end ---";

const PRE_COMMIT_HOOK_BODY: &str = r#"# gitvault: block commits if plaintext secrets are staged
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

const PRE_PUSH_HOOK_BODY: &str = r"# gitvault: run safety check before push
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

fn managed_block(body: &str) -> String {
    format!(
        "{MANAGED_BLOCK_BEGIN}\n{}\n{MANAGED_BLOCK_END}\n",
        body.trim_end()
    )
}

fn managed_script(body: &str) -> String {
    format!("#!/usr/bin/env sh\n{}", managed_block(body))
}

fn upsert_managed_block(existing: &str, body: &str) -> String {
    let new_block = managed_block(body);

    if let Some(start) = existing.find(MANAGED_BLOCK_BEGIN)
        && let Some(end_rel) = existing[start..].find(MANAGED_BLOCK_END)
    {
        let end = start + end_rel + MANAGED_BLOCK_END.len();
        let mut out = String::new();
        out.push_str(&existing[..start]);
        out.push_str(&new_block);
        let tail = existing[end..].trim_start_matches('\n');
        if !tail.is_empty() {
            out.push_str(tail);
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }

    let mut out = existing.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&new_block);
    out
}

fn ensure_executable(hook_path: &Path) -> Result<(), GitvaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(hook_path, perms)?;
    }
    Ok(())
}

pub(crate) fn resolve_hooks_dir(repo_root: &Path) -> PathBuf {
    fn to_real_or_absolute(path: PathBuf) -> PathBuf {
        path.canonicalize().unwrap_or(path)
    }

    let output = Command::new("git")
        .args(["rev-parse", "--git-path", "hooks"])
        .current_dir(repo_root)
        .output();

    if let Ok(out) = output
        && out.status.success()
    {
        let resolved = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !resolved.is_empty() {
            let path = PathBuf::from(&resolved);
            let absolute = if path.is_absolute() {
                path
            } else {
                repo_root.join(path)
            };

            return to_real_or_absolute(absolute);
        }
    }

    to_real_or_absolute(repo_root.join(".git").join("hooks"))
}

fn install_hook(hook_path: &Path, body: &str) -> Result<(), GitvaultError> {
    if hook_path.exists() {
        let existing = fs::read_to_string(hook_path)?;
        if existing.contains("gitvault") && !existing.contains(MANAGED_BLOCK_BEGIN) {
            ensure_executable(hook_path)?;
            return Ok(());
        }

        let content = upsert_managed_block(&existing, body);
        atomic_write(hook_path, content.as_bytes())?;
    } else {
        let content = managed_script(body);
        atomic_write(hook_path, content.as_bytes())?;
    }

    ensure_executable(hook_path)?;

    Ok(())
}

/// Install gitvault git hooks into the active hooks directory. REQ-31.
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
    let hooks_dir = resolve_hooks_dir(repo_root);
    if !hooks_dir.exists() {
        let default_hooks_dir = repo_root.join(".git").join("hooks");
        if hooks_dir == default_hooks_dir {
            // Not a git repo (or bare repo) — skip silently
            return Ok(());
        }
        fs::create_dir_all(&hooks_dir)?;
    }

    install_hook(&hooks_dir.join("pre-commit"), PRE_COMMIT_HOOK_BODY)?;
    install_hook(&hooks_dir.join("pre-push"), PRE_PUSH_HOOK_BODY)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_git_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .status()
            .expect("git init should run");
        assert!(status.success());
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
        assert_eq!(content.matches(MANAGED_BLOCK_BEGIN).count(), 1);
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
        assert!(content.contains(MANAGED_BLOCK_BEGIN));
    }

    /// Covers lines 550-551 in `test_recipients_dedup_on_add` by taking the
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

    #[test]
    fn test_install_git_hooks_honors_core_hooks_path() {
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());

        let status = Command::new("git")
            .args(["config", "--local", "core.hooksPath", ".githooks"])
            .current_dir(dir.path())
            .status()
            .expect("git config core.hooksPath should run");
        assert!(status.success());

        install_git_hooks(dir.path()).unwrap();

        assert!(dir.path().join(".githooks/pre-commit").exists());
        assert!(dir.path().join(".githooks/pre-push").exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_install_hook_repairs_executable_bit_for_existing_gitvault_hook() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        let hook_path = dir.path().join(".git/hooks/pre-commit");

        std::fs::write(
            &hook_path,
            "#!/usr/bin/env sh\n# gitvault: existing\nset -e\n",
        )
        .unwrap();

        let mut perms = std::fs::metadata(&hook_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&hook_path, perms).unwrap();

        install_git_hooks(dir.path()).unwrap();

        let mode = std::fs::metadata(&hook_path).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "hook should be executable");
    }

    #[test]
    fn test_upsert_managed_block_preserves_content_after_block() {
        // When existing content has a managed block followed by extra content,
        // upsert_managed_block must preserve that trailing content.
        // Covers lines 61-64 (the !tail.is_empty() branch).
        let existing = format!(
            "#!/usr/bin/env sh\n{MANAGED_BLOCK_BEGIN}\nold body\n{MANAGED_BLOCK_END}\nextra trailing line\n"
        );
        let result = upsert_managed_block(&existing, "new body");

        assert!(
            result.contains("new body"),
            "replaced block should contain new body"
        );
        assert!(!result.contains("old body"), "old body should be replaced");
        assert!(
            result.contains("extra trailing line"),
            "trailing content after block should be preserved"
        );
        // Should end with a newline
        assert!(result.ends_with('\n'));
    }
}
