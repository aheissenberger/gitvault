use crate::error::GitvaultError;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

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
    let mut recipients = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        if let Some(recipient) = parse_recipient_line(line).map_err(|message| {
            GitvaultError::Usage(format!(
                "Invalid recipient entry in {}:{}: {message}",
                RECIPIENTS_FILE,
                line_no + 1
            ))
        })? {
            recipients.push(recipient);
        }
    }
    Ok(recipients)
}

fn parse_recipient_line(line: &str) -> Result<Option<String>, &'static str> {
    static BLANK_OR_COMMENT_RE: OnceLock<Regex> = OnceLock::new();
    static RECIPIENT_RE: OnceLock<Regex> = OnceLock::new();

    let blank_or_comment = BLANK_OR_COMMENT_RE
        .get_or_init(|| Regex::new(r"^\s*(?:#.*)?$").expect("blank/comment regex must compile"));
    if blank_or_comment.is_match(line) {
        return Ok(None);
    }

    let recipient_re = RECIPIENT_RE.get_or_init(|| {
        Regex::new(r"^\s*(age1[0-9a-z]+)\s*(?:#.*)?$").expect("recipient regex must compile")
    });
    if let Some(captures) = recipient_re.captures(line) {
        return Ok(Some(captures[1].to_string()));
    }

    Err("expected age recipient key")
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
#[allow(dead_code)]
pub fn get_encrypted_path(repo_root: &Path, name: &str) -> PathBuf {
    repo_root.join(SECRETS_DIR).join(name)
}

/// Get the directory for env-scoped encrypted artifacts under `secrets/<env>/`.
pub fn get_env_encrypted_dir(repo_root: &Path, env: &str) -> PathBuf {
    repo_root.join(SECRETS_DIR).join(env)
}

/// Get the path for an encrypted artifact under `secrets/<env>/`.
pub fn get_env_encrypted_path(repo_root: &Path, env: &str, name: &str) -> PathBuf {
    get_env_encrypted_dir(repo_root, env).join(name)
}

/// List encrypted files for an environment.
///
/// Prefers env-scoped layout `secrets/<env>/*.age` and falls back to legacy
/// layout `secrets/*.age` when no env-scoped files exist.
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
#[allow(dead_code)]
pub fn get_plain_path(repo_root: &Path, env: &str, name: &str) -> PathBuf {
    repo_root.join(PLAIN_BASE_DIR).join(env).join(name)
}

/// Ensure all required directories exist.
pub fn ensure_dirs(repo_root: &Path, env: &str) -> Result<(), GitvaultError> {
    fs::create_dir_all(repo_root.join(SECRETS_DIR))?;
    fs::create_dir_all(get_env_encrypted_dir(repo_root, env))?;
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
    gitvault status --no-prompt --fail-if-dirty
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

/// Walk up from `start` to find the directory containing `.git`.
///
/// Returns [`crate::error::GitvaultError::Usage`] if no `.git` is found — the caller is
/// not inside a git repository.
pub fn find_repo_root_from(start: &std::path::Path) -> Result<std::path::PathBuf, crate::error::GitvaultError> {
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

/// Find the repository root starting from `std::env::current_dir()`.
pub fn find_repo_root() -> Result<std::path::PathBuf, crate::error::GitvaultError> {
    let cwd = std::env::current_dir()?;
    find_repo_root_from(&cwd)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_read_recipients_supports_inline_comment() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(RECIPIENTS_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p # laptop\n",
        )
        .unwrap();

        let recipients = read_recipients(dir.path()).unwrap();
        assert_eq!(
            recipients,
            vec!["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string()]
        );
    }

    #[test]
    fn test_read_recipients_rejects_invalid_line() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(RECIPIENTS_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not-a-recipient\n").unwrap();

        let result = read_recipients(dir.path());
        match result {
            Err(GitvaultError::Usage(message)) => {
                assert!(message.contains("Invalid recipient entry"));
                assert!(message.contains(".secrets/recipients:1"));
            }
            other => panic!("expected usage error, got: {other:?}"),
        }
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

    #[test]
    fn test_has_secrets_drift_nonexistent_repo_root_returns_clean() {
        let dir = TempDir::new().unwrap();
        let missing_root = dir.path().join("missing");
        let drift = has_secrets_drift(&missing_root).unwrap();
        assert!(!drift);
    }

    #[test]
    fn test_check_no_tracked_plaintext_git_invocation_failure() {
        let dir = TempDir::new().unwrap();
        let missing_root = dir.path().join("missing");
        let err = check_no_tracked_plaintext(&missing_root).unwrap_err();
        assert!(matches!(err, GitvaultError::Other(_)));
    }

    #[test]
    fn test_check_no_tracked_plaintext_detects_tracked_files() {
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());

        std::fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        let add_status = Command::new("git")
            .args(["add", ".env"])
            .current_dir(dir.path())
            .status()
            .expect("git add should run");
        assert!(add_status.success());

        let err = check_no_tracked_plaintext(dir.path()).unwrap_err();
        match err {
            GitvaultError::PlaintextLeak(files) => {
                assert!(files.contains(".env"));
            }
            other => panic!("expected plaintext leak error, got: {other:?}"),
        }
    }

    // ─── find_repo_root_from tests ───────────────────────────────────────────

    #[test]
    fn find_repo_root_from_finds_git_dir() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let found = find_repo_root_from(tmp.path()).unwrap();
        assert_eq!(found, tmp.path());
    }

    #[test]
    fn find_repo_root_from_walks_up() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let sub = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&sub).unwrap();
        let found = find_repo_root_from(&sub).unwrap();
        assert_eq!(found, tmp.path());
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
}
