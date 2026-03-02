//! Admin/status commands: harden, status, check, allow-prod, revoke-prod, merge-driver.

use std::path::PathBuf;

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::load_identity;
use crate::merge::merge_env_content;
use crate::{barrier, crypto, env, repo};

/// Check repository safety status
pub fn cmd_status(json: bool, fail_if_dirty: bool) -> Result<CommandOutcome, GitvaultError> {
    // REQ-44: no decryption performed
    let repo_root = crate::repo::find_repo_root()?;
    repo::check_no_tracked_plaintext(&repo_root)?;
    let env = env::resolve_env(&repo_root);

    // REQ-32: drift check
    if fail_if_dirty && repo::has_secrets_drift(&repo_root)? {
        return Err(GitvaultError::Drift(
            "secrets/ has uncommitted changes (drift detected)".to_string(),
        ));
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "env": env,
                "plaintext_leaked": false
            })
        );
    } else {
        println!("Status: OK");
        println!("Environment: {env}");
        println!("No tracked plaintext detected.");
    }

    Ok(CommandOutcome::Success)
}

/// Harden the repository: update .gitignore, install git hooks
pub fn cmd_harden(json: bool) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    crate::materialize::ensure_gitignored(
        &repo_root,
        crate::materialize::REQUIRED_GITIGNORE_ENTRIES,
    )?;
    repo::install_git_hooks(&repo_root)?;
    crate::output::output_success(
        "Repository hardened: .gitignore updated, git hooks installed.",
        json,
    );
    Ok(CommandOutcome::Success)
}

/// Write a timed production allow token (REQ-14)
pub fn cmd_allow_prod(ttl: u64, json: bool) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let expiry = barrier::allow_prod(&repo_root, ttl)?;
    crate::output::output_success(
        &format!("Production access allowed for {ttl}s (expires at Unix time {expiry})"),
        json,
    );
    Ok(CommandOutcome::Success)
}

/// Immediately revoke the production allow token (REQ-14)
pub fn cmd_revoke_prod(json: bool) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    barrier::revoke_prod(&repo_root)?;
    crate::output::output_success("Production allow token revoked.", json);
    Ok(CommandOutcome::Success)
}

/// Run as git merge driver for .env files (REQ-34, REQ-48)
pub fn cmd_merge_driver(
    base: String,
    ours: String,
    theirs: String,
    json: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let base_content = std::fs::read_to_string(&base)?;
    let ours_content = std::fs::read_to_string(&ours)?;
    let theirs_content = std::fs::read_to_string(&theirs)?;

    let (merged_content, has_conflict) =
        merge_env_content(&base_content, &ours_content, &theirs_content);

    let ours_path = PathBuf::from(&ours);
    let tmp =
        tempfile::NamedTempFile::new_in(ours_path.parent().unwrap_or(std::path::Path::new(".")))?;
    std::fs::write(tmp.path(), &merged_content)?;
    tmp.persist(&ours_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    if has_conflict {
        if json {
            eprintln!(
                "{}",
                serde_json::json!({"status": "conflict", "message": "Merge conflict in .env file"})
            );
        }
        return Ok(CommandOutcome::Exit(1));
    }

    if !has_conflict {
        crate::output::output_success("Merge completed successfully.", json);
    }

    Ok(CommandOutcome::Success)
}

/// Run preflight validation without side effects (REQ-50)
pub fn cmd_check(
    env_override: Option<String>,
    identity_path: Option<String>,
    json: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let env = env_override.unwrap_or_else(|| env::resolve_env(&repo_root));

    // Check 1: no tracked plaintext (REQ-10)
    repo::check_no_tracked_plaintext(&repo_root)?;

    // Check 2: identity is loadable
    let identity_str = load_identity(identity_path)?;
    crypto::parse_identity(&identity_str)?;

    // Check 3: recipients file is readable and all keys are valid
    let recipients = repo::read_recipients(&repo_root)?;
    for key in &recipients {
        crypto::parse_recipient(key).map_err(|e| {
            GitvaultError::Usage(format!(
                "Invalid recipient in .secrets/recipients: {key}: {e}"
            ))
        })?;
    }

    // Check 4: secrets count for active env (with legacy fallback)
    let secrets_count = repo::list_encrypted_files_for_env(&repo_root, &env)?.len();

    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "env": env,
                "identity": "valid",
                "recipients": recipients.len(),
                "secrets": secrets_count,
                "format_version": crypto::GITVAULT_FORMAT_VERSION,
            })
        );
    } else {
        println!("✅ Preflight check passed");
        println!("   Environment : {env}");
        println!("   Identity    : valid");
        println!("   Recipients  : {}", recipients.len());
        println!("   Secrets     : {secrets_count} encrypted file(s)");
    }
    Ok(CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use tempfile::TempDir;

    #[test]
    fn test_cmd_harden_and_status_in_git_repo() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false).expect("harden should succeed");
        cmd_status(false, false).expect("status should succeed in clean repo");

        let gitignore = std::fs::read_to_string(dir.path().join(".gitignore"))
            .expect("gitignore should exist after harden");
        assert!(gitignore.contains(".env"));
        assert!(gitignore.contains(".secrets/plain/"));

        let pre_push = std::fs::read_to_string(dir.path().join(".git/hooks/pre-push"))
            .expect("pre-push hook should be created");
        assert!(pre_push.contains("--fail-if-dirty"));
    }

    #[test]
    fn test_cmd_allow_prod_and_check() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            cmd_allow_prod(30, false).expect("allow-prod should succeed");
            cmd_check(None, None, true).expect("check should succeed with identity and clean repo");
        });
    }

    #[test]
    fn test_cmd_status_fail_if_dirty_returns_plaintext_leak() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        std::fs::create_dir_all(dir.path().join("secrets/dev")).unwrap();
        std::fs::write(dir.path().join("secrets/dev/app.env.age"), b"x").unwrap();

        let err = cmd_status(true, true).unwrap_err();
        assert!(matches!(err, GitvaultError::Drift(_)));
    }

    #[test]
    fn test_cmd_status_json_output() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false).expect("harden should succeed");
        // json=true covers the JSON output branch (lines 649-656).
        cmd_status(true, false).expect("status json should succeed");
    }

    #[test]
    fn test_cmd_check_plain_output_succeeds() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            cmd_check(None, None, false).expect("plain check should succeed");
        });
    }

    #[test]
    fn test_cmd_check_invalid_recipient_fails() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let recipients_path = dir.path().join(".secrets/recipients");
        std::fs::create_dir_all(recipients_path.parent().unwrap()).unwrap();
        std::fs::write(&recipients_path, "not-a-valid-recipient\n").unwrap();

        with_identity_env(identity_file.path(), || {
            let err = cmd_check(None, None, true).unwrap_err();
            assert!(matches!(err, GitvaultError::Usage(_)));
        });
    }

    #[test]
    fn test_cmd_check_validates_recipient_keys_in_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Write a valid recipient so that the for loop on lines 995-1000 executes.
        let pubkey = identity.to_public().to_string();
        repo::write_recipients(dir.path(), &[pubkey]).expect("write_recipients should succeed");

        with_identity_env(identity_file.path(), || {
            cmd_check(None, None, false).expect("check with valid recipient should succeed");
        });
    }

    #[test]
    fn test_merge_driver_clean_merge() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        // base: A=1, B=2
        // ours: A=1, B=3  (changed B)
        // theirs: A=2, B=2  (changed A)
        // expected merge: A=2, B=3
        std::fs::write(&base, "A=1\nB=2\n").unwrap();
        std::fs::write(&ours, "A=1\nB=3\n").unwrap();
        std::fs::write(&theirs, "A=2\nB=2\n").unwrap();

        cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
            false,
        )
        .unwrap();

        let result = std::fs::read_to_string(&ours).unwrap();
        let kv: std::collections::HashMap<_, _> = result
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .collect();

        assert_eq!(kv.get("A"), Some(&"2"), "A should be taken from theirs");
        assert_eq!(kv.get("B"), Some(&"3"), "B should be kept from ours");
    }

    #[test]
    fn test_merge_driver_preserves_unchanged_line_formatting() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        let line = "A = 1 # keep-comment";
        std::fs::write(&base, format!("{line}\n")).unwrap();
        std::fs::write(&ours, format!("{line}\n")).unwrap();
        std::fs::write(&theirs, format!("{line}\n")).unwrap();

        cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
            false,
        )
        .unwrap();

        let result = std::fs::read_to_string(&ours).unwrap();
        assert!(
            result.contains(line),
            "unchanged assignment line should be preserved byte-for-byte"
        );
    }

    #[test]
    fn test_merge_driver_preserves_prefix_and_inline_comment_on_change() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        std::fs::write(&base, "A = 1 # keep-comment\n").unwrap();
        std::fs::write(&ours, "A = 1 # keep-comment\n").unwrap();
        std::fs::write(&theirs, "A = 2\n").unwrap();

        cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
            false,
        )
        .unwrap();

        let result = std::fs::read_to_string(&ours).unwrap();
        assert!(
            result.contains("A = 2 # keep-comment"),
            "changed assignment should keep original lhs spacing and inline comment"
        );
    }

    #[test]
    fn test_merge_driver_conflict_returns_exit_outcome() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        std::fs::write(&base, "A=1\n").unwrap();
        std::fs::write(&ours, "A=2\n").unwrap();
        std::fs::write(&theirs, "A=3\n").unwrap();

        let outcome = cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
            false,
        )
        .expect("merge driver should return outcome");

        assert_eq!(outcome, CommandOutcome::Exit(1));
    }

    #[test]
    fn test_cmd_revoke_prod_succeeds() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Create a token first so revoke has something to remove.
        cmd_allow_prod(60, false).expect("allow-prod should create token");
        assert!(dir.path().join(".secrets/.prod-token").exists());

        cmd_revoke_prod(false).expect("revoke-prod should succeed");
        // After revoking, the token should be gone.
        assert!(!dir.path().join(".secrets/.prod-token").exists());

        // Also test json=true path.
        cmd_allow_prod(60, false).expect("allow-prod for json test");
        cmd_revoke_prod(true).expect("revoke-prod json should succeed");
    }

    #[test]
    fn test_merge_driver_conflict_json_output() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        // Both sides change A → conflict.
        std::fs::write(&base, "A=1\n").unwrap();
        std::fs::write(&ours, "A=2\n").unwrap();
        std::fs::write(&theirs, "A=3\n").unwrap();

        // json=true exercises the JSON conflict output branch (lines 100-103).
        let outcome = cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
            true,
        )
        .expect("merge driver conflict with json should return outcome");
        assert_eq!(outcome, CommandOutcome::Exit(1));
    }

    #[test]
    fn test_cmd_check_age_format_valid_but_crypto_invalid_recipient() {
        // Write a recipient that passes the read_recipients regex (age1[0-9a-z]+)
        // but is rejected by crypto::parse_recipient (invalid bech32 checksum).
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        // This key matches age1[0-9a-z]+ but has an invalid bech32 checksum.
        let bad_key = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let recipients_path = dir.path().join(".secrets/recipients");
        std::fs::create_dir_all(recipients_path.parent().unwrap()).unwrap();
        std::fs::write(&recipients_path, format!("{bad_key}\n")).unwrap();

        with_identity_env(identity_file.path(), || {
            let err = cmd_check(None, None, false).unwrap_err();
            // The error should come from the parse_recipient call in the for loop.
            assert!(
                matches!(err, GitvaultError::Usage(_)),
                "expected Usage error, got: {err:?}"
            );
        });
    }

    #[test]
    fn test_cmd_harden_json_output() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // json=true exercises the output_success(json=true) path in cmd_harden.
        cmd_harden(true).expect("harden with json flag should succeed");
    }
}
