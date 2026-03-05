//! Admin/status commands: harden, status, check, allow-prod, revoke-prod, merge-driver.
//!
//! # Sub-module layout
//!
//! | Module            | Responsibility                                        |
//! |-------------------|-------------------------------------------------------|
//! | [`gitattributes`] | Merge-driver git-config registration.                 |
//! | [`hooks`]         | Git hook installation status (pre-commit, pre-push).  |
//! | [`gitignore`]     | `.gitignore` entry management.                        |

mod gitattributes;
pub mod gitignore;
pub mod hooks;

use std::path::PathBuf;

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::git::git_output_raw;
use crate::identity::{load_identity_with_selector, probe_identity_sources};
use crate::merge::merge_env_content;
use crate::{barrier, crypto, env, repo};

/// Check repository safety status
///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root cannot be found, tracked plaintext
/// is detected, or drift detection fails.
pub fn cmd_status(json: bool, fail_if_dirty: bool) -> Result<CommandOutcome, GitvaultError> {
    // REQ-44: no decryption performed
    let repo_root = crate::repo::find_repo_root()?;
    repo::check_no_tracked_plaintext(&repo_root)?;
    let config = crate::config::effective_config(&repo_root)?;
    let env = env::resolve_env(&repo_root, &config.env);

    // REQ-32: drift check
    let store_dirty = if fail_if_dirty {
        repo::has_secrets_drift(&repo_root)?
    } else {
        false
    };

    // REQ-112 AC14: seal drift check
    let seal_drift_entries = crate::commands::seal::check_seal_drift(&repo_root, &config.seal);
    let has_seal_drift = seal_drift_entries
        .iter()
        .any(|e| e.status == crate::commands::seal::SealDriftStatus::Drift);

    if fail_if_dirty && (store_dirty || has_seal_drift) {
        return Err(GitvaultError::Drift(
            "drift detected (secrets or sealed files)".to_string(),
        ));
    }

    if json {
        let seal_json: Vec<serde_json::Value> = seal_drift_entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "path": e.path,
                    "status": match e.status {
                        crate::commands::seal::SealDriftStatus::Ok => "ok",
                        crate::commands::seal::SealDriftStatus::Drift => "drifted",
                        crate::commands::seal::SealDriftStatus::Excluded => "excluded",
                    },
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "status": if has_seal_drift { "drift" } else { "ok" },
                "env": env,
                "plaintext_leaked": false,
                "seal": seal_json,
            })
        );
    } else {
        println!("Status: {}", if has_seal_drift { "DRIFT" } else { "OK" });
        println!("Environment: {env}");
        println!("No tracked plaintext detected.");

        if !seal_drift_entries.is_empty() {
            println!("\nSealed:");
            for entry in &seal_drift_entries {
                let icon = match entry.status {
                    crate::commands::seal::SealDriftStatus::Ok => "✓",
                    crate::commands::seal::SealDriftStatus::Drift => "✗",
                    crate::commands::seal::SealDriftStatus::Excluded => " ",
                };
                let detail = match entry.status {
                    crate::commands::seal::SealDriftStatus::Ok => {
                        if entry.total_count > 0 {
                            format!(
                                "({}/{} fields sealed)",
                                entry.sealed_count, entry.total_count
                            )
                        } else {
                            "(all fields sealed)".to_string()
                        }
                    }
                    crate::commands::seal::SealDriftStatus::Drift => {
                        format!("drift: run 'gitvault seal {}'", entry.path)
                    }
                    crate::commands::seal::SealDriftStatus::Excluded => "excluded".to_string(),
                };
                println!("  {icon}  {}  {detail}", entry.path);
            }
        }
    }

    Ok(CommandOutcome::Success)
}

/// Harden the repository: update .gitignore, install git hooks, register merge driver in .gitattributes
///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root cannot be found, `.gitignore` or
/// `.gitattributes` update fails, git hook installation fails, or git config
/// registration fails.
pub fn cmd_harden(json: bool, no_prompt: bool) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    crate::materialize::ensure_gitignored(
        &repo_root,
        crate::materialize::REQUIRED_GITIGNORE_ENTRIES,
    )?;
    repo::install_git_hooks(&repo_root)?;
    crate::materialize::ensure_gitattributes(
        &repo_root,
        &[crate::materialize::GITATTRIBUTES_MERGE_DRIVER_ENTRY],
    )?;
    gitattributes::ensure_merge_driver_git_config(&repo_root)?;

    // REQ-64/65/66/67/68: external hook-manager adapter (repo config + global fallback)
    let config = crate::config::effective_config(&repo_root)?;
    if let Some(adapter) = &config.hooks.adapter {
        match crate::repo::find_adapter_binary(adapter) {
            crate::repo::AdapterLookup::Found(path) => {
                crate::repo::invoke_adapter_harden(&path, &repo_root)?;
            }
            crate::repo::AdapterLookup::NotFound { binary } => {
                let msg = format!(
                    "hook adapter '{binary}' not found on PATH. Install it with: cargo install {binary}"
                );
                if no_prompt {
                    return Err(GitvaultError::Usage(msg));
                }
                eprintln!("warning: {msg}");
            }
        }
    }

    crate::output::output_success(
        "Repository hardened: .gitignore updated, git hooks installed, .gitattributes updated, merge driver configured.",
        json,
    );
    Ok(CommandOutcome::Success)
}

/// Write a timed production allow token (REQ-14)
///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root cannot be found or writing
/// the allow token fails.
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
///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root cannot be found or the
/// token file cannot be removed.
pub fn cmd_revoke_prod(json: bool) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    barrier::revoke_prod(&repo_root)?;
    crate::output::output_success("Production allow token revoked.", json);
    Ok(CommandOutcome::Success)
}

/// Run as git merge driver for .env files (REQ-34, REQ-48)
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if any input file cannot be read or the merged
/// output cannot be written. Returns [`GitvaultError::Usage`] if any file is not
/// valid `.env` syntax.
// String params are intentionally owned: this is a public API called from CLI
// dispatch where the values are moved out of the parsed command struct.
#[allow(clippy::needless_pass_by_value)]
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
        merge_env_content(&base_content, &ours_content, &theirs_content)?;

    let ours_path = PathBuf::from(&ours);
    let tmp = tempfile::NamedTempFile::new_in(
        ours_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    )?;
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
///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root is not found, tracked plaintext
/// is detected, the identity cannot be loaded or parsed, or no encrypted secrets exist.
#[allow(clippy::needless_pass_by_value)]
pub fn cmd_check(
    env_override: Option<String>,
    identity_path: Option<String>,
    selector: Option<String>,
    json: bool,
    skip_history_check: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let cfg = crate::config::effective_config(&repo_root)?;
    let env = env_override.unwrap_or_else(|| env::resolve_env(&repo_root, &cfg.env));

    // Check 1: no tracked plaintext (REQ-10)
    repo::check_no_tracked_plaintext(&repo_root)?;

    // Check 1b: committed history scan (REQ-81)
    if !skip_history_check {
        let history_leaks = repo::find_history_plaintext_leaks(&repo_root)?;
        if !history_leaks.is_empty() {
            return Err(GitvaultError::PlaintextLeak(history_leaks.join(", ")));
        }
    }

    // Probe identity source states for reporting (REQ-50)
    let source_states = probe_identity_sources(identity_path.as_deref(), selector.as_deref());

    // Check 2: identity is loadable
    let identity_str = load_identity_with_selector(identity_path, selector.as_deref())?;
    crypto::parse_identity_any(&identity_str)?;

    // Check 3: recipients directory is readable and all keys are valid
    let recipients = repo::read_recipients(&repo_root, cfg.paths.recipients_dir())?;
    for key in &recipients {
        crypto::parse_recipient(key).map_err(|e| {
            GitvaultError::Usage(format!(
                "Invalid recipient in .gitvault/recipients: {key}: {e}"
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
                "identity_sources": source_states,
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
        println!("   Sources:");
        for state in &source_states {
            match state {
                crate::identity::IdentitySourceState::Resolved { source } => {
                    println!("     ✓ {source}: resolved");
                }
                crate::identity::IdentitySourceState::SourceNotAvailable { source, reason } => {
                    println!("     - {source}: not available ({reason})");
                }
                crate::identity::IdentitySourceState::Ambiguous { source, count } => {
                    println!("     ⚠ {source}: ambiguous ({count} keys)");
                }
            }
        }
    }
    Ok(CommandOutcome::Success)
}

/// Per-file result produced by [`cmd_harden_with_files`].
struct FileImportResult {
    file: String,
    encrypted_path: String,
    /// One of `"encrypted"`, `"skipped"`, `"would-encrypt"`, `"error"`.
    status: String,
    error: Option<String>,
}

/// Harden the repository and optionally import plain files as encrypted secrets (REQ-70).
///
/// When `files` is empty this delegates to [`cmd_harden`], preserving the existing
/// repo-level hardening behaviour (gitignore, hooks, gitattributes).
///
/// When `files` is non-empty the function:
/// 1. Runs [`cmd_harden`] to ensure the repo is hardened.
/// 2. Expands each entry in `files` as a glob pattern.
/// 3. For every resolved path: encrypts it, writes the `.age` artifact to
///    `.secrets/<env>/<filename>.age`, runs `git rm --cached`, appends the
///    filename to `.gitignore`, and optionally removes the source file.
///
/// Idempotent: if `.secrets/<env>/<filename>.age` already exists the file is skipped.
///
/// # Errors
///
/// Returns [`GitvaultError`] if repo-root detection, repo hardening, recipient key
/// resolution, or any non-file-level I/O fails.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn cmd_harden_with_files(
    files: Vec<String>,
    env_name: Option<String>,
    dry_run: bool,
    remove_source: bool,
    extra_recipients: Vec<String>,
    json: bool,
    no_prompt: bool,
    _identity_selector: Option<String>,
) -> Result<CommandOutcome, GitvaultError> {
    if files.is_empty() {
        return cmd_harden(json, no_prompt);
    }

    // Step 1: always run repo hardening first.
    cmd_harden(json, no_prompt)?;

    let repo_root = crate::repo::find_repo_root()?;
    let cfg = crate::config::effective_config(&repo_root)?;
    let active_env = env_name.unwrap_or_else(|| crate::env::resolve_env(&repo_root, &cfg.env));

    // Step 2: expand globs; fall back to treating each pattern as a literal path.
    let mut src_paths: Vec<PathBuf> = Vec::new();
    for pattern in &files {
        let matched: Vec<PathBuf> = glob::glob(pattern)
            .map_err(|e| GitvaultError::Usage(format!("Invalid glob pattern '{pattern}': {e}")))?
            .filter_map(|r| r.ok())
            .collect();

        if matched.is_empty() {
            // No glob matches — treat as literal path so the caller gets a
            // meaningful "file not found" error rather than silent skipping.
            src_paths.push(PathBuf::from(pattern));
        } else {
            src_paths.extend(matched);
        }
    }

    // Step 3: resolve recipient keys once for all files.
    let recipient_keys = crate::identity::resolve_recipient_keys(&repo_root, extra_recipients)?;

    let mut results: Vec<FileImportResult> = Vec::new();

    for src_path in src_paths {
        // Extract filename; skip paths with no file-name component.
        let filename = match src_path.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => {
                results.push(FileImportResult {
                    file: src_path.display().to_string(),
                    encrypted_path: String::new(),
                    status: "error".to_string(),
                    error: Some("path has no file name component".to_string()),
                });
                continue;
            }
        };

        let age_name = format!("{filename}.age");
        let target_path = crate::repo::get_env_encrypted_path(&repo_root, &active_env, &age_name);

        // Path-traversal guard on the output path.
        if let Err(e) = crate::repo::validate_write_path(&repo_root, &target_path) {
            results.push(FileImportResult {
                file: src_path.display().to_string(),
                encrypted_path: target_path.display().to_string(),
                status: "error".to_string(),
                error: Some(e.to_string()),
            });
            continue;
        }

        // AC5: idempotent — skip if the .age counterpart already exists.
        if target_path.exists() {
            results.push(FileImportResult {
                file: src_path.display().to_string(),
                encrypted_path: target_path.display().to_string(),
                status: "skipped".to_string(),
                error: None,
            });
            continue;
        }

        // Dry-run: record intent without writing anything.
        if dry_run {
            results.push(FileImportResult {
                file: src_path.display().to_string(),
                encrypted_path: target_path.display().to_string(),
                status: "would-encrypt".to_string(),
                error: None,
            });
            continue;
        }

        // Read plaintext.
        let plaintext = match std::fs::read(&src_path) {
            Ok(b) => b,
            Err(e) => {
                results.push(FileImportResult {
                    file: src_path.display().to_string(),
                    encrypted_path: target_path.display().to_string(),
                    status: "error".to_string(),
                    error: Some(e.to_string()),
                });
                continue;
            }
        };

        // Parse recipient keys.
        let recipients: Vec<Box<dyn age::Recipient + Send>> = match recipient_keys
            .iter()
            .map(|k| {
                crypto::parse_recipient(k).map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(r) => r,
            Err(e) => {
                results.push(FileImportResult {
                    file: src_path.display().to_string(),
                    encrypted_path: target_path.display().to_string(),
                    status: "error".to_string(),
                    error: Some(e.to_string()),
                });
                continue;
            }
        };

        // Encrypt.
        let ciphertext = match crypto::encrypt(recipients, &plaintext) {
            Ok(c) => c,
            Err(e) => {
                results.push(FileImportResult {
                    file: src_path.display().to_string(),
                    encrypted_path: target_path.display().to_string(),
                    status: "error".to_string(),
                    error: Some(e.to_string()),
                });
                continue;
            }
        };

        // Create parent directories.
        if let Some(parent) = target_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            results.push(FileImportResult {
                file: src_path.display().to_string(),
                encrypted_path: target_path.display().to_string(),
                status: "error".to_string(),
                error: Some(e.to_string()),
            });
            continue;
        }

        // Atomic write.
        let write_result: Result<(), std::io::Error> = (|| {
            let parent = target_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let tmp = tempfile::NamedTempFile::new_in(parent)?;
            std::fs::write(tmp.path(), &ciphertext)?;
            tmp.persist(&target_path).map_err(|e| e.error)?;
            Ok(())
        })();

        if let Err(e) = write_result {
            results.push(FileImportResult {
                file: src_path.display().to_string(),
                encrypted_path: target_path.display().to_string(),
                status: "error".to_string(),
                error: Some(e.to_string()),
            });
            continue;
        }

        // git rm --cached (ignore errors; file may not be tracked).
        let path_str = src_path.to_string_lossy();
        let _ = git_output_raw(&["rm", "--cached", "--quiet", "--", &path_str], &repo_root);

        // Append source filename to .gitignore if not already present.
        let gitignore_entry = format!("/{filename}");
        if let Err(e) =
            crate::materialize::ensure_gitignored(&repo_root, &[gitignore_entry.as_str()])
        {
            results.push(FileImportResult {
                file: src_path.display().to_string(),
                encrypted_path: target_path.display().to_string(),
                status: "error".to_string(),
                error: Some(e.to_string()),
            });
            continue;
        }

        // Optionally remove the source file.
        if remove_source {
            let _ = std::fs::remove_file(&src_path);
        }

        results.push(FileImportResult {
            file: src_path.display().to_string(),
            encrypted_path: target_path.display().to_string(),
            status: "encrypted".to_string(),
            error: None,
        });
    }

    // Tally results.
    let encrypted = results.iter().filter(|r| r.status == "encrypted").count();
    let skipped = results.iter().filter(|r| r.status == "skipped").count();
    let errors = results.iter().filter(|r| r.status == "error").count();
    let would_encrypt = results
        .iter()
        .filter(|r| r.status == "would-encrypt")
        .count();

    if json {
        let items: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "file": r.file,
                    "encrypted_path": r.encrypted_path,
                    "status": r.status,
                    "error": r.error,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "results": items,
                "summary": {
                    "encrypted": encrypted,
                    "skipped": skipped,
                    "errors": errors,
                }
            })
        );
    } else {
        for r in &results {
            match r.status.as_str() {
                "encrypted" => println!("✓ {} → {}", r.file, r.encrypted_path),
                "skipped" => println!("- {} (already imported, skipped)", r.file),
                "would-encrypt" => println!("[dry-run] {} → {}", r.file, r.encrypted_path),
                "error" => eprintln!(
                    "✗ {}: {}",
                    r.file,
                    r.error.as_deref().unwrap_or("unknown error")
                ),
                _ => {}
            }
        }
        if dry_run {
            println!(
                "Dry-run: would encrypt {} file(s), {} already imported",
                would_encrypt, skipped
            );
        } else {
            println!(
                "Encrypted {} file(s), {} skipped, {} error(s)",
                encrypted, skipped, errors
            );
        }
    }

    Ok(CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;
    use crate::commands::admin::gitattributes::{
        MERGE_DRIVER_CONFIG_KEY, MERGE_DRIVER_CONFIG_VALUE,
    };
    use crate::commands::test_helpers::*;

    fn local_git_config(repo_root: &Path, key: &str) -> Option<String> {
        let output = Command::new("git")
            .args(["config", "--local", "--get", key])
            .current_dir(repo_root)
            .output()
            .expect("git config should run");

        if !output.status.success() {
            return None;
        }

        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    #[test]
    fn test_cmd_harden_writes_gitattributes() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false, false).expect("harden should succeed");

        let gitattributes = std::fs::read_to_string(dir.path().join(".gitattributes"))
            .expect(".gitattributes should exist after harden");
        assert!(
            gitattributes.contains("*.env merge=gitvault-env"),
            ".gitattributes should register the gitvault-env merge driver"
        );
    }

    #[test]
    fn test_cmd_harden_gitattributes_idempotent() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Run harden twice — entry must appear exactly once.
        cmd_harden(false, false).expect("first harden should succeed");
        cmd_harden(false, false).expect("second harden should succeed");

        let gitattributes = std::fs::read_to_string(dir.path().join(".gitattributes"))
            .expect(".gitattributes should exist after harden");
        assert_eq!(
            gitattributes.matches("*.env merge=gitvault-env").count(),
            1,
            "merge driver entry should appear exactly once even after running harden twice"
        );
    }

    #[test]
    fn test_cmd_harden_registers_merge_driver_git_config() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false, false).expect("harden should succeed");

        let value = local_git_config(dir.path(), MERGE_DRIVER_CONFIG_KEY)
            .expect("merge driver git config should be set");
        assert_eq!(value, MERGE_DRIVER_CONFIG_VALUE);
    }

    #[test]
    fn test_cmd_harden_preserves_existing_merge_driver_git_config() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let custom_value = "custom-merge-command %O %A %B";
        let status = Command::new("git")
            .args(["config", "--local", MERGE_DRIVER_CONFIG_KEY, custom_value])
            .current_dir(dir.path())
            .status()
            .expect("git config should run");
        assert!(status.success());

        cmd_harden(false, false).expect("harden should succeed");

        let value = local_git_config(dir.path(), MERGE_DRIVER_CONFIG_KEY)
            .expect("merge driver git config should remain set");
        assert_eq!(value, custom_value);
    }

    #[test]
    fn test_cmd_harden_and_status_in_git_repo() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false, false).expect("harden should succeed");
        cmd_status(false, false).expect("status should succeed in clean repo");

        let gitignore = std::fs::read_to_string(dir.path().join(".gitignore"))
            .expect("gitignore should exist after harden");
        assert!(gitignore.contains(".env"));
        assert!(
            !gitignore.contains(".secrets/plain/"),
            "plain dir is under .git/ and must not be in .gitignore"
        );

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
            cmd_check(None, None, None, true, true)
                .expect("check should succeed with identity and clean repo");
        });
    }

    #[test]
    fn test_cmd_status_fail_if_dirty_returns_plaintext_leak() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        std::fs::create_dir_all(dir.path().join(".gitvault/store/dev")).unwrap();
        std::fs::write(dir.path().join(".gitvault/store/dev/app.env.age"), b"x").unwrap();

        let err = cmd_status(true, true).unwrap_err();
        assert!(matches!(err, GitvaultError::Drift(_)));
    }

    #[test]
    fn test_cmd_status_json_output() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false, false).expect("harden should succeed");
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
            cmd_check(None, None, None, false, true).expect("plain check should succeed");
        });
    }

    #[test]
    fn test_cmd_check_invalid_recipient_fails() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let recipients_dir = dir.path().join(".gitvault/recipients");
        std::fs::create_dir_all(&recipients_dir).unwrap();
        std::fs::write(recipients_dir.join("bad.pub"), "not-a-valid-recipient\n").unwrap();

        with_identity_env(identity_file.path(), || {
            let err = cmd_check(None, None, None, true, true).unwrap_err();
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

        // Write a valid recipient so that the for loop executes.
        let pubkey = identity.to_public().to_string();
        repo::write_recipients(
            dir.path(),
            crate::defaults::RECIPIENTS_DIR,
            "default",
            &pubkey,
        )
        .expect("write_recipients should succeed");

        with_identity_env(identity_file.path(), || {
            cmd_check(None, None, None, false, true)
                .expect("check with valid recipient should succeed");
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
        assert!(dir.path().join(".git/gitvault/.prod-token").exists());

        cmd_revoke_prod(false).expect("revoke-prod should succeed");
        // After revoking, the token should be gone.
        assert!(!dir.path().join(".git/gitvault/.prod-token").exists());

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
        let recipients_dir = dir.path().join(".gitvault/recipients");
        std::fs::create_dir_all(&recipients_dir).unwrap();
        std::fs::write(recipients_dir.join("bad.pub"), format!("{bad_key}\n")).unwrap();

        with_identity_env(identity_file.path(), || {
            let err = cmd_check(None, None, None, false, true).unwrap_err();
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
        cmd_harden(true, false).expect("harden with json flag should succeed");
    }

    // -----------------------------------------------------------------------
    // REQ-64/65/66/67: hook-manager adapter tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cmd_harden_no_config_uses_builtin() {
        // No .gitvault/config.toml present → harden succeeds using built-in hooks.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false, false).expect("harden without config should succeed");

        // Built-in hooks should be installed.
        assert!(dir.path().join(".git/hooks/pre-commit").exists());
        assert!(dir.path().join(".git/hooks/pre-push").exists());
    }

    #[test]
    fn test_cmd_harden_unknown_adapter_fails() {
        // A config.toml with an unknown adapter name must return a Usage error.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let gitvault_dir = dir.path().join(".gitvault");
        std::fs::create_dir_all(&gitvault_dir).unwrap();
        std::fs::write(
            gitvault_dir.join("config.toml"),
            "[hooks]\nadapter = \"unknown-adapter\"\n",
        )
        .unwrap();

        let err = cmd_harden(false, false).expect_err("unknown adapter should fail");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error, got: {err:?}"
        );
    }

    #[test]
    fn test_cmd_harden_missing_adapter_no_prompt_fails() {
        // Valid adapter name but binary not on PATH + no_prompt=true → Usage error.
        // gitvault-husky is not installed in this environment, so it will not be found.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let gitvault_dir = dir.path().join(".gitvault");
        std::fs::create_dir_all(&gitvault_dir).unwrap();
        std::fs::write(
            gitvault_dir.join("config.toml"),
            "[hooks]\nadapter = \"husky\"\n",
        )
        .unwrap();

        // gitvault-husky is not installed, so find_adapter_binary returns NotFound.
        // no_prompt=true should turn that into a Usage error.
        let err = cmd_harden(false, true).expect_err("missing adapter with no_prompt should fail");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error, got: {err:?}"
        );
        assert!(
            err.to_string().contains("not found"),
            "error should mention 'not found': {err}"
        );
    }

    #[test]
    fn test_cmd_harden_missing_adapter_interactive_warns() {
        // Valid adapter name but binary not on PATH + no_prompt=false → succeeds (warning to stderr).
        // gitvault-husky is not installed in this environment, so it will not be found.
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let gitvault_dir = dir.path().join(".gitvault");
        std::fs::create_dir_all(&gitvault_dir).unwrap();
        std::fs::write(
            gitvault_dir.join("config.toml"),
            "[hooks]\nadapter = \"husky\"\n",
        )
        .unwrap();

        // gitvault-husky is not installed; no_prompt=false means we just warn and continue.
        let result = cmd_harden(false, false);
        assert!(
            result.is_ok(),
            "missing adapter in interactive mode should succeed (with warning): {result:?}"
        );
        assert_eq!(result.unwrap(), CommandOutcome::Success);
    }

    /// Helper to create fake ssh-add binary that returns N ED25519 keys.
    #[cfg(unix)]
    fn make_fake_ssh_add_dir(key_count: usize) -> TempDir {
        use std::os::unix::fs::PermissionsExt;
        let bin_dir = TempDir::new().unwrap();
        let mut lines = String::new();
        for i in 0..key_count {
            use std::fmt::Write as _;
            writeln!(lines, "256 SHA256:fakeprint{i} test_key_{i} (ED25519)").unwrap();
        }
        let ssh_add_path = bin_dir.path().join("ssh-add");
        std::fs::write(&ssh_add_path, format!("#!/bin/sh\nprintf '%s' '{lines}'\n")).unwrap();
        std::fs::set_permissions(&ssh_add_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Also provide a stub ssh-keygen so PATH resolution doesn't fail
        let ssh_keygen_path = bin_dir.path().join("ssh-keygen");
        std::fs::write(&ssh_keygen_path, "#!/bin/sh\necho ''\n").unwrap();
        std::fs::set_permissions(&ssh_keygen_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin_dir
    }

    /// When SSH agent has 2 ED25519 keys, `probe_identity_sources` returns Ambiguous.
    /// `cmd_check` should report it in plain-text output (covers lines 283-285 in Ambiguous arm).
    #[cfg(unix)]
    #[test]
    fn test_cmd_check_reports_ambiguous_ssh_source() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        // Set up fake ssh-add returning 2 ED25519 keys so SSH source is Ambiguous.
        let bin_dir = make_fake_ssh_add_dir(2);
        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        with_env_var("PATH", Some(new_path.as_str()), || {
            with_env_var("SSH_AUTH_SOCK", Some("/tmp/fake-agent.sock"), || {
                with_identity_env(identity_file.path(), || {
                    // cmd_check with json=false triggers the for loop over source_states,
                    // hitting the Ambiguous arm (lines 283-285) for the ssh-agent source.
                    let result = cmd_check(None, None, None, false, true);
                    // Should succeed overall because GITVAULT_IDENTITY is available.
                    assert!(result.is_ok(), "cmd_check should succeed: {result:?}");
                });
            });
        });
    }

    // -----------------------------------------------------------------------
    // REQ-70: cmd_harden_with_files tests
    // -----------------------------------------------------------------------

    /// Basic file-import test: file is encrypted, .age artifact created, gitignore updated.
    #[test]
    fn test_harden_with_files_encrypts_and_gitignores() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Create a plaintext file to import.
        let env_file = dir.path().join(".env");
        std::fs::write(&env_file, "SECRET=hunter2\n").unwrap();

        // Generate an identity and use its public key as explicit recipient.
        let (identity_file, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();

        with_identity_env(identity_file.path(), || {
            cmd_harden_with_files(
                vec![env_file.to_string_lossy().to_string()],
                Some("dev".to_string()),
                false,        // dry_run
                false,        // remove_source
                vec![pubkey], // extra_recipients
                false,        // json
                false,        // no_prompt
                None,         // identity_selector
            )
            .expect("harden-with-files should succeed");
        });

        // The .age artifact should exist.
        let age_path = dir.path().join(".gitvault/store/dev/.env.age");
        assert!(age_path.exists(), ".env.age should have been created");

        // .gitignore should contain the source filename.
        let gitignore = std::fs::read_to_string(dir.path().join(".gitignore"))
            .expect(".gitignore should exist");
        assert!(
            gitignore.contains("/.env"),
            ".gitignore should contain /.env, got: {gitignore}"
        );
    }

    /// Idempotent: running a second time with the same file skips it because
    /// the .age counterpart already exists (AC5).
    #[test]
    fn test_harden_with_files_idempotent() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let env_file = dir.path().join(".env");
        std::fs::write(&env_file, "SECRET=hunter2\n").unwrap();

        let (identity_file, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();

        with_identity_env(identity_file.path(), || {
            // First import.
            cmd_harden_with_files(
                vec![env_file.to_string_lossy().to_string()],
                Some("dev".to_string()),
                false,
                false,
                vec![pubkey.clone()],
                true, // json — cover JSON branch on second run too
                false,
                None,
            )
            .expect("first import should succeed");

            // Second import — should succeed (file reported as skipped).
            cmd_harden_with_files(
                vec![env_file.to_string_lossy().to_string()],
                Some("dev".to_string()),
                false,
                false,
                vec![pubkey],
                true,
                false,
                None,
            )
            .expect("second import should succeed (idempotent)");
        });

        // The .age artifact should still exist.
        assert!(dir.path().join(".gitvault/store/dev/.env.age").exists());
    }

    /// Empty files vec → delegates to existing repo-harden behaviour, no file logic runs.
    #[test]
    fn test_harden_no_files_delegates_to_repo_harden() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden_with_files(
            vec![], // no files → delegate
            None,
            false,
            false,
            vec![],
            false,
            false,
            None,
        )
        .expect("harden-with-files with no files should succeed");

        // Standard repo-harden artefacts must exist.
        assert!(
            dir.path().join(".git/hooks/pre-commit").exists(),
            "pre-commit hook should be installed"
        );
        assert!(
            dir.path().join(".gitignore").exists(),
            ".gitignore should be created by repo harden"
        );
    }

    /// --dry-run flag: nothing is written, but the call succeeds.
    #[test]
    fn test_harden_with_files_dry_run_does_not_write() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let env_file = dir.path().join(".env");
        std::fs::write(&env_file, "SECRET=hunter2\n").unwrap();

        let (identity_file, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();

        with_identity_env(identity_file.path(), || {
            cmd_harden_with_files(
                vec![env_file.to_string_lossy().to_string()],
                Some("dev".to_string()),
                true, // dry_run = true
                false,
                vec![pubkey],
                false,
                false,
                None,
            )
            .expect("dry-run should succeed");
        });

        // The .age artifact must NOT have been created.
        assert!(
            !dir.path().join(".gitvault/store/dev/.env.age").exists(),
            "dry-run must not write any .age artifact"
        );
    }

    // ── REQ-81: history scan in cmd_check ────────────────────────────────────

    /// `cmd_check` with `skip_history_check: false` succeeds on a clean repo
    /// (no plaintext files in committed history). Covers lines 241-243.
    #[test]
    fn test_cmd_check_history_scan_clean_repo_succeeds() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            let result = cmd_check(None, None, None, false, false);
            assert!(
                result.is_ok(),
                "cmd_check with history scan should succeed on clean repo: {result:?}"
            );
        });
    }

    /// `cmd_check` with `skip_history_check: false` fails when a `.env` file
    /// appears in committed history. Covers line 244 (PlaintextLeak return).
    #[test]
    fn test_cmd_check_history_scan_detects_committed_env() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Commit a .env file so it appears in git history.
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET=leaked\n").unwrap();
        Command::new("git")
            .args(["add", ".env"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "add secrets"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        // Remove the file so check_no_tracked_plaintext doesn't fail first.
        std::fs::remove_file(dir.path().join(".env")).unwrap();

        let (identity_file, _) = setup_identity_file();
        with_identity_env(identity_file.path(), || {
            let err = cmd_check(None, None, None, false, false).unwrap_err();
            assert!(
                matches!(err, GitvaultError::PlaintextLeak(_)),
                "history scan should report PlaintextLeak, got: {err:?}"
            );
        });
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    /// Write a minimal `.gitvault/config.toml` so that `cmd_status` picks up
    /// the `[seal]` rule configuration we want to test.
    fn write_seal_config(repo_root: &Path, toml: &str) {
        let config_dir = repo_root.join(".gitvault");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.toml"), toml).unwrap();
    }

    // ── cmd_status: seal drift JSON output ───────────────────────────────────

    /// `cmd_status --json` with a sealed file produces JSON that includes the
    /// `seal` array. Covers the JSON branch of the seal-drift block (lines 55–75).
    #[test]
    fn test_cmd_status_seal_drift_json_sealed_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // A file whose value starts with "age:" is considered sealed (Ok).
        std::fs::write(dir.path().join("config.env"), "SECRET=age:YWdl\n").unwrap();
        write_seal_config(
            dir.path(),
            "[[seal.rule]]\naction = \"allow\"\npath = \"config.env\"\n",
        );

        cmd_status(true, false).expect("cmd_status --json should succeed with sealed file");
    }

    /// `cmd_status --json` with a file that has drift (no age:-prefixed values)
    /// still succeeds when `fail_if_dirty=false`. Covers the JSON branch with
    /// a `drifted` entry in the `seal` array.
    #[test]
    fn test_cmd_status_seal_drift_json_drifted_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Plaintext value — drift detected.
        std::fs::write(dir.path().join("config.env"), "SECRET=plaintext\n").unwrap();
        write_seal_config(
            dir.path(),
            "[[seal.rule]]\naction = \"allow\"\npath = \"config.env\"\n",
        );

        cmd_status(true, false).expect("cmd_status --json should succeed even with drift");
    }

    // ── cmd_status: seal drift plain-text output ──────────────────────────────

    /// `cmd_status` (plain text) with a sealed file shows the ✓ icon.
    /// Covers the plain-text seal-drift loop (lines 76–108) with Ok status.
    #[test]
    fn test_cmd_status_seal_drift_plain_ok_icon() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        std::fs::write(dir.path().join("config.env"), "SECRET=age:YWdl\n").unwrap();
        write_seal_config(
            dir.path(),
            "[[seal.rule]]\naction = \"allow\"\npath = \"config.env\"\n",
        );

        cmd_status(false, false).expect("cmd_status should succeed with sealed file");
    }

    /// `cmd_status` (plain text) with a drifted file shows the ✗ icon and the
    /// `fail_if_dirty=false` path continues without error.
    /// Covers the Drift branch inside the plain-text loop.
    #[test]
    fn test_cmd_status_seal_drift_plain_drift_icon() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Plaintext value — no age: prefix → drift.
        std::fs::write(dir.path().join("config.env"), "SECRET=plaintext\n").unwrap();
        write_seal_config(
            dir.path(),
            "[[seal.rule]]\naction = \"allow\"\npath = \"config.env\"\n",
        );

        // fail_if_dirty=false → should succeed even with drift.
        cmd_status(false, false)
            .expect("cmd_status should succeed when fail_if_dirty=false despite drift");
    }

    /// `cmd_status` (plain text) with an excluded file shows the excluded icon.
    /// Covers the `SealDriftStatus::Excluded` arm in the plain-text loop.
    #[test]
    fn test_cmd_status_seal_drift_plain_excluded() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        std::fs::write(dir.path().join("config.env"), "SECRET=plaintext\n").unwrap();
        write_seal_config(
            dir.path(),
            "[[seal.rule]]\naction = \"allow\"\npath = \"config.env\"\n\n[[seal.rule]]\naction = \"deny\"\npath = \"config.env\"\n",
        );

        cmd_status(false, false).expect("cmd_status should succeed with an excluded seal entry");
    }

    /// `cmd_status` (plain text) with a rule keys entry shows the
    /// "(N/N fields sealed)" detail when `total_count > 0`.
    /// Covers the `total_count > 0` branch inside the Ok arm.
    #[test]
    fn test_cmd_status_seal_drift_plain_override_ok_with_count() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // SECRET is sealed; the override lists exactly that field.
        std::fs::write(dir.path().join("config.env"), "SECRET=age:YWdl\n").unwrap();
        write_seal_config(
            dir.path(),
            "[[seal.rule]]\naction = \"allow\"\npath = \"config.env\"\nkeys = [\"SECRET\"]\n",
        );

        cmd_status(false, false).expect("cmd_status should succeed with override ok entry");
    }

    /// `cmd_status` with `fail_if_dirty=true` and a drifted sealed file must
    /// return `Err(GitvaultError::Drift(...))`. Covers the seal-drift leg of the
    /// fail-if-dirty guard (the `has_seal_drift` branch).
    #[test]
    fn test_cmd_status_seal_drift_fail_if_dirty_returns_drift_err() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Plaintext value → drift.
        std::fs::write(dir.path().join("config.env"), "SECRET=plaintext\n").unwrap();
        write_seal_config(
            dir.path(),
            "[[seal.rule]]\naction = \"allow\"\npath = \"config.env\"\n",
        );

        let err = cmd_status(false, true).unwrap_err();
        assert!(
            matches!(err, GitvaultError::Drift(_)),
            "should return Drift error, got: {err:?}"
        );
    }

    // ── cmd_harden_with_files: remove_source ─────────────────────────────────

    /// `cmd_harden_with_files` with `remove_source=true` must delete the
    /// plaintext source file after encrypting it.
    /// Covers line 551 (`std::fs::remove_file`).
    #[test]
    fn test_harden_with_files_removes_source_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let env_file = dir.path().join("secrets.env");
        std::fs::write(&env_file, "TOKEN=hunter2\n").unwrap();

        let (identity_file, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();

        with_identity_env(identity_file.path(), || {
            cmd_harden_with_files(
                vec![env_file.to_string_lossy().to_string()],
                Some("dev".to_string()),
                false, // dry_run
                true,  // remove_source ← key flag
                vec![pubkey],
                false,
                false,
                None,
            )
            .expect("harden-with-files --remove-source should succeed");
        });

        assert!(
            !env_file.exists(),
            "source file should have been removed with --remove-source"
        );
        assert!(
            dir.path()
                .join(".gitvault/store/dev/secrets.env.age")
                .exists(),
            "encrypted artifact should still exist"
        );
    }

    // ── cmd_harden_with_files: plain-text error output ────────────────────────

    /// When a requested source file does not exist, `cmd_harden_with_files`
    /// (with `json=false`) should still return `Ok` but record an error status
    /// for that file (printed to stderr). This covers the `"error" =>` arm in
    /// the plain-text result loop (lines 600–604).
    #[test]
    fn test_harden_with_files_plain_error_output_for_missing_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let (identity_file, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();

        with_identity_env(identity_file.path(), || {
            // "ghost.env" does not exist — the per-file read will fail.
            let result = cmd_harden_with_files(
                vec!["ghost.env".to_string()],
                Some("dev".to_string()),
                false,
                false,
                vec![pubkey],
                false, // json=false → plain-text error output branch
                false,
                None,
            );
            // The top-level call still succeeds; per-file errors are non-fatal.
            assert!(
                result.is_ok(),
                "harden-with-files should return Ok even when a file is missing: {result:?}"
            );
        });
    }

    /// Same scenario with `json=true` — a missing file produces an `"error"`
    /// entry in the JSON results array. Covers the JSON output path alongside
    /// the plain-text test above.
    #[test]
    fn test_harden_with_files_json_error_output_for_missing_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let (identity_file, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();

        with_identity_env(identity_file.path(), || {
            let result = cmd_harden_with_files(
                vec!["ghost.env".to_string()],
                Some("dev".to_string()),
                false,
                false,
                vec![pubkey],
                true, // json=true
                false,
                None,
            );
            assert!(result.is_ok(), "should succeed even when file is missing");
        });
    }

    // ── local_git_config helper: absent key ──────────────────────────────────

    /// `local_git_config` returns `None` when the requested key is absent from
    /// the repository config. Covers the `return None` at line 645.
    #[test]
    fn test_local_git_config_returns_none_for_absent_key() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());

        let result = local_git_config(dir.path(), "gitvault.test.nonexistent-key-xyz");
        assert!(
            result.is_none(),
            "local_git_config should return None for an absent key"
        );
    }
}
