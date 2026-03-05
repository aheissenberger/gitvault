//! `gitvault edit` command implementation.
//!
//! Opens a sealed file in an editor, then re-seals on save.
//!
//! # Workflow
//! 1. Resolve `[[seal.override]]` fields from config (same as `cmd_seal`).
//! 2. Unseal content to a temp file in `std::env::temp_dir()`.
//! 3. Set temp file permissions to `0o600` (Unix only).
//! 4. Capture original bytes before launching editor.
//! 5. Launch editor and wait for exit.
//! 6. Re-read temp file; if changed, re-seal original; if unchanged, report "No changes".
//! 7. Zeroize temp buffer and delete temp file.

use std::path::{Path, PathBuf};
use std::process::Command;

use zeroize::Zeroize;

use crate::commands::effects::CommandOutcome;
use crate::commands::seal::{seal_content, unseal_content, validated_extension};
use crate::error::GitvaultError;

// ---------------------------------------------------------------------------
// Public options struct
// ---------------------------------------------------------------------------

/// Options for `gitvault edit`.
pub struct EditOptions {
    pub file: String,
    pub identity: Option<String>,
    pub env: Option<String>,
    pub fields: Option<String>,
    pub editor: Option<String>,
    pub json: bool,
    pub no_prompt: bool,
    pub selector: Option<String>,
}

// ---------------------------------------------------------------------------
// Editor resolution
// ---------------------------------------------------------------------------

/// Resolve the editor command tokens to use.
///
/// Priority (first non-empty wins):
/// 1. `cli_editor` CLI flag
/// 2. `config_editor` from `[editor] command` in config
/// 3. `$VISUAL` env var
/// 4. `$EDITOR` env var
/// 5. Platform fallback (`open -W -n` on macOS, `notepad.exe` on Windows, `vi` elsewhere)
///
/// Returns a `Vec<String>` where index 0 is the binary and the rest are args
/// (the temp file path is appended by the caller).
pub fn resolve_editor(cli_editor: Option<&str>, config_editor: Option<&str>) -> Vec<String> {
    // 1. CLI flag
    if let Some(cmd) = cli_editor.filter(|s| !s.is_empty()) {
        return shell_split(cmd);
    }

    // 2. Config file
    if let Some(cmd) = config_editor.filter(|s| !s.is_empty()) {
        return shell_split(cmd);
    }

    // 3. $VISUAL
    if let Ok(vis) = std::env::var("VISUAL")
        && !vis.is_empty()
    {
        return shell_split(&vis);
    }

    // 4. $EDITOR
    if let Ok(ed) = std::env::var("EDITOR")
        && !ed.is_empty()
    {
        return shell_split(&ed);
    }

    // 5. Platform fallback
    platform_fallback_editor()
}

/// Split an editor command string on whitespace (shell-like, no quoting).
fn shell_split(cmd: &str) -> Vec<String> {
    cmd.split_whitespace().map(str::to_string).collect()
}

/// Return platform-specific default editor tokens.
fn platform_fallback_editor() -> Vec<String> {
    if cfg!(target_os = "macos") {
        vec!["open".to_string(), "-W".to_string(), "-n".to_string()]
    } else if cfg!(target_os = "windows") {
        vec!["notepad.exe".to_string()]
    } else {
        vec!["vi".to_string()]
    }
}

// ---------------------------------------------------------------------------
// Command entry point
// ---------------------------------------------------------------------------

/// `gitvault edit <FILE>` — unseal, open in editor, re-seal on change.
///
/// # Errors
///
/// Returns [`GitvaultError`] on IO, parse, encryption, or decryption failures.
#[allow(clippy::needless_pass_by_value)]
pub fn cmd_edit(opts: EditOptions) -> Result<CommandOutcome, GitvaultError> {
    let file_path = PathBuf::from(&opts.file);
    let repo_root = crate::repo::find_repo_root()?;

    // Validate file format.
    let ext = validated_extension(&file_path)?;

    // Resolve absolute paths.
    let abs_file = if file_path.is_absolute() {
        file_path.clone()
    } else {
        std::env::current_dir()?.join(&file_path)
    };
    let abs_repo = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.clone());
    let abs_file_canon = abs_file.canonicalize().unwrap_or_else(|_| abs_file.clone());

    // Compute repo-relative path for config override lookup.
    let rel_path = relative_path_to_repo(&abs_file_canon, &abs_repo);

    // Resolve fields from CLI flag or [[seal.override]] config.
    let cli_fields: Option<Vec<String>> = opts
        .fields
        .as_deref()
        .map(|f| f.split(',').map(|s| s.trim().to_string()).collect());
    let config_fields: Option<Vec<String>> =
        crate::config::load_config(&repo_root).ok().and_then(|cfg| {
            cfg.seal
                .overrides
                .into_iter()
                .find(|o| pattern_matches(&o.pattern, &rel_path))
                .map(|o| o.fields)
        });
    let fields_opt = cli_fields.or(config_fields);

    // Load identity for unsealing.
    let identity_str = crate::identity::load_identity_with_selector(
        opts.identity.clone(),
        opts.selector.as_deref(),
    )?;
    let any_identity = crate::crypto::parse_identity_any_with_passphrase(
        &identity_str,
        crate::identity::try_fetch_ssh_passphrase(
            crate::defaults::KEYRING_SERVICE,
            crate::defaults::KEYRING_ACCOUNT,
            opts.no_prompt,
        ),
    )?;
    let identity = any_identity.as_identity();

    // Read sealed file content.
    let sealed_content = std::fs::read_to_string(&file_path)
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;

    // Unseal to plain text.
    let mut plain = unseal_content(&sealed_content, &ext, fields_opt.as_deref(), identity)?;

    // Write plain text to a named temp file.
    let suffix = format!(".{ext}");
    let tmp = tempfile::Builder::new()
        .suffix(&suffix)
        .tempfile()
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(&tmp_path, plain.as_bytes())
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;

    // Set restrictive permissions on Unix.
    set_permissions_600(&tmp_path)?;

    // Capture content before editor launch for change detection.
    let before_bytes = std::fs::read(&tmp_path)
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;

    // Resolve editor.
    let config_editor = crate::config::load_config(&repo_root)
        .ok()
        .and_then(|cfg| cfg.editor.command);
    let mut editor_tokens = resolve_editor(opts.editor.as_deref(), config_editor.as_deref());

    if editor_tokens.is_empty() {
        return Err(GitvaultError::Usage(
            "could not determine editor to use".to_string(),
        ));
    }

    // Append temp file path.
    editor_tokens.push(tmp_path.to_string_lossy().into_owned());

    // Launch editor and wait.
    let binary = editor_tokens.remove(0);
    let status = Command::new(&binary)
        .args(&editor_tokens)
        .status()
        .map_err(|e| GitvaultError::Usage(format!("failed to launch editor '{binary}': {e}")))?;

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        // Zeroize and clean up before returning.
        plain.zeroize();
        return Err(GitvaultError::Usage(format!(
            "editor exited with non-zero status: {code}"
        )));
    }

    // Read back temp file after editor.
    let after_bytes = std::fs::read(&tmp_path)
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;

    // Zeroize the original plain buffer — no longer needed.
    plain.zeroize();

    if after_bytes == before_bytes {
        // No change — skip re-sealing.
        crate::output::output_success("No changes", opts.json);
        return Ok(CommandOutcome::Success);
    }

    // Content changed — re-seal.
    let new_plain = String::from_utf8(after_bytes)
        .map_err(|e| GitvaultError::Usage(format!("editor produced non-UTF-8 content: {e}")))?;

    // Load recipients for re-sealing.
    let recipient_keys = crate::identity::resolve_recipient_keys(&repo_root, vec![])?;

    let resealed = seal_content(&new_plain, &ext, fields_opt.as_deref(), &recipient_keys)?;

    // Write sealed content back atomically.
    crate::fs_util::atomic_write(&file_path, resealed.as_bytes())?;

    crate::output::output_success(&format!("Sealed: {}", file_path.display()), opts.json);
    Ok(CommandOutcome::Success)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Compute repo-relative path string.
fn relative_path_to_repo(abs_file: &Path, abs_repo: &Path) -> String {
    abs_file
        .strip_prefix(abs_repo)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| abs_file.to_string_lossy().into_owned())
}

/// Return whether `path` matches `pattern` (same logic as seal.rs).
fn pattern_matches(pattern: &str, path: &str) -> bool {
    // Delegate to the same glob logic used by seal.
    glob::Pattern::new(pattern)
        .map(|p| p.matches(path))
        .unwrap_or(false)
}

/// Set file permissions to 0o600 on Unix; no-op on other platforms.
#[allow(unused_variables)]
fn set_permissions_600(path: &Path) -> Result<(), GitvaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use tempfile::TempDir;

    // ── resolve_editor tests ────────────────────────────────────────────────

    #[test]
    fn test_resolve_editor_cli_flag_takes_precedence() {
        // Even if VISUAL/EDITOR are set and a config command is given,
        // the CLI flag wins.
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with_env_var("VISUAL", Some("emacs"), || {
            with_env_var("EDITOR", Some("nano"), || {
                let tokens = resolve_editor(Some("code --wait"), Some("vim"));
                assert_eq!(tokens, vec!["code", "--wait"]);
            });
        });
    }

    #[test]
    fn test_resolve_editor_uses_visual_when_no_config() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with_env_var("VISUAL", Some("emacs"), || {
            with_env_var("EDITOR", Some("nano"), || {
                let tokens = resolve_editor(None, None);
                assert_eq!(tokens, vec!["emacs"]);
            });
        });
    }

    #[test]
    fn test_resolve_editor_uses_editor_when_no_visual() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with_env_var("VISUAL", None, || {
            with_env_var("EDITOR", Some("nano"), || {
                let tokens = resolve_editor(None, None);
                assert_eq!(tokens, vec!["nano"]);
            });
        });
    }

    #[test]
    fn test_resolve_editor_platform_fallback() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with_env_var("VISUAL", None, || {
            with_env_var("EDITOR", None, || {
                let tokens = resolve_editor(None, None);
                // Platform fallback — just verify it's non-empty.
                assert!(!tokens.is_empty(), "platform fallback must return tokens");
                // On Linux in CI the fallback is "vi".
                #[cfg(not(any(target_os = "macos", target_os = "windows")))]
                assert_eq!(tokens, vec!["vi"]);
            });
        });
    }

    // ── cmd_edit integration test ───────────────────────────────────────────

    /// Full integration test: editor that does NOT modify the file → "No changes".
    #[test]
    #[cfg(unix)]
    fn test_cmd_edit_no_change_skips_reseal() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let dir = TempDir::new().expect("temp dir should be created");
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Create recipient + identity.
        let (identity_file, identity) = setup_identity_file();
        let pub_key = {
            use age::x25519::Identity;
            let id: &Identity = &identity;
            id.to_public().to_string()
        };

        // Write recipients dir so cmd_seal / cmd_edit can find a recipient.
        let recipients_dir = dir.path().join(".gitvault").join("recipients");
        std::fs::create_dir_all(&recipients_dir).expect("recipients dir should be created");
        std::fs::write(recipients_dir.join("test.pub"), &pub_key)
            .expect("recipient file should be written");

        // Create a simple .env file and seal it.
        let env_file = dir.path().join(".env");
        std::fs::write(&env_file, "SECRET=hunter2\n").expect("env file should be written");

        with_identity_env(identity_file.path(), || {
            // Seal the file first.
            crate::commands::seal::cmd_seal(crate::commands::seal::SealOptions {
                file: env_file.to_string_lossy().into_owned(),
                recipients: vec![],
                env: None,
                fields: None,
                json: true,
                no_prompt: true,
                selector: None,
            })
            .expect("cmd_seal should succeed");

            // Record the sealed content before editing.
            let sealed_before = std::fs::read(&env_file).expect("sealed file should be readable");

            // Use `true` as editor — it exits 0 without touching any file.
            let outcome = cmd_edit(EditOptions {
                file: env_file.to_string_lossy().into_owned(),
                identity: Some(identity_file.path().to_string_lossy().into_owned()),
                env: None,
                fields: None,
                editor: Some("true".to_string()),
                json: true,
                no_prompt: true,
                selector: None,
            })
            .expect("cmd_edit should succeed");

            assert_eq!(outcome, CommandOutcome::Success);

            // Sealed file must be unchanged.
            let sealed_after =
                std::fs::read(&env_file).expect("sealed file should still be readable");
            assert_eq!(
                sealed_before, sealed_after,
                "file should be unchanged when editor makes no modifications"
            );
        });
    }
}
