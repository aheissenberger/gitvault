//! SSM path helpers and local `.ssm-refs.json` persistence.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use crate::error::GitvaultError;

/// Return the SSM parameter path for a given app, environment, and key.
/// Format: `/{app}/{env}/{key}`
pub fn ssm_path(app: &str, env: &str, key: &str) -> String {
    format!("/{app}/{env}/{key}")
}

/// Return the path to the local SSM refs file for the given environment.
/// Path: `{repo_root}/secrets/{env}/.ssm-refs.json`
pub fn refs_file_path(repo_root: &Path, env: &str) -> PathBuf {
    repo_root.join("secrets").join(env).join(".ssm-refs.json")
}

/// Validate that an SSM app name only contains safe path characters.
pub(super) fn validate_app_name(app_name: &str) -> Result<(), GitvaultError> {
    if !app_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(GitvaultError::Usage(format!(
            "SSM app name '{app_name}' contains invalid characters (must match [A-Za-z0-9_.-])"
        )));
    }
    Ok(())
}

/// Derive the application name from the git remote URL, falling back to the
/// repository directory name.  Returns an error if the derived name contains
/// characters that are unsafe in an SSM parameter path.
pub(super) async fn get_app_name(repo_root: &Path) -> Result<String, GitvaultError> {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(repo_root)
        .output()
        .await;

    if let Ok(out) = output
        && out.status.success()
    {
        let url = String::from_utf8_lossy(&out.stdout);
        let url = url.trim();
        // Last path component, stripped of ".git"
        if let Some(name) = url.split('/').next_back() {
            let name = name.trim_end_matches(".git").trim();
            if !name.is_empty() {
                validate_app_name(name)?;
                return Ok(name.to_string());
            }
        }
    }

    let name = repo_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app")
        .to_string();
    validate_app_name(&name)?;
    Ok(name)
}

/// Load the refs map from disk.  Returns an empty map when the file does not
/// exist yet.
pub(super) async fn load_refs(
    repo_root: &Path,
    env: &str,
) -> Result<HashMap<String, String>, GitvaultError> {
    let path = refs_file_path(repo_root, env);
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let text = tokio::fs::read_to_string(&path).await?;
    let map: HashMap<String, String> =
        serde_json::from_str(&text).map_err(|e| GitvaultError::Other(e.to_string()))?;
    Ok(map)
}

/// Persist the refs map to disk, creating parent directories as needed.
pub(super) async fn save_refs(
    repo_root: &Path,
    env: &str,
    refs: &HashMap<String, String>,
) -> Result<(), GitvaultError> {
    let path = refs_file_path(repo_root, env);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let text =
        serde_json::to_string_pretty(refs).map_err(|e| GitvaultError::Other(e.to_string()))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".gitvault-tmp-")
        .tempfile_in(path.parent().unwrap_or(Path::new(".")))?;
    tmp.write_all(text.as_bytes())?;
    tmp.persist(&path).map_err(|e| GitvaultError::Io(e.error))?;
    Ok(())
}
