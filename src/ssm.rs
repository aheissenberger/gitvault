//! AWS SSM Parameter Store backend (REQ-26 to REQ-30, REQ-49).
//!
//! All functions in this module are gated behind the `ssm` Cargo feature.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use aws_sdk_ssm::types::ParameterType;

use crate::aws_config::AwsConfig;
use crate::error::GitvaultError;

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

/// Derive the application name from the git remote URL, falling back to the
/// repository directory name.
fn get_app_name(repo_root: &Path) -> String {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(repo_root)
        .output();

    if let Ok(out) = output
        && out.status.success()
    {
        let url = String::from_utf8_lossy(&out.stdout);
        let url = url.trim();
        // Last path component, stripped of ".git"
        if let Some(name) = url.split('/').next_back() {
            let name = name.trim_end_matches(".git").trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }

    repo_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app")
        .to_string()
}

/// Load the refs map from disk.  Returns an empty map when the file does not
/// exist yet.
fn load_refs(repo_root: &Path, env: &str) -> Result<HashMap<String, String>, GitvaultError> {
    let path = refs_file_path(repo_root, env);
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let map: HashMap<String, String> =
        serde_json::from_str(&text).map_err(|e| GitvaultError::Other(e.to_string()))?;
    Ok(map)
}

/// Persist the refs map to disk, creating parent directories as needed.
fn save_refs(
    repo_root: &Path,
    env: &str,
    refs: &HashMap<String, String>,
) -> Result<(), GitvaultError> {
    let path = refs_file_path(repo_root, env);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text =
        serde_json::to_string_pretty(refs).map_err(|e| GitvaultError::Other(e.to_string()))?;
    std::fs::write(&path, text)?;
    Ok(())
}

/// Fetch all SSM parameters under `/{app}/{env}/` with pagination.
async fn fetch_all_params(
    client: &aws_sdk_ssm::Client,
    path_prefix: &str,
) -> Result<Vec<(String, String)>, GitvaultError> {
    let mut results = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client
            .get_parameters_by_path()
            .path(path_prefix)
            .recursive(true)
            .with_decryption(true);

        if let Some(ref tok) = next_token {
            req = req.next_token(tok);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| GitvaultError::Other(e.to_string()))?;

        for param in resp.parameters() {
            if let (Some(name), Some(value)) = (param.name(), param.value()) {
                results.push((name.to_string(), value.to_string()));
            }
        }

        next_token = resp.next_token().map(str::to_string);
        if next_token.is_none() {
            break;
        }
    }

    Ok(results)
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// Pull all parameters under `/{app}/{env}/` from SSM and write the parameter
/// paths to the local `.ssm-refs.json` file.
///
/// REQ-28: pull — read SSM values and compare with local references.
pub async fn cmd_ssm_pull(
    repo_root: &Path,
    env: &str,
    aws: &AwsConfig,
) -> Result<(), GitvaultError> {
    let app = get_app_name(repo_root);
    let client = aws.build_client().await?;
    let prefix = format!("/{app}/{env}/");

    let params = fetch_all_params(&client, &prefix).await?;

    let mut refs: HashMap<String, String> = HashMap::new();
    for (name, _value) in &params {
        // Key is the trailing component after the prefix
        let key = name
            .strip_prefix(&prefix)
            .unwrap_or(name.as_str())
            .to_string();
        refs.insert(key, name.clone());
    }

    save_refs(repo_root, env, &refs)?;

    println!(
        "Pulled {} parameter(s) from SSM path prefix '{}'",
        refs.len(),
        prefix
    );
    Ok(())
}

/// Show a diff between local SSM references and the live SSM values.
/// Values are masked unless `reveal` is true.
///
/// REQ-30: diff without revealing values.
pub async fn cmd_ssm_diff(
    repo_root: &Path,
    env: &str,
    aws: &AwsConfig,
    reveal: bool,
) -> Result<(), GitvaultError> {
    let app = get_app_name(repo_root);
    let client = aws.build_client().await?;
    let prefix = format!("/{app}/{env}/");

    // Current SSM state
    let ssm_params: HashMap<String, String> = fetch_all_params(&client, &prefix)
        .await?
        .into_iter()
        .map(|(name, value)| {
            let key = name
                .strip_prefix(&prefix)
                .unwrap_or(name.as_str())
                .to_string();
            (key, value)
        })
        .collect();

    // Local refs
    let local_refs = load_refs(repo_root, env)?;

    // Keys from both sides
    let mut all_keys: Vec<String> = {
        let mut s: std::collections::HashSet<String> = std::collections::HashSet::new();
        s.extend(ssm_params.keys().cloned());
        s.extend(local_refs.keys().cloned());
        s.into_iter().collect()
    };
    all_keys.sort();

    let mut has_diff = false;
    for key in &all_keys {
        match (local_refs.get(key), ssm_params.get(key)) {
            (None, Some(v)) => {
                has_diff = true;
                let display = if reveal { v.as_str() } else { "***" };
                println!("+ {key} = {display}  (in SSM, not in local refs)");
            }
            (Some(_path), None) => {
                has_diff = true;
                println!("- {key}  (in local refs, not found in SSM)");
            }
            (Some(_path), Some(_v)) => {
                // Key exists in both; no value comparison since refs don't store values
            }
            (None, None) => {}
        }
    }

    if !has_diff {
        println!("No diff — local refs and SSM are in sync.");
    }

    Ok(())
}

/// Write a single SSM parameter and record its path in the local refs file.
///
/// REQ-29: production barrier required.
pub async fn cmd_ssm_set(
    repo_root: &Path,
    env: &str,
    key: &str,
    value: &str,
    aws: &AwsConfig,
    json: bool,
) -> Result<(), GitvaultError> {
    // REQ-29: prod barrier
    crate::barrier::check_prod_barrier(repo_root, env, true, false)?;

    let app = get_app_name(repo_root);
    let path = ssm_path(&app, env, key);
    let client = aws.build_client().await?;

    client
        .put_parameter()
        .name(&path)
        .value(value)
        .r#type(ParameterType::SecureString)
        .overwrite(true)
        .send()
        .await
        .map_err(|e| GitvaultError::Other(e.to_string()))?;

    // Update local refs
    let mut refs = load_refs(repo_root, env)?;
    refs.insert(key.to_string(), path.clone());
    save_refs(repo_root, env, &refs)?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "key": key, "path": path, "status": "set" })
        );
    } else {
        println!("Set '{key}' → '{path}'");
    }

    Ok(())
}

/// Push all local SSM references to Parameter Store.  Values are read from the
/// environment variables of the calling process (keys must be present).
///
/// REQ-29: production barrier required.
pub async fn cmd_ssm_push(
    repo_root: &Path,
    env: &str,
    aws: &AwsConfig,
    json: bool,
) -> Result<(), GitvaultError> {
    // REQ-29: prod barrier
    crate::barrier::check_prod_barrier(repo_root, env, true, false)?;

    let refs = load_refs(repo_root, env)?;
    if refs.is_empty() {
        return Err(GitvaultError::Other(
            "No local SSM references found. Run `ssm pull` first or use `ssm set`.".to_string(),
        ));
    }

    let client = aws.build_client().await?;
    let mut pushed = 0usize;
    let mut skipped = 0usize;

    for (key, path) in &refs {
        match std::env::var(key) {
            Ok(value) => {
                client
                    .put_parameter()
                    .name(path)
                    .value(&value)
                    .r#type(ParameterType::SecureString)
                    .overwrite(true)
                    .send()
                    .await
                    .map_err(|e| GitvaultError::Other(e.to_string()))?;
                pushed += 1;
            }
            Err(_) => {
                skipped += 1;
                eprintln!("Skipping '{key}' — not set in environment");
            }
        }
    }

    if json {
        println!(
            "{}",
            serde_json::json!({ "pushed": pushed, "skipped": skipped })
        );
    } else {
        println!("Pushed {pushed} parameter(s), skipped {skipped}.");
    }

    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn test_ssm_path_format() {
        assert_eq!(ssm_path("myapp", "prod", "DB_PASS"), "/myapp/prod/DB_PASS");
        assert_eq!(ssm_path("app", "dev", "KEY"), "/app/dev/KEY");
    }

    #[test]
    fn test_refs_file_path() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let expected = repo_root
            .join("secrets")
            .join("prod")
            .join(".ssm-refs.json");
        assert_eq!(refs_file_path(repo_root, "prod"), expected);
    }

    #[test]
    fn test_serde_refs() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path();
        let env = "staging";

        // Build a refs map
        let mut refs: HashMap<String, String> = HashMap::new();
        refs.insert("DB_PASS".to_string(), "/myapp/staging/DB_PASS".to_string());
        refs.insert("API_KEY".to_string(), "/myapp/staging/API_KEY".to_string());

        // Save and reload
        save_refs(repo_root, env, &refs).expect("save_refs should succeed");
        let loaded = load_refs(repo_root, env).expect("load_refs should succeed");

        assert_eq!(
            loaded.get("DB_PASS").map(String::as_str),
            Some("/myapp/staging/DB_PASS")
        );
        assert_eq!(
            loaded.get("API_KEY").map(String::as_str),
            Some("/myapp/staging/API_KEY")
        );
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_load_refs_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let refs = load_refs(dir.path(), "dev").expect("should return empty map");
        assert!(refs.is_empty());
    }
}
