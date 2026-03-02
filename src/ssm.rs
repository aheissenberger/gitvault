//! AWS SSM Parameter Store backend (REQ-26 to REQ-30, REQ-49).
//!
//! All functions in this module are gated behind the `ssm` Cargo feature.
//!
//! # Architecture
//!
//! The [`SsmBackend`] trait abstracts the two SSM operations used by all
//! commands (fetch parameters, put a parameter).  [`RealSsmBackend`] wraps the
//! real `aws_sdk_ssm::Client`; tests inject [`MockSsmBackend`] — an in-memory
//! store — so every command path can be covered without live AWS credentials.
//!
//! Public commands (`cmd_ssm_*`) build a [`RealSsmBackend`] and delegate to
//! the corresponding `*_with` function, keeping all logic testable.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use aws_sdk_ssm::types::ParameterType;

use crate::aws_config::AwsConfig;
use crate::error::GitvaultError;

// ─── Backend trait ────────────────────────────────────────────────────────────

/// Abstraction over AWS SSM Parameter Store operations.
///
/// [`RealSsmBackend`] wraps `aws_sdk_ssm::Client`; in tests the
/// mockall-generated [`MockSsmBackend`] is injected so every command path can
/// be exercised without live AWS credentials.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait SsmBackend: Send + Sync {
    /// Fetch all parameters whose name starts with `prefix`.
    ///
    /// Returns `(name, value)` pairs with the full SSM parameter path as name.
    async fn fetch_params(&self, prefix: &str) -> Result<Vec<(String, String)>, GitvaultError>;

    /// Write `value` to the SSM parameter at `path` as a `SecureString`.
    async fn put_param(&self, path: &str, value: &str) -> Result<(), GitvaultError>;
}

// ─── Real implementation ──────────────────────────────────────────────────────

/// Production [`SsmBackend`] backed by a live `aws_sdk_ssm::Client`.
pub struct RealSsmBackend(pub aws_sdk_ssm::Client);

#[async_trait::async_trait]
impl SsmBackend for RealSsmBackend {
    async fn fetch_params(&self, prefix: &str) -> Result<Vec<(String, String)>, GitvaultError> {
        let mut results = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self
                .0
                .get_parameters_by_path()
                .path(prefix)
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

    async fn put_param(&self, path: &str, value: &str) -> Result<(), GitvaultError> {
        self.0
            .put_parameter()
            .name(path)
            .value(value)
            .r#type(ParameterType::SecureString)
            .overwrite(true)
            .send()
            .await
            .map_err(|e| GitvaultError::Other(e.to_string()))?;
        Ok(())
    }
}

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

/// Validate that an SSM app name only contains safe path characters.
fn validate_app_name(app_name: &str) -> Result<(), GitvaultError> {
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
async fn get_app_name(repo_root: &Path) -> Result<String, GitvaultError> {
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
    let mut tmp = tempfile::Builder::new()
        .prefix(".gitvault-tmp-")
        .tempfile_in(path.parent().unwrap_or(Path::new(".")))?;
    tmp.write_all(text.as_bytes())?;
    tmp.persist(&path).map_err(|e| GitvaultError::Io(e.error))?;
    Ok(())
}

// ─── Internal testable command implementations ────────────────────────────────

/// Core logic for `ssm pull`, injectable via any [`SsmBackend`].
///
/// `app` is the application name (e.g. derived from the git remote).
async fn cmd_ssm_pull_with<B: SsmBackend>(
    repo_root: &Path,
    env: &str,
    backend: &B,
    app: &str,
    json: bool,
) -> Result<(), GitvaultError> {
    let prefix = format!("/{app}/{env}/");
    let params = backend.fetch_params(&prefix).await?;

    let mut refs: HashMap<String, String> = HashMap::new();
    for (name, _value) in &params {
        let key = name
            .strip_prefix(&prefix)
            .unwrap_or(name.as_str())
            .to_string();
        refs.insert(key, name.clone());
    }

    save_refs(repo_root, env, &refs)?;

    if json {
        let mut keys: Vec<&String> = refs.keys().collect();
        keys.sort();
        println!("{}", serde_json::json!({ "pulled": keys, "status": "ok" }));
    } else {
        println!(
            "Pulled {} parameter(s) from SSM path prefix '{}'",
            refs.len(),
            prefix
        );
    }
    Ok(())
}

/// Core logic for `ssm diff`, injectable via any [`SsmBackend`].
async fn cmd_ssm_diff_with<B: SsmBackend>(
    repo_root: &Path,
    env: &str,
    backend: &B,
    app: &str,
    reveal: bool,
    json: bool,
) -> Result<(), GitvaultError> {
    let prefix = format!("/{app}/{env}/");

    let ssm_params: HashMap<String, String> = backend
        .fetch_params(&prefix)
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

    let local_refs = load_refs(repo_root, env)?;

    let mut all_keys: Vec<String> = {
        let mut s: std::collections::HashSet<String> = std::collections::HashSet::new();
        s.extend(ssm_params.keys().cloned());
        s.extend(local_refs.keys().cloned());
        s.into_iter().collect()
    };
    all_keys.sort();

    if json {
        let mut only_local: Vec<&String> = Vec::new();
        let mut only_ssm: Vec<&String> = Vec::new();
        let mut in_sync: Vec<&String> = Vec::new();

        for key in &all_keys {
            match (local_refs.get(key), ssm_params.get(key)) {
                (None, Some(_)) => only_ssm.push(key),
                (Some(_), None) => only_local.push(key),
                (Some(_), Some(_)) => in_sync.push(key),
                (None, None) => {}
            }
        }

        println!(
            "{}",
            serde_json::json!({
                "only_local": only_local,
                "only_ssm": only_ssm,
                "in_sync": in_sync,
            })
        );
    } else {
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
    }

    Ok(())
}

/// Core logic for `ssm set`, injectable via any [`SsmBackend`].
async fn cmd_ssm_set_with<B: SsmBackend>(
    repo_root: &Path,
    env: &str,
    key: &str,
    value: &str,
    backend: &B,
    app: &str,
    json: bool,
) -> Result<(), GitvaultError> {
    let path = ssm_path(app, env, key);
    backend.put_param(&path, value).await?;

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

/// Core logic for `ssm push`, injectable via any [`SsmBackend`].
async fn cmd_ssm_push_with<B: SsmBackend>(
    repo_root: &Path,
    env: &str,
    backend: &B,
    _app: &str,
    json: bool,
) -> Result<(), GitvaultError> {
    let refs = load_refs(repo_root, env)?;
    if refs.is_empty() {
        return Err(GitvaultError::Other(
            "No local SSM references found. Run `ssm pull` first or use `ssm set`.".to_string(),
        ));
    }

    let mut pushed = 0usize;
    let mut skipped = 0usize;

    for (key, path) in &refs {
        match std::env::var(key) {
            Ok(value) => {
                backend.put_param(path, &value).await?;
                pushed += 1;
            }
            Err(_) => {
                skipped += 1;
                eprintln!("Skipping '{key}' — not set in environment");
            }
        }
    }

    if skipped > 0 {
        return Err(GitvaultError::Other(format!(
            "{skipped} parameter(s) not pushed because the corresponding env var(s) were not set. Set them or use --allow-partial (not yet implemented)."
        )));
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

// ─── Public commands ──────────────────────────────────────────────────────────

/// Pull all parameters under `/{app}/{env}/` from SSM and write the parameter
/// paths to the local `.ssm-refs.json` file.
///
/// REQ-28: pull — read SSM values and compare with local references.
pub async fn cmd_ssm_pull(
    repo_root: &Path,
    env: &str,
    aws: &AwsConfig,
    json: bool,
) -> Result<(), GitvaultError> {
    let app = get_app_name(repo_root).await?;
    let client = aws.build_client().await?;
    cmd_ssm_pull_with(repo_root, env, &RealSsmBackend(client), &app, json).await
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
    json: bool,
) -> Result<(), GitvaultError> {
    let app = get_app_name(repo_root).await?;
    let client = aws.build_client().await?;
    cmd_ssm_diff_with(repo_root, env, &RealSsmBackend(client), &app, reveal, json).await
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

    let app = get_app_name(repo_root).await?;
    let client = aws.build_client().await?;
    cmd_ssm_set_with(
        repo_root,
        env,
        key,
        value,
        &RealSsmBackend(client),
        &app,
        json,
    )
    .await
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

    let app = get_app_name(repo_root).await?;
    let client = aws.build_client().await?;
    cmd_ssm_push_with(repo_root, env, &RealSsmBackend(client), &app, json).await
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    // `MockSsmBackend` is auto-generated by mockall from the
    // `#[cfg_attr(test, mockall::automock)]` attribute on `SsmBackend`.

    // ── Pure helper tests (sync) ──────────────────────────────────────────────

    #[test]
    fn test_ssm_path_format() {
        assert_eq!(ssm_path("myapp", "prod", "DB_PASS"), "/myapp/prod/DB_PASS");
        assert_eq!(ssm_path("app", "dev", "KEY"), "/app/dev/KEY");
    }

    #[test]
    fn test_refs_file_path() {
        let dir = TempDir::new().unwrap();
        let expected = dir
            .path()
            .join("secrets")
            .join("prod")
            .join(".ssm-refs.json");
        assert_eq!(refs_file_path(dir.path(), "prod"), expected);
    }

    #[test]
    fn test_serde_refs() {
        let dir = TempDir::new().unwrap();
        let mut refs: HashMap<String, String> = HashMap::new();
        refs.insert("DB_PASS".to_string(), "/myapp/staging/DB_PASS".to_string());
        refs.insert("API_KEY".to_string(), "/myapp/staging/API_KEY".to_string());
        save_refs(dir.path(), "staging", &refs).expect("save_refs should succeed");
        let loaded = load_refs(dir.path(), "staging").expect("load_refs should succeed");
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

    #[test]
    fn test_validate_app_name_accepts_valid() {
        assert!(validate_app_name("myapp").is_ok());
        assert!(validate_app_name("my-app_v2.0").is_ok());
        assert!(validate_app_name("gitvault").is_ok());
    }

    #[test]
    fn test_validate_app_name_rejects_invalid() {
        assert!(validate_app_name("my app").is_err());
        assert!(validate_app_name("app/name").is_err());
        assert!(validate_app_name("app@name").is_err());
    }

    // ── get_app_name ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_app_name_from_git_remote() {
        let dir = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/user/myrepo.git",
            ])
            .current_dir(dir.path())
            .status()
            .unwrap();
        let name = get_app_name(dir.path())
            .await
            .expect("should extract name from remote");
        assert_eq!(name, "myrepo");
    }

    #[tokio::test]
    async fn test_get_app_name_fallback_to_dir_name() {
        let dir = TempDir::new().unwrap();
        // No git repo → git command fails → falls back to directory name.
        // temp-dir names are alphanumeric so validate_app_name succeeds.
        let result = get_app_name(dir.path()).await;
        assert!(
            result.is_ok() || matches!(result, Err(GitvaultError::Usage(_))),
            "unexpected error: {result:?}"
        );
    }

    // ── cmd_ssm_pull_with ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_cmd_ssm_pull_with_writes_refs() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().times(1).returning(|_| {
            Ok(vec![
                ("/myapp/dev/DB_PASS".to_string(), "secret1".to_string()),
                ("/myapp/dev/API_KEY".to_string(), "secret2".to_string()),
            ])
        });

        cmd_ssm_pull_with(dir.path(), "dev", &mock, "myapp", false)
            .await
            .expect("pull should succeed");

        let refs = load_refs(dir.path(), "dev").unwrap();
        assert_eq!(
            refs.get("DB_PASS").map(String::as_str),
            Some("/myapp/dev/DB_PASS")
        );
        assert_eq!(
            refs.get("API_KEY").map(String::as_str),
            Some("/myapp/dev/API_KEY")
        );
        assert_eq!(refs.len(), 2);
    }

    #[tokio::test]
    async fn test_cmd_ssm_pull_with_empty_ssm_writes_empty_refs() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params()
            .times(1)
            .returning(|_| Ok(vec![]));

        cmd_ssm_pull_with(dir.path(), "dev", &mock, "myapp", false)
            .await
            .expect("pull should succeed with empty SSM");

        let refs = load_refs(dir.path(), "dev").unwrap();
        assert!(refs.is_empty());
    }

    #[tokio::test]
    async fn test_cmd_ssm_pull_with_json_output() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params()
            .times(1)
            .returning(|_| Ok(vec![("/myapp/dev/KEY".to_string(), "val".to_string())]));

        cmd_ssm_pull_with(dir.path(), "dev", &mock, "myapp", true)
            .await
            .expect("pull --json should succeed");
    }

    // ── cmd_ssm_diff_with ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_cmd_ssm_diff_with_in_sync() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert("DB_PASS".to_string(), "/myapp/dev/DB_PASS".to_string());
        save_refs(dir.path(), "dev", &refs).unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().times(1).returning(|_| {
            Ok(vec![(
                "/myapp/dev/DB_PASS".to_string(),
                "secret".to_string(),
            )])
        });

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", false, false)
            .await
            .expect("diff should succeed");
    }

    #[tokio::test]
    async fn test_cmd_ssm_diff_with_only_local() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert(
            "MISSING_KEY".to_string(),
            "/myapp/dev/MISSING_KEY".to_string(),
        );
        save_refs(dir.path(), "dev", &refs).unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params()
            .times(1)
            .returning(|_| Ok(vec![]));

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", false, false)
            .await
            .expect("diff should succeed when key only in local");
    }

    #[tokio::test]
    async fn test_cmd_ssm_diff_with_only_ssm() {
        let dir = TempDir::new().unwrap();
        // No local refs — SSM has a new key.
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params()
            .times(1)
            .returning(|_| Ok(vec![("/myapp/dev/NEW_KEY".to_string(), "v".to_string())]));

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", true, false)
            .await
            .expect("diff should succeed when key only in SSM");
    }

    /// JSON diff: exercises the `only_local` and `in_sync` branches in json mode.
    #[tokio::test]
    async fn test_cmd_ssm_diff_with_json_all_branches() {
        let dir = TempDir::new().unwrap();
        // Local has LOCAL_ONLY and IN_SYNC; SSM has IN_SYNC and SSM_ONLY.
        let mut refs = HashMap::new();
        refs.insert(
            "LOCAL_ONLY".to_string(),
            "/myapp/dev/LOCAL_ONLY".to_string(),
        );
        refs.insert("IN_SYNC".to_string(), "/myapp/dev/IN_SYNC".to_string());
        save_refs(dir.path(), "dev", &refs).unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().times(1).returning(|_| {
            Ok(vec![
                ("/myapp/dev/IN_SYNC".to_string(), "v1".to_string()),
                ("/myapp/dev/SSM_ONLY".to_string(), "v2".to_string()),
            ])
        });

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", false, true)
            .await
            .expect("diff --json should cover all match arms");
    }

    #[tokio::test]
    async fn test_cmd_ssm_diff_with_reveal_flag() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().times(1).returning(|_| {
            Ok(vec![(
                "/myapp/dev/SECRET".to_string(),
                "plaintext".to_string(),
            )])
        });

        // reveal=true exposes actual values in the non-json diff output
        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", true, false)
            .await
            .expect("diff --reveal should succeed");
    }

    // ── cmd_ssm_set_with ──────────────────────────────────────────────────────

    /// Verifies the exact SSM path and value passed to `put_param`, and that
    /// the local refs file is updated.
    #[tokio::test]
    async fn test_cmd_ssm_set_with_calls_put_with_correct_args() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_put_param()
            .withf(|path, value| path == "/myapp/dev/DB_PASS" && value == "secret123")
            .times(1)
            .returning(|_, _| Ok(()));

        cmd_ssm_set_with(
            dir.path(),
            "dev",
            "DB_PASS",
            "secret123",
            &mock,
            "myapp",
            false,
        )
        .await
        .expect("set should succeed");

        let refs = load_refs(dir.path(), "dev").unwrap();
        assert_eq!(
            refs.get("DB_PASS").map(String::as_str),
            Some("/myapp/dev/DB_PASS")
        );
    }

    #[tokio::test]
    async fn test_cmd_ssm_set_with_json_output() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_put_param().times(1).returning(|_, _| Ok(()));

        cmd_ssm_set_with(dir.path(), "dev", "API_KEY", "tok", &mock, "myapp", true)
            .await
            .expect("set --json should succeed");
    }

    /// `set` should propagate an error returned by the backend.
    #[tokio::test]
    async fn test_cmd_ssm_set_with_backend_error_propagates() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_put_param()
            .times(1)
            .returning(|_, _| Err(GitvaultError::Other("simulated AWS error".to_string())));

        let result = cmd_ssm_set_with(dir.path(), "dev", "KEY", "val", &mock, "myapp", false).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("simulated AWS error")
        );
    }

    // ── cmd_ssm_push_with ─────────────────────────────────────────────────────

    /// Verifies the exact path/value written to SSM for each ref.
    #[tokio::test]
    async fn test_cmd_ssm_push_with_all_vars_set() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert("MY_VAR".to_string(), "/myapp/dev/MY_VAR".to_string());
        save_refs(dir.path(), "dev", &refs).unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_put_param()
            .withf(|path, value| path == "/myapp/dev/MY_VAR" && value == "hello")
            .times(1)
            .returning(|_, _| Ok(()));

        unsafe { std::env::set_var("MY_VAR", "hello") };
        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", false).await;
        unsafe { std::env::remove_var("MY_VAR") };

        result.expect("push should succeed when all env vars are set");
    }

    #[tokio::test]
    async fn test_cmd_ssm_push_with_json_output() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert("PUSH_VAR".to_string(), "/myapp/dev/PUSH_VAR".to_string());
        save_refs(dir.path(), "dev", &refs).unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_put_param().times(1).returning(|_, _| Ok(()));

        unsafe { std::env::set_var("PUSH_VAR", "value") };
        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", true).await;
        unsafe { std::env::remove_var("PUSH_VAR") };

        result.expect("push --json should succeed");
    }

    /// When an env var is absent the command should fail without calling `put_param`.
    #[tokio::test]
    async fn test_cmd_ssm_push_with_missing_env_var_errors() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert(
            "ABSENT_VAR".to_string(),
            "/myapp/dev/ABSENT_VAR".to_string(),
        );
        save_refs(dir.path(), "dev", &refs).unwrap();

        // `put_param` must NOT be called — mockall panics if it is.
        let mock = MockSsmBackend::new();
        unsafe { std::env::remove_var("ABSENT_VAR") };

        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", false).await;
        assert!(result.is_err(), "push should fail when env var is missing");
    }

    #[tokio::test]
    async fn test_cmd_ssm_push_with_no_refs_errors() {
        let dir = TempDir::new().unwrap();
        // `put_param` must NOT be called.
        let mock = MockSsmBackend::new();

        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", false).await;
        assert!(result.is_err(), "push with no refs should fail");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("No local SSM references"), "error: {msg}");
    }

    /// Backend error during push propagates correctly.
    #[tokio::test]
    async fn test_cmd_ssm_push_with_backend_error_propagates() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert("VAR".to_string(), "/myapp/dev/VAR".to_string());
        save_refs(dir.path(), "dev", &refs).unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_put_param()
            .times(1)
            .returning(|_, _| Err(GitvaultError::Other("put failed".to_string())));

        unsafe { std::env::set_var("VAR", "val") };
        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", false).await;
        unsafe { std::env::remove_var("VAR") };

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("put failed"));
    }
}
