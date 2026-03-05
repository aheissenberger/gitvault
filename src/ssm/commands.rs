//! SSM command implementations: `ssm pull`, `ssm diff`, `ssm set`, `ssm push`.

use std::collections::HashMap;
use std::path::Path;

use crate::aws_config::AwsConfig;
use crate::error::GitvaultError;

use super::backend::{RealSsmBackend, SsmBackend};
use super::refs::{get_app_name, load_refs, save_refs, ssm_path};

// ─── Internal testable command implementations ────────────────────────────────

/// Core logic for `ssm pull`, injectable via any [`SsmBackend`].
///
/// `app` is the application name (e.g. derived from the git remote).
pub(super) async fn cmd_ssm_pull_with<B: SsmBackend>(
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

    save_refs(repo_root, env, &refs).await?;

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
pub(super) async fn cmd_ssm_diff_with<B: SsmBackend>(
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

    let local_refs = load_refs(repo_root, env).await?;

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
pub(super) async fn cmd_ssm_set_with<B: SsmBackend>(
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

    let mut refs = load_refs(repo_root, env).await?;
    refs.insert(key.to_string(), path.clone());
    save_refs(repo_root, env, &refs).await?;

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
pub(super) async fn cmd_ssm_push_with<B: SsmBackend>(
    repo_root: &Path,
    env: &str,
    backend: &B,
    _app: &str,
    json: bool,
) -> Result<(), GitvaultError> {
    let refs = load_refs(repo_root, env).await?;
    if refs.is_empty() {
        return Err(GitvaultError::Other(
            "No local SSM references found. Run `ssm pull` first or use `ssm set`.".to_string(),
        ));
    }

    let mut pushed = 0usize;
    let mut skipped = 0usize;

    for (key, path) in &refs {
        if let Ok(value) = std::env::var(key) {
            backend.put_param(path, &value).await?;
            pushed += 1;
        } else {
            skipped += 1;
            eprintln!("Skipping '{key}' — not set in environment");
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
///
/// # Errors
///
/// Returns [`GitvaultError`] if the app name cannot be resolved, the AWS client
/// cannot be built, or the SSM pull operation or file write fails.
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
///
/// # Errors
///
/// Returns [`GitvaultError`] if the app name cannot be resolved, the AWS client
/// cannot be built, or reading local refs or fetching SSM values fails.
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
///
/// # Errors
///
/// Returns [`GitvaultError::BarrierNotSatisfied`] if the prod barrier is not met.
/// Returns [`GitvaultError`] if the app name cannot be resolved, the AWS client
/// cannot be built, or the SSM put operation or file write fails.
pub async fn cmd_ssm_set(
    repo_root: &Path,
    env: &str,
    key: &str,
    value: &str,
    aws: &AwsConfig,
    json: bool,
    prod: bool,
) -> Result<(), GitvaultError> {
    // REQ-13: prod barrier — only passes when --prod flag is explicitly provided
    crate::barrier::check_prod_barrier(
        repo_root,
        env,
        prod,
        false,
        crate::defaults::DEFAULT_PROD_ENV,
    )?;

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
///
/// # Errors
///
/// Returns [`GitvaultError::BarrierNotSatisfied`] if the prod barrier is not met.
/// Returns [`GitvaultError`] if the app name cannot be resolved, the AWS client
/// cannot be built, any required env var is missing, or a SSM put operation fails.
pub async fn cmd_ssm_push(
    repo_root: &Path,
    env: &str,
    aws: &AwsConfig,
    json: bool,
    prod: bool,
) -> Result<(), GitvaultError> {
    // REQ-13: prod barrier — only passes when --prod flag is explicitly provided
    crate::barrier::check_prod_barrier(
        repo_root,
        env,
        prod,
        false,
        crate::defaults::DEFAULT_PROD_ENV,
    )?;

    let app = get_app_name(repo_root).await?;
    let client = aws.build_client().await?;
    cmd_ssm_push_with(repo_root, env, &RealSsmBackend(client), &app, json).await
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tempfile::TempDir;

    use super::*;
    use crate::ssm::backend::MockSsmBackend;
    use crate::ssm::refs::{refs_file_path, save_refs};

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Read the refs JSON from disk and return it as a `HashMap`.
    fn read_refs(dir: &TempDir, env: &str) -> HashMap<String, String> {
        let path = refs_file_path(dir.path(), env);
        let text = std::fs::read_to_string(&path).expect("refs file should exist");
        serde_json::from_str(&text).expect("refs file should be valid JSON")
    }

    // ── cmd_ssm_pull_with ────────────────────────────────────────────────────

    /// REQ-28: happy path — backend returns params, refs file is written with
    /// correct key → SSM-path mapping.
    #[tokio::test]
    async fn pull_happy_path_creates_refs_file() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().returning(|_| {
            Ok(vec![
                (
                    "/myapp/dev/DB_URL".to_string(),
                    "postgres://localhost".to_string(),
                ),
                ("/myapp/dev/API_KEY".to_string(), "secret123".to_string()),
            ])
        });

        cmd_ssm_pull_with(dir.path(), "dev", &mock, "myapp", false)
            .await
            .unwrap();

        let refs = read_refs(&dir, "dev");
        assert_eq!(
            refs.get("DB_URL"),
            Some(&"/myapp/dev/DB_URL".to_string()),
            "DB_URL should map to its SSM path"
        );
        assert_eq!(
            refs.get("API_KEY"),
            Some(&"/myapp/dev/API_KEY".to_string()),
            "API_KEY should map to its SSM path"
        );
        assert_eq!(refs.len(), 2);
    }

    /// Empty parameter list → refs file is still written but contains an empty
    /// object, which is a valid JSON map.
    #[tokio::test]
    async fn pull_empty_params_creates_empty_refs_file() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().returning(|_| Ok(vec![]));

        cmd_ssm_pull_with(dir.path(), "dev", &mock, "myapp", false)
            .await
            .unwrap();

        let refs = read_refs(&dir, "dev");
        assert!(refs.is_empty(), "refs map should be empty");
    }

    /// JSON output mode must not error (output goes to stdout, not captured
    /// here, but the function must return `Ok`).
    #[tokio::test]
    async fn pull_json_mode_succeeds() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params()
            .returning(|_| Ok(vec![("/myapp/dev/FOO".to_string(), "bar".to_string())]));

        cmd_ssm_pull_with(dir.path(), "dev", &mock, "myapp", true)
            .await
            .unwrap();
    }

    /// A single-param result still produces a properly populated refs file.
    #[tokio::test]
    async fn pull_single_param_recorded() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().returning(|_| {
            Ok(vec![(
                "/app/staging/SECRET".to_string(),
                "value".to_string(),
            )])
        });

        cmd_ssm_pull_with(dir.path(), "staging", &mock, "app", false)
            .await
            .unwrap();

        let refs = read_refs(&dir, "staging");
        assert_eq!(refs.get("SECRET"), Some(&"/app/staging/SECRET".to_string()));
    }

    /// Backend error must be propagated to the caller unchanged.
    #[tokio::test]
    async fn pull_backend_error_propagates() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params()
            .returning(|_| Err(GitvaultError::Other("SSM unavailable".to_string())));

        let result = cmd_ssm_pull_with(dir.path(), "dev", &mock, "myapp", false).await;
        assert!(result.is_err(), "expected an error");
    }

    // ── cmd_ssm_diff_with ────────────────────────────────────────────────────

    /// No local refs file → all SSM params appear as additions (should succeed
    /// without panicking).
    #[tokio::test]
    async fn diff_no_existing_refs_shows_all_as_new() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().returning(|_| {
            Ok(vec![(
                "/myapp/dev/DB_URL".to_string(),
                "postgres://localhost".to_string(),
            )])
        });

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", false, false)
            .await
            .unwrap();
    }

    /// Both local refs and SSM contain the same key → in-sync state, no panic.
    #[tokio::test]
    async fn diff_in_sync_succeeds() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert("DB_URL".to_string(), "/myapp/dev/DB_URL".to_string());
        save_refs(dir.path(), "dev", &refs).await.unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().returning(|_| {
            Ok(vec![(
                "/myapp/dev/DB_URL".to_string(),
                "postgres://localhost".to_string(),
            )])
        });

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", false, false)
            .await
            .unwrap();
    }

    /// Key exists in local refs but not in SSM → shown as a removal.
    #[tokio::test]
    async fn diff_local_only_key_succeeds() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert("ORPHAN".to_string(), "/myapp/dev/ORPHAN".to_string());
        save_refs(dir.path(), "dev", &refs).await.unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().returning(|_| Ok(vec![]));

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", false, false)
            .await
            .unwrap();
    }

    /// JSON output mode with mixed diff state must not error.
    #[tokio::test]
    async fn diff_json_mode_succeeds() {
        let dir = TempDir::new().unwrap();
        // A key only in SSM
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params()
            .returning(|_| Ok(vec![("/myapp/dev/ONLY_SSM".to_string(), "val".to_string())]));

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", false, true)
            .await
            .unwrap();
    }

    /// Reveal mode must not error even when values would be printed.
    #[tokio::test]
    async fn diff_reveal_mode_succeeds() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params().returning(|_| {
            Ok(vec![(
                "/myapp/dev/SECRET".to_string(),
                "actual-secret-value".to_string(),
            )])
        });

        cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", true, false)
            .await
            .unwrap();
    }

    /// Backend error must propagate.
    #[tokio::test]
    async fn diff_backend_error_propagates() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_fetch_params()
            .returning(|_| Err(GitvaultError::Other("SSM error".to_string())));

        let result = cmd_ssm_diff_with(dir.path(), "dev", &mock, "myapp", false, false).await;
        assert!(result.is_err());
    }

    // ── cmd_ssm_set_with ─────────────────────────────────────────────────────

    /// Happy path: `put_param` is invoked with the correct SSM path and value,
    /// and the key→path mapping is persisted in the refs file.
    #[tokio::test]
    async fn set_happy_path_calls_put_and_writes_refs() {
        use mockall::predicate::eq;

        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_put_param()
            .with(eq("/myapp/dev/MY_KEY"), eq("myvalue"))
            .once()
            .returning(|_, _| Ok(()));

        cmd_ssm_set_with(
            dir.path(),
            "dev",
            "MY_KEY",
            "myvalue",
            &mock,
            "myapp",
            false,
        )
        .await
        .unwrap();

        let refs = read_refs(&dir, "dev");
        assert_eq!(
            refs.get("MY_KEY"),
            Some(&"/myapp/dev/MY_KEY".to_string()),
            "MY_KEY should be recorded in refs"
        );
    }

    /// `set` with JSON output mode must not error.
    #[tokio::test]
    async fn set_json_mode_succeeds() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_put_param().returning(|_, _| Ok(()));

        cmd_ssm_set_with(dir.path(), "dev", "KEY", "val", &mock, "myapp", true)
            .await
            .unwrap();
    }

    /// `set` appends to existing refs instead of overwriting them.
    #[tokio::test]
    async fn set_appends_to_existing_refs() {
        let dir = TempDir::new().unwrap();

        // Pre-populate refs with one key.
        let mut existing = HashMap::new();
        existing.insert("OLD_KEY".to_string(), "/myapp/dev/OLD_KEY".to_string());
        save_refs(dir.path(), "dev", &existing).await.unwrap();

        let mut mock = MockSsmBackend::new();
        mock.expect_put_param().returning(|_, _| Ok(()));

        cmd_ssm_set_with(
            dir.path(),
            "dev",
            "NEW_KEY",
            "newval",
            &mock,
            "myapp",
            false,
        )
        .await
        .unwrap();

        let refs = read_refs(&dir, "dev");
        assert!(refs.contains_key("OLD_KEY"), "OLD_KEY must be preserved");
        assert!(refs.contains_key("NEW_KEY"), "NEW_KEY must be added");
    }

    /// Backend error from `put_param` must propagate.
    #[tokio::test]
    async fn set_backend_error_propagates() {
        let dir = TempDir::new().unwrap();
        let mut mock = MockSsmBackend::new();
        mock.expect_put_param()
            .returning(|_, _| Err(GitvaultError::Other("SSM put error".to_string())));

        let result = cmd_ssm_set_with(dir.path(), "dev", "K", "v", &mock, "myapp", false).await;
        assert!(result.is_err());
    }

    // ── cmd_ssm_push_with ────────────────────────────────────────────────────

    /// No local refs file → returns an error explaining that pull must be run
    /// first.
    #[tokio::test]
    async fn push_no_refs_returns_error() {
        let dir = TempDir::new().unwrap();
        let mock = MockSsmBackend::new();

        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", false).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("No local SSM references"),
            "error should mention missing references"
        );
    }

    /// Happy path: env var is set → `put_param` is called with the correct
    /// arguments and the command returns `Ok`.
    #[tokio::test]
    async fn push_happy_path_calls_put_param() {
        use mockall::predicate::eq;

        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        // Use a sufficiently unique name to avoid clashing with parallel tests.
        refs.insert(
            "GITVAULT_TEST_PUSH_HAPPY_VAR".to_string(),
            "/myapp/dev/GITVAULT_TEST_PUSH_HAPPY_VAR".to_string(),
        );
        save_refs(dir.path(), "dev", &refs).await.unwrap();

        // SAFETY: test-only; not parallel with anything that reads this var.
        unsafe { std::env::set_var("GITVAULT_TEST_PUSH_HAPPY_VAR", "push_value") };

        let mut mock = MockSsmBackend::new();
        mock.expect_put_param()
            .with(
                eq("/myapp/dev/GITVAULT_TEST_PUSH_HAPPY_VAR"),
                eq("push_value"),
            )
            .once()
            .returning(|_, _| Ok(()));

        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", false).await;

        // Clean up before asserting so we don't leak the var on failure.
        unsafe { std::env::remove_var("GITVAULT_TEST_PUSH_HAPPY_VAR") };

        result.unwrap();
    }

    /// Missing env var → `push` skips the parameter and returns an error
    /// explaining that vars were not set.
    #[tokio::test]
    async fn push_missing_env_var_returns_error() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert(
            "GITVAULT_TEST_PUSH_MISSING_VAR_XYZ".to_string(),
            "/myapp/dev/GITVAULT_TEST_PUSH_MISSING_VAR_XYZ".to_string(),
        );
        save_refs(dir.path(), "dev", &refs).await.unwrap();

        // Ensure the var is absent.
        unsafe { std::env::remove_var("GITVAULT_TEST_PUSH_MISSING_VAR_XYZ") };

        let mock = MockSsmBackend::new();

        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", false).await;
        assert!(result.is_err(), "expected an error for missing env var");
    }

    /// JSON output mode with all vars present must not error.
    #[tokio::test]
    async fn push_json_mode_succeeds() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert(
            "GITVAULT_TEST_PUSH_JSON_VAR".to_string(),
            "/myapp/dev/GITVAULT_TEST_PUSH_JSON_VAR".to_string(),
        );
        save_refs(dir.path(), "dev", &refs).await.unwrap();

        unsafe { std::env::set_var("GITVAULT_TEST_PUSH_JSON_VAR", "hello") };

        let mut mock = MockSsmBackend::new();
        mock.expect_put_param().returning(|_, _| Ok(()));

        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", true).await;

        unsafe { std::env::remove_var("GITVAULT_TEST_PUSH_JSON_VAR") };

        result.unwrap();
    }

    /// Backend `put_param` error during push must propagate.
    #[tokio::test]
    async fn push_backend_error_propagates() {
        let dir = TempDir::new().unwrap();
        let mut refs = HashMap::new();
        refs.insert(
            "GITVAULT_TEST_PUSH_ERR_VAR".to_string(),
            "/myapp/dev/GITVAULT_TEST_PUSH_ERR_VAR".to_string(),
        );
        save_refs(dir.path(), "dev", &refs).await.unwrap();

        unsafe { std::env::set_var("GITVAULT_TEST_PUSH_ERR_VAR", "value") };

        let mut mock = MockSsmBackend::new();
        mock.expect_put_param()
            .returning(|_, _| Err(GitvaultError::Other("SSM put failure".to_string())));

        let result = cmd_ssm_push_with(dir.path(), "dev", &mock, "myapp", false).await;

        unsafe { std::env::remove_var("GITVAULT_TEST_PUSH_ERR_VAR") };

        assert!(result.is_err());
    }
}
