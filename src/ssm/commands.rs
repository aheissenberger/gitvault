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
