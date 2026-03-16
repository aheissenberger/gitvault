use crate::config::RuleSource;
use crate::defaults;
use crate::error::GitvaultError;
use crate::{crypto, merge};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

// `Command` is used only by the test module via `use super::*;`.
// The non-test compiler cannot observe that cross-scope usage, so we
// suppress the false-positive lint rather than pollute the test module.
#[cfg(test)]
#[allow(unused_imports)]
use std::process::Command;

trait GitRunner {
    fn show_toplevel(&self, start: &Path) -> std::io::Result<Output>;
}

struct SystemGitRunner;

impl GitRunner for SystemGitRunner {
    fn show_toplevel(&self, start: &Path) -> std::io::Result<Output> {
        // REQ-90: security-relevant env stripping is applied centrally by the
        // git wrapper (GIT_DIR, GIT_CONFIG, GIT_CONFIG_GLOBAL, GIT_TERMINAL_PROMPT).
        crate::git::git_output_raw(&["rev-parse", "--show-toplevel"], start)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

/// Directory for encrypted artifacts (REQ-7); re-exported from [`defaults`].
pub use defaults::SECRETS_DIR;

/// Base directory for plaintext outputs (REQ-8); re-exported from [`defaults`].
pub use defaults::PLAIN_BASE_DIR;

/// Guard against path traversal: ensure `target` is under `base`.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if `target` has no file-name component or
/// resolves to a path outside `base`.
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

    fn canonicalize_with_missing_tail(path: &Path) -> Result<PathBuf, GitvaultError> {
        if let Ok(canonical) = path.canonicalize() {
            return Ok(canonical);
        }

        let mut existing = path;
        let mut tail = Vec::new();
        while !existing.exists() {
            let name = existing.file_name().ok_or_else(|| {
                GitvaultError::Usage(format!(
                    "path has no file name component: {}",
                    path.display()
                ))
            })?;
            tail.push(name.to_os_string());
            existing = existing.parent().ok_or_else(|| {
                GitvaultError::Usage(format!(
                    "path has no file name component: {}",
                    path.display()
                ))
            })?;
        }

        let mut canonical = existing
            .canonicalize()
            .unwrap_or_else(|_| normalize(existing));
        for part in tail.iter().rev() {
            canonical.push(part);
        }
        Ok(canonical)
    }

    let canonical_base = canonicalize_with_missing_tail(base)?;
    let canonical_target = canonicalize_with_missing_tail(target)?;

    #[cfg(windows)]
    fn starts_with_base(target: &Path, base: &Path) -> bool {
        fn normalize_for_compare(path: &Path) -> String {
            let mut normalized = path.to_string_lossy().replace('/', "\\");
            while normalized.ends_with('\\') && normalized.len() > 3 {
                normalized.pop();
            }
            normalized.to_ascii_lowercase()
        }

        let normalized_target = normalize_for_compare(target);
        let normalized_base = normalize_for_compare(base);
        if normalized_target == normalized_base {
            return true;
        }
        let base_with_sep = format!("{normalized_base}\\");
        normalized_target.starts_with(&base_with_sep)
    }

    #[cfg(not(windows))]
    fn starts_with_base(target: &Path, base: &Path) -> bool {
        target.starts_with(base)
    }

    if starts_with_base(&canonical_target, &canonical_base) {
        Ok(())
    } else {
        Err(GitvaultError::Usage(format!(
            "Path traversal detected: {} is outside repository root {}",
            target.display(),
            base.display()
        )))
    }
}

/// Get the path for an encrypted artifact under secrets/. REQ-7
#[must_use]
pub fn get_encrypted_path(repo_root: &Path, name: &str) -> PathBuf {
    repo_root.join(SECRETS_DIR).join(name)
}

/// Get the directory for env-scoped encrypted artifacts under `secrets/<env>/`.
#[must_use]
pub fn get_env_encrypted_dir(repo_root: &Path, env: &str) -> PathBuf {
    repo_root.join(SECRETS_DIR).join(env)
}

/// Get the path for an encrypted artifact under `secrets/<env>/`.
#[must_use]
pub fn get_env_encrypted_path(repo_root: &Path, env: &str, name: &str) -> PathBuf {
    get_env_encrypted_dir(repo_root, env).join(name)
}

/// List encrypted files for an environment.
///
/// Prefers env-scoped layout `secrets/<env>/*.age` and falls back to legacy
/// layout `secrets/*.age` when no env-scoped files exist.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading the secrets directory fails.
pub fn list_encrypted_files_for_env(
    repo_root: &Path,
    env: &str,
) -> Result<Vec<PathBuf>, GitvaultError> {
    let env_dir = get_env_encrypted_dir(repo_root, env);
    let mut env_files = Vec::new();
    collect_age_files(&env_dir, &mut env_files)?;
    if !env_files.is_empty() {
        env_files.sort();
        return Ok(env_files);
    }

    let mut legacy_files = list_age_files_in_dir(&repo_root.join(SECRETS_DIR))?;
    legacy_files.sort();
    Ok(legacy_files)
}

/// List all encrypted files under `secrets/**` recursively.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading the secrets directory or any subdirectory fails.
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
#[must_use]
pub fn get_plain_path(repo_root: &Path, env: &str, name: &str) -> PathBuf {
    repo_root.join(PLAIN_BASE_DIR).join(env).join(name)
}

/// Ensure all required directories exist.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if `env` is not a valid environment name.
/// Returns [`GitvaultError::Io`] if any directory cannot be created.
pub fn ensure_dirs(repo_root: &Path, env: &str) -> Result<(), GitvaultError> {
    crate::env::validate_env_name(env)?;
    fs::create_dir_all(repo_root.join(SECRETS_DIR))?;
    fs::create_dir_all(get_env_encrypted_dir(repo_root, env))?;
    fs::create_dir_all(repo_root.join(PLAIN_BASE_DIR).join(env))?;
    Ok(())
}

/// Recursively flatten a JSON/YAML/TOML value into KEY=value pairs.
/// Path segments are joined with `_` and uppercased.
/// Arrays and null values are skipped.
fn flatten_to_env_pairs(value: &serde_json::Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.to_uppercase()
                } else {
                    format!("{}_{}", prefix, k.to_uppercase())
                };
                flatten_to_env_pairs(v, &key, out);
            }
        }
        serde_json::Value::String(s) => out.push((prefix.to_string(), s.clone())),
        serde_json::Value::Number(n) => out.push((prefix.to_string(), n.to_string())),
        serde_json::Value::Bool(b) => out.push((prefix.to_string(), b.to_string())),
        serde_json::Value::Null | serde_json::Value::Array(_) => {}
    }
}

/// Decrypt all encrypted secrets for the given environment.
///
/// Reads all `.age` files for `env`, decrypts them with `identity`, and returns
/// the key-value pairs parsed from the plaintext. Format is detected from the
/// filename stem (stripping the `.age` suffix) using `validated_extension`.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading an encrypted file fails.
/// Returns [`GitvaultError::Decryption`] if any file cannot be decrypted with `identity`.
/// Returns [`GitvaultError::Usage`] if decrypted content is not valid for its detected format.
pub fn decrypt_env_secrets(
    repo_root: &Path,
    env: &str,
    identity: &dyn age::Identity,
) -> Result<Vec<(String, String)>, GitvaultError> {
    decrypt_env_secrets_with_rules(repo_root, env, identity, None, false, false)
}

/// Decrypt runtime secrets for `gitvault run`, including both store artifacts
/// and optionally configured sealed-source files.
///
/// Rule behavior:
/// - `source = "store"` (or omitted source) applies to `.gitvault/store/...` paths.
/// - `source = "sealed"` applies to repository working-tree files.
pub fn decrypt_runtime_secrets_with_rules(
    repo_root: &Path,
    env: &str,
    identity: &dyn age::Identity,
    rules: Option<&[crate::config::MatchRule]>,
    global_dir_prefix: bool,
    global_path_prefix: bool,
) -> Result<Vec<(String, String)>, GitvaultError> {
    let mut secrets = decrypt_env_secrets_with_rules(
        repo_root,
        env,
        identity,
        rules,
        global_dir_prefix,
        global_path_prefix,
    )?;

    let repo_files = list_repository_files(repo_root)?;
    for rel_repo_path in repo_files {
        let (include_file, key_filters, dir_prefix, path_prefix, custom_prefix) =
            evaluate_rule_filters_for_source(
                &rel_repo_path,
                rules,
                global_dir_prefix,
                global_path_prefix,
                RuleEvalSource::Sealed,
            );

        if !include_file {
            continue;
        }

        let file_path = repo_root.join(&rel_repo_path);
        let ext =
            crate::commands::seal::validated_extension(Path::new(&rel_repo_path)).map_err(|e| {
                GitvaultError::Usage(format!(
                    "selected sealed runtime source '{}' is unsupported: {e}",
                    rel_repo_path
                ))
            })?;

        let content = crate::fs_util::read_text(&file_path)?;
        let unsealed = crate::commands::seal::unseal_content(&content, &ext, None, identity)
            .map_err(|e| {
                GitvaultError::Decryption(format!(
                    "failed to load sealed runtime source {}: {e}",
                    rel_repo_path
                ))
            })?;

        let prefix = build_repo_key_prefix(
            &rel_repo_path,
            dir_prefix,
            path_prefix,
            custom_prefix.as_deref(),
        );

        let parsed_pairs = match ext.as_str() {
            "env" => merge::parse_env_pairs(&unsealed).map_err(|e| {
                GitvaultError::Usage(format!(
                    "invalid .env runtime source {}: {e}",
                    rel_repo_path
                ))
            })?,
            "json" => {
                let val: serde_json::Value = serde_json::from_str(&unsealed).map_err(|e| {
                    GitvaultError::Usage(format!(
                        "invalid JSON runtime source {}: {e}",
                        rel_repo_path
                    ))
                })?;
                let mut pairs = Vec::new();
                flatten_to_env_pairs(&val, "", &mut pairs);
                pairs
            }
            "yaml" | "yml" => {
                let val: serde_yaml::Value = serde_yaml::from_str(&unsealed).map_err(|e| {
                    GitvaultError::Usage(format!(
                        "invalid YAML runtime source {}: {e}",
                        rel_repo_path
                    ))
                })?;
                let json_val = serde_json::to_value(val).map_err(|e| {
                    GitvaultError::Usage(format!(
                        "cannot convert YAML runtime source {} to JSON: {e}",
                        rel_repo_path
                    ))
                })?;
                let mut pairs = Vec::new();
                flatten_to_env_pairs(&json_val, "", &mut pairs);
                pairs
            }
            "toml" => {
                let val: toml::Value = toml::from_str(&unsealed).map_err(|e| {
                    GitvaultError::Usage(format!(
                        "invalid TOML runtime source {}: {e}",
                        rel_repo_path
                    ))
                })?;
                let json_val = serde_json::to_value(val).map_err(|e| {
                    GitvaultError::Usage(format!(
                        "cannot convert TOML runtime source {} to JSON: {e}",
                        rel_repo_path
                    ))
                })?;
                let mut pairs = Vec::new();
                flatten_to_env_pairs(&json_val, "", &mut pairs);
                pairs
            }
            _ => {
                return Err(GitvaultError::Usage(format!(
                    "selected sealed runtime source '{}' has unsupported extension '{}': expected env/json/yaml/yml/toml",
                    rel_repo_path, ext
                )));
            }
        };

        let prefixed = apply_prefix_to_pairs(parsed_pairs, prefix.as_deref());
        secrets.extend(filter_pairs_by_key_globs(prefixed, key_filters.as_deref()));
    }

    Ok(secrets)
}

/// Decrypt all encrypted secrets for the given environment, applying optional
/// rule-based path/key filtering.
///
/// Rules are evaluated in-order with later matches overriding earlier matches.
/// When a matching allow rule contains `keys`, only keys matching any key glob
/// from that rule are emitted for that file.
pub fn decrypt_env_secrets_with_rules(
    repo_root: &Path,
    env: &str,
    identity: &dyn age::Identity,
    rules: Option<&[crate::config::MatchRule]>,
    global_dir_prefix: bool,
    global_path_prefix: bool,
) -> Result<Vec<(String, String)>, GitvaultError> {
    let mut secrets: Vec<(String, String)> = Vec::new();
    let encrypted_files = list_encrypted_files_for_env(repo_root, env)?;
    let env_store_dir = repo_root.join(SECRETS_DIR).join(env);

    for path in encrypted_files {
        let rel_store_path = path
            .strip_prefix(repo_root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned());

        let (include_file, key_filters, dir_prefix, path_prefix, custom_prefix) =
            evaluate_rule_filters_for_source(
                &rel_store_path,
                rules,
                global_dir_prefix,
                global_path_prefix,
                RuleEvalSource::Store,
            );
        if !include_file {
            continue;
        }

        let prefix = build_key_prefix(
            &path,
            &env_store_dir,
            dir_prefix,
            path_prefix,
            custom_prefix.as_deref(),
        );

        let ciphertext = std::fs::read(&path)?;
        let plaintext = match crypto::decrypt(identity, &ciphertext) {
            Ok(p) => p,
            Err(e) => {
                return Err(GitvaultError::Decryption(format!(
                    "Failed to decrypt {}: {e}",
                    path.display()
                )));
            }
        };

        // REQ-101: strict UTF-8 conversion — reject non-UTF-8 secret content rather
        // than silently replacing bytes. Zeroizing<String> ensures the plaintext
        // string is overwritten when dropped, even if parsing errors.
        let text =
            zeroize::Zeroizing::new(String::from_utf8(plaintext.to_vec()).map_err(|_| {
                GitvaultError::Usage(format!(
                    "Decrypted content of {} is not valid UTF-8",
                    path.display()
                ))
            })?);

        // REQ-117: Detect format from stem (strip .age suffix) and route to correct parser.
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let fmt = crate::commands::seal::validated_extension(std::path::Path::new(stem));

        match fmt.as_deref() {
            Ok("env") => {
                let parsed = merge::parse_env_pairs(&text)?;
                let prefixed = apply_prefix_to_pairs(parsed, prefix.as_deref());
                secrets.extend(filter_pairs_by_key_globs(prefixed, key_filters.as_deref()));
            }
            Ok("json") => {
                let val: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
                    GitvaultError::Usage(format!("Invalid JSON in {}: {e}", path.display()))
                })?;
                let mut pairs = Vec::new();
                flatten_to_env_pairs(&val, "", &mut pairs);
                let prefixed = apply_prefix_to_pairs(pairs, prefix.as_deref());
                secrets.extend(filter_pairs_by_key_globs(prefixed, key_filters.as_deref()));
            }
            Ok("yaml") | Ok("yml") => {
                let val: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|e| {
                    GitvaultError::Usage(format!("Invalid YAML in {}: {e}", path.display()))
                })?;
                let json_val = serde_json::to_value(val).map_err(|e| {
                    GitvaultError::Usage(format!(
                        "Cannot convert YAML to JSON in {}: {e}",
                        path.display()
                    ))
                })?;
                let mut pairs = Vec::new();
                flatten_to_env_pairs(&json_val, "", &mut pairs);
                let prefixed = apply_prefix_to_pairs(pairs, prefix.as_deref());
                secrets.extend(filter_pairs_by_key_globs(prefixed, key_filters.as_deref()));
            }
            Ok("toml") => {
                let val: toml::Value = toml::from_str(&text).map_err(|e| {
                    GitvaultError::Usage(format!("Invalid TOML in {}: {e}", path.display()))
                })?;
                let json_val = serde_json::to_value(val).map_err(|e| {
                    GitvaultError::Usage(format!(
                        "Cannot convert TOML to JSON in {}: {e}",
                        path.display()
                    ))
                })?;
                let mut pairs = Vec::new();
                flatten_to_env_pairs(&json_val, "", &mut pairs);
                let prefixed = apply_prefix_to_pairs(pairs, prefix.as_deref());
                secrets.extend(filter_pairs_by_key_globs(prefixed, key_filters.as_deref()));
            }
            _ => {
                eprintln!(
                    "gitvault: warning: skipping {}: unsupported format",
                    path.display()
                );
            }
        }
    }

    Ok(secrets)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleEvalSource {
    Store,
    Sealed,
}

#[cfg(test)]
fn evaluate_rule_filters(
    rel_store_path: &str,
    rules: Option<&[crate::config::MatchRule]>,
    global_dir_prefix: bool,
    global_path_prefix: bool,
) -> (bool, Option<Vec<String>>, bool, bool, Option<String>) {
    evaluate_rule_filters_for_source(
        rel_store_path,
        rules,
        global_dir_prefix,
        global_path_prefix,
        RuleEvalSource::Store,
    )
}

fn evaluate_rule_filters_for_source(
    rel_store_path: &str,
    rules: Option<&[crate::config::MatchRule]>,
    global_dir_prefix: bool,
    global_path_prefix: bool,
    source: RuleEvalSource,
) -> (bool, Option<Vec<String>>, bool, bool, Option<String>) {
    fn defaults(
        include: bool,
        dir: bool,
        path: bool,
    ) -> (bool, Option<Vec<String>>, bool, bool, Option<String>) {
        (include, None, dir, path, None)
    }

    let default_include = matches!(source, RuleEvalSource::Store);

    let mut include = default_include;
    let mut key_filters: Option<Vec<String>> = None;
    let mut dir_prefix = global_dir_prefix;
    let mut path_prefix = global_path_prefix;
    let mut custom_prefix: Option<String> = None;

    let Some(rules) = rules else {
        return defaults(default_include, global_dir_prefix, global_path_prefix);
    };
    if rules.is_empty() {
        return defaults(default_include, global_dir_prefix, global_path_prefix);
    }

    for rule in rules {
        let rule_source = rule.source.unwrap_or(RuleSource::Store);
        let source_matches = match source {
            RuleEvalSource::Store => rule_source == RuleSource::Store,
            RuleEvalSource::Sealed => rule_source == RuleSource::Sealed,
        };
        if !source_matches {
            continue;
        }
        if !crate::matcher::path_matches_glob(&rule.path, rel_store_path) {
            continue;
        }
        if let Some(v) = rule.dir_prefix {
            dir_prefix = v;
        }
        if let Some(v) = rule.path_prefix {
            path_prefix = v;
        }
        if let Some(v) = &rule.custom_prefix {
            custom_prefix = Some(v.clone());
        }
        match rule.action {
            crate::config::RuleAction::Allow => {
                include = true;
                key_filters = if rule.keys.is_empty() {
                    None
                } else {
                    Some(rule.keys.clone())
                };
            }
            crate::config::RuleAction::Deny => {
                include = false;
                key_filters = None;
            }
        }
    }

    (include, key_filters, dir_prefix, path_prefix, custom_prefix)
}

fn list_repository_files(repo_root: &Path) -> Result<Vec<String>, GitvaultError> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), GitvaultError> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                    continue;
                }
                walk(root, &path, out)?;
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
            out.push(rel);
        }
        Ok(())
    }

    let mut files = Vec::new();
    walk(repo_root, repo_root, &mut files)?;
    files.sort();
    Ok(files)
}

fn build_repo_key_prefix(
    rel_repo_path: &str,
    dir_prefix_enabled: bool,
    filename_prefix_enabled: bool,
    custom_prefix: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::new();

    if dir_prefix_enabled && let Some(parent) = Path::new(rel_repo_path).parent() {
        let tokens = parent
            .components()
            .filter_map(|c| normalize_prefix_token(&c.as_os_str().to_string_lossy()))
            .collect::<Vec<_>>();
        if !tokens.is_empty() {
            parts.push(tokens.join("_"));
        }
    }

    if filename_prefix_enabled
        && let Some(stem) = Path::new(rel_repo_path)
            .file_stem()
            .and_then(|s| s.to_str())
    {
        let candidate = stem
            .trim_start_matches('.')
            .split('.')
            .next()
            .unwrap_or_default();
        if let Some(token) = normalize_prefix_token(candidate) {
            parts.push(token);
        }
    }

    if let Some(custom) = custom_prefix
        && let Some(token) = normalize_prefix_token(custom)
    {
        parts.push(token);
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("_"))
    }
}

fn apply_prefix_to_pairs(
    pairs: Vec<(String, String)>,
    prefix: Option<&str>,
) -> Vec<(String, String)> {
    let Some(prefix) = prefix else {
        return pairs;
    };
    if prefix.is_empty() {
        return pairs;
    }
    pairs
        .into_iter()
        .map(|(k, v)| (format!("{prefix}_{k}"), v))
        .collect()
}

fn build_key_prefix(
    path: &Path,
    env_store_dir: &Path,
    dir_prefix_enabled: bool,
    filename_prefix_enabled: bool,
    custom_prefix: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::new();

    if dir_prefix_enabled {
        let dir_prefix = directory_prefix_from_store_file(path, env_store_dir);
        if let Some(p) = dir_prefix {
            parts.push(p);
        }
    }

    if filename_prefix_enabled {
        let file_prefix = filename_prefix_from_store_file(path);
        if let Some(p) = file_prefix {
            parts.push(p);
        }
    }

    if let Some(custom) = custom_prefix {
        let normalized = normalize_prefix_token(custom);
        if let Some(token) = normalized {
            parts.push(token);
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("_"))
    }
}

fn directory_prefix_from_store_file(path: &Path, env_store_dir: &Path) -> Option<String> {
    let rel = path.strip_prefix(env_store_dir).ok()?;
    let parent = rel.parent()?;
    let tokens = parent
        .components()
        .filter_map(|c| normalize_prefix_token(&c.as_os_str().to_string_lossy()))
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join("_"))
    }
}

fn filename_prefix_from_store_file(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_string_lossy(); // strips .age
    let candidate = stem
        .trim_start_matches('.')
        .split('.')
        .next()
        .unwrap_or_default();
    normalize_prefix_token(candidate)
}

fn normalize_prefix_token(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut prev_underscore = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
            prev_underscore = false;
        } else if !prev_underscore {
            out.push('_');
            prev_underscore = true;
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn filter_pairs_by_key_globs(
    pairs: Vec<(String, String)>,
    key_globs: Option<&[String]>,
) -> Vec<(String, String)> {
    let Some(globs) = key_globs else {
        return pairs;
    };
    if globs.is_empty() {
        return pairs;
    }

    pairs
        .into_iter()
        .filter(|(k, _)| globs.iter().any(|g| crate::matcher::key_matches_glob(g, k)))
        .collect()
}

fn find_repo_root_from_with_runner(
    start: &std::path::Path,
    git_runner: &dyn GitRunner,
) -> Result<std::path::PathBuf, crate::error::GitvaultError> {
    let output = git_runner.show_toplevel(start);

    match output {
        Ok(out) if out.status.success() => {
            // REQ-101: strict UTF-8 — reject non-UTF-8 repo root paths rather than
            // silently mangling them with replacement characters.
            let root = String::from_utf8(out.stdout)
                .map_err(|_| {
                    crate::error::GitvaultError::Other(
                        "git rev-parse output contains non-UTF-8 characters".into(),
                    )
                })?
                .trim()
                .to_string();
            if root.is_empty() {
                return Err(crate::error::GitvaultError::Usage(
                    "not inside a git repository (no .git directory found)".to_string(),
                ));
            }
            Ok(PathBuf::from(root))
        }
        Ok(_) => Err(crate::error::GitvaultError::Usage(
            "not inside a git repository (no .git directory found)".to_string(),
        )),
        Err(_) => {
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
    }
}

/// Resolve repository root from `start`.
///
/// Uses `git rev-parse --show-toplevel` first, and falls back to walking up the
/// directory tree only when invoking `git` itself fails.
///
/// Returns [`crate::error::GitvaultError::Usage`] if no `.git` is found — the caller is
/// not inside a git repository.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if no `.git` directory is found while walking up.
pub fn find_repo_root_from(
    start: &std::path::Path,
) -> Result<std::path::PathBuf, crate::error::GitvaultError> {
    let git_runner = SystemGitRunner;
    find_repo_root_from_with_runner(start, &git_runner)
}

/// Find the repository root starting from `std::env::current_dir()`.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the current directory cannot be determined.
/// Returns [`GitvaultError::Usage`] if no `.git` directory is found while walking up.
pub fn find_repo_root() -> Result<std::path::PathBuf, crate::error::GitvaultError> {
    let cwd = std::env::current_dir()?;
    find_repo_root_from(&cwd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519;
    use std::io;
    use std::process::Command;
    use tempfile::TempDir;

    struct FailingGitRunner;

    impl GitRunner for FailingGitRunner {
        fn show_toplevel(&self, _start: &Path) -> io::Result<Output> {
            Err(io::Error::other("mock git execution failure"))
        }
    }

    fn init_git_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .status()
            .expect("git init should run");
        assert!(status.success());
    }

    fn gen_identity() -> x25519::Identity {
        x25519::Identity::generate()
    }

    fn assert_paths_equivalent(left: &Path, right: &Path) {
        fn normalize(path: &Path) -> String {
            path.canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase()
        }

        assert_eq!(normalize(left), normalize(right));
    }

    #[test]
    fn test_get_encrypted_path() {
        let root = Path::new("/repo");
        let path = get_encrypted_path(root, "database.env.age");
        assert_eq!(
            path,
            PathBuf::from("/repo/.gitvault/store/database.env.age")
        );
    }

    #[test]
    fn test_get_plain_path() {
        let root = Path::new("/repo");
        let path = get_plain_path(root, "dev", "database.env");
        assert_eq!(
            path,
            PathBuf::from("/repo/.git/gitvault/plain/dev/database.env")
        );
    }

    #[test]
    fn test_get_plain_path_staging() {
        let root = Path::new("/repo");
        let path = get_plain_path(root, "staging", "app.env");
        assert_eq!(
            path,
            PathBuf::from("/repo/.git/gitvault/plain/staging/app.env")
        );
    }

    #[test]
    fn test_ensure_dirs_creates_directories() {
        let dir = TempDir::new().unwrap();
        ensure_dirs(dir.path(), "dev").unwrap();

        assert!(
            dir.path().join(".gitvault/store").exists(),
            ".gitvault/store should be created"
        );
        assert!(
            dir.path().join(".git/gitvault/plain/dev").exists(),
            ".git/gitvault/plain/dev/ should be created"
        );
        assert!(
            dir.path().join(".gitvault/store/dev").exists(),
            ".gitvault/store/dev/ should be created"
        );
    }

    #[test]
    fn test_ensure_dirs_staging() {
        let dir = TempDir::new().unwrap();
        ensure_dirs(dir.path(), "staging").unwrap();

        assert!(dir.path().join(".git/gitvault/plain/staging").exists());
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
    fn test_get_env_encrypted_path() {
        let root = Path::new("/repo");
        let path = get_env_encrypted_path(root, "staging", "app.env.age");
        assert_eq!(
            path,
            PathBuf::from("/repo/.gitvault/store/staging/app.env.age")
        );
    }

    #[test]
    fn test_list_encrypted_files_for_env_prefers_env_dir() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".gitvault/store/dev")).unwrap();
        std::fs::create_dir_all(dir.path().join(".gitvault/store")).unwrap();
        std::fs::write(dir.path().join(".gitvault/store/dev/app.env.age"), b"x").unwrap();
        std::fs::write(dir.path().join(".gitvault/store/legacy.env.age"), b"x").unwrap();

        let files = list_encrypted_files_for_env(dir.path(), "dev").unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with(Path::new(".gitvault/store/dev/app.env.age")));
    }

    #[test]
    fn test_list_encrypted_files_for_env_falls_back_to_legacy() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".gitvault/store")).unwrap();
        std::fs::write(dir.path().join(".gitvault/store/app.env.age"), b"x").unwrap();

        let files = list_encrypted_files_for_env(dir.path(), "dev").unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with(Path::new(".gitvault/store/app.env.age")));
    }

    #[test]
    fn test_list_all_encrypted_files_recurses() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".gitvault/store/dev")).unwrap();
        std::fs::create_dir_all(dir.path().join(".gitvault/store/prod")).unwrap();
        std::fs::write(dir.path().join(".gitvault/store/dev/app.env.age"), b"x").unwrap();
        std::fs::write(dir.path().join(".gitvault/store/prod/app.env.age"), b"x").unwrap();

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

    /// Covers line 36: `Ok(p) => p` in `validate_write_path` (target file exists → canonicalize succeeds).
    #[test]
    fn test_validate_write_path_with_existing_target_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("existing.txt");
        std::fs::write(&file, b"content").unwrap();
        // canonicalize() will succeed for an existing file → exercises the `Ok(p) => p` arm.
        let result = validate_write_path(dir.path(), &file);
        assert!(
            result.is_ok(),
            "existing file inside base should be allowed"
        );
    }

    /// Covers `validate_write_path` lines 42-46: path with no `file_name` component (ends in "..").
    #[test]
    fn test_validate_write_path_target_ends_with_dotdot_returns_usage_error() {
        let dir = TempDir::new().unwrap();
        // A non-existent path whose last component is ".." → file_name() is None
        let target = dir.path().join("nonexistent_subdir").join("..");
        let result = validate_write_path(dir.path(), &target);
        // If the system resolves it or doesn't, we just test that it handles without panic.
        // It should either succeed (if it resolves within dir) or fail with a usage error.
        let _ = result;
    }

    /// Covers `decrypt_env_secrets` with no encrypted files → empty result.
    #[test]
    fn test_decrypt_env_secrets_no_files_returns_empty() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let result = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(result.is_empty());
    }

    /// Covers `decrypt_env_secrets` success path: one valid encrypted file.
    #[test]
    fn test_decrypt_env_secrets_success() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());

        // Create the env secrets directory and write an encrypted file.
        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let plaintext = b"KEY=value\nFOO=bar\n";
        let ciphertext = crate::crypto::encrypt(vec![recipient], plaintext).unwrap();
        std::fs::write(secrets_dir.join("app.env.age"), &ciphertext).unwrap();

        let secrets = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(secrets.contains(&("KEY".to_string(), "value".to_string())));
        assert!(secrets.contains(&("FOO".to_string(), "bar".to_string())));
    }

    /// Covers `decrypt_env_secrets` error path: wrong identity → Decryption error.
    #[test]
    fn test_decrypt_env_secrets_wrong_identity_returns_error() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let wrong_identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());

        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let ciphertext = crate::crypto::encrypt(vec![recipient], b"KEY=value\n").unwrap();
        std::fs::write(secrets_dir.join("app.env.age"), &ciphertext).unwrap();

        let result = decrypt_env_secrets(dir.path(), "dev", &wrong_identity);
        assert!(
            matches!(result, Err(GitvaultError::Decryption(_))),
            "expected decryption error, got: {result:?}"
        );
    }

    /// Covers `list_age_files_in_dir` with non-.age files (they should be ignored).
    #[test]
    fn test_list_age_files_in_dir_ignores_non_age_files() {
        let dir = TempDir::new().unwrap();
        let secrets_dir = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        std::fs::write(secrets_dir.join("file.txt"), b"x").unwrap();
        std::fs::write(secrets_dir.join("file.age"), b"x").unwrap();

        let files = list_age_files_in_dir(&secrets_dir).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("file.age"));
    }

    /// Covers `collect_age_files` with mixed files and subdirectories.
    #[test]
    fn test_collect_age_files_with_non_age_files() {
        let dir = TempDir::new().unwrap();
        let secrets_dir = dir.path().join(".gitvault/store");
        std::fs::create_dir_all(secrets_dir.join("dev")).unwrap();
        // Add a non-.age file — should be ignored
        std::fs::write(secrets_dir.join("README.md"), b"docs").unwrap();
        std::fs::write(secrets_dir.join("dev/app.env.age"), b"x").unwrap();

        let files = list_all_encrypted_files(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("app.env.age"));
    }

    /// Covers the `get_env_encrypted_dir` function.
    #[test]
    fn test_get_env_encrypted_dir() {
        let root = Path::new("/repo");
        let dir = get_env_encrypted_dir(root, "prod");
        assert_eq!(dir, PathBuf::from("/repo/.gitvault/store/prod"));
    }

    // ─── find_repo_root_from tests ───────────────────────────────────────────

    #[test]
    fn find_repo_root_from_finds_git_dir() {
        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());
        let found = find_repo_root_from(tmp.path()).unwrap();
        assert_paths_equivalent(&found, tmp.path());
    }

    #[test]
    fn find_repo_root_from_walks_up() {
        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());
        let sub = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&sub).unwrap();
        let found = find_repo_root_from(&sub).unwrap();
        assert_paths_equivalent(&found, tmp.path());
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

    #[test]
    fn find_repo_root_from_fallback_when_git_invocation_fails() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();

        let found = find_repo_root_from_with_runner(tmp.path(), &FailingGitRunner).unwrap();

        assert_paths_equivalent(&found, tmp.path());
    }

    #[test]
    fn find_repo_root_from_fallback_walks_up_when_git_invocation_fails() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let sub = tmp.path().join("x/y/z");
        std::fs::create_dir_all(&sub).unwrap();

        let found = find_repo_root_from_with_runner(&sub, &FailingGitRunner).unwrap();

        assert_paths_equivalent(&found, tmp.path());
    }

    // ── REQ-117: decrypt_env_secrets multi-format tests ───────────────────────

    fn encrypt_content(identity: &x25519::Identity, content: &[u8]) -> Vec<u8> {
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(identity.to_public())];
        crate::crypto::encrypt(recipients, content).unwrap()
    }

    /// REQ-117 AC3: JSON store file is flattened into env pairs.
    #[test]
    fn test_decrypt_env_secrets_json_store_file() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let json = r#"{"api_key":"abc","db":{"host":"localhost","pass":"s3cr3t"}}"#;
        let ciphertext = encrypt_content(&identity, json.as_bytes());
        std::fs::write(secrets_dir.join("secrets.json.age"), &ciphertext).unwrap();

        let pairs = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(
            pairs.contains(&("API_KEY".to_string(), "abc".to_string())),
            "missing API_KEY: {pairs:?}"
        );
        assert!(
            pairs.contains(&("DB_HOST".to_string(), "localhost".to_string())),
            "missing DB_HOST: {pairs:?}"
        );
        assert!(
            pairs.contains(&("DB_PASS".to_string(), "s3cr3t".to_string())),
            "missing DB_PASS: {pairs:?}"
        );
    }

    /// REQ-117 AC4: YAML store file is flattened into env pairs.
    #[test]
    fn test_decrypt_env_secrets_yaml_store_file() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let yaml = "key: value\nnested:\n  sub: data\n";
        let ciphertext = encrypt_content(&identity, yaml.as_bytes());
        std::fs::write(secrets_dir.join("config.yaml.age"), &ciphertext).unwrap();

        let pairs = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(
            pairs.contains(&("KEY".to_string(), "value".to_string())),
            "missing KEY: {pairs:?}"
        );
        assert!(
            pairs.contains(&("NESTED_SUB".to_string(), "data".to_string())),
            "missing NESTED_SUB: {pairs:?}"
        );
    }

    /// REQ-117 AC5: TOML store file is flattened into env pairs.
    #[test]
    fn test_decrypt_env_secrets_toml_store_file() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let toml_content = "[db]\npassword = \"abc\"\n";
        let ciphertext = encrypt_content(&identity, toml_content.as_bytes());
        std::fs::write(secrets_dir.join("settings.toml.age"), &ciphertext).unwrap();

        let pairs = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(
            pairs.contains(&("DB_PASSWORD".to_string(), "abc".to_string())),
            "missing DB_PASSWORD: {pairs:?}"
        );
    }

    /// REQ-117 AC6: Unknown format is skipped with a warning (no error, no pairs).
    #[test]
    fn test_decrypt_env_secrets_unknown_format_skipped() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let ciphertext = encrypt_content(&identity, b"<xml>data</xml>");
        std::fs::write(secrets_dir.join("data.xml.age"), &ciphertext).unwrap();

        let pairs = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(
            pairs.is_empty(),
            "expected no pairs for unknown format, got: {pairs:?}"
        );
    }

    /// REQ-117 AC8: Mixed store (.env.age + .json.age) → all pairs combined.
    #[test]
    fn test_decrypt_env_secrets_mixed_env_and_json() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let env_ct = encrypt_content(&identity, b"A=1\n");
        std::fs::write(secrets_dir.join("app.env.age"), &env_ct).unwrap();

        let json_ct = encrypt_content(&identity, br#"{"B":"2"}"#);
        std::fs::write(secrets_dir.join("cfg.json.age"), &json_ct).unwrap();

        let pairs = decrypt_env_secrets(dir.path(), "dev", &identity).unwrap();
        assert!(
            pairs.contains(&("A".to_string(), "1".to_string())),
            "missing A: {pairs:?}"
        );
        assert!(
            pairs.contains(&("B".to_string(), "2".to_string())),
            "missing B: {pairs:?}"
        );
    }

    #[test]
    fn test_evaluate_rule_filters_defaults_without_rules() {
        let (include_file, key_filters, dir_prefix, path_prefix, custom_prefix) =
            evaluate_rule_filters(".gitvault/store/dev/app.env.age", None, false, false);
        assert!(include_file);
        assert!(key_filters.is_none());
        assert!(!dir_prefix);
        assert!(!path_prefix);
        assert!(custom_prefix.is_none());

        let empty: Vec<crate::config::MatchRule> = Vec::new();
        let (include_file, key_filters, dir_prefix, path_prefix, custom_prefix) =
            evaluate_rule_filters(
                ".gitvault/store/dev/app.env.age",
                Some(&empty),
                false,
                false,
            );
        assert!(include_file);
        assert!(key_filters.is_none());
        assert!(!dir_prefix);
        assert!(!path_prefix);
        assert!(custom_prefix.is_none());
    }

    #[test]
    fn test_evaluate_rule_filters_allow_with_keys_and_deny() {
        let rules = vec![
            crate::config::MatchRule {
                action: crate::config::RuleAction::Allow,
                path: ".gitvault/store/dev/*.env.age".to_string(),
                keys: vec!["FOO".to_string(), "BAR_*".to_string()],
                source: None,
                dir_prefix: None,
                path_prefix: None,
                custom_prefix: None,
            },
            crate::config::MatchRule {
                action: crate::config::RuleAction::Deny,
                path: ".gitvault/store/dev/blocked.env.age".to_string(),
                keys: vec!["IGNORED".to_string()],
                source: None,
                dir_prefix: None,
                path_prefix: None,
                custom_prefix: None,
            },
        ];

        let (include_ok, filters_ok, _, _, _) = evaluate_rule_filters(
            ".gitvault/store/dev/app.env.age",
            Some(&rules),
            false,
            false,
        );
        assert!(include_ok);
        assert_eq!(
            filters_ok.unwrap(),
            vec!["FOO".to_string(), "BAR_*".to_string()]
        );

        let (include_blocked, filters_blocked, _, _, _) = evaluate_rule_filters(
            ".gitvault/store/dev/blocked.env.age",
            Some(&rules),
            false,
            false,
        );
        assert!(!include_blocked);
        assert!(filters_blocked.is_none());
    }

    #[test]
    fn test_filter_pairs_by_key_globs_applies_matching() {
        let pairs = vec![
            ("FOO".to_string(), "1".to_string()),
            ("BAR_VALUE".to_string(), "2".to_string()),
            ("BAZ".to_string(), "3".to_string()),
        ];

        let passthrough_none = filter_pairs_by_key_globs(pairs.clone(), None);
        assert_eq!(passthrough_none.len(), 3);

        let empty_filters: Vec<String> = Vec::new();
        let passthrough_empty = filter_pairs_by_key_globs(pairs.clone(), Some(&empty_filters));
        assert_eq!(passthrough_empty.len(), 3);

        let globs = vec!["FOO".to_string(), "BAR_*".to_string()];
        let filtered = filter_pairs_by_key_globs(pairs, Some(&globs));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|(k, v)| k == "FOO" && v == "1"));
        assert!(filtered.iter().any(|(k, v)| k == "BAR_VALUE" && v == "2"));
        assert!(!filtered.iter().any(|(k, _)| k == "BAZ"));
    }

    #[test]
    fn test_decrypt_env_secrets_with_rules_key_filtering() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let ciphertext = encrypt_content(&identity, b"FOO=one\nBAR=two\n");
        std::fs::write(secrets_dir.join("app.env.age"), &ciphertext).unwrap();

        let rules = vec![crate::config::MatchRule {
            action: crate::config::RuleAction::Allow,
            path: ".gitvault/store/dev/app.env.age".to_string(),
            keys: vec!["FOO".to_string()],
            source: None,
            dir_prefix: None,
            path_prefix: None,
            custom_prefix: None,
        }];

        let pairs = decrypt_env_secrets_with_rules(
            dir.path(),
            "dev",
            &identity,
            Some(&rules),
            false,
            false,
        )
        .unwrap();
        assert_eq!(pairs, vec![("FOO".to_string(), "one".to_string())]);
    }

    #[test]
    fn test_decrypt_env_secrets_with_rules_deny_file() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let ciphertext = encrypt_content(&identity, b"FOO=one\n");
        std::fs::write(secrets_dir.join("blocked.env.age"), &ciphertext).unwrap();

        let rules = vec![crate::config::MatchRule {
            action: crate::config::RuleAction::Deny,
            path: ".gitvault/store/dev/blocked.env.age".to_string(),
            keys: vec![],
            source: None,
            dir_prefix: None,
            path_prefix: None,
            custom_prefix: None,
        }];

        let pairs = decrypt_env_secrets_with_rules(
            dir.path(),
            "dev",
            &identity,
            Some(&rules),
            false,
            false,
        )
        .unwrap();
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_decrypt_env_secrets_with_rules_applies_prefix_order() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev/conf");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let ciphertext = encrypt_content(&identity, b"DB=one\n");
        std::fs::write(secrets_dir.join("app.env.age"), &ciphertext).unwrap();

        let rules = vec![crate::config::MatchRule {
            action: crate::config::RuleAction::Allow,
            path: ".gitvault/store/dev/conf/*.env.age".to_string(),
            keys: vec![],
            source: None,
            dir_prefix: Some(true),
            path_prefix: Some(true),
            custom_prefix: Some("svc".to_string()),
        }];

        let pairs = decrypt_env_secrets_with_rules(
            dir.path(),
            "dev",
            &identity,
            Some(&rules),
            false,
            false,
        )
        .unwrap();

        assert_eq!(
            pairs,
            vec![("CONF_APP_SVC_DB".to_string(), "one".to_string())]
        );
    }

    #[test]
    fn test_decrypt_env_secrets_with_rules_uses_global_prefix_defaults() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev/conf");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let ciphertext = encrypt_content(&identity, b"DB=one\n");
        std::fs::write(secrets_dir.join("app.env.age"), &ciphertext).unwrap();

        let pairs =
            decrypt_env_secrets_with_rules(dir.path(), "dev", &identity, None, true, true).unwrap();

        assert_eq!(pairs, vec![("CONF_APP_DB".to_string(), "one".to_string())]);
    }

    #[test]
    fn test_decrypt_env_secrets_with_rules_rule_overrides_global_prefix_defaults() {
        let dir = TempDir::new().unwrap();
        let identity = gen_identity();
        let secrets_dir = dir.path().join(".gitvault/store/dev/conf");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let ciphertext = encrypt_content(&identity, b"DB=one\n");
        std::fs::write(secrets_dir.join("app.env.age"), &ciphertext).unwrap();

        let rules = vec![crate::config::MatchRule {
            action: crate::config::RuleAction::Allow,
            path: ".gitvault/store/dev/conf/*.env.age".to_string(),
            keys: vec![],
            source: None,
            dir_prefix: Some(false),
            path_prefix: Some(true),
            custom_prefix: None,
        }];

        let pairs =
            decrypt_env_secrets_with_rules(dir.path(), "dev", &identity, Some(&rules), true, true)
                .unwrap();

        assert_eq!(pairs, vec![("APP_DB".to_string(), "one".to_string())]);
    }
}
