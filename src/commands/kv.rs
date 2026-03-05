//! `gitvault get` / `gitvault set` — single key-value access (REQ-116).
//!
//! # Sealed-file mode (`.json`, `.yaml`, `.yml`, `.toml`, `.env`)
//! 1. Unseal the entire file to plaintext using [`unseal_content`].
//! 2. Extract / update the key value.
//! 3. For `set`: re-seal and write atomically back.
//!
//! # Store-file mode (`.age` or source path resolving via `store::resolve_store_path`)
//! 1. Decrypt the `.age` archive with the provided identity.
//! 2. Detect the plaintext format from the `.age` file's stem extension.
//! 3. Extract / update the key value.
//! 4. For `set`: re-encrypt and write atomically back.
//!
//! All plaintext bytes are zeroized before return.

use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::commands::effects::CommandOutcome;
use crate::commands::seal::{seal_content, unseal_content, validated_extension};
use crate::error::GitvaultError;

// ---------------------------------------------------------------------------
// Public option structs
// ---------------------------------------------------------------------------

/// Options for `gitvault get`.
pub struct GetOptions {
    pub file: String,
    pub key: String,
    pub identity: Option<String>,
    pub env: Option<String>,
    pub json: bool,
    pub no_prompt: bool,
    pub selector: Option<String>,
}

/// Options for `gitvault set`.
pub struct SetOptions {
    pub file: String,
    pub key: String,
    /// New value provided on the command line (mutually exclusive with `stdin`).
    pub value: Option<String>,
    /// Read new value from stdin (mutually exclusive with `value`).
    pub stdin: bool,
    pub identity: Option<String>,
    pub env: Option<String>,
    pub json: bool,
    pub no_prompt: bool,
    pub selector: Option<String>,
}

// ---------------------------------------------------------------------------
// Command entry points
// ---------------------------------------------------------------------------

/// `gitvault get <FILE> <KEY>` (REQ-116 AC1, AC3–AC5).
///
/// # Errors
///
/// Returns [`GitvaultError`] on IO, decrypt, or missing-key failures.
#[allow(clippy::needless_pass_by_value)]
pub fn cmd_get(opts: GetOptions) -> Result<CommandOutcome, GitvaultError> {
    let file_path = PathBuf::from(&opts.file);
    let repo_root = crate::repo::find_repo_root()?;
    let abs_repo = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.clone());

    let probe_env = opts
        .env
        .clone()
        .or_else(|| std::env::var("GITVAULT_ENV").ok())
        .unwrap_or_else(|| crate::defaults::DEFAULT_ENV.to_string());
    let is_store_file = is_age(&file_path)
        || crate::store::resolve_store_path(&file_path, &probe_env, &abs_repo).is_ok();

    let value = if is_store_file {
        get_store(&opts, &repo_root, &abs_repo, &file_path, &probe_env)?
    } else {
        get_sealed(&opts, &repo_root, &abs_repo, &file_path)?
    };

    if opts.json {
        let out = serde_json::json!({
            "file": opts.file,
            "key": opts.key,
            "value": value,
        });
        println!("{out}");
    } else {
        println!("{value}");
    }

    Ok(CommandOutcome::Success)
}

/// `gitvault set <FILE> <KEY> [VALUE|--stdin]` (REQ-116 AC2, AC6–AC9).
///
/// # Errors
///
/// Returns [`GitvaultError`] on IO, decrypt, or update failures.
#[allow(clippy::needless_pass_by_value)]
pub fn cmd_set(opts: SetOptions) -> Result<CommandOutcome, GitvaultError> {
    // AC6: --stdin and positional value are mutually exclusive.
    if opts.stdin && opts.value.is_some() {
        return Err(GitvaultError::Usage(
            "cannot use both --stdin and a positional VALUE argument".to_string(),
        ));
    }
    if !opts.stdin && opts.value.is_none() {
        return Err(GitvaultError::Usage(
            "provide a VALUE argument or use --stdin to read the value from standard input"
                .to_string(),
        ));
    }

    let mut new_value = if opts.stdin {
        let mut buf = String::new();
        use std::io::Read;
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
        // Trim exactly one trailing newline (as produced by `echo`).
        if buf.ends_with('\n') {
            buf.pop();
        }
        buf
    } else {
        opts.value.clone().unwrap_or_default()
    };

    let file_path = PathBuf::from(&opts.file);
    let repo_root = crate::repo::find_repo_root()?;
    let abs_repo = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.clone());

    let probe_env = opts
        .env
        .clone()
        .or_else(|| std::env::var("GITVAULT_ENV").ok())
        .unwrap_or_else(|| crate::defaults::DEFAULT_ENV.to_string());
    let is_store_file = is_age(&file_path)
        || crate::store::resolve_store_path(&file_path, &probe_env, &abs_repo).is_ok();

    let outcome = if is_store_file {
        set_store(
            &opts, &new_value, &repo_root, &abs_repo, &file_path, &probe_env,
        )
    } else {
        set_sealed(&opts, &new_value, &repo_root, &abs_repo, &file_path)
    };
    new_value.zeroize();
    outcome
}

// ---------------------------------------------------------------------------
// Sealed-file mode: get
// ---------------------------------------------------------------------------

fn get_sealed(
    opts: &GetOptions,
    repo_root: &Path,
    abs_repo: &Path,
    file_path: &Path,
) -> Result<String, GitvaultError> {
    let ext = validated_extension(file_path)?;
    let identity = load_identity(
        opts.identity.as_deref(),
        opts.selector.as_deref(),
        opts.no_prompt,
    )?;
    let ident_ref = identity.as_identity();

    let sealed_content = std::fs::read_to_string(file_path)
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;

    // Unseal the entire file (all fields).
    let mut plain = unseal_content(&sealed_content, &ext, None, ident_ref)?;
    let result = extract_value(&plain, &ext, &opts.key);
    plain.zeroize();

    let _ = (repo_root, abs_repo); // used for completeness; not needed for get_sealed
    result
}

// ---------------------------------------------------------------------------
// Sealed-file mode: set
// ---------------------------------------------------------------------------

fn set_sealed(
    opts: &SetOptions,
    new_value: &str,
    repo_root: &Path,
    abs_repo: &Path,
    file_path: &Path,
) -> Result<CommandOutcome, GitvaultError> {
    let ext = validated_extension(file_path)?;

    // Resolve override fields from config (for re-sealing).
    let abs_file = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(file_path)
    };
    let abs_file_canon = abs_file.canonicalize().unwrap_or_else(|_| abs_file.clone());
    let rel_path = relative_path_to_repo(&abs_file_canon, abs_repo);
    let config_fields: Option<Vec<String>> =
        crate::config::load_config(repo_root).ok().and_then(|cfg| {
            cfg.seal
                .overrides
                .into_iter()
                .find(|o| pattern_matches(&o.pattern, &rel_path))
                .map(|o| o.fields)
        });

    let identity = load_identity(
        opts.identity.as_deref(),
        opts.selector.as_deref(),
        opts.no_prompt,
    )?;
    let ident_ref = identity.as_identity();

    let sealed_content = std::fs::read_to_string(file_path)
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;

    // Unseal all fields to get plaintext.
    let mut plain = unseal_content(&sealed_content, &ext, None, ident_ref)?;

    // Update the key in plaintext.
    let mut updated = update_value(&plain, &ext, &opts.key, new_value)?;
    plain.zeroize();

    // Re-seal using the same field rules.
    let recipient_keys = crate::identity::resolve_recipient_keys(repo_root, vec![])?;
    let resealed = seal_content(&updated, &ext, config_fields.as_deref(), &recipient_keys)?;
    updated.zeroize();

    crate::fs_util::atomic_write(file_path, resealed.as_bytes())?;
    crate::output::output_success(
        &format!(
            "Updated {key} in {file}",
            key = opts.key,
            file = file_path.display()
        ),
        opts.json,
    );
    Ok(CommandOutcome::Success)
}

// ---------------------------------------------------------------------------
// Store-file mode: get
// ---------------------------------------------------------------------------

fn get_store(
    opts: &GetOptions,
    _repo_root: &Path,
    abs_repo: &Path,
    file_path: &Path,
    active_env: &str,
) -> Result<String, GitvaultError> {
    let age_path = resolve_age_path(file_path, active_env, abs_repo)?;
    let ext = stem_extension(&age_path)?;

    let identity = load_identity(
        opts.identity.as_deref(),
        opts.selector.as_deref(),
        opts.no_prompt,
    )?;
    let ident_ref = identity.as_identity();

    let encrypted_bytes = std::fs::read(&age_path)
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
    let plain_z = crate::crypto::decrypt(ident_ref, &encrypted_bytes)?;
    let mut plain = String::from_utf8(plain_z.to_vec())
        .map_err(|e| GitvaultError::Usage(format!("encrypted file contains non-UTF-8: {e}")))?;

    let result = extract_value(&plain, &ext, &opts.key);
    plain.zeroize();
    result
}

// ---------------------------------------------------------------------------
// Store-file mode: set
// ---------------------------------------------------------------------------

fn set_store(
    opts: &SetOptions,
    new_value: &str,
    repo_root: &Path,
    abs_repo: &Path,
    file_path: &Path,
    active_env: &str,
) -> Result<CommandOutcome, GitvaultError> {
    let age_path = resolve_age_path(file_path, active_env, abs_repo)?;
    let ext = stem_extension(&age_path)?;

    let identity = load_identity(
        opts.identity.as_deref(),
        opts.selector.as_deref(),
        opts.no_prompt,
    )?;
    let ident_ref = identity.as_identity();

    let encrypted_bytes = std::fs::read(&age_path)
        .map_err(|e| GitvaultError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
    let plain_z = crate::crypto::decrypt(ident_ref, &encrypted_bytes)?;
    let mut plain = String::from_utf8(plain_z.to_vec())
        .map_err(|e| GitvaultError::Usage(format!("encrypted file contains non-UTF-8: {e}")))?;

    let mut updated = update_value(&plain, &ext, &opts.key, new_value)?;
    plain.zeroize();

    // Re-encrypt to the same .age path.
    let recipient_keys = crate::identity::resolve_recipient_keys(repo_root, vec![])?;
    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r = crate::crypto::parse_recipient(k)?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;
    let mut plaintext_bytes = updated.into_bytes();
    let encrypted = crate::crypto::encrypt(recipients, &plaintext_bytes)?;
    plaintext_bytes.zeroize();
    updated = String::new(); // already moved into bytes

    crate::fs_util::atomic_write(&age_path, &encrypted)?;
    crate::output::output_success(
        &format!(
            "Updated {key} in {file}",
            key = opts.key,
            file = age_path.display()
        ),
        opts.json,
    );
    let _ = updated; // suppress unused variable warning
    Ok(CommandOutcome::Success)
}

// ---------------------------------------------------------------------------
// Key extraction
// ---------------------------------------------------------------------------

/// Extract the value at `key` from `content` according to `ext`.
fn extract_value(content: &str, ext: &str, key: &str) -> Result<String, GitvaultError> {
    match ext {
        "json" => {
            let path: Vec<&str> = key.split('.').collect();
            let value: serde_json::Value = serde_json::from_str(content)
                .map_err(|e| GitvaultError::Usage(format!("JSON parse error: {e}")))?;
            json_get(&value, &path, key)
        }
        "yaml" | "yml" => {
            let path: Vec<&str> = key.split('.').collect();
            let value: serde_yaml::Value = serde_yaml::from_str(content)
                .map_err(|e| GitvaultError::Usage(format!("YAML parse error: {e}")))?;
            yaml_get(&value, &path, key)
        }
        "toml" => {
            let path: Vec<&str> = key.split('.').collect();
            let value: toml::Value = content
                .parse::<toml::Value>()
                .map_err(|e| GitvaultError::Usage(format!("TOML parse error: {e}")))?;
            toml_get(&value, &path, key)
        }
        "env" => env_get(content, key),
        _ => Err(GitvaultError::Usage(format!(
            "unsupported extension: {ext}"
        ))),
    }
}

fn json_get(value: &serde_json::Value, path: &[&str], key: &str) -> Result<String, GitvaultError> {
    if path.is_empty() {
        return match value {
            serde_json::Value::String(s) => Ok(s.clone()),
            other => Ok(other.to_string()),
        };
    }
    match value {
        serde_json::Value::Object(map) => match map.get(path[0]) {
            Some(v) => json_get(v, &path[1..], key),
            None => Err(GitvaultError::NotFound(format!("key '{key}' not found"))),
        },
        _ => Err(GitvaultError::NotFound(format!("key '{key}' not found"))),
    }
}

fn yaml_get(value: &serde_yaml::Value, path: &[&str], key: &str) -> Result<String, GitvaultError> {
    if path.is_empty() {
        return match value {
            serde_yaml::Value::String(s) => Ok(s.clone()),
            serde_yaml::Value::Number(n) => Ok(n.to_string()),
            serde_yaml::Value::Bool(b) => Ok(b.to_string()),
            other => serde_yaml::to_string(other)
                .map(|s| s.trim().to_string())
                .map_err(|e| GitvaultError::Usage(format!("YAML serialize error: {e}"))),
        };
    }
    match value {
        serde_yaml::Value::Mapping(map) => {
            let k = serde_yaml::Value::String(path[0].to_string());
            match map.get(&k) {
                Some(v) => yaml_get(v, &path[1..], key),
                None => Err(GitvaultError::NotFound(format!("key '{key}' not found"))),
            }
        }
        _ => Err(GitvaultError::NotFound(format!("key '{key}' not found"))),
    }
}

fn toml_get(value: &toml::Value, path: &[&str], key: &str) -> Result<String, GitvaultError> {
    if path.is_empty() {
        return match value {
            toml::Value::String(s) => Ok(s.clone()),
            toml::Value::Integer(n) => Ok(n.to_string()),
            toml::Value::Float(f) => Ok(f.to_string()),
            toml::Value::Boolean(b) => Ok(b.to_string()),
            other => Ok(other.to_string()),
        };
    }
    match value {
        toml::Value::Table(map) => match map.get(path[0]) {
            Some(v) => toml_get(v, &path[1..], key),
            None => Err(GitvaultError::NotFound(format!("key '{key}' not found"))),
        },
        _ => Err(GitvaultError::NotFound(format!("key '{key}' not found"))),
    }
}

fn env_get(content: &str, key: &str) -> Result<String, GitvaultError> {
    if key.contains('.') {
        return Err(GitvaultError::Usage(
            "dot-path keys are not supported for .env files; use the variable name directly"
                .to_string(),
        ));
    }
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some((_k, v)) = line.split_once('=').filter(|(k, _)| k.trim() == key) {
            // Strip optional surrounding quotes.
            let v = v.trim();
            let v = strip_quotes(v);
            return Ok(v.to_string());
        }
    }
    Err(GitvaultError::NotFound(format!("key '{key}' not found")))
}

// ---------------------------------------------------------------------------
// Key update
// ---------------------------------------------------------------------------

/// Update the value at `key` in `content` and return the modified content.
fn update_value(
    content: &str,
    ext: &str,
    key: &str,
    new_value: &str,
) -> Result<String, GitvaultError> {
    match ext {
        "json" => json_set(content, key, new_value),
        "yaml" | "yml" => yaml_set(content, key, new_value),
        "toml" => toml_set(content, key, new_value),
        "env" => env_set(content, key, new_value),
        _ => Err(GitvaultError::Usage(format!(
            "unsupported extension: {ext}"
        ))),
    }
}

fn json_set(content: &str, key: &str, new_value: &str) -> Result<String, GitvaultError> {
    let path: Vec<&str> = key.split('.').collect();
    let mut value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| GitvaultError::Usage(format!("JSON parse error: {e}")))?;

    // AC7: nested path creation not supported; top-level upsert is OK.
    if path.len() > 1 {
        // Check that the parent path exists.
        let parent = &path[..path.len() - 1];
        if json_field_mut_ro(&value, parent).is_none() {
            return Err(GitvaultError::Usage(format!(
                "key '{key}' not found and nested key creation is not supported; create it manually first"
            )));
        }
    }

    json_set_mut(&mut value, &path, new_value, key)?;

    serde_json::to_string_pretty(&value)
        .map(|s| s + "\n")
        .map_err(|e| GitvaultError::Usage(format!("JSON serialize error: {e}")))
}

fn json_set_mut(
    value: &mut serde_json::Value,
    path: &[&str],
    new_value: &str,
    full_key: &str,
) -> Result<(), GitvaultError> {
    if path.len() == 1 {
        match value {
            serde_json::Value::Object(map) => {
                map.insert(
                    path[0].to_string(),
                    serde_json::Value::String(new_value.to_string()),
                );
                Ok(())
            }
            _ => Err(GitvaultError::NotFound(format!(
                "key '{full_key}' not found"
            ))),
        }
    } else {
        match value {
            serde_json::Value::Object(map) => match map.get_mut(path[0]) {
                Some(v) => json_set_mut(v, &path[1..], new_value, full_key),
                None => Err(GitvaultError::NotFound(format!(
                    "key '{full_key}' not found"
                ))),
            },
            _ => Err(GitvaultError::NotFound(format!(
                "key '{full_key}' not found"
            ))),
        }
    }
}

fn json_field_mut_ro<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Option<&'a serde_json::Value> {
    if path.is_empty() {
        return Some(value);
    }
    match value {
        serde_json::Value::Object(map) => map
            .get(path[0])
            .and_then(|v| json_field_mut_ro(v, &path[1..])),
        _ => None,
    }
}

fn yaml_set(content: &str, key: &str, new_value: &str) -> Result<String, GitvaultError> {
    let path: Vec<&str> = key.split('.').collect();
    let mut value: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| GitvaultError::Usage(format!("YAML parse error: {e}")))?;

    if path.len() > 1 && yaml_field_ro(&value, &path[..path.len() - 1]).is_none() {
        return Err(GitvaultError::Usage(format!(
            "key '{key}' not found and nested key creation is not supported; create it manually first"
        )));
    }

    yaml_set_mut(&mut value, &path, new_value, key)?;

    serde_yaml::to_string(&value)
        .map_err(|e| GitvaultError::Usage(format!("YAML serialize error: {e}")))
}

fn yaml_set_mut(
    value: &mut serde_yaml::Value,
    path: &[&str],
    new_value: &str,
    full_key: &str,
) -> Result<(), GitvaultError> {
    if path.len() == 1 {
        match value {
            serde_yaml::Value::Mapping(map) => {
                let k = serde_yaml::Value::String(path[0].to_string());
                map.insert(k, serde_yaml::Value::String(new_value.to_string()));
                Ok(())
            }
            _ => Err(GitvaultError::NotFound(format!(
                "key '{full_key}' not found"
            ))),
        }
    } else {
        match value {
            serde_yaml::Value::Mapping(map) => {
                let k = serde_yaml::Value::String(path[0].to_string());
                match map.get_mut(&k) {
                    Some(v) => yaml_set_mut(v, &path[1..], new_value, full_key),
                    None => Err(GitvaultError::NotFound(format!(
                        "key '{full_key}' not found"
                    ))),
                }
            }
            _ => Err(GitvaultError::NotFound(format!(
                "key '{full_key}' not found"
            ))),
        }
    }
}

fn yaml_field_ro<'a>(value: &'a serde_yaml::Value, path: &[&str]) -> Option<&'a serde_yaml::Value> {
    if path.is_empty() {
        return Some(value);
    }
    match value {
        serde_yaml::Value::Mapping(map) => {
            let k = serde_yaml::Value::String(path[0].to_string());
            map.get(&k).and_then(|v| yaml_field_ro(v, &path[1..]))
        }
        _ => None,
    }
}

/// Update a TOML field using `toml_edit` to preserve comments and formatting (AC11).
fn toml_set(content: &str, key: &str, new_value: &str) -> Result<String, GitvaultError> {
    let path: Vec<&str> = key.split('.').collect();
    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .map_err(|e| GitvaultError::Usage(format!("TOML parse error: {e}")))?;

    toml_edit_set(&mut doc, &path, new_value, key)?;

    Ok(doc.to_string())
}

fn toml_edit_set(
    doc: &mut toml_edit::DocumentMut,
    path: &[&str],
    new_value: &str,
    full_key: &str,
) -> Result<(), GitvaultError> {
    if path.is_empty() {
        return Err(GitvaultError::Usage("empty key path".to_string()));
    }
    if path.len() == 1 {
        // Top-level key — upsert.
        doc[path[0]] = toml_edit::value(new_value);
        return Ok(());
    }
    // Nested: traverse tables; fail if intermediate segment missing.
    let mut item = doc.as_item_mut();
    for (i, segment) in path.iter().enumerate() {
        let is_last = i == path.len() - 1;
        if is_last {
            match item.as_table_mut() {
                Some(t) => {
                    t[*segment] = toml_edit::value(new_value);
                    return Ok(());
                }
                None => {
                    return Err(GitvaultError::NotFound(format!(
                        "key '{full_key}' not found"
                    )));
                }
            }
        } else {
            item = item
                .get_mut(*segment)
                .ok_or_else(|| GitvaultError::Usage(format!(
                    "key '{full_key}' not found and nested key creation is not supported; create it manually first"
                )))?;
        }
    }
    Ok(())
}

/// Update a `.env` variable while preserving all other lines, comments, and blank lines (AC11).
fn env_set(content: &str, key: &str, new_value: &str) -> Result<String, GitvaultError> {
    if key.contains('.') {
        return Err(GitvaultError::Usage(
            "dot-path keys are not supported for .env files; use the variable name directly"
                .to_string(),
        ));
    }

    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                return line.to_string();
            }
            if line.split_once('=').is_some_and(|(k, _)| k.trim() == key) {
                found = true;
                return format!("{key}={new_value}");
            }
            line.to_string()
        })
        .collect();

    if !found {
        // AC2: upsert — append at end.
        lines.push(format!("{key}={new_value}"));
    }

    let mut result = lines.join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_age(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("age")
}

/// Resolve the `.age` file path from either an explicit `.age` path or a source path.
fn resolve_age_path(
    file_path: &Path,
    active_env: &str,
    abs_repo: &Path,
) -> Result<PathBuf, GitvaultError> {
    if is_age(file_path) {
        if file_path.is_absolute() {
            Ok(file_path.to_path_buf())
        } else {
            Ok(std::env::current_dir()?.join(file_path))
        }
    } else {
        crate::store::resolve_store_path(file_path, active_env, abs_repo)
    }
}

/// Determine the plaintext format from the `.age` file's stem extension.
///
/// E.g. `secrets.json.age` → `json`, `config.yaml.age` → `yaml`.
fn stem_extension(age_path: &Path) -> Result<String, GitvaultError> {
    let stem = age_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let stem_path = Path::new(stem);
    match stem_path.extension().and_then(|e| e.to_str()) {
        Some(ext) => Ok(ext.to_string()),
        None => Err(GitvaultError::Usage(format!(
            "cannot determine file format from '{}'  — expected a name like 'config.json.age'",
            age_path.display()
        ))),
    }
}

/// Load the age identity for decryption.
fn load_identity(
    identity: Option<&str>,
    selector: Option<&str>,
    no_prompt: bool,
) -> Result<crate::crypto::AnyIdentity, GitvaultError> {
    let identity_str =
        crate::identity::load_identity_with_selector(identity.map(ToString::to_string), selector)?;
    crate::crypto::parse_identity_any_with_passphrase(
        &identity_str,
        crate::identity::try_fetch_ssh_passphrase(
            crate::defaults::KEYRING_SERVICE,
            crate::defaults::KEYRING_ACCOUNT,
            no_prompt,
        ),
    )
}

fn strip_quotes(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Compute the repository-relative path for a canonical absolute path.
fn relative_path_to_repo(abs_file: &Path, abs_repo: &Path) -> String {
    abs_file
        .strip_prefix(abs_repo)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| abs_file.to_string_lossy().into_owned())
}

/// Match a glob pattern against a repository-relative file path.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(path))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_value: JSON ────────────────────────────────────────────────

    #[test]
    fn test_json_get_top_level() {
        let content = r#"{"db": {"password": "secret", "host": "localhost"}, "port": 5432}"#;
        assert_eq!(extract_value(content, "json", "port").unwrap(), "5432");
    }

    #[test]
    fn test_json_get_nested() {
        let content = r#"{"db": {"password": "secret"}}"#;
        assert_eq!(
            extract_value(content, "json", "db.password").unwrap(),
            "secret"
        );
    }

    #[test]
    fn test_json_get_missing() {
        let content = r#"{"a": "1"}"#;
        assert!(matches!(
            extract_value(content, "json", "b"),
            Err(GitvaultError::NotFound(_))
        ));
    }

    // ── extract_value: YAML ────────────────────────────────────────────────

    #[test]
    fn test_yaml_get_nested() {
        let content = "server:\n  tls:\n    cert: mycert\n";
        assert_eq!(
            extract_value(content, "yaml", "server.tls.cert").unwrap(),
            "mycert"
        );
    }

    #[test]
    fn test_yaml_get_missing() {
        let content = "a: 1\n";
        assert!(matches!(
            extract_value(content, "yaml", "b"),
            Err(GitvaultError::NotFound(_))
        ));
    }

    // ── extract_value: TOML ────────────────────────────────────────────────

    #[test]
    fn test_toml_get_nested() {
        let content = "[database]\npassword = \"dbpass\"\n";
        assert_eq!(
            extract_value(content, "toml", "database.password").unwrap(),
            "dbpass"
        );
    }

    // ── extract_value: env ─────────────────────────────────────────────────

    #[test]
    fn test_env_get_simple() {
        let content = "# comment\nAPI_KEY=myapikey\nOTHER=val\n";
        assert_eq!(
            extract_value(content, "env", "API_KEY").unwrap(),
            "myapikey"
        );
    }

    #[test]
    fn test_env_get_quoted() {
        let content = "SECRET=\"quoted value\"\n";
        assert_eq!(
            extract_value(content, "env", "SECRET").unwrap(),
            "quoted value"
        );
    }

    #[test]
    fn test_env_get_dot_path_rejected() {
        let content = "FOO=bar\n";
        assert!(matches!(
            extract_value(content, "env", "FOO.BAR"),
            Err(GitvaultError::Usage(_))
        ));
    }

    // ── update_value: JSON ─────────────────────────────────────────────────

    #[test]
    fn test_json_set_top_level() {
        let content = r#"{"name": "old"}"#;
        let updated = update_value(content, "json", "name", "new").unwrap();
        let v: serde_json::Value = serde_json::from_str(&updated).unwrap();
        assert_eq!(v["name"], "new");
    }

    #[test]
    fn test_json_set_nested() {
        let content = r#"{"db": {"password": "old"}}"#;
        let updated = update_value(content, "json", "db.password", "newsecret").unwrap();
        let v: serde_json::Value = serde_json::from_str(&updated).unwrap();
        assert_eq!(v["db"]["password"], "newsecret");
    }

    #[test]
    fn test_json_set_upsert_top_level() {
        let content = r#"{"a": "1"}"#;
        let updated = update_value(content, "json", "newkey", "newval").unwrap();
        let v: serde_json::Value = serde_json::from_str(&updated).unwrap();
        assert_eq!(v["newkey"], "newval");
    }

    #[test]
    fn test_json_set_nested_missing_parent_fails() {
        let content = r#"{"a": "1"}"#;
        let result = update_value(content, "json", "missing.key", "val");
        assert!(matches!(result, Err(GitvaultError::Usage(_))));
    }

    // ── update_value: YAML ─────────────────────────────────────────────────

    #[test]
    fn test_yaml_set_nested() {
        let content = "db:\n  password: old\n";
        let updated = update_value(content, "yaml", "db.password", "newpass").unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&updated).unwrap();
        assert_eq!(v["db"]["password"].as_str().unwrap(), "newpass");
    }

    // ── update_value: TOML ─────────────────────────────────────────────────

    #[test]
    fn test_toml_set_nested_preserves_comment() {
        let content = "# DB config\n[database]\n# the password\npassword = \"old\"\n";
        let updated = update_value(content, "toml", "database.password", "newsecret").unwrap();
        // toml_edit must have preserved the comment.
        assert!(updated.contains("# DB config"), "comment lost: {updated}");
        assert!(
            updated.contains("# the password"),
            "inline comment lost: {updated}"
        );
        assert!(
            updated.contains("newsecret"),
            "value not updated: {updated}"
        );
    }

    #[test]
    fn test_toml_set_top_level_upsert() {
        let content = "[section]\nkey = \"val\"\n";
        let updated = update_value(content, "toml", "newkey", "nv").unwrap();
        assert!(updated.contains("newkey = \"nv\""), "not found: {updated}");
    }

    // ── update_value: env ──────────────────────────────────────────────────

    #[test]
    fn test_env_set_updates_existing() {
        let content = "# comment\nAPI_KEY=old\nOTHER=val\n";
        let updated = update_value(content, "env", "API_KEY", "newkey").unwrap();
        assert!(updated.contains("API_KEY=newkey"));
        assert!(updated.contains("OTHER=val"));
        assert!(updated.contains("# comment"));
    }

    #[test]
    fn test_env_set_upserts_missing() {
        let content = "FOO=bar\n";
        let updated = update_value(content, "env", "NEW_VAR", "nv").unwrap();
        assert!(updated.contains("NEW_VAR=nv"));
        assert!(updated.contains("FOO=bar"));
    }

    #[test]
    fn test_env_set_preserves_trailing_newline() {
        let content = "A=1\n";
        let updated = update_value(content, "env", "A", "2").unwrap();
        assert!(updated.ends_with('\n'));
    }

    #[test]
    fn test_env_set_dot_path_rejected() {
        let content = "A=1\n";
        let result = update_value(content, "env", "A.B", "2");
        assert!(matches!(result, Err(GitvaultError::Usage(_))));
    }

    // ── stem_extension ─────────────────────────────────────────────────────

    #[test]
    fn test_stem_extension_json() {
        let p = Path::new("/store/secrets.json.age");
        assert_eq!(stem_extension(p).unwrap(), "json");
    }

    #[test]
    fn test_stem_extension_yaml() {
        let p = Path::new("config.yaml.age");
        assert_eq!(stem_extension(p).unwrap(), "yaml");
    }
}
