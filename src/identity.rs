use crate::error::GitvaultError;
use crate::{crypto, fhsm, keyring_store, repo};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

pub(crate) fn extract_identity_key(content: &str) -> Option<String> {
    static IDENTITY_LINE_RE: OnceLock<Regex> = OnceLock::new();
    let identity_line_re = IDENTITY_LINE_RE.get_or_init(|| {
        Regex::new(r"(?m)^\s*(AGE-SECRET-KEY-[A-Z0-9]+)\s*(?:#.*)?$")
            .expect("identity regex must compile")
    });

    identity_line_re
        .captures(content)
        .map(|captures| captures[1].to_string())
}

pub(crate) fn load_identity_source(source: &str, source_name: &str) -> Result<String, GitvaultError> {
    let value = source.trim();

    if value.starts_with("AGE-SECRET-KEY-") {
        return Ok(value.to_string());
    }

    let file_content = std::fs::read_to_string(value).map_err(|e| {
        GitvaultError::Usage(format!(
            "{source_name} must be an identity file path or AGE-SECRET-KEY value: {e}"
        ))
    })?;

    extract_identity_key(&file_content).ok_or_else(|| {
        GitvaultError::Usage(format!(
            "{source_name} file does not contain a valid AGE-SECRET-KEY line"
        ))
    })
}

/// Load identity key string from file path or GITVAULT_IDENTITY env var
pub(crate) fn load_identity(path: Option<String>) -> Result<String, GitvaultError> {
    load_identity_with(path, keyring_store::keyring_get)
}

pub(crate) fn load_identity_with<F>(
    path: Option<String>,
    keyring_get_fn: F,
) -> Result<String, GitvaultError>
where
    F: Fn() -> Result<String, String>,
{
    if let Some(p) = path {
        return load_identity_source(&p, "--identity");
    }
    if let Ok(key) = std::env::var("GITVAULT_IDENTITY") {
        return load_identity_source(&key, "GITVAULT_IDENTITY");
    }
    // REQ-39: load from OS keyring if GITVAULT_KEYRING=1
    if std::env::var("GITVAULT_KEYRING").as_deref() == Ok("1") {
        return keyring_get_fn().map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")));
    }
    Err(GitvaultError::Usage(
        "No identity provided. Use --identity <file>, set GITVAULT_IDENTITY, or use GITVAULT_KEYRING=1".to_string(),
    ))
}

/// Map an [`fhsm::IdentitySource`] to a raw identity key string.
///
/// The `Inline("")` sentinel (emitted by the FHSM when no path was supplied)
/// triggers the standard env-var / keyring fallback via [`load_identity`].
pub(crate) fn load_identity_from_source(
    source: &fhsm::IdentitySource,
) -> Result<String, GitvaultError> {
    match source {
        fhsm::IdentitySource::FilePath(p) => load_identity_source(p, "--identity"),
        fhsm::IdentitySource::EnvVar(v) => load_identity_source(v, "GITVAULT_IDENTITY"),
        fhsm::IdentitySource::Keyring => keyring_store::keyring_get()
            .map_err(|e| GitvaultError::Other(format!("Keyring error: {e}"))),
        fhsm::IdentitySource::Inline(s) if !s.is_empty() => Ok(s.clone()),
        // Empty Inline is the FHSM sentinel meaning "executor must resolve from env vars".
        fhsm::IdentitySource::Inline(_) => load_identity(None),
    }
}

pub(crate) fn resolve_recipient_keys(
    repo_root: &Path,
    recipient_keys: Vec<String>,
) -> Result<Vec<String>, GitvaultError> {
    if !recipient_keys.is_empty() {
        return Ok(recipient_keys);
    }

    // Try persistent recipients file (REQ-36)
    let from_file = repo::read_recipients(repo_root)?;
    if !from_file.is_empty() {
        return Ok(from_file);
    }

    // Fall back to local identity public key
    let identity_str = load_identity(None)?;
    let identity = crypto::parse_identity(&identity_str)?;
    Ok(vec![identity.to_public().to_string()])
}
