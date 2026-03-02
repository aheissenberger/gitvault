use crate::error::GitvaultError;
use crate::{crypto, fhsm, keyring_store, repo};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;
use zeroize::Zeroizing;

pub fn extract_identity_key(content: &str) -> Option<String> {
    static IDENTITY_LINE_RE: OnceLock<Regex> = OnceLock::new();
    let identity_line_re = IDENTITY_LINE_RE.get_or_init(|| {
        Regex::new(r"(?m)^\s*(AGE-SECRET-KEY-[A-Z0-9]+)\s*(?:#.*)?$")
            .expect("identity regex must compile")
    });

    identity_line_re
        .captures(content)
        .map(|captures| captures[1].to_string())
}

pub fn load_identity_source(
    source: &str,
    source_name: &str,
) -> Result<Zeroizing<String>, GitvaultError> {
    let value = source.trim();

    if value.starts_with("AGE-SECRET-KEY-") {
        return Ok(Zeroizing::new(value.to_string()));
    }

    let file_content = std::fs::read_to_string(value).map_err(|e| {
        GitvaultError::Usage(format!(
            "{source_name} must be an identity file path or AGE-SECRET-KEY value: {e}"
        ))
    })?;

    extract_identity_key(&file_content)
        .map(Zeroizing::new)
        .ok_or_else(|| {
            GitvaultError::Usage(format!(
                "{source_name} file does not contain a valid AGE-SECRET-KEY line"
            ))
        })
}

/// Load identity key string from file path or GITVAULT_IDENTITY env var
pub fn load_identity(path: Option<String>) -> Result<Zeroizing<String>, GitvaultError> {
    load_identity_with(path, keyring_store::keyring_get)
}

pub fn load_identity_with<F>(
    path: Option<String>,
    keyring_get_fn: F,
) -> Result<Zeroizing<String>, GitvaultError>
where
    F: Fn() -> Result<Zeroizing<String>, GitvaultError>,
{
    if let Some(p) = path {
        return load_identity_source(&p, "--identity");
    }
    if let Ok(key) = std::env::var("GITVAULT_IDENTITY") {
        return load_identity_source(&key, "GITVAULT_IDENTITY");
    }
    // REQ-39: load from OS keyring if GITVAULT_KEYRING=1
    if std::env::var("GITVAULT_KEYRING").as_deref() == Ok("1") {
        return keyring_get_fn();
    }
    Err(GitvaultError::Usage(
        "No identity provided. Use --identity <file>, set GITVAULT_IDENTITY, or use GITVAULT_KEYRING=1".to_string(),
    ))
}

/// Map an [`fhsm::IdentitySource`] to a raw identity key string.
///
/// The `Unresolved` variant (emitted by the FHSM when no path was supplied)
/// triggers the standard env-var / keyring fallback via [`load_identity`].
pub fn load_identity_from_source(
    source: &fhsm::IdentitySource,
) -> Result<Zeroizing<String>, GitvaultError> {
    match source {
        fhsm::IdentitySource::FilePath(p) => load_identity_source(p, "--identity"),
        fhsm::IdentitySource::EnvVar(v) => load_identity_source(v, "GITVAULT_IDENTITY"),
        fhsm::IdentitySource::Keyring => keyring_store::keyring_get(),
        fhsm::IdentitySource::Inline(s) if !s.is_empty() => Ok(Zeroizing::new(s.clone())),
        fhsm::IdentitySource::Inline(_) => load_identity(None),
        // Unresolved: executor must run the full priority chain at runtime
        fhsm::IdentitySource::Unresolved => load_identity(None),
    }
}

pub fn resolve_recipient_keys(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::{global_test_lock, setup_identity_file, with_env_var};
    use crate::error::GitvaultError;
    use crate::fhsm;
    use age::secrecy::ExposeSecret;
    use age::x25519;
    use tempfile::NamedTempFile;

    // ─── load_identity_from_source ────────────────────────────────────────────

    #[test]
    fn load_identity_from_source_file_path_valid() {
        let (tmp_file, _) = setup_identity_file();
        let source = fhsm::IdentitySource::FilePath(tmp_file.path().to_string_lossy().to_string());
        assert!(load_identity_from_source(&source).is_ok());
    }

    #[test]
    fn load_identity_from_source_file_path_nonexistent_errors() {
        let source =
            fhsm::IdentitySource::FilePath("/nonexistent/path/to/identity.age".to_string());
        assert!(load_identity_from_source(&source).is_err());
    }

    #[test]
    fn load_identity_from_source_env_var_with_file_path() {
        // EnvVar(v) passes `v` as the value to load_identity_source, so a file path works.
        let (tmp_file, _) = setup_identity_file();
        let source = fhsm::IdentitySource::EnvVar(tmp_file.path().to_string_lossy().to_string());
        assert!(load_identity_from_source(&source).is_ok());
    }

    #[test]
    fn load_identity_from_source_inline_nonempty_returns_ok() {
        let (_, identity) = setup_identity_file();
        let key_str = identity.to_string().expose_secret().to_string();
        let source = fhsm::IdentitySource::Inline(key_str);
        assert!(load_identity_from_source(&source).is_ok());
    }

    #[test]
    fn load_identity_from_source_inline_empty_falls_back_to_env_var() {
        let _lock = global_test_lock().lock().unwrap();
        let (tmp_file, _) = setup_identity_file();
        let source = fhsm::IdentitySource::Inline(String::new());
        // Provide GITVAULT_IDENTITY so load_identity(None) can resolve it.
        let result = with_env_var(
            "GITVAULT_IDENTITY",
            Some(tmp_file.path().to_string_lossy().as_ref()),
            || {
                with_env_var("GITVAULT_KEYRING", None, || {
                    load_identity_from_source(&source)
                })
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn load_identity_from_source_keyring_without_setup_errors() {
        // Install a fresh mock backend with an empty store so the test is
        // deterministic: no previously stored key can leak from another test
        // that already wrote to the shared mock store (e.g. keyring_store tests
        // install the mock globally, which persists across test threads).
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let source = fhsm::IdentitySource::Keyring;
        // Fresh mock store has no entry for gitvault/age-identity → must error.
        assert!(load_identity_from_source(&source).is_err());
    }

    // ─── load_identity_with ───────────────────────────────────────────────────

    #[test]
    fn test_load_identity_with_uses_keyring_when_enabled() {
        let _lock = global_test_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_IDENTITY");
            std::env::set_var("GITVAULT_KEYRING", "1");
        }

        let value = load_identity_with(None, || {
            Ok(Zeroizing::new("AGE-SECRET-KEY-TEST".to_string()))
        })
        .unwrap();

        unsafe {
            std::env::remove_var("GITVAULT_KEYRING");
        }
        assert_eq!(*value, "AGE-SECRET-KEY-TEST");
    }

    #[test]
    fn test_load_identity_with_maps_keyring_error() {
        let _lock = global_test_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_IDENTITY");
            std::env::set_var("GITVAULT_KEYRING", "1");
        }

        let err = load_identity_with(None, || Err(GitvaultError::Keyring("no key".to_string())))
            .unwrap_err();

        unsafe {
            std::env::remove_var("GITVAULT_KEYRING");
        }
        assert!(matches!(err, GitvaultError::Keyring(_)));
    }

    // ─── load_identity_source ─────────────────────────────────────────────────

    #[test]
    fn test_load_identity_source_accepts_key_file_with_newline() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let identity_file = NamedTempFile::new().expect("temp file should be created");

        std::fs::write(
            identity_file.path(),
            format!("{}\n", identity_secret.expose_secret()),
        )
        .expect("identity should be written to temp file");

        let loaded =
            load_identity_source(&identity_file.path().to_string_lossy(), "GITVAULT_IDENTITY")
                .expect("identity file with newline should parse");

        assert_eq!(loaded.as_str(), identity_secret.expose_secret().as_str());
    }

    #[test]
    fn test_load_identity_source_accepts_age_keygen_style_file() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let identity_file = NamedTempFile::new().expect("temp file should be created");

        let key_file_content = format!(
            "# created: 2026-03-01T00:00:00Z\n# public key: {}\n{}\n",
            identity.to_public(),
            identity_secret.expose_secret()
        );
        std::fs::write(identity_file.path(), key_file_content)
            .expect("identity should be written to temp file");

        let loaded =
            load_identity_source(&identity_file.path().to_string_lossy(), "GITVAULT_IDENTITY")
                .expect("age-keygen style identity file should parse");

        assert_eq!(loaded.as_str(), identity_secret.expose_secret().as_str());
    }

    #[test]
    fn test_load_identity_source_accepts_inline_comment_after_key() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let identity_file = NamedTempFile::new().expect("temp file should be created");

        std::fs::write(
            identity_file.path(),
            format!("{} # local-dev\n", identity_secret.expose_secret()),
        )
        .expect("identity should be written to temp file");

        let loaded =
            load_identity_source(&identity_file.path().to_string_lossy(), "GITVAULT_IDENTITY")
                .expect("identity file with inline comment should parse");

        assert_eq!(loaded.as_str(), identity_secret.expose_secret().as_str());
    }

    #[test]
    fn test_load_identity_source_file_without_age_key_errors() {
        let tmp = NamedTempFile::new().expect("temp file should be created");
        std::fs::write(tmp.path(), "not-an-age-key\nsome: yaml: content\n")
            .expect("write should succeed");
        let result = load_identity_source(tmp.path().to_str().unwrap(), "test-source");
        assert!(matches!(result, Err(GitvaultError::Usage(_))));
    }
}
