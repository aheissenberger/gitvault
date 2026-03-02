use crate::error::GitvaultError;
use crate::{crypto, fhsm, keyring_store, repo};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;
use zeroize::Zeroizing;

// ─── IdentitySourceState ──────────────────────────────────────────────────────

/// Reports the resolution outcome of a single identity source in the chain.
///
/// Used by `cmd_check` to surface per-source diagnostics (REQ-50).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IdentitySourceState {
    /// The source resolved successfully and provided a usable identity.
    Resolved { source: String },
    /// The source was tried but the identity was not available (e.g. keyring empty,
    /// SSH-agent not running, env var not set).  The chain continues.
    SourceNotAvailable { source: String, reason: String },
    /// Multiple candidates exist and no selector was provided to disambiguate.
    /// The chain fails closed on this state.
    Ambiguous { source: String, count: usize },
}

// ─── SSH-agent support ────────────────────────────────────────────────────────

/// A key entry reported by the SSH agent.
#[derive(Debug, Clone)]
pub struct SshAgentKey {
    /// SHA-256 fingerprint as reported by `ssh-add -l -E sha256` (e.g. `SHA256:abc…`).
    pub fingerprint: String,
    /// Human-readable comment / label attached to the key in the agent.
    pub comment: String,
}

/// Internal error type for SSH-agent operations.
#[derive(Debug)]
pub enum SshAgentError {
    /// The agent is not reachable or has no usable keys.
    NotAvailable(String),
    /// Multiple usable keys are present and no selector was given.
    Ambiguous(usize),
}

impl std::fmt::Display for SshAgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable(msg) => write!(f, "SSH agent not available: {msg}"),
            Self::Ambiguous(n) => write!(f, "SSH agent has {n} ambiguous keys"),
        }
    }
}

/// List ED25519 keys currently loaded in the SSH agent using `ssh-add -l -E sha256`.
///
/// Returns the list of matching keys, or an [`SshAgentError`] if the agent is
/// unavailable or no usable keys are found.
///
/// # Errors
///
/// Returns [`SshAgentError::NotAvailable`] when `ssh-add` cannot be executed or the
/// agent has no identities.
pub fn list_ssh_agent_keys() -> Result<Vec<SshAgentKey>, SshAgentError> {
    let output = std::process::Command::new("ssh-add")
        .args(["-l", "-E", "sha256"])
        .output()
        .map_err(|e| SshAgentError::NotAvailable(format!("ssh-add not available: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // "The agent has no identities." → empty list
    if stdout.contains("no identities") || stdout.trim().is_empty() {
        return Ok(vec![]);
    }

    // Parse lines: "256 SHA256:xxx comment (ED25519)"
    let keys: Vec<SshAgentKey> = stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, ' ');
            let _bits = parts.next()?;
            let fingerprint = parts.next()?.to_string();
            let rest = parts.next()?;
            // Filter for ED25519 keys only (age-ssh compatible)
            if !rest.ends_with("(ED25519)") && !rest.ends_with("(ED25519-SK)") {
                return None;
            }
            // Extract comment (everything before the final " (TYPE)")
            let comment = rest
                .rfind(" (")
                .map_or_else(|| rest.to_string(), |i| rest[..i].to_string());
            Some(SshAgentKey {
                fingerprint,
                comment,
            })
        })
        .collect();

    Ok(keys)
}

/// Find the SSH private key file on disk that corresponds to `key`.
///
/// Checks common locations (`~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`) and verifies
/// the fingerprint by running `ssh-keygen -l -E sha256 -f <path>`.
fn find_ssh_key_file(key: &SshAgentKey) -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let ssh_dir = std::path::Path::new(&home).join(".ssh");

    let candidates = ["id_ed25519", "id_ecdsa", "identity"];

    for name in &candidates {
        let path = ssh_dir.join(name);
        if !path.exists() {
            continue;
        }
        // Verify fingerprint by querying the public key
        if let Ok(fp_output) = std::process::Command::new("ssh-keygen")
            .args(["-l", "-E", "sha256", "-f"])
            .arg(&path)
            .output()
        {
            let fp_str = String::from_utf8_lossy(&fp_output.stdout);
            if fp_str.contains(&key.fingerprint) {
                return Some(path);
            }
        }
    }

    // Fallback: try comment as a filename within ~/.ssh/
    let by_comment = ssh_dir.join(&key.comment);
    if by_comment.exists() {
        return Some(by_comment);
    }

    None
}

/// Load an SSH identity from the agent, resolving to the corresponding private key
/// file content.
///
/// Applies `selector` (if provided) to filter agent keys by fingerprint or comment.
/// Returns the raw OpenSSH private key file content as a [`Zeroizing<String>`].
///
/// # Errors
///
/// - [`SshAgentError::NotAvailable`] when the agent is unreachable, has no usable
///   ED25519 keys, or no private key file is found on disk.
/// - [`SshAgentError::Ambiguous`] when multiple keys match and no selector is given.
fn load_ssh_agent_identity(selector: Option<&str>) -> Result<Zeroizing<String>, SshAgentError> {
    let mut keys = list_ssh_agent_keys()?;

    if keys.is_empty() {
        return Err(SshAgentError::NotAvailable(
            "SSH agent has no usable ED25519 identities".to_string(),
        ));
    }

    // Apply selector: filter by fingerprint substring or comment substring
    if let Some(sel) = selector {
        keys.retain(|k| k.fingerprint.contains(sel) || k.comment.contains(sel));
    }

    match keys.len() {
        0 => Err(SshAgentError::NotAvailable(
            "no SSH-agent key matches the provided selector".to_string(),
        )),
        1 => {
            let key = &keys[0];
            let path = find_ssh_key_file(key).ok_or_else(|| {
                SshAgentError::NotAvailable(format!(
                    "SSH key {} has no corresponding private key file in ~/.ssh/",
                    key.fingerprint
                ))
            })?;
            let content = std::fs::read_to_string(&path).map_err(|e| {
                SshAgentError::NotAvailable(format!(
                    "failed to read SSH private key {}: {e}",
                    path.display()
                ))
            })?;
            Ok(Zeroizing::new(content))
        }
        count => Err(SshAgentError::Ambiguous(count)),
    }
}

/// Probe each source in the identity chain and return an [`IdentitySourceState`] for each.
///
/// Used by `cmd_check` to report per-source resolution status without loading the key.
pub fn probe_identity_sources(
    path: Option<&str>,
    selector: Option<&str>,
) -> Vec<IdentitySourceState> {
    let mut states: Vec<IdentitySourceState> = Vec::new();

    // Source 1: Explicit (--identity / GITVAULT_IDENTITY)
    if let Some(p) = path {
        match load_identity_source(p, "--identity") {
            Ok(_) => states.push(IdentitySourceState::Resolved {
                source: "--identity".to_string(),
            }),
            Err(e) => states.push(IdentitySourceState::SourceNotAvailable {
                source: "--identity".to_string(),
                reason: e.to_string(),
            }),
        }
    } else if let Ok(val) = std::env::var("GITVAULT_IDENTITY") {
        match load_identity_source(&val, "GITVAULT_IDENTITY") {
            Ok(_) => states.push(IdentitySourceState::Resolved {
                source: "GITVAULT_IDENTITY".to_string(),
            }),
            Err(e) => states.push(IdentitySourceState::SourceNotAvailable {
                source: "GITVAULT_IDENTITY".to_string(),
                reason: e.to_string(),
            }),
        }
    } else {
        states.push(IdentitySourceState::SourceNotAvailable {
            source: "--identity/GITVAULT_IDENTITY".to_string(),
            reason: "not provided".to_string(),
        });
    }

    // Source 2: OS keyring
    match keyring_store::keyring_get() {
        Ok(_) => states.push(IdentitySourceState::Resolved {
            source: "keyring".to_string(),
        }),
        Err(e) => states.push(IdentitySourceState::SourceNotAvailable {
            source: "keyring".to_string(),
            reason: e.to_string(),
        }),
    }

    // Source 3: SSH-agent (probed if enabled)
    let ssh_enabled = std::env::var("GITVAULT_SSH_AGENT").as_deref() == Ok("1")
        || std::env::var("SSH_AUTH_SOCK").is_ok();

    if ssh_enabled {
        match list_ssh_agent_keys() {
            Err(SshAgentError::NotAvailable(reason)) => {
                states.push(IdentitySourceState::SourceNotAvailable {
                    source: "ssh-agent".to_string(),
                    reason,
                });
            }
            Err(SshAgentError::Ambiguous(count)) => {
                states.push(IdentitySourceState::Ambiguous {
                    source: "ssh-agent".to_string(),
                    count,
                });
            }
            Ok(mut keys) => {
                if keys.is_empty() {
                    states.push(IdentitySourceState::SourceNotAvailable {
                        source: "ssh-agent".to_string(),
                        reason: "no usable ED25519 keys in agent".to_string(),
                    });
                } else {
                    if let Some(sel) = selector {
                        keys.retain(|k| k.fingerprint.contains(sel) || k.comment.contains(sel));
                    }
                    match keys.len() {
                        0 => states.push(IdentitySourceState::SourceNotAvailable {
                            source: "ssh-agent".to_string(),
                            reason: "no agent key matches selector".to_string(),
                        }),
                        1 => states.push(IdentitySourceState::Resolved {
                            source: "ssh-agent".to_string(),
                        }),
                        count => states.push(IdentitySourceState::Ambiguous {
                            source: "ssh-agent".to_string(),
                            count,
                        }),
                    }
                }
            }
        }
    } else {
        states.push(IdentitySourceState::SourceNotAvailable {
            source: "ssh-agent".to_string(),
            reason: "SSH_AUTH_SOCK not set and GITVAULT_SSH_AGENT != 1".to_string(),
        });
    }

    states
}

// ─── extract_identity_key ─────────────────────────────────────────────────────

/// Extract the first `AGE-SECRET-KEY-…` line from a text blob.
///
/// Returns `None` if no valid key line is found.
///
/// # Panics
///
/// Never panics in practice; the identity regex literal always compiles.
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

// ─── load_identity_source ─────────────────────────────────────────────────────

/// Load an identity key from an inline `AGE-SECRET-KEY-…` value or a file path.
///
/// If `source` starts with `AGE-SECRET-KEY-`, it is used directly. Otherwise,
/// `source` is treated as a file path and the first key line is extracted.
/// If the file is an OpenSSH private key (SSH), the raw file content is returned
/// for use with [`crypto::parse_identity_any`].
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if `source` is a file path that cannot be read
/// or does not contain a valid identity.
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

    // If the file is an OpenSSH private key, return the raw content for SSH identity parsing
    let trimmed_content = file_content.trim_start();
    if trimmed_content.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        || trimmed_content.starts_with("-----BEGIN RSA PRIVATE KEY-----")
        || trimmed_content.starts_with("-----BEGIN EC PRIVATE KEY-----")
    {
        return Ok(Zeroizing::new(file_content));
    }

    extract_identity_key(&file_content)
        .map(Zeroizing::new)
        .ok_or_else(|| {
            GitvaultError::Usage(format!(
                "{source_name} file does not contain a valid AGE-SECRET-KEY line"
            ))
        })
}

// ─── load_identity ────────────────────────────────────────────────────────────

/// Load identity key string from file path or env vars, using the full resolution chain.
///
/// # Errors
///
/// Returns [`GitvaultError`] if no identity source is configured or the
/// identity cannot be loaded from the specified source.
pub fn load_identity(path: Option<String>) -> Result<Zeroizing<String>, GitvaultError> {
    load_identity_with(path, keyring_store::keyring_get, None)
}

/// Like [`load_identity`] but with an explicit key selector for SSH-agent disambiguation.
///
/// # Errors
///
/// Returns [`GitvaultError`] if no identity source resolves or an ambiguous
/// SSH-agent state is detected without a sufficient selector.
pub fn load_identity_with_selector(
    path: Option<String>,
    selector: Option<&str>,
) -> Result<Zeroizing<String>, GitvaultError> {
    load_identity_with(path, keyring_store::keyring_get, selector)
}

/// Dependency-injected variant of [`load_identity`].
///
/// Resolves identity using the priority chain below, calling `keyring_get_fn`
/// instead of the real OS keyring.
///
/// Priority chain:
/// 1. `path` argument (`--identity` flag value).
/// 2. `GITVAULT_IDENTITY` environment variable.
/// 3. OS keyring (always tried; treated as source-not-available on error).
/// 4. SSH-agent (tried when `GITVAULT_SSH_AGENT=1` or `SSH_AUTH_SOCK` is set).
/// 5. Fail closed if no source resolved.
///
/// # Errors
///
/// - [`GitvaultError::Usage`] when no source resolves (fail-closed) or the
///   SSH-agent exposes multiple keys without a selector.
/// - Propagates errors from explicit sources.
pub fn load_identity_with<F>(
    path: Option<String>,
    keyring_get_fn: F,
    selector: Option<&str>,
) -> Result<Zeroizing<String>, GitvaultError>
where
    F: Fn() -> Result<Zeroizing<String>, GitvaultError>,
{
    // 1. Explicit: --identity flag
    if let Some(p) = path {
        return load_identity_source(&p, "--identity");
    }
    // 2. Explicit: GITVAULT_IDENTITY env var
    if let Ok(key) = std::env::var("GITVAULT_IDENTITY") {
        return load_identity_source(&key, "GITVAULT_IDENTITY");
    }

    // 3. OS keyring (always tried; source-not-available on any error)
    if let Ok(key) = keyring_get_fn() {
        return Ok(key);
    }

    // 4. SSH-agent (optional: requires GITVAULT_SSH_AGENT=1 or SSH_AUTH_SOCK set)
    let ssh_enabled = std::env::var("GITVAULT_SSH_AGENT").as_deref() == Ok("1")
        || std::env::var("SSH_AUTH_SOCK").is_ok();

    if ssh_enabled {
        match load_ssh_agent_identity(selector) {
            Ok(key) => return Ok(key),
            Err(SshAgentError::Ambiguous(count)) => {
                return Err(GitvaultError::Usage(format!(
                    "SSH-agent has {count} usable ED25519 key(s) but no selector was provided; \
                     use --identity-selector or GITVAULT_IDENTITY_SELECTOR to disambiguate"
                )));
            }
            Err(SshAgentError::NotAvailable(_)) => {
                // source-not-available — continue to fail-closed
            }
        }
    }

    // 5. Fail closed
    Err(GitvaultError::Usage(
        "No identity resolved. Use --identity <file>, GITVAULT_IDENTITY, \
         OS keyring, or SSH-agent (GITVAULT_SSH_AGENT=1 / SSH_AUTH_SOCK)"
            .to_string(),
    ))
}

// ─── load_identity_from_source ────────────────────────────────────────────────

/// Map an [`fhsm::IdentitySource`] to a raw identity key string.
///
/// The `Unresolved` variant triggers the standard env-var / keyring / SSH-agent
/// fallback via [`load_identity`].
///
/// # Errors
///
/// Returns [`GitvaultError`] if the identity cannot be loaded from the resolved source.
pub fn load_identity_from_source(
    source: &fhsm::IdentitySource,
) -> Result<Zeroizing<String>, GitvaultError> {
    load_identity_from_source_with_selector(source, None)
}

/// Like [`load_identity_from_source`] but with an explicit selector for SSH-agent
/// disambiguation (REQ-39/46).
///
/// # Errors
///
/// Returns [`GitvaultError`] if the identity cannot be loaded from the resolved source.
pub fn load_identity_from_source_with_selector(
    source: &fhsm::IdentitySource,
    selector: Option<&str>,
) -> Result<Zeroizing<String>, GitvaultError> {
    match source {
        fhsm::IdentitySource::FilePath(p) => load_identity_source(p, "--identity"),
        fhsm::IdentitySource::EnvVar(v) => load_identity_source(v, "GITVAULT_IDENTITY"),
        fhsm::IdentitySource::Keyring => keyring_store::keyring_get(),
        fhsm::IdentitySource::Inline(s) if !s.is_empty() => Ok(Zeroizing::new(s.clone())),
        // Unresolved: executor must run the full priority chain at runtime
        fhsm::IdentitySource::Inline(_) | fhsm::IdentitySource::Unresolved => {
            load_identity_with_selector(None, selector)
        }
    }
}

// ─── resolve_recipient_keys ───────────────────────────────────────────────────

/// Resolve the final recipient key list, falling back to the recipients file and
/// then the caller's own identity public key.
///
/// # Errors
///
/// Returns [`GitvaultError`] if reading the recipients file fails or the identity
/// cannot be loaded to derive the default recipient public key.
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

    // Fall back to local identity public key (X25519 path)
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
        let key_str = identity.to_string().expose_secret().clone();
        let source = fhsm::IdentitySource::Inline(key_str);
        assert!(load_identity_from_source(&source).is_ok());
    }

    #[test]
    fn load_identity_from_source_inline_empty_falls_back_to_env_var() {
        let _lock = global_test_lock().lock().unwrap();
        let (tmp_file, _) = setup_identity_file();
        let source = fhsm::IdentitySource::Inline(String::new());
        // Provide GITVAULT_IDENTITY so the full priority chain can resolve it.
        let result = with_env_var(
            "GITVAULT_IDENTITY",
            Some(tmp_file.path().to_string_lossy().as_ref()),
            || with_env_var("SSH_AUTH_SOCK", None, || load_identity_from_source(&source)),
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
            std::env::remove_var("SSH_AUTH_SOCK");
            std::env::remove_var("GITVAULT_SSH_AGENT");
        }

        // Under the new chain, keyring is always tried (GITVAULT_KEYRING=1 no longer needed).
        let value = load_identity_with(
            None,
            || Ok(Zeroizing::new("AGE-SECRET-KEY-TEST".to_string())),
            None,
        )
        .unwrap();

        assert_eq!(*value, "AGE-SECRET-KEY-TEST");
    }

    #[test]
    fn test_load_identity_with_keyring_error_treats_as_source_not_available() {
        let _lock = global_test_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_IDENTITY");
            std::env::remove_var("SSH_AUTH_SOCK");
            std::env::remove_var("GITVAULT_SSH_AGENT");
        }

        // Under the new chain, a keyring error is treated as source-not-available and
        // the chain continues.  With no SSH-agent configured, the result is fail-closed
        // (Usage error), NOT a Keyring error.
        let err = load_identity_with(
            None,
            || Err(GitvaultError::Keyring("no key".to_string())),
            None,
        )
        .unwrap_err();

        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "keyring error should fall through to fail-closed Usage error, got: {err:?}"
        );
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
