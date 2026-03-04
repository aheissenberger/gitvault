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
    Resolved {
        /// Human-readable name of the identity source (e.g. `"keyring"`).
        source: String,
    },
    /// The source was tried but the identity was not available (e.g. keyring empty,
    /// SSH-agent not running, env var not set).  The chain continues.
    SourceNotAvailable {
        /// Human-readable name of the identity source.
        source: String,
        /// Short explanation of why the source was unavailable.
        reason: String,
    },
    /// Multiple candidates exist and no selector was provided to disambiguate.
    /// The chain fails closed on this state.
    Ambiguous {
        /// Human-readable name of the identity source.
        source: String,
        /// Number of ambiguous candidates that were found.
        count: usize,
    },
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
/// Search order:
/// 1. Standard names (`id_ed25519`, `id_ecdsa`, `identity`) in `~/.ssh/`.
/// 2. Agent key comment used as a filename within `~/.ssh/`.
/// 3. All private-key-like files in `~/.ssh/` (no `.pub`, not config/known_hosts/
///    authorized_keys, not a directory), verified by fingerprint.
///
/// Fingerprint verification uses `ssh-keygen -l -E sha256 -f <path>`.
fn find_ssh_key_file(key: &SshAgentKey) -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let ssh_dir = std::path::Path::new(&home).join(".ssh");

    // Returns true if the file's fingerprint matches the agent key.
    let matches_fingerprint = |path: &std::path::Path| -> bool {
        std::process::Command::new("ssh-keygen")
            .args(["-l", "-E", "sha256", "-f"])
            .arg(path)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&key.fingerprint))
            .unwrap_or(false)
    };

    // Priority 1: standard names.
    let standard = ["id_ed25519", "id_ecdsa", "identity"];
    for name in &standard {
        let path = ssh_dir.join(name);
        if path.exists() && matches_fingerprint(&path) {
            return Some(path);
        }
    }

    // Priority 2: comment as filename.
    if !key.comment.is_empty() {
        let by_comment = ssh_dir.join(&key.comment);
        if by_comment.exists() && matches_fingerprint(&by_comment) {
            return Some(by_comment);
        }
    }

    // Priority 3: scan all private-key-like files in ~/.ssh/ (covers non-standard names
    // such as ~/.ssh/work_key or ~/.ssh/github_ed25519).
    let skip: std::collections::HashSet<&str> = standard
        .iter()
        .copied()
        .chain([
            "known_hosts",
            "known_hosts.old",
            "config",
            "authorized_keys",
        ])
        .collect();

    if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
        let mut entries: Vec<_> = entries.flatten().collect();
        // Sort for determinism.
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Skip public keys, known config files, and already-checked standard names.
            if name_str.ends_with(".pub") || skip.contains(name_str.as_ref()) {
                continue;
            }
            if matches_fingerprint(&path) {
                return Some(path);
            }
        }
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
#[must_use]
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
    match keyring_store::keyring_get(
        crate::defaults::KEYRING_SERVICE,
        crate::defaults::KEYRING_ACCOUNT,
    ) {
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
                        1 => {
                            // Verify that the private key file is also accessible (REQ-39 AC6).
                            if find_ssh_key_file(&keys[0]).is_some() {
                                states.push(IdentitySourceState::Resolved {
                                    source: "ssh-agent".to_string(),
                                });
                            } else {
                                states.push(IdentitySourceState::SourceNotAvailable {
                                    source: "ssh-agent".to_string(),
                                    reason: format!(
                                        "agent key {} found but no matching private key file in ~/.ssh/; \
                                         ensure the key file is accessible",
                                        keys[0].fingerprint
                                    ),
                                });
                            }
                        }
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
    load_identity_with(
        path,
        || {
            keyring_store::keyring_get(
                crate::defaults::KEYRING_SERVICE,
                crate::defaults::KEYRING_ACCOUNT,
            )
        },
        None,
    )
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
    load_identity_with(
        path,
        || {
            keyring_store::keyring_get(
                crate::defaults::KEYRING_SERVICE,
                crate::defaults::KEYRING_ACCOUNT,
            )
        },
        selector,
    )
}

/// Dependency-injected variant of [`load_identity`].
///
/// Tries the `GITVAULT_IDENTITY_PASSPHRASE` environment variable first, then
/// checks the OS keyring for a stored SSH key passphrase (`{account}-passphrase`).
/// Returns `None` (source-not-available) when neither source provides a passphrase.
/// In `--no-prompt` / CI mode this never blocks.
///
/// This passphrase is intended for passphrase-encrypted SSH identity files.
/// X25519 age keys do not use a passphrase.
pub(crate) fn try_fetch_ssh_passphrase(
    service: &str,
    account: &str,
    no_prompt: bool,
) -> Option<Zeroizing<String>> {
    // 1. Env var override (useful in CI environments)
    if let Ok(p) = std::env::var("GITVAULT_IDENTITY_PASSPHRASE")
        && !p.is_empty()
    {
        return Some(Zeroizing::new(p));
    }
    if no_prompt {
        // In CI/no-prompt mode, only accept env var; don't block on keyring I/O.
        return None;
    }
    // 2. OS keyring (optional; source-not-available on any error)
    keyring_store::keyring_get_identity_passphrase(service, account)
}

/// Load an identity and parse it as [`AnyIdentity`] with optional SSH passphrase support.
///
/// This combines identity string resolution (via the standard priority chain) with
/// optional SSH passphrase fetching from `GITVAULT_IDENTITY_PASSPHRASE` or the OS
/// keyring (`{account}-passphrase` entry).  For passphrase-encrypted SSH keys the
/// resolved passphrase is applied via callbacks so decryption succeeds without a
/// prompt (REQ-39 AC3, Spec-20 AC1).
///
/// # Errors
///
/// Returns [`GitvaultError`] if no identity source resolves.
pub fn load_any_identity_with_passphrase(
    path: Option<String>,
    no_prompt: bool,
    selector: Option<&str>,
) -> Result<crate::crypto::AnyIdentity, GitvaultError> {
    let identity_str = load_identity_with_selector(path, selector)?;
    let passphrase = try_fetch_ssh_passphrase(
        crate::defaults::KEYRING_SERVICE,
        crate::defaults::KEYRING_ACCOUNT,
        no_prompt,
    );
    crate::crypto::parse_identity_any_with_passphrase(&identity_str, passphrase)
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
        fhsm::IdentitySource::Keyring => keyring_store::keyring_get(
            crate::defaults::KEYRING_SERVICE,
            crate::defaults::KEYRING_ACCOUNT,
        ),
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

    // Try persistent recipients directory (REQ-36, REQ-72 AC15)
    let from_file = repo::read_recipients(repo_root, crate::defaults::RECIPIENTS_DIR)?;
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

        // The keyring is always tried automatically; no env var is needed.
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

    // ─── SshAgentError Display ────────────────────────────────────────────────

    #[test]
    fn test_ssh_agent_error_display_not_available() {
        let err = SshAgentError::NotAvailable("agent not running".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("SSH agent not available"));
        assert!(msg.contains("agent not running"));
    }

    #[test]
    fn test_ssh_agent_error_display_ambiguous() {
        let err = SshAgentError::Ambiguous(3);
        let msg = format!("{err}");
        assert!(msg.contains('3'));
        assert!(msg.contains("ambiguous"));
    }

    // ─── list_ssh_agent_keys ─────────────────────────────────────────────────

    #[test]
    fn test_list_ssh_agent_keys_no_agent_returns_ok_or_not_available() {
        // Without an SSH agent connected, ssh-add returns empty stdout → Ok([])
        // or errors with NotAvailable.  Both are valid outcomes.
        let result = with_env_var("SSH_AUTH_SOCK", None, list_ssh_agent_keys);
        match result {
            Ok(keys) => {
                // ssh-add ran but found no identities (expected when no agent)
                let _ = keys; // may be empty vec
            }
            Err(SshAgentError::NotAvailable(_)) => {
                // Also acceptable — agent socket not set
            }
            Err(SshAgentError::Ambiguous(_)) => panic!("unexpected Ambiguous error"),
        }
    }

    // ─── probe_identity_sources ───────────────────────────────────────────────

    #[test]
    fn test_probe_identity_sources_with_explicit_valid_path() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (tmp_file, _) = setup_identity_file();
        let states = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("SSH_AUTH_SOCK", None, || {
                with_env_var("GITVAULT_SSH_AGENT", None, || {
                    probe_identity_sources(Some(tmp_file.path().to_str().unwrap()), None)
                })
            })
        });
        assert_eq!(states.len(), 3, "should have 3 source states");
        // Source 1: --identity with a valid file → Resolved
        assert!(
            matches!(&states[0], IdentitySourceState::Resolved { source } if source == "--identity"),
            "source 1 should be Resolved for --identity, got: {:?}",
            states[0]
        );
        // Source 3: ssh-agent disabled (no SSH env vars) → SourceNotAvailable
        assert!(
            matches!(&states[2], IdentitySourceState::SourceNotAvailable { source, .. } if source == "ssh-agent"),
            "source 3 should be ssh-agent SourceNotAvailable, got: {:?}",
            states[2]
        );
    }

    #[test]
    fn test_probe_identity_sources_with_invalid_path() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let states = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("SSH_AUTH_SOCK", None, || {
                with_env_var("GITVAULT_SSH_AGENT", None, || {
                    probe_identity_sources(Some("/nonexistent/identity/file"), None)
                })
            })
        });
        assert_eq!(states.len(), 3);
        // Source 1: --identity with nonexistent file → SourceNotAvailable
        assert!(
            matches!(&states[0], IdentitySourceState::SourceNotAvailable { source, .. } if source == "--identity"),
            "source 1 should be SourceNotAvailable for bad --identity path, got: {:?}",
            states[0]
        );
    }

    #[test]
    fn test_probe_identity_sources_with_gitvault_identity_env_var() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (tmp_file, _) = setup_identity_file();
        let states = with_env_var(
            "GITVAULT_IDENTITY",
            Some(tmp_file.path().to_str().unwrap()),
            || {
                with_env_var("SSH_AUTH_SOCK", None, || {
                    with_env_var("GITVAULT_SSH_AGENT", None, || {
                        // No explicit path → falls back to env var
                        probe_identity_sources(None, None)
                    })
                })
            },
        );
        assert_eq!(states.len(), 3);
        // Source 1: GITVAULT_IDENTITY set to valid path → Resolved
        assert!(
            matches!(&states[0], IdentitySourceState::Resolved { source } if source == "GITVAULT_IDENTITY"),
            "source 1 should be Resolved for GITVAULT_IDENTITY, got: {:?}",
            states[0]
        );
    }

    #[test]
    fn test_probe_identity_sources_no_identity_no_ssh() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let states = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("SSH_AUTH_SOCK", None, || {
                with_env_var("GITVAULT_SSH_AGENT", None, || {
                    probe_identity_sources(None, None)
                })
            })
        });
        assert_eq!(states.len(), 3);
        // Source 1: no explicit source → SourceNotAvailable
        assert!(
            matches!(&states[0], IdentitySourceState::SourceNotAvailable { source, reason } if source == "--identity/GITVAULT_IDENTITY" && reason.contains("not provided")),
            "source 1 should be SourceNotAvailable with 'not provided', got: {:?}",
            states[0]
        );
        // Source 3: no SSH → SourceNotAvailable with SSH_AUTH_SOCK reason
        assert!(
            matches!(&states[2], IdentitySourceState::SourceNotAvailable { source, .. } if source == "ssh-agent"),
            "source 3 should be ssh-agent SourceNotAvailable, got: {:?}",
            states[2]
        );
    }

    #[test]
    fn test_probe_identity_sources_ssh_agent_enabled_no_real_agent() {
        // With GITVAULT_SSH_AGENT=1 but no real agent, list_ssh_agent_keys returns
        // Ok([]) (ssh-add exits with empty stdout), so the probe reports
        // SourceNotAvailable for ssh-agent.
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let states = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("SSH_AUTH_SOCK", None, || {
                with_env_var("GITVAULT_SSH_AGENT", Some("1"), || {
                    probe_identity_sources(None, None)
                })
            })
        });
        assert_eq!(states.len(), 3);
        // Source 3: SSH enabled but no usable keys → SourceNotAvailable
        let ssh_state = &states[2];
        assert!(
            matches!(ssh_state, IdentitySourceState::SourceNotAvailable { source, .. } if source == "ssh-agent"),
            "source 3 should be ssh-agent SourceNotAvailable, got: {ssh_state:?}"
        );
    }

    // ─── load_identity_with SSH-agent branches ────────────────────────────────

    #[test]
    fn test_load_identity_with_ssh_agent_enabled_no_real_agent_fails_closed() {
        // When GITVAULT_SSH_AGENT=1 but no agent is available, the chain should
        // fall through to fail-closed with a Usage error.
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let err = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("SSH_AUTH_SOCK", None, || {
                with_env_var("GITVAULT_SSH_AGENT", Some("1"), || {
                    load_identity_with(
                        None,
                        || Err(GitvaultError::Keyring("no key".to_string())),
                        None,
                    )
                })
            })
        })
        .expect_err("should fail closed when no identity source resolves");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected fail-closed Usage error, got: {err:?}"
        );
    }

    // ─── extract_identity_key ─────────────────────────────────────────────────

    #[test]
    fn test_extract_identity_key_returns_none_for_empty_string() {
        assert!(extract_identity_key("").is_none());
    }

    #[test]
    fn test_extract_identity_key_returns_none_for_non_age_content() {
        assert!(extract_identity_key("# just a comment\nFOO=bar\n").is_none());
    }

    #[test]
    fn test_extract_identity_key_extracts_key_with_comment() {
        let (_, identity) = setup_identity_file();
        let key = identity.to_string();
        let content = format!("# some comment\n{} # inline\n", key.expose_secret());
        let result = extract_identity_key(&content);
        assert_eq!(result.as_deref(), Some(key.expose_secret().as_str()));
    }

    // ─── resolve_recipient_keys ───────────────────────────────────────────────

    #[test]
    fn test_resolve_recipient_keys_with_provided_recipients() {
        // When recipient_keys is non-empty, return immediately without touching the repo.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let keys = vec!["age1abc".to_string(), "age1def".to_string()];
        let result = resolve_recipient_keys(dir.path(), keys.clone())
            .expect("resolve with provided keys should succeed");
        assert_eq!(result, keys);
    }

    #[test]
    fn test_resolve_recipient_keys_from_recipients_dir() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::TempDir::new().expect("temp dir");

        // Write a valid recipient into the directory model
        let (_, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();
        let recipients_dir = dir.path().join(".gitvault/recipients");
        std::fs::create_dir_all(&recipients_dir).expect("create recipients dir");
        std::fs::write(recipients_dir.join("default.pub"), format!("{pubkey}\n"))
            .expect("write recipient pub file");

        let result = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("SSH_AUTH_SOCK", None, || {
                resolve_recipient_keys(dir.path(), vec![])
            })
        })
        .expect("resolve from recipients directory should succeed");
        assert_eq!(result, vec![pubkey]);
    }

    #[test]
    fn test_resolve_recipient_keys_fallback_to_identity() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (identity_file, identity) = setup_identity_file();
        let pubkey = identity.to_public().to_string();

        // No recipients file → falls back to identity's public key
        let result = with_env_var(
            "GITVAULT_IDENTITY",
            Some(identity_file.path().to_str().unwrap()),
            || {
                with_env_var("SSH_AUTH_SOCK", None, || {
                    resolve_recipient_keys(dir.path(), vec![])
                })
            },
        )
        .expect("fallback resolve should succeed");
        assert_eq!(result, vec![pubkey]);
    }

    // ─── load_identity_from_source_with_selector (Unresolved) ────────────────

    #[test]
    fn test_load_identity_from_source_unresolved_falls_back_to_chain() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (tmp_file, _) = setup_identity_file();
        let source = fhsm::IdentitySource::Unresolved;
        // Provide GITVAULT_IDENTITY so the full chain can resolve
        let result = with_env_var(
            "GITVAULT_IDENTITY",
            Some(tmp_file.path().to_str().unwrap()),
            || {
                with_env_var("SSH_AUTH_SOCK", None, || {
                    load_identity_from_source_with_selector(&source, None)
                })
            },
        );
        assert!(
            result.is_ok(),
            "Unresolved should fall back to chain: {result:?}"
        );
    }

    #[test]
    fn test_load_identity_from_source_with_selector_inline_nonempty() {
        let (_, identity) = setup_identity_file();
        let key_str = identity.to_string().expose_secret().clone();
        let source = fhsm::IdentitySource::Inline(key_str.clone());
        let result = load_identity_from_source_with_selector(&source, Some("anysel"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), key_str.as_str());
    }

    // ─── load_identity_source: OpenSSH key branch ─────────────────────────────

    #[test]
    fn test_load_identity_source_openssh_key_file_returns_raw_content() {
        // A file beginning with the OpenSSH private key header should be returned
        // as-is without extracting an AGE-SECRET-KEY line (covers line 347).
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let content = "-----BEGIN OPENSSH PRIVATE KEY-----\nfakebase64==\n-----END OPENSSH PRIVATE KEY-----\n";
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        let result = load_identity_source(f.path().to_str().unwrap(), "test-source");
        assert!(
            result.is_ok(),
            "OpenSSH key file should succeed: {result:?}"
        );
        assert_eq!(result.unwrap().as_str(), content);
    }

    // ─── probe_identity_sources: GITVAULT_IDENTITY error branch ──────────────

    #[test]
    fn test_probe_identity_sources_gitvault_identity_invalid_path_is_not_available() {
        // When GITVAULT_IDENTITY is set to a non-existent path, source 1 should be
        // SourceNotAvailable with source == "GITVAULT_IDENTITY" (covers lines 214-217).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let states = with_env_var(
            "GITVAULT_IDENTITY",
            Some("/nonexistent/path/to/identity_key_xyz"),
            || {
                with_env_var("SSH_AUTH_SOCK", None, || {
                    with_env_var("GITVAULT_SSH_AGENT", None, || {
                        // No explicit path → falls back to GITVAULT_IDENTITY
                        probe_identity_sources(None, None)
                    })
                })
            },
        );
        assert_eq!(states.len(), 3);
        assert!(
            matches!(
                &states[0],
                IdentitySourceState::SourceNotAvailable { source, .. }
                if source == "GITVAULT_IDENTITY"
            ),
            "expected SourceNotAvailable for GITVAULT_IDENTITY, got: {:?}",
            states[0]
        );
    }

    // ─── probe_identity_sources: keyring resolved branch ─────────────────────

    // Note: lines 228-230 (keyring Resolved) require a real OS keyring and
    // cannot be covered in headless CI. They remain in the accepted exceptions list.

    // ─── SSH agent mock infrastructure ───────────────────────────────────────

    /// Create a temp directory containing fake `ssh-add` and `ssh-keygen` binaries.
    /// Returns the `TempDir` (caller must keep it alive).
    #[cfg(unix)]
    fn setup_fake_ssh_binaries(ssh_add_output: &str, ssh_keygen_output: &str) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let bin_dir = tempfile::TempDir::new().unwrap();

        let ssh_add_path = bin_dir.path().join("ssh-add");
        std::fs::write(
            &ssh_add_path,
            format!("#!/bin/sh\nprintf '%s\\n' '{ssh_add_output}'\n"),
        )
        .unwrap();
        std::fs::set_permissions(&ssh_add_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let ssh_keygen_path = bin_dir.path().join("ssh-keygen");
        std::fs::write(
            &ssh_keygen_path,
            format!("#!/bin/sh\nprintf '%s\\n' '{ssh_keygen_output}'\n"),
        )
        .unwrap();
        std::fs::set_permissions(&ssh_keygen_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        bin_dir
    }

    // ─── list_ssh_agent_keys: parsing loop ───────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_list_ssh_agent_keys_with_mock_returns_ed25519_key() {
        // Uses a fake ssh-add binary to test the ED25519 key parsing loop
        // in list_ssh_agent_keys (covers lines 75-100).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bin_dir =
            setup_fake_ssh_binaries("256 SHA256:testfingerprint id_ed25519 (ED25519)", "");

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let result = with_env_var("PATH", Some(&new_path), list_ssh_agent_keys);

        let keys = result.expect("should succeed with mock ssh-add");
        assert_eq!(keys.len(), 1, "should have exactly 1 ED25519 key");
        assert!(
            keys[0].fingerprint.contains("SHA256:testfingerprint"),
            "unexpected fingerprint: {}",
            keys[0].fingerprint
        );
        assert_eq!(keys[0].comment, "id_ed25519");
    }

    #[cfg(unix)]
    #[test]
    fn test_list_ssh_agent_keys_with_mock_filters_non_ed25519() {
        // When ssh-add output contains a non-ED25519 key, it should be filtered out.
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bin_dir = setup_fake_ssh_binaries("256 SHA256:rsafp rsa_key (RSA)", "");

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let result = with_env_var("PATH", Some(&new_path), list_ssh_agent_keys);
        let keys = result.expect("should succeed with mock ssh-add");
        assert_eq!(keys.len(), 0, "RSA key should be filtered out");
    }

    // ─── find_ssh_key_file: fingerprint match path ────────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_find_ssh_key_file_with_mock_keygen_finds_matching_file() {
        // Tests find_ssh_key_file with fake HOME and fake ssh-keygen that returns
        // a matching fingerprint (covers lines 107-128).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let home_dir = tempfile::TempDir::new().unwrap();
        let ssh_dir = home_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        // Create fake "identity" (last candidate) so "id_ed25519" and "id_ecdsa" don't exist
        // → covers the `continue` branch for non-existent candidates (line 116)
        let key_file = ssh_dir.join("identity");
        std::fs::write(
            &key_file,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();

        // Fake ssh-keygen returns the matching fingerprint
        let bin_dir = setup_fake_ssh_binaries("", "256 SHA256:fp12345 test@host (ED25519)");

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let key = SshAgentKey {
            fingerprint: "SHA256:fp12345".to_string(),
            comment: "identity".to_string(),
        };

        let result = with_env_var("HOME", Some(home_dir.path().to_str().unwrap()), || {
            with_env_var("PATH", Some(&new_path), || find_ssh_key_file(&key))
        });

        assert!(
            result.is_some(),
            "find_ssh_key_file should find the key file"
        );
        assert_eq!(result.unwrap(), key_file);
    }

    // ─── find_ssh_key_file: priority 2 (comment as filename) ─────────────────

    /// Covers lines 153-154: priority 2 — file named after key.comment found and
    /// fingerprint matches → returns `Some(by_comment)`.
    #[cfg(unix)]
    #[test]
    fn test_find_ssh_key_file_priority2_comment_match() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let home_dir = tempfile::TempDir::new().unwrap();
        let ssh_dir = home_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        // Create a key file with a non-standard name (not id_ed25519/id_ecdsa/identity).
        let key_name = "my_project_key";
        let key_file = ssh_dir.join(key_name);
        std::fs::write(&key_file, "fake-key-content").unwrap();

        // Fake ssh-keygen returns matching fingerprint for this file.
        let fingerprint = "SHA256:priority2test";
        let bin_dir =
            setup_fake_ssh_binaries("", &format!("256 {fingerprint} test@host (ED25519)"));

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        // comment = key_name → priority 2 path: ~/.ssh/{comment} exists + fingerprint matches.
        let key = SshAgentKey {
            fingerprint: fingerprint.to_string(),
            comment: key_name.to_string(),
        };

        let result = with_env_var("HOME", Some(home_dir.path().to_str().unwrap()), || {
            with_env_var("PATH", Some(&new_path), || find_ssh_key_file(&key))
        });

        assert!(
            result.is_some(),
            "find_ssh_key_file priority 2 should find the key file"
        );
        assert_eq!(result.unwrap(), key_file);
    }

    // ─── find_ssh_key_file: priority 3 (full scan of ~/.ssh/) ────────────────

    /// Covers lines 157-188: priority 3 — scan all files in ~/.ssh/ by fingerprint.
    /// Priority 1 misses (no standard names), priority 2 misses (comment doesn't match any
    /// filename), so priority 3 scans and finds the key by fingerprint.
    #[cfg(unix)]
    #[test]
    fn test_find_ssh_key_file_priority3_scan() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let home_dir = tempfile::TempDir::new().unwrap();
        let ssh_dir = home_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        // Non-standard key file name (not a standard name, and comment won't match it).
        let key_name = "work_key";
        let key_file = ssh_dir.join(key_name);
        std::fs::write(&key_file, "fake-key-content").unwrap();

        // Also create a .pub file (should be skipped) and a config file (should be skipped).
        std::fs::write(ssh_dir.join("work_key.pub"), "public-key").unwrap();
        std::fs::write(ssh_dir.join("config"), "Host *").unwrap();
        // Create a subdir (should be skipped).
        std::fs::create_dir_all(ssh_dir.join("subdir")).unwrap();

        let fingerprint = "SHA256:priority3test";
        let bin_dir =
            setup_fake_ssh_binaries("", &format!("256 {fingerprint} test@host (ED25519)"));

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        // comment = "nonexistent" → priority 2 fails; priority 3 scans and finds work_key.
        let key = SshAgentKey {
            fingerprint: fingerprint.to_string(),
            comment: "nonexistent_comment_xyz".to_string(),
        };

        let result = with_env_var("HOME", Some(home_dir.path().to_str().unwrap()), || {
            with_env_var("PATH", Some(&new_path), || find_ssh_key_file(&key))
        });

        assert!(
            result.is_some(),
            "find_ssh_key_file priority 3 should find the key file"
        );
        assert_eq!(result.unwrap(), key_file);
    }

    /// Covers the `None` return from `find_ssh_key_file` when no file matches the fingerprint.
    #[cfg(unix)]
    #[test]
    fn test_find_ssh_key_file_no_match_returns_none() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let home_dir = tempfile::TempDir::new().unwrap();
        let ssh_dir = home_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        // Create a file, but fake ssh-keygen returns a NON-matching fingerprint.
        std::fs::write(ssh_dir.join("some_key"), "fake-key").unwrap();

        // Fake ssh-keygen returns a different fingerprint — no match.
        let bin_dir = setup_fake_ssh_binaries("", "256 SHA256:DIFFERENT other@host (ED25519)");

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let key = SshAgentKey {
            fingerprint: "SHA256:EXPECTED_BUT_NOT_FOUND".to_string(),
            comment: "some_key".to_string(),
        };

        let result = with_env_var("HOME", Some(home_dir.path().to_str().unwrap()), || {
            with_env_var("PATH", Some(&new_path), || find_ssh_key_file(&key))
        });

        assert!(
            result.is_none(),
            "find_ssh_key_file should return None when no file matches"
        );
    }

    // ─── load_ssh_agent_identity: full success path ───────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_load_ssh_agent_identity_one_key_returns_file_content() {
        // Tests the full path: list → find file → read content (covers lines 152-183).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let home_dir = tempfile::TempDir::new().unwrap();
        let ssh_dir = home_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        let key_content =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekey\n-----END OPENSSH PRIVATE KEY-----\n";
        let key_file = ssh_dir.join("identity");
        std::fs::write(&key_file, key_content).unwrap();

        let fingerprint = "SHA256:fp_for_load_test";
        let bin_dir = setup_fake_ssh_binaries(
            &format!("256 {fingerprint} identity (ED25519)"),
            &format!("256 {fingerprint} test@host (ED25519)"),
        );

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let result = with_env_var("HOME", Some(home_dir.path().to_str().unwrap()), || {
            with_env_var("PATH", Some(&new_path), || load_ssh_agent_identity(None))
        });

        let content = result.expect("load_ssh_agent_identity should succeed");
        assert!(
            content.contains("OPENSSH PRIVATE KEY"),
            "content should be the key file content"
        );
    }

    // ─── load_ssh_agent_identity: empty keys branch ───────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_load_ssh_agent_identity_empty_keys_returns_not_available() {
        // When ssh-add returns empty output, list_ssh_agent_keys returns Ok([]).
        // load_ssh_agent_identity should then return Err(NotAvailable).
        // Covers lines 154-157 (keys.is_empty() true branch).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Fake ssh-add returns empty output → Ok([]) from list_ssh_agent_keys
        let bin_dir = setup_fake_ssh_binaries("", "");

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let result = with_env_var("PATH", Some(&new_path), || load_ssh_agent_identity(None));

        assert!(
            matches!(result, Err(SshAgentError::NotAvailable(_))),
            "expected NotAvailable for empty agent, got: {result:?}"
        );
    }

    // ─── load_ssh_agent_identity: selector no match ───────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_load_ssh_agent_identity_selector_no_match_returns_not_available() {
        // When a selector matches no keys, Err(NotAvailable) is returned.
        // Covers lines 161-168 (selector filtering + 0 match arm).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let fingerprint = "SHA256:fp_selector_test";
        let bin_dir = setup_fake_ssh_binaries(&format!("256 {fingerprint} mykey (ED25519)"), "");

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        // selector "NOMATCH" doesn't match the fingerprint or comment
        let result = with_env_var("PATH", Some(&new_path), || {
            load_ssh_agent_identity(Some("NOMATCH_SELECTOR_XYZ"))
        });

        assert!(
            matches!(result, Err(SshAgentError::NotAvailable(_))),
            "expected NotAvailable when selector matches nothing, got: {result:?}"
        );
    }

    // ─── load_identity_with: SSH Ambiguous error path ─────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_load_identity_with_ssh_ambiguous_two_keys_returns_usage_error() {
        // When SSH agent has 2 keys and no selector is given, load_identity_with
        // should return a Usage error mentioning ambiguity.
        // Covers lines 430-434 (SshAgentError::Ambiguous arm) and line 185 in
        // load_ssh_agent_identity (count => Ambiguous(count)).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Fake ssh-add returns 2 ED25519 keys → list_ssh_agent_keys returns Ok([k1, k2])
        // → load_ssh_agent_identity sees keys.len() = 2 → Err(Ambiguous(2))
        let bin_dir = setup_fake_ssh_binaries(
            "256 SHA256:fp1 key1 (ED25519)\n256 SHA256:fp2 key2 (ED25519)",
            "",
        );

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let result = with_env_var("GITVAULT_SSH_AGENT", Some("1"), || {
            with_env_var("GITVAULT_IDENTITY", None, || {
                with_env_var("PATH", Some(&new_path), || {
                    load_identity_with(
                        None,
                        || Err(GitvaultError::Keyring("no keyring in test".to_string())),
                        None, // no selector → triggers Ambiguous error
                    )
                })
            })
        });

        let err = result.expect_err("should fail with ambiguous SSH keys");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error for ambiguous SSH, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains('2'),
            "error message should mention count 2: {msg}"
        );
    }

    // ─── probe_identity_sources: SSH with one key → Resolved ─────────────────

    #[cfg(unix)]
    #[test]
    fn test_probe_identity_sources_ssh_one_key_resolved() {
        // When SSH agent has exactly one ED25519 key AND a matching private key file
        // is on disk, probe should report IdentitySourceState::Resolved for ssh-agent.
        // Covers lines 241, 255-276 (Ok path → key count = 1 → file found → Resolved).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let fingerprint = "SHA256:fp_probe_test";

        // Create a fake HOME with a .ssh/id_ed25519 private key file so that
        // find_ssh_key_file succeeds.  The fake ssh-keygen returns the matching
        // fingerprint for any path it is given.
        let fake_home = tempfile::TempDir::new().unwrap();
        let ssh_dir = fake_home.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(
            ssh_dir.join("id_ed25519"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();

        let keygen_output = format!("256 {fingerprint} comment (ED25519)");
        let bin_dir = setup_fake_ssh_binaries(
            &format!("256 {fingerprint} probe_key (ED25519)"),
            &keygen_output,
        );

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let states = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("GITVAULT_SSH_AGENT", Some("1"), || {
                with_env_var("SSH_AUTH_SOCK", None, || {
                    with_env_var("HOME", Some(fake_home.path().to_str().unwrap()), || {
                        with_env_var("PATH", Some(&new_path), || {
                            probe_identity_sources(None, None)
                        })
                    })
                })
            })
        });

        assert_eq!(states.len(), 3);
        // SSH source should be Resolved (1 key, file found)
        assert!(
            matches!(
                &states[2],
                IdentitySourceState::Resolved { source } if source == "ssh-agent"
            ),
            "expected ssh-agent Resolved, got: {:?}",
            states[2]
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_probe_identity_sources_ssh_one_key_no_file_not_available() {
        // When SSH agent has one ED25519 key but no matching private key file on disk,
        // probe should report SourceNotAvailable (REQ-39 AC6: file must be accessible).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let fingerprint = "SHA256:fp_nofile_test";
        // Fake ssh-keygen returns a NON-matching fingerprint so no file matches.
        let keygen_output = "256 SHA256:DIFFERENT other_comment (ED25519)";
        let bin_dir = setup_fake_ssh_binaries(
            &format!("256 {fingerprint} probe_key (ED25519)"),
            keygen_output,
        );

        let fake_home = tempfile::TempDir::new().unwrap();
        let ssh_dir = fake_home.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Create a key file but with a non-matching fingerprint per fake ssh-keygen.
        std::fs::write(ssh_dir.join("id_ed25519"), "fake").unwrap();

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let states = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("GITVAULT_SSH_AGENT", Some("1"), || {
                with_env_var("SSH_AUTH_SOCK", None, || {
                    with_env_var("HOME", Some(fake_home.path().to_str().unwrap()), || {
                        with_env_var("PATH", Some(&new_path), || {
                            probe_identity_sources(None, None)
                        })
                    })
                })
            })
        });

        assert_eq!(states.len(), 3);
        assert!(
            matches!(
                &states[2],
                IdentitySourceState::SourceNotAvailable { source, .. } if source == "ssh-agent"
            ),
            "expected ssh-agent SourceNotAvailable (no file), got: {:?}",
            states[2]
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_probe_identity_sources_ssh_two_keys_ambiguous() {
        // When SSH agent has 2 keys and no selector, probe should report Ambiguous.
        // Covers lines 273-276 (count => Ambiguous in probe).
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let bin_dir = setup_fake_ssh_binaries(
            "256 SHA256:fp_a key_a (ED25519)\n256 SHA256:fp_b key_b (ED25519)",
            "",
        );

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.path().display(), original_path);

        let states = with_env_var("GITVAULT_IDENTITY", None, || {
            with_env_var("GITVAULT_SSH_AGENT", Some("1"), || {
                with_env_var("SSH_AUTH_SOCK", None, || {
                    with_env_var("PATH", Some(&new_path), || {
                        probe_identity_sources(None, None)
                    })
                })
            })
        });

        assert_eq!(states.len(), 3);
        // SSH source should be Ambiguous (2 keys, no selector)
        assert!(
            matches!(
                &states[2],
                IdentitySourceState::Ambiguous { source, count } if source == "ssh-agent" && *count == 2
            ),
            "expected ssh-agent Ambiguous(2), got: {:?}",
            states[2]
        );
    }
}
