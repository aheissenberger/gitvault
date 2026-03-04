//! Production barrier enforcement.
//!
//! REQ-13: accessing prod requires --prod flag AND (valid allow token OR interactive confirmation).
//! REQ-14: allow token expires automatically (default TTL: 3600 seconds).
//! REQ-15: fail closed — any unmet condition returns `BarrierNotSatisfied`.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::defaults;
use crate::error::GitvaultError;
use crate::permissions;

type HmacSha256 = Hmac<Sha256>;

/// Key file for the HMAC signing key (REQ-79).
const TOKEN_KEY_FILE: &str = ".git/gitvault/.token-key";

/// Hard upper bound on production token TTL (REQ-97). 24 hours.
pub const MAX_TOKEN_TTL_SECS: u64 = 86_400;

/// Default token TTL in seconds (1 hour); re-exported from [`defaults`] for
/// call-sites that import directly from this module.
pub use defaults::DEFAULT_BARRIER_TTL_SECS as DEFAULT_TOKEN_TTL_SECS;

/// Check the production barrier for the given environment.
///
/// REQ-13: if `env` == `prod_name`, requires:
///   - `prod_flag` == true   (explicit --prod opt-in), AND
///   - valid unexpired allow token OR interactive confirmation (blocked when `no_prompt`)
///
/// REQ-15: fails closed — returns Err(BarrierNotSatisfied) if any condition is unmet.
/// Non-prod environments pass immediately.
///
/// `prod_name` is the environment name that triggers the barrier (default: `"prod"`).
/// Use [`defaults::DEFAULT_PROD_ENV`] or `cfg.env.prod_name()` to supply this value.
///
/// # Errors
///
/// Returns [`GitvaultError::BarrierNotSatisfied`] if `env` matches `prod_name` and the
/// `--prod` flag was not set, no valid token exists, or the user declines the prompt.
/// Returns [`GitvaultError::Io`] if reading the token file or stdin fails.
pub fn check_prod_barrier(
    repo_root: &Path,
    env: &str,
    prod_flag: bool,
    no_prompt: bool,
    prod_name: &str,
) -> Result<(), GitvaultError> {
    check_prod_barrier_with_confirm(
        repo_root,
        env,
        prod_flag,
        no_prompt,
        prod_name,
        prompt_prod_confirmation,
    )
}

pub(crate) fn check_prod_barrier_with_confirm<F>(
    repo_root: &Path,
    env: &str,
    prod_flag: bool,
    no_prompt: bool,
    prod_name: &str,
    confirm: F,
) -> Result<(), GitvaultError>
where
    F: FnOnce() -> Result<bool, GitvaultError>,
{
    if env != prod_name {
        return Ok(());
    }

    // REQ-13: explicit --prod flag required
    if !prod_flag {
        return Err(GitvaultError::BarrierNotSatisfied(
            "add --prod to confirm production access".to_string(),
        ));
    }

    // REQ-13 + REQ-14: check for a valid (unexpired) allow token
    if has_valid_token(repo_root) {
        return Ok(());
    }

    // REQ-13: fall back to interactive confirmation
    if no_prompt {
        return Err(GitvaultError::BarrierNotSatisfied(
            "no valid prod allow token and --no-prompt is set; run `gitvault allow-prod` first"
                .to_string(),
        ));
    }

    if confirm()? {
        Ok(())
    } else {
        Err(GitvaultError::BarrierNotSatisfied(
            "production access denied by user".to_string(),
        ))
    }
}

fn prompt_prod_confirmation() -> Result<bool, GitvaultError> {
    eprint!("⚠️  You are about to access PRODUCTION secrets. Confirm? [y/N] ");
    let mut stdin = std::io::stdin().lock();
    read_confirmation_from(&mut stdin)
}

fn read_confirmation_from(reader: &mut impl std::io::BufRead) -> Result<bool, GitvaultError> {
    let mut input = String::new();
    reader.read_line(&mut input).map_err(GitvaultError::Io)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

/// Write a timed allow token to `.secrets/.prod-token`. REQ-14, REQ-79.
///
/// Token format: `<expiry>:<hex(hmac-sha256(key, expiry_be_bytes))>`
/// The HMAC key is stored in `.git/gitvault/.token-key` (0600); created on first use.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if `ttl_secs` exceeds [`MAX_TOKEN_TTL_SECS`].
/// Returns [`GitvaultError::Other`] if the expiry timestamp overflows.
/// Returns [`GitvaultError::Io`] if creating or writing the token file fails.
pub fn allow_prod(repo_root: &Path, ttl_secs: u64) -> Result<u64, GitvaultError> {
    // REQ-97: enforce hard TTL cap independent of config.
    if ttl_secs > MAX_TOKEN_TTL_SECS {
        return Err(GitvaultError::Usage(format!(
            "TTL {ttl_secs}s exceeds maximum {MAX_TOKEN_TTL_SECS}s (24 h)"
        )));
    }
    let now = now_secs()?;
    let expiry = now
        .checked_add(ttl_secs)
        .ok_or_else(|| GitvaultError::Other("timestamp overflow".to_string()))?;

    let token_path = repo_root.join(defaults::BARRIER_TOKEN_FILE);
    if let Some(parent) = token_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let key = load_or_create_token_key(repo_root)?;
    let mac = compute_hmac(&key, expiry)?;
    let token_str = format!("{expiry}:{mac}");

    // fs_util::atomic_write not used here: permission step required between write and persist.
    let token_parent = token_path.parent().unwrap_or(repo_root);
    let tmp = tempfile::NamedTempFile::new_in(token_parent)?;
    fs::write(tmp.path(), &token_str)?;
    // REQ-18: restrict permissions BEFORE persist so the rename carries the ACL.
    enforce_restricted_token_permissions(tmp.path())?;
    tmp.persist(&token_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    Ok(expiry)
}

fn enforce_restricted_token_permissions(path: &Path) -> Result<(), GitvaultError> {
    permissions::enforce_owner_rw(path, "production token")
}

/// Revoke the allow token by removing the token file.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the token file exists but cannot be removed.
pub fn revoke_prod(repo_root: &Path) -> Result<(), GitvaultError> {
    let token_path = repo_root.join(defaults::BARRIER_TOKEN_FILE);
    match fs::remove_file(&token_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(GitvaultError::Io(e)),
    }
    Ok(())
}

/// Returns true if a valid (unexpired), HMAC-authenticated allow token exists. REQ-14, REQ-79.
fn has_valid_token(repo_root: &Path) -> bool {
    let token_path = repo_root.join(defaults::BARRIER_TOKEN_FILE);
    let Ok(content) = fs::read_to_string(&token_path) else {
        return false;
    };
    let Some((expiry_str, mac_hex)) = content.trim().split_once(':') else {
        // Bare timestamp (legacy) or malformed — reject (REQ-79).
        return false;
    };
    let Ok(expiry) = expiry_str.parse::<u64>() else {
        return false;
    };
    // REQ-86: treat clock-before-epoch as invalid (log to stderr; do not grant access).
    let Ok(now) = now_secs() else {
        eprintln!("gitvault: system clock error — cannot validate prod token; access denied");
        return false;
    };
    if now >= expiry {
        return false;
    }
    // REQ-79: HMAC verification (constant-time).
    let Ok(key) = load_or_create_token_key(repo_root) else {
        return false;
    };
    let Ok(expected_mac) = compute_hmac(&key, expiry) else {
        return false;
    };
    // subtle::ConstantTimeEq for constant-time byte comparison.
    use subtle::ConstantTimeEq;
    mac_hex.as_bytes().ct_eq(expected_mac.as_bytes()).into()
}

/// Current Unix timestamp in seconds. REQ-86.
///
/// Returns `Err` when the system clock is set before the Unix epoch (year 1970).
fn now_secs() -> Result<u64, GitvaultError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| GitvaultError::Other(format!("system clock before Unix epoch: {e}")))
}

/// Compute HMAC-SHA256 of the expiry timestamp and return the lowercase hex string.
///
/// REQ-88: `expiry` is encoded as 8 big-endian bytes (`to_be_bytes()`) for
/// canonical, unambiguous MAC input rather than a decimal ASCII string.
///
/// REQ-103: returns `Result` instead of using `expect()`, propagating any
/// HMAC key initialisation failure as `GitvaultError::Other`.
fn compute_hmac(key: &[u8; 32], expiry: u64) -> Result<String, GitvaultError> {
    // new_from_slice accepts any non-empty slice; a [u8; 32] always satisfies this,
    // so the error branch is statically unreachable — but we propagate rather than panic.
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| GitvaultError::Other("HMAC key initialisation failed".into()))?;
    // REQ-88: canonical big-endian encoding, not decimal string.
    mac.update(&expiry.to_be_bytes());
    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result))
}

/// Load the HMAC signing key from disk, creating it (with restricted permissions) if absent.
///
/// REQ-89: key material is held in [`Zeroizing`] wrappers so memory is overwritten on drop.
/// REQ-91: uses `match` on the `read_to_string` result instead of `exists()` to
///          eliminate a TOCTOU race between the existence check and the read.
/// REQ-92: rejects an all-zero key (possible file tampering) with a hard error.
fn load_or_create_token_key(repo_root: &Path) -> Result<[u8; 32], GitvaultError> {
    let key_path = repo_root.join(TOKEN_KEY_FILE);

    // REQ-91: match directly on read result — no exists() pre-check.
    match fs::read_to_string(&key_path) {
        Ok(raw) => {
            // REQ-102: verify the key file has restricted permissions (0600 on Unix)
            // before using the key. A world-readable key file on a shared system allows
            // another user to forge prod tokens.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&key_path)?.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(GitvaultError::Other(format!(
                        "token key file has insecure permissions (mode {mode:04o}); \
                         expected 0600 — run `gitvault allow-prod` to regenerate"
                    )));
                }
            }
            // REQ-89: zeroize the raw content string on drop.
            let content = Zeroizing::new(raw);
            // REQ-89: zeroize the decoded bytes on drop.
            let bytes = Zeroizing::new(
                hex::decode(content.trim())
                    .map_err(|e| GitvaultError::Other(format!("invalid token key format: {e}")))?,
            );
            // REQ-92: reject all-zero key (possible file tampering or zeroed-out disk sector).
            if bytes.iter().all(|&b| b == 0) {
                return Err(GitvaultError::Other(
                    "token key is all-zeros — possible file tampering".to_string(),
                ));
            }
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| GitvaultError::Other("token key has wrong length".to_string()))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // REQ-89: zeroize the key array on drop.
            let mut key = Zeroizing::new([0u8; 32]);
            rand::thread_rng().fill_bytes(key.as_mut());
            // REQ-89: zeroize the hex string on drop.
            let hex_key = Zeroizing::new(hex::encode(*key));
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)?;
            }
            // fs_util::atomic_write not used here: permission step required between write and persist.
            let tmp = tempfile::NamedTempFile::new_in(key_path.parent().unwrap_or(repo_root))?;
            fs::write(tmp.path(), hex_key.as_bytes())?;
            permissions::enforce_owner_rw(tmp.path(), "token key")?;
            tmp.persist(&key_path)
                .map_err(|e| GitvaultError::Io(e.error))?;
            Ok(*key)
        }
        Err(e) => Err(GitvaultError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn root() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn non_prod_env_always_passes() {
        let dir = root();
        assert!(
            check_prod_barrier(dir.path(), "dev", false, true, defaults::DEFAULT_PROD_ENV).is_ok()
        );
        assert!(
            check_prod_barrier(
                dir.path(),
                "staging",
                false,
                true,
                defaults::DEFAULT_PROD_ENV
            )
            .is_ok()
        );
    }

    #[test]
    fn prod_without_prod_flag_fails() {
        let dir = root();
        let err = check_prod_barrier(dir.path(), "prod", false, true, defaults::DEFAULT_PROD_ENV)
            .unwrap_err();
        assert!(matches!(err, GitvaultError::BarrierNotSatisfied(_)));
    }

    #[test]
    fn prod_with_prod_flag_no_token_no_prompt_fails() {
        let dir = root();
        let err = check_prod_barrier(dir.path(), "prod", true, true, defaults::DEFAULT_PROD_ENV)
            .unwrap_err();
        assert!(matches!(err, GitvaultError::BarrierNotSatisfied(_)));
    }

    #[test]
    fn prod_with_valid_token_passes() {
        let dir = root();
        allow_prod(dir.path(), 3600).unwrap();
        assert!(
            check_prod_barrier(dir.path(), "prod", true, true, defaults::DEFAULT_PROD_ENV).is_ok()
        );
    }

    #[test]
    fn prod_with_expired_token_fails() {
        let dir = root();
        // Write an already-expired HMAC token.
        let token_path = dir.path().join(".git/gitvault/.prod-token");
        std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        // Create key and write a token with expiry=1 (1970-01-01 00:00:01 UTC).
        let key = load_or_create_token_key(dir.path()).unwrap();
        let mac = compute_hmac(&key, 1).unwrap();
        std::fs::write(&token_path, format!("1:{mac}")).unwrap();
        let err = check_prod_barrier(dir.path(), "prod", true, true, defaults::DEFAULT_PROD_ENV)
            .unwrap_err();
        assert!(matches!(err, GitvaultError::BarrierNotSatisfied(_)));
    }

    #[test]
    fn allow_prod_writes_future_expiry() {
        let dir = root();
        let expiry = allow_prod(dir.path(), 3600).unwrap();
        assert!(expiry > now_secs().unwrap());
        assert!(has_valid_token(dir.path()));
    }

    #[test]
    fn revoke_prod_removes_token() {
        let dir = root();
        allow_prod(dir.path(), 3600).unwrap();
        assert!(has_valid_token(dir.path()));
        revoke_prod(dir.path()).unwrap();
        assert!(!has_valid_token(dir.path()));
    }

    #[test]
    fn token_path_constant_is_under_secrets_dir() {
        assert!(defaults::BARRIER_TOKEN_FILE.starts_with(".git/gitvault/"));
    }

    #[test]
    fn prod_with_interactive_confirm_yes_passes() {
        let dir = root();
        let result = check_prod_barrier_with_confirm(
            dir.path(),
            "prod",
            true,
            false,
            defaults::DEFAULT_PROD_ENV,
            || Ok(true),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn prod_with_interactive_confirm_no_fails() {
        let dir = root();
        let result = check_prod_barrier_with_confirm(
            dir.path(),
            "prod",
            true,
            false,
            defaults::DEFAULT_PROD_ENV,
            || Ok(false),
        );
        assert!(matches!(result, Err(GitvaultError::BarrierNotSatisfied(_))));
    }

    #[test]
    fn prod_confirmation_error_is_propagated() {
        let dir = root();
        let result = check_prod_barrier_with_confirm(
            dir.path(),
            "prod",
            true,
            false,
            defaults::DEFAULT_PROD_ENV,
            || Err(GitvaultError::Io(std::io::Error::other("read failed"))),
        );
        assert!(matches!(result, Err(GitvaultError::Io(_))));
    }

    #[test]
    fn read_confirmation_from_accepts_yes_case_insensitive() {
        let mut input = Cursor::new(b"Y\n".to_vec());
        let accepted = read_confirmation_from(&mut input).unwrap();
        assert!(accepted);
    }

    #[test]
    fn read_confirmation_from_rejects_other_values() {
        let mut input = Cursor::new(b"n\n".to_vec());
        let accepted = read_confirmation_from(&mut input).unwrap();
        assert!(!accepted);
    }

    /// REQ-85: confirm helper uses closure injection — no env-var hook needed.
    #[test]
    fn check_prod_barrier_interactive_yes_via_prompt_helper() {
        let dir = root();
        let result = check_prod_barrier_with_confirm(
            dir.path(),
            "prod",
            true,
            false,
            defaults::DEFAULT_PROD_ENV,
            || Ok(true),
        );
        assert!(result.is_ok());
    }

    /// REQ-85: confirm helper uses closure injection — no env-var hook needed.
    #[test]
    fn check_prod_barrier_interactive_no_via_prompt_helper() {
        let dir = root();
        let result = check_prod_barrier_with_confirm(
            dir.path(),
            "prod",
            true,
            false,
            defaults::DEFAULT_PROD_ENV,
            || Ok(false),
        );
        assert!(matches!(result, Err(GitvaultError::BarrierNotSatisfied(_))));
    }

    #[test]
    fn malformed_token_content_is_treated_as_invalid() {
        let dir = root();
        let token_path = dir.path().join(".git/gitvault/.prod-token");
        std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        std::fs::write(&token_path, "not-a-timestamp").unwrap();
        assert!(!has_valid_token(dir.path()));
    }

    /// REQ-79: bare timestamp (legacy format) must be rejected.
    #[test]
    fn bare_timestamp_token_is_rejected() {
        let dir = root();
        let token_path = dir.path().join(".git/gitvault/.prod-token");
        std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        // Write a future expiry but without HMAC — legacy format.
        std::fs::write(&token_path, "9999999999").unwrap();
        assert!(!has_valid_token(dir.path()));
    }

    /// REQ-79: token with wrong HMAC is rejected.
    #[test]
    fn tampered_hmac_token_is_rejected() {
        let dir = root();
        allow_prod(dir.path(), 3600).unwrap();
        // Overwrite with correct format but wrong MAC.
        let token_path = dir.path().join(".git/gitvault/.prod-token");
        let expiry = now_secs().unwrap() + 3600;
        std::fs::write(&token_path, format!("{expiry}:deadbeef")).unwrap();
        assert!(!has_valid_token(dir.path()));
    }

    #[test]
    fn revoke_prod_when_no_token_exists_is_noop() {
        let dir = root();
        revoke_prod(dir.path()).unwrap();
        assert!(!has_valid_token(dir.path()));
    }

    #[test]
    fn allow_prod_with_overflow_ttl_returns_error() {
        let dir = root();
        // u64::MAX exceeds MAX_TOKEN_TTL_SECS — should return Usage error (REQ-97).
        let result = allow_prod(dir.path(), u64::MAX);
        assert!(
            matches!(result, Err(GitvaultError::Usage(_))),
            "expected Usage error for TTL exceeding cap, got: {result:?}"
        );
    }

    /// REQ-97: TTL at exactly the cap is accepted.
    #[test]
    fn allow_prod_with_max_ttl_is_accepted() {
        let dir = root();
        assert!(allow_prod(dir.path(), MAX_TOKEN_TTL_SECS).is_ok());
    }

    /// REQ-97: TTL one second over the cap is rejected.
    #[test]
    fn allow_prod_with_ttl_over_cap_returns_usage_error() {
        let dir = root();
        let result = allow_prod(dir.path(), MAX_TOKEN_TTL_SECS + 1);
        assert!(
            matches!(result, Err(GitvaultError::Usage(_))),
            "expected Usage error for TTL {}, got: {result:?}",
            MAX_TOKEN_TTL_SECS + 1
        );
    }

    /// REQ-92: all-zero key loaded from disk is rejected.
    #[test]
    #[cfg(unix)]
    fn load_or_create_token_key_rejects_all_zero_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = root();
        let key_path = dir.path().join(TOKEN_KEY_FILE);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        // Write a 32-byte all-zero key as hex with correct 0600 permissions so that
        // the permissions check (REQ-102) passes and the entropy check (REQ-92) fires.
        std::fs::write(&key_path, hex::encode([0u8; 32])).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let result = load_or_create_token_key(dir.path());
        assert!(
            matches!(result, Err(GitvaultError::Other(ref m)) if m.contains("all-zeros")),
            "expected all-zeros error, got: {result:?}"
        );
    }

    /// REQ-102: key file with insecure permissions is rejected on load (Unix only).
    #[test]
    #[cfg(unix)]
    fn load_or_create_token_key_rejects_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = root();
        let key_path = dir.path().join(TOKEN_KEY_FILE);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        // Write a valid random key but with world-readable permissions.
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        std::fs::write(&key_path, hex::encode(key)).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let result = load_or_create_token_key(dir.path());
        assert!(
            matches!(result, Err(GitvaultError::Other(ref m)) if m.contains("insecure permissions")),
            "expected insecure permissions error, got: {result:?}"
        );
    }

    /// REQ-91: key file that doesn't exist causes a fresh key to be created (not a TOCTOU check).
    #[test]
    fn load_or_create_token_key_creates_key_when_absent() {
        let dir = root();
        let key = load_or_create_token_key(dir.path()).unwrap();
        assert_ne!(key, [0u8; 32], "freshly created key must not be all-zeros");
        let key_path = dir.path().join(TOKEN_KEY_FILE);
        assert!(key_path.exists(), "key file must be written to disk");
    }

    #[test]
    fn now_secs_returns_reasonable_timestamp() {
        assert!(now_secs().unwrap() > 946_684_800);
    }

    #[test]
    fn read_confirmation_from_returns_false_for_empty_input() {
        let mut input = Cursor::new(b"".to_vec());
        let accepted = read_confirmation_from(&mut input).unwrap();
        assert!(!accepted);
    }

    #[test]
    fn read_confirmation_from_accepts_lowercase_y() {
        let mut input = Cursor::new(b"y\n".to_vec());
        let accepted = read_confirmation_from(&mut input).unwrap();
        assert!(accepted);
    }

    /// Covers the `map_err(GitvaultError::Io)?` error branch in `read_confirmation_from`.
    #[test]
    fn read_confirmation_from_returns_io_error_on_read_failure() {
        struct FailingRead;
        impl std::io::Read for FailingRead {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("simulated read failure"))
            }
        }
        let mut reader = std::io::BufReader::new(FailingRead);
        let result = read_confirmation_from(&mut reader);
        assert!(matches!(result, Err(GitvaultError::Io(_))));
    }

    /// Covers the `fs::create_dir_all(parent)?` error branch in `allow_prod`
    /// by placing a regular file where the `.secrets` directory needs to be.
    #[test]
    fn allow_prod_fails_when_secrets_path_is_a_file() {
        let dir = root();
        std::fs::write(dir.path().join(".git"), "not a directory").unwrap();
        let result = allow_prod(dir.path(), 3600);
        assert!(
            result.is_err(),
            "allow_prod should fail when .secrets is a regular file"
        );
    }

    /// Covers the `NamedTempFile::new_in(token_parent)?` error branch in `allow_prod`
    /// by making the `.secrets` directory read-only after creating it.
    #[test]
    #[cfg(unix)]
    fn allow_prod_fails_when_token_dir_is_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = root();
        let secrets = dir.path().join(".git/gitvault");
        std::fs::create_dir_all(&secrets).unwrap();

        let mut perms = std::fs::metadata(&secrets).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&secrets, perms).unwrap();

        let result = allow_prod(dir.path(), 3600);

        let mut perms = std::fs::metadata(&secrets).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&secrets, perms).unwrap();

        assert!(
            result.is_err(),
            "allow_prod should fail with read-only .git/gitvault dir"
        );
    }

    /// Covers the `fs::remove_file(&token_path)?` error branch in `revoke_prod`
    /// by placing a directory at the token file path (`remove_file` on a dir → EISDIR).
    #[test]
    fn revoke_prod_fails_when_token_path_is_a_directory() {
        let dir = root();
        let token_dir = dir.path().join(".git/gitvault/.prod-token");
        std::fs::create_dir_all(&token_dir).unwrap();

        let result = revoke_prod(dir.path());
        assert!(
            result.is_err(),
            "revoke_prod should fail when token path is a directory"
        );
    }

    /// Covers line 183: `has_valid_token` returns false when expiry is non-numeric.
    #[test]
    fn has_valid_token_non_numeric_expiry_returns_false() {
        let dir = root();
        let token_path = dir.path().join(defaults::BARRIER_TOKEN_FILE);
        std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        std::fs::write(&token_path, "notanumber:fakemac").unwrap();
        assert!(
            !has_valid_token(dir.path()),
            "non-numeric expiry must be rejected"
        );
    }

    /// Covers line 195: `has_valid_token` returns false when the key file contains bad hex.
    #[test]
    fn has_valid_token_corrupt_key_file_returns_false() {
        let dir = root();
        // Write a future-expiry token in valid format.
        let expiry = now_secs().unwrap() + 9999;
        let token_path = dir.path().join(defaults::BARRIER_TOKEN_FILE);
        std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        std::fs::write(&token_path, format!("{expiry}:fakemachex")).unwrap();
        // Write corrupt hex to the key file.
        let key_path = dir.path().join(TOKEN_KEY_FILE);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(&key_path, "not_valid_hex!!").unwrap();
        assert!(
            !has_valid_token(dir.path()),
            "corrupt key file must cause token rejection"
        );
    }

    /// REQ-18 / C7: permissions must be set on the temp file BEFORE `persist()`
    #[test]
    #[cfg(unix)]
    fn test_token_permissions_applied_before_persist_no_toctou() {
        use std::os::unix::fs::PermissionsExt;

        let dir = root();
        let secrets = dir.path().join(".secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let tmp = tempfile::NamedTempFile::new_in(&secrets).unwrap();
        std::fs::write(tmp.path(), "9999999999").unwrap();

        let tmp_path = tmp.path().to_path_buf();
        enforce_restricted_token_permissions(&tmp_path).unwrap();

        let meta = std::fs::metadata(&tmp_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "temp token file must have 0600 BEFORE persist — got {mode:o}"
        );

        let final_path = secrets.join(".prod-token");
        tmp.persist(&final_path).unwrap();
        let final_meta = std::fs::metadata(&final_path).unwrap();
        let final_mode = final_meta.permissions().mode() & 0o777;
        assert_eq!(
            final_mode, 0o600,
            "final token file must have 0600 after persist — got {final_mode:o}"
        );
    }
}
