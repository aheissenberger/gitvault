//! `gitvault decrypt` command implementation.
//!
//! REQ-114: Accepts either the original source path (e.g. `services/auth/config.json`)
//! or an explicit `.age` store path for backward compatibility.

use std::path::{Path, PathBuf};

use crate::commands::effects::CommandOutcome;
use crate::error::GitvaultError;
use crate::identity::{load_identity_from_source_with_selector, load_identity_with_selector};
use crate::path_utils::make_repo_relative;
use crate::{crypto, fhsm, store};

/// Options for the [`cmd_decrypt`] command.
pub struct DecryptOptions {
    /// Path to the source file or explicit `.age` store path.
    pub file: String,
    /// Path to an age identity file.
    pub identity: Option<String>,
    /// Environment for store path resolution.
    pub env: Option<String>,
    /// Print decrypted value to stdout instead of writing to file.
    pub reveal: bool,
    /// Emit JSON output.
    pub json: bool,
    /// Suppress interactive prompts.
    pub no_prompt: bool,
    /// Identity selector to narrow the identity source.
    pub selector: Option<String>,
}

/// Apply the two-part explicit-store-path check (AC2).
///
/// Returns `true` when `repo_relative` has the `.age` extension **and** begins
/// with `.gitvault/store/`.
///
/// All checks are purely lexical — no filesystem access.
fn is_explicit_store_path(repo_relative: &Path) -> bool {
    let has_age = repo_relative.extension().is_some_and(|e| e == "age");
    has_age && repo_relative.starts_with(".gitvault/store/")
}

/// Parse the environment name from an explicit store path.
///
/// Expects the store path (repo-relative) to begin with `.gitvault/store/<env>/`.
/// Returns the first path component after `.gitvault/store/`.
fn parse_env_from_store_path(repo_relative: &Path) -> Result<String, GitvaultError> {
    // Strip ".gitvault/store/" prefix
    let after_store = repo_relative.strip_prefix(".gitvault/store").map_err(|_| {
        GitvaultError::Usage(format!(
            "explicit .age store path must begin with '.gitvault/store/': {}",
            repo_relative.display()
        ))
    })?;

    // The first remaining component is the env.
    let env = after_store
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
        .ok_or_else(|| {
            GitvaultError::Usage(format!(
                "cannot parse environment from store path: {}",
                repo_relative.display()
            ))
        })?
        .to_string();
    Ok(env)
}

/// Derive the relative source path from an absolute store path.
///
/// Strips `<repo_root>/.gitvault/store/<env>/` and the trailing `.age` suffix.
///
/// Example: `/repo/.gitvault/store/prod/services/auth/config.json.age`
/// → `services/auth/config.json`
fn derive_relative_source(
    abs_store_path: &Path,
    env: &str,
    repo_root: &Path,
) -> Result<PathBuf, GitvaultError> {
    // Make store path repo-relative.
    let rel = make_repo_relative(abs_store_path, repo_root);

    // Strip ".gitvault/store/<env>/" prefix.
    let prefix = PathBuf::from(".gitvault/store").join(env);
    let after_prefix = rel.strip_prefix(&prefix).map_err(|_| {
        GitvaultError::Usage(format!(
            "store path '{}' does not begin with '.gitvault/store/{env}/'",
            rel.display()
        ))
    })?;

    // Strip the ".age" suffix from the file name.
    let file_name = after_prefix
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| GitvaultError::Usage("store path has no file name".to_string()))?;
    let source_name = file_name
        .strip_suffix(".age")
        .unwrap_or(file_name)
        .to_string();

    let source_rel = match after_prefix.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(source_name),
        _ => PathBuf::from(source_name),
    };
    Ok(source_rel)
}

/// Decrypt a file from the `.gitvault/store/<env>/` archive.
///
/// Accepts either the original source path (source-path resolution) or an
/// explicit `.age` store path (backward compatibility).
///
/// # Errors
///
/// Returns [`GitvaultError`] if the identity cannot be loaded, the store path
/// cannot be found or read, decryption fails, or the output path is outside
/// the repository root.
pub fn cmd_decrypt(opts: DecryptOptions) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let input_path = PathBuf::from(&opts.file);

    // ── Determine whether this is an explicit store path (AC2) ───────────────
    let repo_relative = make_repo_relative(&input_path, &repo_root);
    let explicit = is_explicit_store_path(&repo_relative);

    let (store_path, env_name): (PathBuf, String) = if explicit {
        // Parse env from the store path itself.
        let env_from_path = parse_env_from_store_path(&repo_relative)?;

        // If the user also supplied --env, warn that it is ignored (AC6).
        if let Some(ref user_env) = opts.env {
            eprintln!(
                "gitvault: warning: --env {user_env} is ignored when an explicit .age store path is given; using env '{env_from_path}' from the store path."
            );
        }

        // Normalise to absolute path (lexical, no canonicalize).
        let abs = if input_path.is_absolute() {
            input_path.clone()
        } else {
            repo_root.join(&input_path)
        };
        (abs, env_from_path)
    } else {
        // Source-path resolution: need an env name.
        let env_name = opts
            .env
            .clone()
            .unwrap_or_else(|| crate::env::resolve_env(&repo_root, &Default::default()));

        // Validate env name (prevents path traversal via env).
        crate::env::validate_env_name(&env_name)?;

        let resolved = store::resolve_store_path(&input_path, &env_name, &repo_root)?;
        (resolved, env_name)
    };

    // ── Load identity ────────────────────────────────────────────────────────
    let event = fhsm::Event::Decrypt {
        file: opts.file.clone(),
        identity: opts.identity.clone(),
        no_prompt: opts.no_prompt,
        output: None,
    };
    let effects = fhsm::transition(&event)?;
    let identity_str = effects
        .iter()
        .find_map(|e| {
            if let fhsm::Effect::ResolveIdentity { source } = e {
                Some(load_identity_from_source_with_selector(
                    source,
                    opts.selector.as_deref(),
                ))
            } else {
                None
            }
        })
        .unwrap_or_else(|| load_identity_with_selector(None, opts.selector.as_deref()))?;

    let any_identity = crypto::parse_identity_any_with_passphrase(
        &identity_str,
        crate::identity::try_fetch_ssh_passphrase(
            crate::defaults::KEYRING_SERVICE,
            crate::defaults::KEYRING_ACCOUNT,
            opts.no_prompt,
        ),
    )?;
    let identity = any_identity.as_identity();

    // ── Reveal mode (AC6) ────────────────────────────────────────────────────
    if opts.reveal {
        let in_file = std::io::BufReader::new(std::fs::File::open(&store_path)?);
        let mut stdout = std::io::BufWriter::new(std::io::stdout());
        crypto::decrypt_stream(identity, in_file, &mut stdout)?;
        return Ok(CommandOutcome::Success);
    }

    // ── Materialise: write to <PLAIN_BASE_DIR>/<env>/<relative-source-path> ─
    let rel_source = derive_relative_source(&store_path, &env_name, &repo_root)?;
    let out_path = repo_root
        .join(crate::defaults::PLAIN_BASE_DIR)
        .join(&env_name)
        .join(&rel_source);

    // REQ-42: prevent path traversal.
    crate::repo::validate_write_path(&repo_root, &out_path)?;

    if let Some(parent) = out_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }

    // Streaming decryption via temp file (atomic write).
    let tmp = tempfile::NamedTempFile::new_in(
        out_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    )?;
    {
        let in_file = std::io::BufReader::new(std::fs::File::open(&store_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::decrypt_stream(identity, in_file, &mut out_file)?;
    }
    tmp.persist(&out_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    crate::output::output_success(&format!("Decrypted to {}", out_path.display()), opts.json);
    Ok(CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use tempfile::TempDir;

    /// Normalize a [`TempDir`] path so Windows 8.3 short names (e.g. `RUNNER~1`)
    /// are expanded to their long-name equivalents before use in assertions.
    fn norm_root(dir: &TempDir) -> PathBuf {
        crate::path_utils::normalize_for_comparison(dir.path())
    }

    /// Reveal mode: explicit store path → decrypts to stdout.
    #[test]
    fn test_cmd_decrypt_reveal_explicit_store_path() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Write encrypted file directly to store path.
        write_encrypted_env_file(
            dir.path(),
            "dev",
            "secret.env.age",
            &identity,
            "TOP_SECRET=1\n",
        );
        let store_path = crate::repo::get_env_encrypted_path(dir.path(), "dev", "secret.env.age");

        cmd_decrypt(DecryptOptions {
            file: store_path.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            env: None,
            reveal: true,
            json: true,
            no_prompt: true,
            selector: None,
        })
        .expect("reveal mode with explicit store path should succeed");
    }

    /// Reveal mode: source path → auto-resolves store path, decrypts to stdout.
    #[test]
    fn test_cmd_decrypt_reveal_source_path() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Create the source file before encrypting.
        std::fs::write(dir.path().join("app.env"), "SECRET=hello\n").unwrap();

        // Encrypt `app.env` into the store.
        with_identity_env(identity_file.path(), || {
            crate::commands::encrypt::cmd_encrypt(
                "app.env".to_string(),
                vec![identity.to_public().to_string()],
                None,
                false,
            )
            .expect("encrypt should succeed");
        });

        // Decrypt by source path with --reveal.
        cmd_decrypt(DecryptOptions {
            file: "app.env".to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            env: Some("dev".to_string()),
            reveal: true,
            json: true,
            no_prompt: true,
            selector: None,
        })
        .expect("source-path reveal should succeed");
    }

    /// Materialisation: source path → writes to <PLAIN_BASE_DIR>/<env>/<relative-source-path>.
    #[test]
    fn test_cmd_decrypt_materialise_writes_to_plain_base_dir() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Create a nested source file and encrypt it.
        let nested = dir.path().join("services/auth");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("config.json"), r#"{"key":"val"}"#).unwrap();

        with_identity_env(identity_file.path(), || {
            crate::commands::encrypt::cmd_encrypt(
                "services/auth/config.json".to_string(),
                vec![identity.to_public().to_string()],
                Some("prod".to_string()),
                false,
            )
            .expect("encrypt should succeed");
        });

        // Decrypt by source path (no --reveal) → materialise.
        cmd_decrypt(DecryptOptions {
            file: "services/auth/config.json".to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            env: Some("prod".to_string()),
            reveal: false,
            json: true,
            no_prompt: true,
            selector: None,
        })
        .expect("materialise should succeed");

        // AC10: output must be at <PLAIN_BASE_DIR>/prod/services/auth/config.json
        let expected = dir
            .path()
            .join(crate::defaults::PLAIN_BASE_DIR)
            .join("prod/services/auth/config.json");
        assert!(
            expected.exists(),
            "expected materialised file at {}",
            expected.display()
        );
        let content = std::fs::read_to_string(&expected).unwrap();
        assert!(
            content.contains("\"key\""),
            "content should be the decrypted JSON"
        );
    }

    /// AC10: source-path resolution delegates to compute_store_path correctly.
    #[test]
    fn test_resolve_store_path_via_source_computes_correct_mirrored_path() {
        let dir = TempDir::new().unwrap();
        let repo_root = norm_root(&dir);
        let repo_root = repo_root.as_path();
        let source = repo_root.join("services/auth/config.json");

        // Create the store file so exists-check passes.
        let store_dir = repo_root.join(".gitvault/store/prod/services/auth");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::write(store_dir.join("config.json.age"), b"").unwrap();

        let result = store::resolve_store_path(&source, "prod", repo_root).unwrap();
        assert_eq!(
            result,
            repo_root.join(".gitvault/store/prod/services/auth/config.json.age"),
            "source path should resolve to mirrored .age store path"
        );
    }

    /// AC10: absolute .age store path under repo root is recognised as explicit store path.
    #[test]
    fn test_absolute_age_store_path_is_recognised_as_explicit() {
        let dir = TempDir::new().unwrap();
        let repo_root = norm_root(&dir);
        let repo_root = repo_root.as_path();
        // Absolute path under .gitvault/store/
        let abs_store = repo_root.join(".gitvault/store/dev/app.env.age");

        let result = store::resolve_store_path(&abs_store, "dev", repo_root).unwrap();
        assert_eq!(
            result, abs_store,
            "absolute store path should be returned unchanged"
        );
    }

    /// AC10: materialisation writes to <PLAIN_BASE_DIR>/<env>/<relative-source-path>.
    #[test]
    fn test_materialisation_path_not_adjacent_to_input() {
        let dir = TempDir::new().unwrap();
        let repo_root = norm_root(&dir);
        let repo_root = repo_root.as_path();
        let env = "staging";

        // Simulate an explicit .age store path.
        let store_path = repo_root.join(".gitvault/store/staging/app/config.yaml.age");
        let rel = derive_relative_source(&store_path, env, repo_root).unwrap();
        let out = repo_root
            .join(crate::defaults::PLAIN_BASE_DIR)
            .join(env)
            .join(&rel);

        let expected = repo_root
            .join(crate::defaults::PLAIN_BASE_DIR)
            .join("staging/app/config.yaml");
        assert_eq!(
            out, expected,
            "materialised path should be under PLAIN_BASE_DIR"
        );
    }

    /// Source-path resolution fails with NotFound when no store file exists.
    #[test]
    fn test_cmd_decrypt_source_path_not_found_error() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let err = cmd_decrypt(DecryptOptions {
            file: "nonexistent.env".to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            env: Some("dev".to_string()),
            reveal: true,
            json: false,
            no_prompt: true,
            selector: None,
        })
        .expect_err("missing source file should fail");

        assert!(
            matches!(err, GitvaultError::NotFound(_)),
            "expected NotFound error, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("No encrypted archive found"),
            "error should have AC5 message: {msg}"
        );
    }

    /// Explicit store path: env warning is emitted when --env is also given.
    #[test]
    fn test_env_warning_when_explicit_store_path_and_env_given() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        write_encrypted_env_file(dir.path(), "dev", "warn.env.age", &identity, "W=1\n");
        let store_path = crate::repo::get_env_encrypted_path(dir.path(), "dev", "warn.env.age");

        // Should succeed even though --env prod conflicts with path env 'dev'.
        // (warning emitted to stderr; we just verify the command succeeds)
        let result = cmd_decrypt(DecryptOptions {
            file: store_path.to_string_lossy().to_string(),
            identity: Some(identity_file.path().to_string_lossy().to_string()),
            env: Some("prod".to_string()),
            reveal: true,
            json: false,
            no_prompt: true,
            selector: None,
        });
        assert!(
            result.is_ok(),
            "should succeed despite env mismatch: {result:?}"
        );
    }

    /// derive_relative_source: correctly strips prefix and .age suffix.
    #[test]
    fn test_derive_relative_source_nested() {
        let dir = TempDir::new().unwrap();
        let repo_root = norm_root(&dir);
        let repo_root = repo_root.as_path();
        let store_path = repo_root.join(".gitvault/store/prod/svc/api/config.json.age");

        let rel = derive_relative_source(&store_path, "prod", repo_root).unwrap();
        assert_eq!(rel, PathBuf::from("svc").join("api").join("config.json"));
    }

    /// parse_env_from_store_path: extracts environment from repo-relative store path.
    #[test]
    fn test_parse_env_from_store_path() {
        let rel = std::path::Path::new(".gitvault/store/staging/app.env.age");
        let env = parse_env_from_store_path(rel).unwrap();
        assert_eq!(env, "staging");
    }

    /// parse_env_from_store_path: error when path doesn't start with .gitvault/store
    #[test]
    fn test_parse_env_from_store_path_error_when_wrong_prefix() {
        let rel = std::path::Path::new("wrong/path/app.env.age");
        let err = parse_env_from_store_path(rel).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    /// is_explicit_store_path: correct positive case
    #[test]
    fn test_is_explicit_store_path_positive() {
        let path = std::path::Path::new(".gitvault/store/dev/app.env.age");
        assert!(is_explicit_store_path(path));
    }

    /// is_explicit_store_path: false for source paths
    #[test]
    fn test_is_explicit_store_path_negative_no_age() {
        let path = std::path::Path::new(".gitvault/store/dev/app.env");
        assert!(!is_explicit_store_path(path));
    }

    #[test]
    fn test_is_explicit_store_path_negative_wrong_prefix() {
        let path = std::path::Path::new("other/store/dev/app.env.age");
        assert!(!is_explicit_store_path(path));
    }

    /// parse_env_from_store_path: error when path ends at .gitvault/store with no env component.
    #[test]
    fn test_parse_env_from_store_path_error_when_no_env_component() {
        let rel = std::path::Path::new(".gitvault/store");
        let err = parse_env_from_store_path(rel).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    /// derive_relative_source: error when store path does not match the given env.
    #[test]
    fn test_derive_relative_source_error_on_prefix_mismatch() {
        let dir = TempDir::new().unwrap();
        let repo_root = norm_root(&dir);
        let repo_root = repo_root.as_path();
        let store_path = repo_root.join(".gitvault/store/prod/file.age");
        let err = derive_relative_source(&store_path, "staging", repo_root).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    /// derive_relative_source: flat file (no subdirectory) yields just the filename.
    #[test]
    fn test_derive_relative_source_flat_file() {
        let dir = TempDir::new().unwrap();
        let repo_root = norm_root(&dir);
        let repo_root = repo_root.as_path();
        let store_path = repo_root.join(".gitvault/store/prod/config.json.age");
        let rel = derive_relative_source(&store_path, "prod", repo_root).unwrap();
        assert_eq!(rel, PathBuf::from("config.json"));
    }
}
