//! Project-level configuration loaded from `.gitvault/config.toml`.
//!
//! The config file lives at `<repo-root>/.gitvault/config.toml` and is
//! optional — a missing file (or missing section) yields a default config.
//!
//! A user-global config at `~/.config/gitvault/config.toml` provides a
//! fallback layer.  Precedence (highest → lowest):
//! 1. Repository config  `.gitvault/config.toml`
//! 2. User-global config `~/.config/gitvault/config.toml`
//! 3. Built-in defaults

use std::path::Path;
use std::str::FromStr;

use crate::error::GitvaultError;

// ---------------------------------------------------------------------------
// HookAdapter
// ---------------------------------------------------------------------------

/// Known hook-manager adapter names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookAdapter {
    /// Husky — JS/TS hook manager (`gitvault-husky`).
    Husky,
    /// pre-commit — Python hook manager (`gitvault-pre-commit`).
    PreCommit,
    /// Lefthook — Go hook manager (`gitvault-lefthook`).
    Lefthook,
}

impl HookAdapter {
    /// Binary name to look up on PATH (e.g. `"gitvault-husky"`).
    #[must_use]
    pub const fn binary_name(&self) -> &'static str {
        match self {
            Self::Husky => "gitvault-husky",
            Self::PreCommit => "gitvault-pre-commit",
            Self::Lefthook => "gitvault-lefthook",
        }
    }

    /// Human-readable short name (e.g. `"husky"`).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Husky => "husky",
            Self::PreCommit => "pre-commit",
            Self::Lefthook => "lefthook",
        }
    }
}

impl FromStr for HookAdapter {
    type Err = GitvaultError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "husky" => Ok(Self::Husky),
            "pre-commit" => Ok(Self::PreCommit),
            "lefthook" => Ok(Self::Lefthook),
            other => Err(GitvaultError::Usage(format!(
                "unknown hook adapter '{other}'. Valid values: husky, pre-commit, lefthook"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Config structs
// ---------------------------------------------------------------------------

/// Configuration for the `[hooks]` section.
#[derive(Debug, Default)]
pub struct HooksConfig {
    /// The selected hook-manager adapter, if any.
    pub adapter: Option<HookAdapter>,
}

/// Top-level gitvault project configuration.
#[derive(Debug, Default)]
pub struct GitvaultConfig {
    /// Hook-manager configuration.
    pub hooks: HooksConfig,
}

// ---------------------------------------------------------------------------
// Serde intermediates (private)
// ---------------------------------------------------------------------------

/// Intermediate TOML representation for `[hooks]`.
///
/// Unknown fields inside `[hooks]` are rejected via `deny_unknown_fields`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHooksConfig {
    adapter: Option<String>,
}

/// Intermediate TOML representation for the whole config file.
///
/// Unknown top-level sections are silently ignored; only recognised sections
/// (`hooks`) are processed.
#[derive(Debug, serde::Deserialize)]
struct RawConfig {
    hooks: Option<RawHooksConfig>,
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Parse a TOML config text into a [`GitvaultConfig`].
///
/// `config_path` is only used in error messages.
/// Empty adapter strings are treated as `None` (unset).
fn parse_config_text(raw_text: &str, config_path: &Path) -> Result<GitvaultConfig, GitvaultError> {
    let raw: RawConfig = toml::from_str(raw_text).map_err(|e| {
        GitvaultError::Usage(format!("failed to parse {}: {e}", config_path.display()))
    })?;

    let hooks = match raw.hooks {
        None => HooksConfig { adapter: None },
        Some(raw_hooks) => {
            // An empty string is treated as "not set" — the next precedence
            // layer (or the built-in default) will supply the value.
            let adapter = raw_hooks
                .adapter
                .filter(|s| !s.is_empty())
                .map(|name| HookAdapter::from_str(&name))
                .transpose()?;
            HooksConfig { adapter }
        }
    };

    Ok(GitvaultConfig { hooks })
}

/// Inner implementation for [`load_global_config`] that accepts an optional
/// home-directory override (used by tests to avoid touching `HOME`).
fn load_global_config_impl(
    home_override: Option<&Path>,
) -> Result<GitvaultConfig, GitvaultError> {
    let home_path = match home_override {
        Some(p) => p.to_path_buf(),
        None => match std::env::var("HOME") {
            Ok(h) if !h.is_empty() => std::path::PathBuf::from(h),
            _ => return Ok(GitvaultConfig::default()),
        },
    };

    let config_path = home_path
        .join(".config")
        .join("gitvault")
        .join("config.toml");

    let raw_text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GitvaultConfig::default());
        }
        Err(e) => {
            return Err(GitvaultError::Usage(format!(
                "failed to read {}: {e}",
                config_path.display()
            )));
        }
    };

    parse_config_text(&raw_text, &config_path)
}

/// Inner implementation for [`effective_config`] that accepts an optional
/// home-directory override (used by tests).
fn effective_config_impl(
    repo_root: &Path,
    home_override: Option<&Path>,
) -> Result<GitvaultConfig, GitvaultError> {
    let repo = load_config(repo_root)?;
    let global = load_global_config_impl(home_override)?;

    // Repo config wins; fall back to global when repo has no value.
    let adapter = repo.hooks.adapter.or(global.hooks.adapter);

    Ok(GitvaultConfig {
        hooks: HooksConfig { adapter },
    })
}

// ---------------------------------------------------------------------------
// load_config
// ---------------------------------------------------------------------------

/// Load `.gitvault/config.toml` from `repo_root`.
///
/// Returns [`GitvaultConfig::default()`] when the file is absent or when the
/// `[hooks]` section is not present.  Returns [`GitvaultError::Usage`] for
/// unknown adapter names, unknown keys inside known sections, or TOML parse
/// errors.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] when the TOML cannot be parsed, when an
/// unknown adapter name is encountered, or when unknown keys appear inside the
/// `[hooks]` section.
pub fn load_config(repo_root: &Path) -> Result<GitvaultConfig, GitvaultError> {
    let config_path = repo_root.join(".gitvault").join("config.toml");

    let raw_text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GitvaultConfig::default());
        }
        Err(e) => {
            return Err(GitvaultError::Usage(format!(
                "failed to read {}: {e}",
                config_path.display()
            )));
        }
    };

    parse_config_text(&raw_text, &config_path)
}

// ---------------------------------------------------------------------------
// load_global_config
// ---------------------------------------------------------------------------

/// Load the user-global config from `~/.config/gitvault/config.toml`.
///
/// Returns [`GitvaultConfig::default()`] when:
/// - the file does not exist, or
/// - the `HOME` environment variable is unset or empty.
///
/// Returns [`GitvaultError::Usage`] when the TOML is malformed or when unknown
/// keys appear inside a known section.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] when the TOML cannot be parsed or when
/// unknown keys appear inside the `[hooks]` section.
pub fn load_global_config() -> Result<GitvaultConfig, GitvaultError> {
    load_global_config_impl(None)
}

// ---------------------------------------------------------------------------
// effective_config
// ---------------------------------------------------------------------------

/// Merge repository config and user-global config with deterministic precedence.
///
/// Precedence (highest → lowest):
/// 1. Repository config  `.gitvault/config.toml` (via `repo_root`)
/// 2. User-global config `~/.config/gitvault/config.toml`
/// 3. Built-in defaults
///
/// Empty-string adapter values in either layer are treated as unset so that
/// the next layer's value is used.
///
/// # Errors
///
/// Propagates any [`GitvaultError::Usage`] from either config loader.
pub fn effective_config(repo_root: &Path) -> Result<GitvaultConfig, GitvaultError> {
    effective_config_impl(repo_root, None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::commands::test_helpers::global_test_lock;

    fn make_config_file(dir: &TempDir, content: &str) {
        let gitvault_dir = dir.path().join(".gitvault");
        std::fs::create_dir_all(&gitvault_dir).unwrap();
        std::fs::write(gitvault_dir.join("config.toml"), content).unwrap();
    }

    /// Write a global config file at `<home_dir>/.config/gitvault/config.toml`.
    fn make_global_config_file(home_dir: &TempDir, content: &str) {
        let config_dir = home_dir.path().join(".config").join("gitvault");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.toml"), content).unwrap();
    }

    #[test]
    fn test_load_config_absent_file() {
        let dir = TempDir::new().unwrap();
        // No .gitvault directory at all.
        let config = load_config(dir.path()).expect("absent file should yield default config");
        assert!(config.hooks.adapter.is_none());
    }

    #[test]
    fn test_load_config_no_hooks_section() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[other]\nkey = \"value\"\n");
        let config =
            load_config(dir.path()).expect("missing hooks section should yield default config");
        assert!(config.hooks.adapter.is_none());
    }

    #[test]
    fn test_load_config_husky() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[hooks]\nadapter = \"husky\"\n");
        let config = load_config(dir.path()).expect("husky config should parse");
        assert_eq!(config.hooks.adapter, Some(HookAdapter::Husky));
    }

    #[test]
    fn test_load_config_pre_commit() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[hooks]\nadapter = \"pre-commit\"\n");
        let config = load_config(dir.path()).expect("pre-commit config should parse");
        assert_eq!(config.hooks.adapter, Some(HookAdapter::PreCommit));
    }

    #[test]
    fn test_load_config_lefthook() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[hooks]\nadapter = \"lefthook\"\n");
        let config = load_config(dir.path()).expect("lefthook config should parse");
        assert_eq!(config.hooks.adapter, Some(HookAdapter::Lefthook));
    }

    #[test]
    fn test_load_config_unknown_adapter() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[hooks]\nadapter = \"unknown-tool\"\n");
        let err = load_config(dir.path()).expect_err("unknown adapter should return error");
        assert!(matches!(err, GitvaultError::Usage(_)));
        assert!(err.to_string().contains("unknown-tool"));
    }

    #[test]
    fn test_load_config_empty_hooks() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[hooks]\n");
        let config = load_config(dir.path()).expect("[hooks] with no adapter key should parse");
        assert!(config.hooks.adapter.is_none());
    }

    #[test]
    fn test_hook_adapter_binary_names() {
        assert_eq!(HookAdapter::Husky.binary_name(), "gitvault-husky");
        assert_eq!(HookAdapter::PreCommit.binary_name(), "gitvault-pre-commit");
        assert_eq!(HookAdapter::Lefthook.binary_name(), "gitvault-lefthook");
    }

    #[test]
    fn test_hook_adapter_as_str() {
        assert_eq!(HookAdapter::Husky.as_str(), "husky");
        assert_eq!(HookAdapter::PreCommit.as_str(), "pre-commit");
        assert_eq!(HookAdapter::Lefthook.as_str(), "lefthook");
    }

    #[test]
    fn test_hook_adapter_from_str_valid() {
        assert_eq!(HookAdapter::from_str("husky").unwrap(), HookAdapter::Husky);
        assert_eq!(
            HookAdapter::from_str("pre-commit").unwrap(),
            HookAdapter::PreCommit
        );
        assert_eq!(
            HookAdapter::from_str("lefthook").unwrap(),
            HookAdapter::Lefthook
        );
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "this is not valid toml ::::\n");
        let err = load_config(dir.path()).expect_err("invalid TOML should return Usage error");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    // -----------------------------------------------------------------------
    // REQ-68: load_global_config tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_global_config_absent_returns_default() {
        // A home dir with no .config/gitvault directory at all.
        let home = TempDir::new().unwrap();
        let config = load_global_config_impl(Some(home.path()))
            .expect("absent global config file should yield default config");
        assert!(config.hooks.adapter.is_none());
    }

    #[test]
    fn test_global_config_valid() {
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "[hooks]\nadapter = \"lefthook\"\n");
        let config = load_global_config_impl(Some(home.path()))
            .expect("valid global config should parse");
        assert_eq!(config.hooks.adapter, Some(HookAdapter::Lefthook));
    }

    #[test]
    fn test_global_config_malformed_toml() {
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "this is not valid toml ::::\n");
        let err = load_global_config_impl(Some(home.path()))
            .expect_err("malformed global config should return Usage error");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_global_config_unknown_key() {
        // Unknown field inside [hooks] must be rejected by deny_unknown_fields.
        let home = TempDir::new().unwrap();
        make_global_config_file(
            &home,
            "[hooks]\nadapter = \"husky\"\nunknown_field = \"bad\"\n",
        );
        let err = load_global_config_impl(Some(home.path()))
            .expect_err("unknown key in [hooks] should return Usage error");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    // -----------------------------------------------------------------------
    // REQ-68: effective_config tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_effective_config_repo_wins_over_global() {
        // Repo config has pre-commit; global has husky.  Repo should win.
        let repo_dir = TempDir::new().unwrap();
        make_config_file(&repo_dir, "[hooks]\nadapter = \"pre-commit\"\n");
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "[hooks]\nadapter = \"husky\"\n");

        let config = effective_config_impl(repo_dir.path(), Some(home.path()))
            .expect("effective_config should succeed");
        assert_eq!(
            config.hooks.adapter,
            Some(HookAdapter::PreCommit),
            "repo config (pre-commit) should win over global config (husky)"
        );
    }

    #[test]
    fn test_effective_config_global_fills_missing_repo() {
        // Repo config has no adapter; global has lefthook.  Global fills in.
        let repo_dir = TempDir::new().unwrap();
        make_config_file(&repo_dir, "[hooks]\n");
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "[hooks]\nadapter = \"lefthook\"\n");

        let config = effective_config_impl(repo_dir.path(), Some(home.path()))
            .expect("effective_config should succeed");
        assert_eq!(
            config.hooks.adapter,
            Some(HookAdapter::Lefthook),
            "global config (lefthook) should fill in when repo has no adapter"
        );
    }

    #[test]
    fn test_effective_config_empty_adapter_treated_as_unset() {
        // Repo config explicitly sets adapter to empty string → treated as unset.
        // Global config has lefthook → should be used as fallback.
        let repo_dir = TempDir::new().unwrap();
        make_config_file(&repo_dir, "[hooks]\nadapter = \"\"\n");
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "[hooks]\nadapter = \"lefthook\"\n");

        let config = effective_config_impl(repo_dir.path(), Some(home.path()))
            .expect("effective_config should succeed");
        assert_eq!(
            config.hooks.adapter,
            Some(HookAdapter::Lefthook),
            "empty adapter string should be treated as unset, falling back to global (lefthook)"
        );
    }

    #[test]
    fn test_effective_config_no_files() {
        // Both repo and global configs absent → all defaults (adapter = None).
        let repo_dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();

        let config = effective_config_impl(repo_dir.path(), Some(home.path()))
            .expect("effective_config with no files should succeed");
        assert!(
            config.hooks.adapter.is_none(),
            "with no config files at all, adapter should be None"
        );
    }

    // -----------------------------------------------------------------------
    // Additional coverage: load_global_config public fn + error paths
    // -----------------------------------------------------------------------

    /// Covers the public `load_global_config()` function (lines 242-244).
    #[test]
    fn test_load_global_config_public_function_uses_home() {
        let _lock = global_test_lock().lock().unwrap();
        // Point HOME to an empty temp dir → no global config file → returns default.
        let home = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let result = load_global_config();
        match original_home {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let config = result.expect("load_global_config with no global config should succeed");
        assert!(config.hooks.adapter.is_none());
    }

    /// Covers line 148: HOME is empty → load_global_config_impl returns default without reading.
    #[test]
    fn test_load_global_config_empty_home_returns_default() {
        let _lock = global_test_lock().lock().unwrap();
        let original_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", "") };
        let result = load_global_config_impl(None);
        match original_home {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let config = result.expect("empty HOME should yield default config");
        assert!(config.hooks.adapter.is_none());
    }

    /// Covers lines 162-166: non-NotFound IO error reading global config.
    /// We create a directory at the config.toml path so reading it yields EISDIR.
    #[test]
    fn test_load_global_config_io_error_returns_usage_error() {
        let home = TempDir::new().unwrap();
        // Create a *directory* at the config.toml path → read_to_string fails with EISDIR.
        let config_toml_path = home.path().join(".config").join("gitvault").join("config.toml");
        std::fs::create_dir_all(&config_toml_path).unwrap();
        let err = load_global_config_impl(Some(home.path()))
            .expect_err("reading a dir as config should fail");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error, got: {err}"
        );
    }

    /// Covers lines 214-218: non-NotFound IO error reading repo config.
    #[test]
    fn test_load_config_io_error_returns_usage_error() {
        let dir = TempDir::new().unwrap();
        // Create a *directory* at .gitvault/config.toml → read_to_string fails with EISDIR.
        let config_toml_path = dir.path().join(".gitvault").join("config.toml");
        std::fs::create_dir_all(&config_toml_path).unwrap();
        let err = load_config(dir.path()).expect_err("reading a dir as config should fail");
        assert!(
            matches!(err, GitvaultError::Usage(_)),
            "expected Usage error, got: {err}"
        );
    }
}
