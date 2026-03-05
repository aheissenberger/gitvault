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

/// Configuration for the `[env]` section.
///
/// All fields are `Option` — `None` means "use the built-in default from
/// [`defaults`]".  Callers resolve with e.g.
/// `cfg.env.default_env.as_deref().unwrap_or(defaults::DEFAULT_ENV)`.
#[derive(Debug, Default)]
pub struct EnvConfig {
    /// Default environment name when `GITVAULT_ENV` and the env file are both absent.
    /// `None` → [`defaults::DEFAULT_ENV`] (`"dev"`).
    pub default_env: Option<String>,

    /// Environment name that triggers the production barrier check.
    /// `None` → [`defaults::DEFAULT_PROD_ENV`] (`"prod"`).
    pub prod_name: Option<String>,
}

impl EnvConfig {
    /// Resolve the effective default environment name.
    #[must_use]
    pub fn default_env(&self) -> &str {
        self.default_env
            .as_deref()
            .unwrap_or(crate::defaults::DEFAULT_ENV)
    }

    /// Resolve the effective production environment name.
    #[must_use]
    pub fn prod_name(&self) -> &str {
        self.prod_name
            .as_deref()
            .unwrap_or(crate::defaults::DEFAULT_PROD_ENV)
    }
}

/// Configuration for the `[barrier]` section.
#[derive(Debug, Default)]
pub struct BarrierConfig {
    /// Token lifetime in seconds.
    /// `None` → [`defaults::DEFAULT_BARRIER_TTL_SECS`] (3600).
    pub ttl_secs: Option<u64>,
}

impl BarrierConfig {
    /// Resolve the effective TTL.
    #[must_use]
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
            .unwrap_or(crate::defaults::DEFAULT_BARRIER_TTL_SECS)
    }
}

/// Configuration for the `[paths]` section.
#[derive(Debug, Default)]
pub struct PathsConfig {
    /// Repository-relative path of the recipients directory (REQ-72 AC15).
    /// `None` → [`defaults::RECIPIENTS_DIR`] (`".secrets/recipients"`).
    pub recipients_dir: Option<String>,

    /// Filename written by `gitvault materialize`.
    /// `None` → [`defaults::MATERIALIZE_OUTPUT`] (`".env"`).
    pub materialize_output: Option<String>,

    /// Repository-relative path of the encrypted secrets store directory.
    /// `None` → [`defaults::SECRETS_DIR`] (`".gitvault/store"`).
    pub store_dir: Option<String>,
}

impl PathsConfig {
    /// Resolve the effective recipients directory path.
    #[must_use]
    pub fn recipients_dir(&self) -> &str {
        self.recipients_dir
            .as_deref()
            .unwrap_or(crate::defaults::RECIPIENTS_DIR)
    }

    /// Resolve the effective materialize output filename.
    #[must_use]
    pub fn materialize_output(&self) -> &str {
        self.materialize_output
            .as_deref()
            .unwrap_or(crate::defaults::MATERIALIZE_OUTPUT)
    }

    /// Resolve the effective encrypted store directory path.
    #[must_use]
    pub fn store_dir(&self) -> &str {
        self.store_dir
            .as_deref()
            .unwrap_or(crate::defaults::SECRETS_DIR)
    }
}

/// Configuration for the `[keyring]` section.
#[derive(Debug, Default)]
pub struct KeyringConfig {
    /// OS keyring service name.
    /// `None` → [`defaults::KEYRING_SERVICE`] (`"gitvault"`).
    pub service: Option<String>,

    /// OS keyring account / username.
    /// `None` → [`defaults::KEYRING_ACCOUNT`] (`"age-identity"`).
    pub account: Option<String>,
}

impl KeyringConfig {
    /// Resolve the effective keyring service name.
    #[must_use]
    pub fn service(&self) -> &str {
        self.service
            .as_deref()
            .unwrap_or(crate::defaults::KEYRING_SERVICE)
    }

    /// Resolve the effective keyring account name.
    #[must_use]
    pub fn account(&self) -> &str {
        self.account
            .as_deref()
            .unwrap_or(crate::defaults::KEYRING_ACCOUNT)
    }
}

/// Top-level gitvault project configuration.
#[derive(Debug, Default)]
pub struct GitvaultConfig {
    /// Hook-manager configuration.
    pub hooks: HooksConfig,
    /// Environment resolution configuration.
    pub env: EnvConfig,
    /// Production barrier configuration.
    pub barrier: BarrierConfig,
    /// Repository path layout configuration.
    pub paths: PathsConfig,
    /// OS keyring configuration.
    pub keyring: KeyringConfig,
    /// Seal configuration (REQ-112).
    pub seal: SealConfig,
}

// ---------------------------------------------------------------------------
// SealConfig (REQ-112 AC18)
// ---------------------------------------------------------------------------

/// Configuration for the `[seal]` section (REQ-112).
#[derive(Debug, Default)]
pub struct SealConfig {
    /// Glob patterns of files whose string fields should be sealed.
    pub patterns: Vec<String>,
    /// Per-file field overrides.
    pub overrides: Vec<SealOverride>,
    /// Files excluded from drift detection.
    pub excludes: Vec<SealExclude>,
}

/// A `[[seal.override]]` entry restricting sealing to named dot-path fields.
#[derive(Debug, Clone)]
pub struct SealOverride {
    pub pattern: String,
    pub fields: Vec<String>,
}

/// A `[[seal.exclude]]` entry that suppresses drift detection for matching files.
#[derive(Debug, Clone)]
pub struct SealExclude {
    pub pattern: String,
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

/// Intermediate TOML representation for `[env]`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvConfig {
    default: Option<String>,
    prod_name: Option<String>,
}

/// Intermediate TOML representation for `[barrier]`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBarrierConfig {
    ttl_secs: Option<u64>,
}

/// Intermediate TOML representation for `[paths]`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPathsConfig {
    recipients_dir: Option<String>,
    materialize_output: Option<String>,
    store_dir: Option<String>,
}

/// Intermediate TOML representation for `[keyring]`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyringConfig {
    service: Option<String>,
    account: Option<String>,
}

/// Intermediate TOML representation for the whole config file.
///
/// Unknown top-level sections are silently ignored; only recognised sections
/// are processed.
#[derive(Debug, serde::Deserialize)]
struct RawConfig {
    hooks: Option<RawHooksConfig>,
    env: Option<RawEnvConfig>,
    barrier: Option<RawBarrierConfig>,
    paths: Option<RawPathsConfig>,
    keyring: Option<RawKeyringConfig>,
    seal: Option<RawSealConfig>,
}

/// Intermediate TOML representation for `[[seal.override]]`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSealOverride {
    pattern: String,
    fields: Vec<String>,
}

/// Intermediate TOML representation for `[[seal.exclude]]`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSealExclude {
    pattern: String,
}

/// Intermediate TOML representation for `[seal]`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSealConfig {
    #[serde(default)]
    patterns: Vec<String>,
    #[serde(rename = "override", default)]
    overrides: Vec<RawSealOverride>,
    #[serde(rename = "exclude", default)]
    excludes: Vec<RawSealExclude>,
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

    let env = raw.env.map_or_else(EnvConfig::default, |r| EnvConfig {
        default_env: r.default.filter(|s| !s.is_empty()),
        prod_name: r.prod_name.filter(|s| !s.is_empty()),
    });

    let barrier = raw
        .barrier
        .map_or_else(BarrierConfig::default, |r| BarrierConfig {
            ttl_secs: r.ttl_secs,
        });

    let paths = raw
        .paths
        .map_or_else(PathsConfig::default, |r| PathsConfig {
            recipients_dir: r.recipients_dir.filter(|s| !s.is_empty()),
            materialize_output: r.materialize_output.filter(|s| !s.is_empty()),
            store_dir: r.store_dir.filter(|s| !s.trim().is_empty()),
        });

    let keyring = raw
        .keyring
        .map_or_else(KeyringConfig::default, |r| KeyringConfig {
            service: r.service.filter(|s| !s.is_empty()),
            account: r.account.filter(|s| !s.is_empty()),
        });

    let seal = raw.seal.map_or_else(SealConfig::default, |r| SealConfig {
        patterns: r.patterns,
        overrides: r
            .overrides
            .into_iter()
            .map(|o| SealOverride {
                pattern: o.pattern,
                fields: o.fields,
            })
            .collect(),
        excludes: r
            .excludes
            .into_iter()
            .map(|e| SealExclude { pattern: e.pattern })
            .collect(),
    });

    Ok(GitvaultConfig {
        hooks,
        env,
        barrier,
        paths,
        keyring,
        seal,
    })
}

/// Inner implementation for [`load_global_config`] that accepts an optional
/// home-directory override (used by tests to avoid touching `HOME`).
fn load_global_config_impl(home_override: Option<&Path>) -> Result<GitvaultConfig, GitvaultError> {
    let home_path = match home_override {
        Some(p) => p.to_path_buf(),
        // REQ-99: use dirs::home_dir() for cross-platform home resolution.
        None => match dirs::home_dir() {
            Some(h) => h,
            None => return Ok(GitvaultConfig::default()),
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

    let env = EnvConfig {
        default_env: repo.env.default_env.or(global.env.default_env),
        prod_name: repo.env.prod_name.or(global.env.prod_name),
    };

    let barrier = BarrierConfig {
        ttl_secs: repo.barrier.ttl_secs.or(global.barrier.ttl_secs),
    };

    let paths = PathsConfig {
        recipients_dir: repo.paths.recipients_dir.or(global.paths.recipients_dir),
        materialize_output: repo
            .paths
            .materialize_output
            .or(global.paths.materialize_output),
        store_dir: repo.paths.store_dir.or(global.paths.store_dir),
    };

    let keyring = KeyringConfig {
        service: repo.keyring.service.or(global.keyring.service),
        account: repo.keyring.account.or(global.keyring.account),
    };

    // Seal config: repo wins (repo-level config is authoritative).
    let seal = if !repo.seal.patterns.is_empty()
        || !repo.seal.overrides.is_empty()
        || !repo.seal.excludes.is_empty()
    {
        repo.seal
    } else {
        global.seal
    };

    Ok(GitvaultConfig {
        hooks: HooksConfig { adapter },
        env,
        barrier,
        paths,
        keyring,
        seal,
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
    use crate::commands::test_helpers::global_test_lock;
    use tempfile::TempDir;

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
        let config =
            load_global_config_impl(Some(home.path())).expect("valid global config should parse");
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

    /// Covers line 148: HOME is empty → `load_global_config_impl` returns default without reading.
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
        let config_toml_path = home
            .path()
            .join(".config")
            .join("gitvault")
            .join("config.toml");
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

    // -----------------------------------------------------------------------
    // [env] section tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_config_defaults() {
        let cfg = EnvConfig::default();
        assert_eq!(cfg.default_env(), crate::defaults::DEFAULT_ENV);
        assert_eq!(cfg.prod_name(), crate::defaults::DEFAULT_PROD_ENV);
    }

    #[test]
    fn test_parse_env_section_all_keys() {
        let dir = TempDir::new().unwrap();
        make_config_file(
            &dir,
            "[env]\ndefault = \"staging\"\nprod_name = \"production\"\n",
        );
        let config = load_config(dir.path()).expect("env section should parse");
        assert_eq!(config.env.default_env(), "staging");
        assert_eq!(config.env.prod_name(), "production");
    }

    #[test]
    fn test_parse_env_section_unknown_key_rejected() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[env]\nunknown_key = \"bad\"\n");
        let err = load_config(dir.path()).expect_err("unknown key in [env] should fail");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_env_empty_string_treated_as_unset() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[env]\ndefault = \"\"\n");
        let config = load_config(dir.path()).expect("empty env.default should parse as unset");
        assert_eq!(
            config.env.default_env(),
            crate::defaults::DEFAULT_ENV,
            "empty string should fall back to built-in default"
        );
    }

    // -----------------------------------------------------------------------
    // [barrier] section tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_barrier_config_defaults() {
        let cfg = BarrierConfig::default();
        assert_eq!(cfg.ttl_secs(), crate::defaults::DEFAULT_BARRIER_TTL_SECS);
    }

    #[test]
    fn test_parse_barrier_ttl_secs() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[barrier]\nttl_secs = 7200\n");
        let config = load_config(dir.path()).expect("barrier section should parse");
        assert_eq!(config.barrier.ttl_secs(), 7200);
    }

    #[test]
    fn test_parse_barrier_unknown_key_rejected() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[barrier]\nunknown = true\n");
        let err = load_config(dir.path()).expect_err("unknown key in [barrier] should fail");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    // -----------------------------------------------------------------------
    // [paths] section tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_paths_config_defaults() {
        let cfg = PathsConfig::default();
        assert_eq!(cfg.recipients_dir(), crate::defaults::RECIPIENTS_DIR);
        assert_eq!(
            cfg.materialize_output(),
            crate::defaults::MATERIALIZE_OUTPUT
        );
    }

    #[test]
    fn test_parse_paths_section() {
        let dir = TempDir::new().unwrap();
        make_config_file(
            &dir,
            "[paths]\nrecipients_dir = \".keys/recipients\"\nmaterialize_output = \"env.out\"\n",
        );
        let config = load_config(dir.path()).expect("paths section should parse");
        assert_eq!(config.paths.recipients_dir(), ".keys/recipients");
        assert_eq!(config.paths.materialize_output(), "env.out");
    }

    #[test]
    fn test_parse_paths_unknown_key_rejected() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[paths]\nbad_key = \"x\"\n");
        let err = load_config(dir.path()).expect_err("unknown key in [paths] should fail");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    // -----------------------------------------------------------------------
    // [keyring] section tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_keyring_config_defaults() {
        let cfg = KeyringConfig::default();
        assert_eq!(cfg.service(), crate::defaults::KEYRING_SERVICE);
        assert_eq!(cfg.account(), crate::defaults::KEYRING_ACCOUNT);
    }

    #[test]
    fn test_parse_keyring_section() {
        let dir = TempDir::new().unwrap();
        make_config_file(
            &dir,
            "[keyring]\nservice = \"myapp\"\naccount = \"my-key\"\n",
        );
        let config = load_config(dir.path()).expect("keyring section should parse");
        assert_eq!(config.keyring.service(), "myapp");
        assert_eq!(config.keyring.account(), "my-key");
    }

    #[test]
    fn test_parse_keyring_unknown_key_rejected() {
        let dir = TempDir::new().unwrap();
        make_config_file(&dir, "[keyring]\nbad_key = \"x\"\n");
        let err = load_config(dir.path()).expect_err("unknown key in [keyring] should fail");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    // -----------------------------------------------------------------------
    // effective_config merging for new sections
    // -----------------------------------------------------------------------

    #[test]
    fn test_effective_config_env_repo_wins_over_global() {
        let repo_dir = TempDir::new().unwrap();
        make_config_file(&repo_dir, "[env]\ndefault = \"repo-env\"\n");
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "[env]\ndefault = \"global-env\"\n");
        let config = effective_config_impl(repo_dir.path(), Some(home.path())).unwrap();
        assert_eq!(config.env.default_env(), "repo-env");
    }

    #[test]
    fn test_effective_config_env_global_fills_missing_repo() {
        let repo_dir = TempDir::new().unwrap();
        make_config_file(&repo_dir, "# no env section\n");
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "[env]\ndefault = \"global-env\"\n");
        let config = effective_config_impl(repo_dir.path(), Some(home.path())).unwrap();
        assert_eq!(config.env.default_env(), "global-env");
    }

    #[test]
    fn test_effective_config_barrier_merge() {
        let repo_dir = TempDir::new().unwrap();
        make_config_file(&repo_dir, "[barrier]\nttl_secs = 1800\n");
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "[barrier]\nttl_secs = 900\n");
        let config = effective_config_impl(repo_dir.path(), Some(home.path())).unwrap();
        assert_eq!(config.barrier.ttl_secs(), 1800, "repo ttl_secs should win");
    }

    #[test]
    fn test_effective_config_keyring_global_fills() {
        let repo_dir = TempDir::new().unwrap();
        make_config_file(&repo_dir, "# no keyring\n");
        let home = TempDir::new().unwrap();
        make_global_config_file(&home, "[keyring]\nservice = \"corp-vault\"\n");
        let config = effective_config_impl(repo_dir.path(), Some(home.path())).unwrap();
        assert_eq!(config.keyring.service(), "corp-vault");
        assert_eq!(
            config.keyring.account(),
            crate::defaults::KEYRING_ACCOUNT,
            "account not in global → built-in default"
        );
    }
}
