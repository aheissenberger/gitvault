//! Project-level configuration loaded from `.gitvault/config.toml`.
//!
//! The config file lives at `<repo-root>/.gitvault/config.toml` and is
//! optional — a missing file (or missing section) yields a default config.

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
#[derive(Debug, serde::Deserialize)]
struct RawHooksConfig {
    adapter: Option<String>,
}

/// Intermediate TOML representation for the whole config file.
#[derive(Debug, serde::Deserialize)]
struct RawConfig {
    hooks: Option<RawHooksConfig>,
}

// ---------------------------------------------------------------------------
// load_config
// ---------------------------------------------------------------------------

/// Load `.gitvault/config.toml` from `repo_root`.
///
/// Returns [`GitvaultConfig::default()`] when the file is absent or when the
/// `[hooks]` section is not present.  Returns [`GitvaultError::Usage`] for
/// unknown adapter names or TOML parse errors.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] when the TOML cannot be parsed or when an
/// unknown adapter name is encountered.
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

    let raw: RawConfig = toml::from_str(&raw_text).map_err(|e| {
        GitvaultError::Usage(format!("failed to parse {}: {e}", config_path.display()))
    })?;

    let hooks = match raw.hooks {
        None => HooksConfig { adapter: None },
        Some(raw_hooks) => {
            let adapter = raw_hooks
                .adapter
                .map(|name| HookAdapter::from_str(&name))
                .transpose()?;
            HooksConfig { adapter }
        }
    };

    Ok(GitvaultConfig { hooks })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_config_file(dir: &TempDir, content: &str) {
        let gitvault_dir = dir.path().join(".gitvault");
        std::fs::create_dir_all(&gitvault_dir).unwrap();
        std::fs::write(gitvault_dir.join("config.toml"), content).unwrap();
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
}
