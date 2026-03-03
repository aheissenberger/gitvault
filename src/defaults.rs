//! Application-wide built-in default values.
//!
//! Every constant here is the value used when no configuration file or
//! environment variable provides an override. Centralising them in one place
//! makes it straightforward to later wire each one to a `[config.toml]` key
//! without hunting through the source tree.
//!
//! # Adding a new configurable default
//! 1. Define the constant here with a doc-comment explaining its role.
//! 2. Replace the hardcoded literal at the call-site with `defaults::THE_CONST`.
//! 3. When adding config-file support, keep the constant as the fallback value
//!    and apply the override with `config_value.unwrap_or(defaults::THE_CONST)`.

// ── Environment ───────────────────────────────────────────────────────────────

/// Environment name used when neither `GITVAULT_ENV` nor [`ENV_FILE`] is set.
pub const DEFAULT_ENV: &str = "dev";

/// Environment name that triggers the production barrier check.
pub const DEFAULT_PROD_ENV: &str = "prod";

/// Repository-relative path of the file that stores the active environment name.
pub const ENV_FILE: &str = ".secrets/env";

// ── Production barrier ────────────────────────────────────────────────────────

/// Default TTL in seconds for a production allow-token (REQ-14).
pub const DEFAULT_BARRIER_TTL_SECS: u64 = 3600;

/// Repository-relative path of the production allow-token file.
pub const BARRIER_TOKEN_FILE: &str = ".secrets/.prod-token";

// ── Repository layout ─────────────────────────────────────────────────────────

/// Directory under the repo root that holds encrypted `.age` artifacts (REQ-7).
pub const SECRETS_DIR: &str = "secrets";

/// Base directory under the repo root for decrypted plaintext outputs (REQ-8).
pub const PLAIN_BASE_DIR: &str = ".secrets/plain";

/// Repository-relative path of the persistent recipients list.
pub const RECIPIENTS_FILE: &str = ".secrets/recipients";

/// Repository-relative path written by `gitvault materialize` (REQ-16).
pub const MATERIALIZE_OUTPUT: &str = ".env";

// ── OS keyring ────────────────────────────────────────────────────────────────

/// OS keyring service name used to namespace gitvault credentials.
pub const KEYRING_SERVICE: &str = "gitvault";

/// OS keyring account / username under which the age identity key is stored.
pub const KEYRING_ACCOUNT: &str = "age-identity";
