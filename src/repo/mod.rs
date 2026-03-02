//! `repo` module — git repository helpers for gitvault.
//!
//! Submodules:
//! - [`paths`]      — path helpers, directory management, encrypted/plain file listing
//! - [`hooks`]      — git hook installation/management
//! - [`drift`]      — uncommitted-change detection (drift)
//! - [`recipients`] — recipient key reading/writing

pub mod drift;
pub mod hooks;
pub mod paths;
pub mod plugin;
pub mod recipients;

// Re-export the full public API so callers using `crate::repo::*` continue to work
// without any changes.

pub use drift::{check_no_tracked_plaintext, has_secrets_drift};
pub use hooks::install_git_hooks;
pub use paths::{
    PLAIN_BASE_DIR, SECRETS_DIR, decrypt_env_secrets, ensure_dirs, find_repo_root,
    find_repo_root_from, get_encrypted_path, get_env_encrypted_dir, get_env_encrypted_path,
    get_plain_path, list_all_encrypted_files, list_encrypted_files_for_env, validate_write_path,
};
pub use recipients::{RECIPIENTS_FILE, read_recipients, write_recipients};

pub use plugin::{AdapterLookup, find_adapter_binary, invoke_adapter_harden};
