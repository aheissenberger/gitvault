//! `.gitignore` management helpers.
//!
//! Gitignore entries are written via [`crate::materialize::ensure_gitignored`].
//! This module is the designated home for admin-layer gitignore logic (entry
//! validation, section management, etc.) that may be extracted here in the
//! future.
//!
//! # Required entries (managed by `cmd_harden`)
//!
//! The set of required gitignore patterns is defined in
//! [`crate::materialize::REQUIRED_GITIGNORE_ENTRIES`].  Additional per-file
//! patterns (e.g. `/.env`) are appended by `cmd_harden_with_files` when
//! individual plaintext files are imported as encrypted secrets.
