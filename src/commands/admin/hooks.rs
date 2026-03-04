//! Git hook helpers — installation status and hook-presence checks.
//!
//! Hook *installation* is performed by [`crate::repo::install_git_hooks`];
//! hook *removal* is handled by the corresponding `repo` helper.
//! This module is the designated home for any admin-layer hook logic (status
//! reporting, hook-file inspection, etc.) that may be extracted here in the
//! future.
//!
//! # Currently installed hooks
//!
//! | Hook       | Purpose                                           |
//! |------------|---------------------------------------------------|
//! | pre-commit | Block commits of tracked plaintext `.env` files.  |
//! | pre-push   | Run drift detection before every push.            |
