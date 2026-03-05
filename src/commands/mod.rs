//! Command implementations split from `main.rs`.
//!
//! Each sub-module owns one logical command group and its unit tests.

pub mod admin;
pub mod ai;
pub mod decrypt;
pub mod effects;
pub mod encrypt;
pub mod identity;
pub mod init;
pub mod keyring;
pub mod materialize;
pub mod recipients;
pub mod run_cmd;
pub mod seal;

#[cfg(test)]
pub mod test_helpers;

pub use effects::CommandOutcome;
