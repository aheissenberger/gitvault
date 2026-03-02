//! Command implementations split from `main.rs`.
//!
//! Each sub-module owns one logical command group and its unit tests.

pub mod admin;
pub mod decrypt;
pub mod effects;
pub mod encrypt;
pub mod identity;
pub mod keyring;
pub mod materialize;
pub mod recipients;
pub mod run_cmd;

#[cfg(test)]
pub mod test_helpers;

pub use effects::CommandOutcome;
