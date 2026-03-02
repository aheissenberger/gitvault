//! Command implementations split from `main.rs`.
//!
//! Each sub-module owns one logical command group and its unit tests.

pub(crate) mod admin;
pub(crate) mod decrypt;
pub(crate) mod effects;
pub(crate) mod encrypt;
pub(crate) mod keyring;
pub(crate) mod materialize;
pub(crate) mod recipients;
pub(crate) mod run_cmd;

#[cfg(test)]
pub(crate) mod test_helpers;

pub(crate) use effects::CommandOutcome;
