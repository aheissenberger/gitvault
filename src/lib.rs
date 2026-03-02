//! gitvault — git-native age-encrypted secrets manager.
//!
//! This library crate exposes the core modules for use in integration tests,
//! benchmarks, and as a dependency in other tools.

#[cfg(feature = "ssm")]
pub mod aws_config;
pub mod barrier;
pub mod cli;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod dispatch;
pub mod env;
pub mod error;
pub mod fhsm;
pub mod identity;
pub mod keyring_store;
pub mod materialize;
pub mod merge;
pub mod output;
pub mod permissions;
pub mod repo;
pub mod run;
#[cfg(feature = "ssm")]
pub mod ssm;
pub mod structured;
