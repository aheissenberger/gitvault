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
pub mod defaults;
pub mod dispatch;
pub mod env;
pub mod error;
pub mod fhsm;
pub mod fs_util;
pub mod git;
pub mod identity;
pub mod keyring_store;
pub mod matcher;
pub mod materialize;
pub mod merge;
pub mod output;
pub(crate) mod path_utils;
pub mod permissions;
pub mod repo;
pub mod run;
pub mod ssh;
#[cfg(feature = "ssm")]
pub mod ssm;
pub mod store;
pub mod structured;
