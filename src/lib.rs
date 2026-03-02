//! gitvault — Git-native secrets manager library.
//!
//! Re-exports the public API for use as a library crate.
//! This minimal set exposes the core error types and pure-logic modules
//! that are safe to use from downstream crates without pulling in binary-only deps.

pub mod error;
pub mod fhsm;
