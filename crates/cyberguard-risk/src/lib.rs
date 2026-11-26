//! cyberguard-risk: Mathematical Tri-Factor Prioritizer & Rust Reachability Engine for Aegix.
//!
//! Computes `CVSS * EPSS * Reachability`, analyzes Cargo workspaces via `cargo metadata` (or pure-Rust
//! fallback) and deterministic Rust source call graphs, and enriches SARIF telemetry cleanly.

#![deny(unsafe_code)]

pub mod error;
pub mod models;
pub mod traits;

pub use error::*;
pub use models::*;
pub use traits::*;
