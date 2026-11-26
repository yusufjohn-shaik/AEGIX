//! cyberguard-risk: Mathematical Tri-Factor Prioritizer & Rust Reachability Engine for Aegix.
//!
//! Computes `CVSS * EPSS * Reachability`, analyzes Cargo workspaces via `cargo metadata` (or pure-Rust
//! fallback) and deterministic Rust source call graphs, and enriches SARIF telemetry cleanly.

#![deny(unsafe_code)]

pub mod call_graph;
pub mod cargo_graph;
pub mod engine;
pub mod epss;
pub mod error;
pub mod export;
pub mod models;
pub mod scorer;
pub mod traits;

pub use call_graph::*;
pub use cargo_graph::*;
pub use engine::*;
pub use epss::*;
pub use error::*;
pub use export::*;
pub use models::*;
pub use scorer::*;
pub use traits::*;
