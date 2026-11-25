//! cyberguard-graph: In-memory Attack Path Graph and Exploit Correlation Engine for Aegix.
//!
//! Connects external entrypoints -> services -> vulnerabilities -> secrets -> assets -> impacts,
//! calculates compounding path risk, and isolates high-leverage remediation choke points.

#![deny(unsafe_code)]

pub mod error;
pub mod models;
pub mod traits;

pub use error::*;
pub use models::*;
pub use traits::*;
