//! cyberguard-graph: In-memory Attack Path Graph and Exploit Correlation Engine for Aegix.
//!
//! Connects external entrypoints -> services -> vulnerabilities -> secrets -> assets -> impacts,
//! calculates compounding path risk, and isolates high-leverage remediation choke points.

#![deny(unsafe_code)]

pub mod correlation;
pub mod error;
pub mod ingestion;
pub mod models;
pub mod traits;

pub use correlation::*;
pub use error::*;
pub use ingestion::*;
pub use models::*;
pub use traits::*;
