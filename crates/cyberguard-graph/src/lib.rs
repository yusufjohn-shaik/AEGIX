//! cyberguard-graph: In-memory Attack Path Graph and Exploit Correlation Engine for Aegix.
//!
//! Connects external entrypoints -> services -> vulnerabilities -> secrets -> assets -> impacts,
//! calculates compounding path risk, and isolates high-leverage remediation choke points.

#![deny(unsafe_code)]

pub mod correlation;
pub mod error;
pub mod export;
pub mod ingestion;
pub mod models;
pub mod scoring;
pub mod traits;
pub mod traversal;

pub use correlation::*;
pub use error::*;
pub use export::*;
pub use ingestion::*;
pub use models::*;
pub use scoring::*;
pub use traits::*;
pub use traversal::*;
