//! cyberguard-threat: Automated Threat Modeling & ATT&CK Matrix Engine for Aegix.
//!
//! Provides deterministic MITRE ATT&CK Enterprise/Cloud/Mobile/Container mapping,
//! STRIDE security property classification, and official ATT&CK Navigator Layer
//! (v4.5/v5.0) JSON exports.

#![deny(unsafe_code)]

pub mod catalog;
pub mod error;
pub mod mapper;
pub mod models;
pub mod navigator;
pub mod report;
pub mod scorer;
pub mod traits;

pub use catalog::*;
pub use error::ThreatError;
pub use mapper::*;
pub use models::*;
pub use navigator::*;
pub use report::*;
pub use scorer::*;
pub use traits::*;
