#![deny(unsafe_code)]
//! # CyberGuard Cloud (`aegix-cloud`)
//!
//! Cloud Security Posture Management (CSPM) and Cloud Infrastructure Entitlement
//! Management (CIEM) static audit engine in pure Rust.

pub mod ciem;
pub mod cspm;
pub mod engine;
pub mod error;
pub mod models;
pub mod parser;
pub mod traits;

pub use engine::CloudEngine;
pub use error::CloudError;
pub use models::{
    CloudAuditReport, CloudConfig, CloudFinding, CloudProvider, CloudResource, CloudResourceType,
    IamPolicy, Principal, SecurityGroupRule, Statement, StatementEffect, StringOrVec,
};
pub use traits::{CiemAuditor, CloudScanner, CspmAuditor};

pub mod prelude {
    pub use crate::engine::CloudEngine;
    pub use crate::error::CloudError;
    pub use crate::models::*;
    pub use crate::traits::*;
}
