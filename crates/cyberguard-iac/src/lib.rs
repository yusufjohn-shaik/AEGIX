#![deny(unsafe_code)]

//! # cyberguard-iac
//!
//! Pure-Rust Infrastructure as Code (IaC) static security engine for Aegix.
//! Inspects Kubernetes manifests (single/multi-doc YAML/JSON), Helm rendered templates,
//! and Terraform definitions (`.tf`, `.tf.json`, plan JSON) against CIS Kubernetes Benchmarks,
//! NSA/CISA Hardening Guidance, and CIS Cloud Foundations.
//!
//! Emits standardized OASIS SARIF v2.1.0 telemetry with baseline snapshot suppression,
//! deterministic location fingerprints (`logicalLocationTokenHash/v1`), and typed confidence.

pub mod engine;
pub mod error;
pub mod k8s;
pub mod models;
pub mod parser;
pub mod terraform;
pub mod traits;

pub use engine::IacEngine;
pub use error::IacError;
pub use models::*;
pub use traits::{IacScanner, K8sAuditor, TerraformAuditor};

pub mod prelude {
    pub use crate::engine::IacEngine;
    pub use crate::error::IacError;
    pub use crate::models::*;
    pub use crate::traits::{IacScanner, K8sAuditor, TerraformAuditor};
}
