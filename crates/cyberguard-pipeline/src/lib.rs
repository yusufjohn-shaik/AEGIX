#![deny(unsafe_code)]

//! # CyberGuard Pipeline (`cyberguard-pipeline`)
//!
//! High-performance, deterministic CI/CD Pipeline and SLSA Provenance Security Engine.
//! Audits GitHub Actions workflows, GitLab CI definitions, and SLSA v0.2 / v1.0
//! provenance attestations (including DSSE envelopes) against OWASP Top 10 CI/CD
//! security risks and CIS Software Supply Chain Security benchmarks.

pub mod engine;
pub mod error;
pub mod models;
pub mod parser;
pub mod slsa;
pub mod traits;
pub mod workflow;

pub use engine::PipelineEngine;
pub use error::PipelineError;
pub use models::{
    PipelineDocument, PipelineFinding, PipelineFormat, PipelineReport, PipelineRuleId,
    SlsaPredicate, SlsaStatement, WorkflowDefinition, WorkflowJob, WorkflowPermissions,
    WorkflowStep, WorkflowTriggers,
};
pub use traits::{PipelineScanner, SlsaAuditor, WorkflowAuditor};
