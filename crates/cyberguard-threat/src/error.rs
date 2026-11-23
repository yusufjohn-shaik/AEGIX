//! Strongly typed error taxonomy for Module 15 Threat Modeling & ATT&CK Matrix Engine.

#![deny(unsafe_code)]

use thiserror::Error;

/// Errors encountered during threat modeling, STRIDE classification, and ATT&CK mapping.
#[derive(Error, Debug)]
pub enum ThreatError {
    #[error("I/O error during threat model processing: {0}")]
    Io(#[from] std::io::Error),

    #[error("SARIF v2.1.0 log deserialization error: {0}")]
    SarifParse(String),

    #[error("JSON serialization/deserialization failure: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Unknown or malformed MITRE ATT&CK tactic identifier: '{0}'")]
    InvalidTactic(String),

    #[error("Unknown or uncataloged MITRE ATT&CK technique identifier: '{0}'")]
    InvalidTechnique(String),

    #[error("Unsupported MITRE ATT&CK matrix domain: '{0}'")]
    InvalidDomain(String),

    #[error("Unrecognized STRIDE threat category: '{0}'")]
    InvalidStrideCategory(String),

    #[error("ATT&CK Navigator layer generation or export failure: {0}")]
    NavigatorExport(String),

    #[error("Threat scoring or color interpolation error: {0}")]
    Scoring(String),

    #[error("Baseline snapshot comparison error: {0}")]
    Baseline(String),

    #[error("Empty threat report: No findings or components available to evaluate")]
    EmptyReport,
}
