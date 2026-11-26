//! Typed error taxonomy for the Aegix Tri-Factor Prioritizer and Reachability Engine.

#![deny(unsafe_code)]

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RiskError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Core engine error: {0}")]
    Cyberguard(#[from] cyberguard_core::CyberguardError),

    #[error("SCA engine error: {0}")]
    Sca(#[from] cyberguard_sca::ScaError),

    #[error("Formatting error: {0}")]
    Fmt(#[from] std::fmt::Error),

    #[error("Invalid target path: {0}")]
    InvalidTarget(PathBuf),

    #[error("Cargo metadata execution failed: {0}")]
    CargoMetadataFailed(String),

    #[error("Malformed SARIF telemetry: {0}")]
    MalformedSarif(String),
}
