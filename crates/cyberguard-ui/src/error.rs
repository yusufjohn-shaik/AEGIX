//! Error taxonomy for Aegix UI, dashboard, and executive reporting engine.

#![deny(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UiError {
    #[error("I/O error during report generation: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid SARIF telemetry structure: {0}")]
    InvalidSarif(String),

    #[error("Report generation failure: {0}")]
    ReportGeneration(String),
}
