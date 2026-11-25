//! Strongly typed error taxonomy for the Aegix Attack Path Engine.

#![deny(unsafe_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GraphError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Node not found in graph: '{0}'")]
    NodeNotFound(String),

    #[error("Malformed SARIF telemetry: {0}")]
    MalformedSarif(String),

    #[error("Graph topology error: {0}")]
    TopologyError(String),

    #[error("Export formatting error: {0}")]
    ExportError(String),

    #[error("Invalid path or traversal configuration: {0}")]
    InvalidConfig(String),
}
