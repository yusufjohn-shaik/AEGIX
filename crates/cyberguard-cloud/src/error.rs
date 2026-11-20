//! Strongly typed error handling for the Cloud Security & IAM Posture Engine.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CloudError {
    #[error("I/O error reading cloud configuration: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse JSON cloud configuration: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Failed to parse YAML cloud configuration: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error(
        "File size limit exceeded: {size} bytes exceeds maximum allowed ({max_allowed} bytes)"
    )]
    FileSizeLimitExceeded { size: usize, max_allowed: usize },

    #[error("Unrecognized or unsupported cloud provider configuration format in '{0}'")]
    UnrecognizedProvider(String),

    #[error("Invalid port or port range specification: '{0}'")]
    InvalidPortRange(String),

    #[error("SARIF export error: {0}")]
    SarifExport(String),
}
