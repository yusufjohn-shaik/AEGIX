use thiserror::Error;

#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("I/O error reading pipeline configuration: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML deserialization error in workflow: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("JSON deserialization error in SLSA attestation: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Base64 decoding error in DSSE envelope: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Pipeline file size limit exceeded: {size} bytes exceeds maximum allowed ceiling of {max_allowed} bytes")]
    FileSizeLimitExceeded { size: usize, max_allowed: usize },

    #[error("Unrecognized or unsupported pipeline format for target: '{0}'")]
    UnrecognizedFormat(String),

    #[error("Invalid cryptographic digest format: {0}")]
    InvalidDigest(String),

    #[error("Artifact verification failed: file '{path}' not found: {reason}")]
    ArtifactNotFound { path: String, reason: String },

    #[error("SARIF v2.1.0 telemetry export error: {0}")]
    SarifExport(String),
}
