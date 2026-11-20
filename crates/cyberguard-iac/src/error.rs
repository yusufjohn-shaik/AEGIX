use thiserror::Error;

/// Strongly typed errors produced during Infrastructure as Code parsing and auditing.
#[derive(Error, Debug)]
pub enum IacError {
    #[error("I/O error reading IaC configuration: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML deserialization error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("JSON deserialization error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Structural HCL syntax error at line {line}, col {col}: {message}")]
    HclParse {
        line: usize,
        col: usize,
        message: String,
    },

    #[error("IaC file size limit exceeded: {size} bytes exceeds maximum allowed ceiling of {max_allowed} bytes")]
    FileSizeLimitExceeded { size: usize, max_allowed: usize },

    #[error("Multi-document stream document count exceeded: {count} exceeds ceiling of {max_allowed} documents")]
    DocumentCountExceeded { count: usize, max_allowed: usize },

    #[error("Unrecognized or unsupported IaC format for target: '{0}'")]
    UnrecognizedFormat(String),

    #[error("SARIF v2.1.0 telemetry export error: {0}")]
    SarifExport(String),
}
