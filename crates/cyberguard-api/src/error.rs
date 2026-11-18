//! Strongly typed error definitions for the API Security & Spec Fuzzing engine.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("I/O error reading specification: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse YAML specification: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("Failed to parse JSON specification: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Unsupported specification dialect or missing version: {0}")]
    UnsupportedVersion(String),

    #[error("External network $ref URIs are strictly forbidden to prevent SSRF: {0}")]
    ExternalNetworkRefForbidden(String),

    #[error("Local $ref path escapes specification directory: {0}")]
    InvalidRefPath(String),

    #[error("Recursion depth limit exceeded ({0}) while dereferencing schema")]
    RecursionLimitExceeded(usize),

    #[error("Target base URL is required for active API contract fuzzing")]
    TargetUrlRequired,

    #[error("Invalid target URL: {0}")]
    InvalidTargetUrl(String),

    #[error("Scope authorization violation: {0}")]
    ScopeViolation(String),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Process execution error: {0}")]
    Process(#[from] cyberguard_core::error::CyberguardError),

    #[error("DAST transport error: {0}")]
    Dast(#[from] cyberguard_dast::DastError),

    #[error("Invalid specification: {0}")]
    InvalidSpec(String),
}
