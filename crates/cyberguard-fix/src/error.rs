use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FixError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Core engine error: {0}")]
    Cyberguard(#[from] cyberguard_core::CyberguardError),

    #[error("Formatting error: {0}")]
    Fmt(#[from] std::fmt::Error),

    #[error("Unsupported programming language: {0}")]
    UnsupportedLanguage(String),

    #[error("Target path does not exist: {0}")]
    TargetNotFound(PathBuf),

    #[error("Source file exceeds maximum size limit ({size} > {limit} bytes)")]
    FileTooLarge { size: u64, limit: u64 },

    #[error("Syntax parsing failure in {file}:{line} - {details}")]
    ParseFailure {
        file: String,
        line: usize,
        details: String,
    },

    #[error("Patch application conflict at line {line}: {details}")]
    PatchConflict { line: usize, details: String },

    #[error("SARIF finding correlation failed: {0}")]
    FindingNotFound(String),
}
