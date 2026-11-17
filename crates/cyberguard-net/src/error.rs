//! Error types for `cyberguard-net`.

use std::net::IpAddr;
use thiserror::Error;

/// Specific errors encountered during network reconnaissance and scope gating.
#[derive(Debug, Error)]
pub enum NetError {
    #[error("Scope violation: {0}")]
    ScopeViolation(String),

    #[error("Target {target} ({ip}) is blacklisted bogon or metadata address: {reason}")]
    BogonBlacklisted {
        target: String,
        ip: IpAddr,
        reason: String,
    },

    #[error("Scope expired on {expired_at}, current time is {now}")]
    ScopeExpired { expired_at: String, now: String },

    #[error("Scope not yet valid: valid from {valid_from}, current time is {now}")]
    ScopeNotYetValid { valid_from: String, now: String },

    #[error("Cryptographic signature mismatch for scope engagement {engagement_id}")]
    InvalidSignature { engagement_id: String },

    #[error("Signature missing on scope file, but signature verification was enforced")]
    MissingSignature,

    #[error("Failed to parse scope definition: {0}")]
    ScopeParseError(String),

    #[error("Invalid target format: {0}")]
    InvalidTarget(String),

    #[error("DNS resolution failed for {host}: {reason}")]
    DnsResolutionFailed { host: String, reason: String },

    #[error("I/O error during network operation: {0}")]
    Io(#[from] std::io::Error),

    #[error("Operation timed out: {0}")]
    Timeout(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Process supervisor error: {0}")]
    Process(#[from] cyberguard_core::CyberguardError),
}
