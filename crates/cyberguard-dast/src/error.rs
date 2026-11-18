use std::net::IpAddr;

#[derive(Debug, thiserror::Error)]
pub enum DastError {
    #[error("Scope authorization violation: {0}")]
    ScopeViolation(String),

    #[error("Network/HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Redirect limit exceeded (max {max_hops} hops)")]
    RedirectLimitExceeded { max_hops: usize },

    #[error("SSRF redirect blocked to target IP: {0}")]
    SsrfBlocked(IpAddr),

    #[error("Response body exceeded hard ceiling of {limit_bytes} bytes")]
    BodyTooLarge { limit_bytes: usize },

    #[error("Decompression ratio violated ({ratio}:1) or bomb detected")]
    DecompressionBomb { ratio: usize },

    #[error("Scan phase execution timeout after {duration_ms}ms")]
    Timeout { duration_ms: u64 },

    #[error("Invalid target URL: {0}")]
    InvalidUrl(String),

    #[error("Failed to parse YAML rule: {0}")]
    RuleParse(String),

    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Supervised external process failed: {0}")]
    Subprocess(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
