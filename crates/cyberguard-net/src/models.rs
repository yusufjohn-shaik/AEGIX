//! Data models for `cyberguard-net`.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Cryptographic and declarative scope definition (`.security-scope.yaml`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityScope {
    /// Unique identifier for the testing engagement or authorization contract.
    pub engagement_id: String,

    /// Earliest timestamp (RFC3339) when this scope is valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,

    /// Expiration timestamp (RFC3339) after which this scope becomes invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,

    /// Whitelisted CIDR subnets and IP addresses authorized for reconnaissance.
    #[serde(default)]
    pub authorized_cidrs: Vec<String>,

    /// Blacklisted or strictly excluded CIDR subnets and IP addresses.
    #[serde(default)]
    pub excluded_cidrs: Vec<String>,

    /// Explicitly authorized domain names and subdomains (e.g., `example.com`, `*.test.com`).
    #[serde(default)]
    pub authorized_domains: Vec<String>,

    /// Explicitly permitted TCP ports. If empty, all safe ports within scanner limits are permitted.
    #[serde(default)]
    pub authorized_ports: Vec<u16>,

    /// Optional cryptographic HMAC-SHA256 signature proving authorization authenticity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Scope-validated and DNS-resolved target pinned to a concrete IP address.
/// Eliminates Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTarget {
    pub hostname: String,
    pub ip: IpAddr,
    pub port: u16,
}

impl PinnedTarget {
    #[must_use]
    pub fn new(hostname: impl Into<String>, ip: IpAddr, port: u16) -> Self {
        Self {
            hostname: hostname.into(),
            ip,
            port,
        }
    }

    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

/// Status of an audited TCP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

impl std::fmt::Display for PortStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Filtered => write!(f, "filtered"),
        }
    }
}

/// Details of a discovered port and service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortFinding {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub status: PortStatus,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    pub protocol: String,
}

/// Security or scope violation detected during target pre-flight checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeViolation {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offending_ip: Option<String>,
    pub reason: String,
    pub severity: String,
}

/// Consolidated network reconnaissance audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAuditReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engagement_id: Option<String>,
    pub target: String,
    pub pinned_ip: String,
    pub scanned_ports: usize,
    pub open_ports: usize,
    pub findings: Vec<PortFinding>,
    pub violations: Vec<ScopeViolation>,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sarif: Option<cyberguard_core::SarifLog>,
}
