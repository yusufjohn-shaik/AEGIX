//! CyberGuard Network Reconnaissance & Scope Gate Engine (`cyberguard-net`).
//!
//! Provides cryptographic Proof-of-Authorization scope gating, DNS-rebinding
//! resistant target pinning, asynchronous TCP port scanning, safe banner grabbing,
//! supervised Nmap integration, and OASIS SARIF v2.1.0 telemetry export.

#![deny(unsafe_code)]

pub mod cidr;
pub mod engine;
pub mod error;
pub mod models;
pub mod nmap;
pub mod scanner;
pub mod scope;
pub mod traits;

pub use engine::NetworkEngine;
pub use error::NetError;
pub use models::{
    NetworkAuditReport, PinnedTarget, PortFinding, PortStatus, ScopeViolation, SecurityScope,
};
pub use scanner::{probe_banner, sanitize_banner, TcpScanner, DEFAULT_TOP_PORTS};
pub use scope::{generate_scope_hmac, verify_scope_hmac, ScopeGate};
pub use traits::NetworkScanner;
