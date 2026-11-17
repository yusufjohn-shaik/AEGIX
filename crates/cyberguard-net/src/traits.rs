//! Asynchronous Network Scanner trait.

use crate::error::NetError;
use crate::models::{NetworkAuditReport, PinnedTarget};
use async_trait::async_trait;

#[async_trait]
pub trait NetworkScanner: Send + Sync {
    /// Validates a target host and returns a DNS-pinned target address.
    async fn validate_scope(&self, target: &str, port: u16) -> Result<PinnedTarget, NetError>;

    /// Scans a pinned target against a set of ports.
    async fn scan(&self, target: &str, ports: &[u16]) -> Result<NetworkAuditReport, NetError>;
}
