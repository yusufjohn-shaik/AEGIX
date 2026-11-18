use crate::error::DastError;
use crate::models::{DastAuditReport, DastTarget};
use async_trait::async_trait;
use cyberguard_net::ScopeGate;

#[async_trait]
pub trait DastScanner: Send + Sync {
    async fn scan(
        &self,
        target: &DastTarget,
        scope: &ScopeGate,
    ) -> Result<DastAuditReport, DastError>;
}
