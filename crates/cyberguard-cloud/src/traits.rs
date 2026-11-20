//! Auditor and scanner trait contracts for Cloud Security & IAM Posture Engine.

use crate::error::CloudError;
use crate::models::{CloudAuditReport, CloudConfig, CloudFinding, CloudResource, IamPolicy};
use async_trait::async_trait;
use std::path::Path;

/// Primary orchestrator trait for multi-cloud scanning.
#[async_trait]
pub trait CloudScanner: Send + Sync {
    /// Executes a security posture audit against pre-parsed canonical cloud IR.
    async fn scan(&self, config: &CloudConfig) -> Result<CloudAuditReport, CloudError>;

    /// Parses and evaluates a static cloud configuration file from disk.
    async fn scan_file(&self, path: &Path) -> Result<CloudAuditReport, CloudError>;
}

/// Posture Auditor trait (CSPM: storage encryption, open ports, public exposure).
pub trait CspmAuditor: Send + Sync {
    /// Audits infrastructure resources against CSPM rules (CG-CLOUD-003, 004, 005, 007, 009).
    fn audit_posture(&self, resources: &[CloudResource]) -> Result<Vec<CloudFinding>, CloudError>;
}

/// Entitlements Auditor trait (CIEM: wildcard admin, privilege escalation, permissive RBAC, root MFA).
pub trait CiemAuditor: Send + Sync {
    /// Audits IAM policies and role assignments against CIEM rules (CG-CLOUD-001, 002, 006, 008, 010).
    fn audit_entitlements(
        &self,
        policies: &[IamPolicy],
        resources: &[CloudResource],
    ) -> Result<Vec<CloudFinding>, CloudError>;
}
