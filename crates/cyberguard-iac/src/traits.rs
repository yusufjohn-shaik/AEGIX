use crate::error::IacError;
use crate::models::{
    IacDocument, IacFinding, IacReport, K8sManifest, TerraformLocal, TerraformResource,
    TerraformVariable,
};
use async_trait::async_trait;
use std::io::Read;
use std::path::Path;

/// Primary orchestrator trait for Infrastructure as Code static scanning.
#[async_trait]
pub trait IacScanner: Send + Sync {
    /// Evaluates pre-parsed IaC documents in memory.
    async fn scan(&self, documents: &[IacDocument]) -> Result<IacReport, IacError>;

    /// Reads, parses, and evaluates an IaC file from the local filesystem.
    async fn scan_file(&self, path: &Path) -> Result<IacReport, IacError>;

    /// Ingests and evaluates IaC configuration from a generic reader stream (e.g. STDIN).
    async fn scan_reader(
        &self,
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<IacReport, IacError>;
}

/// Static auditor for Kubernetes workloads and manifests.
pub trait K8sAuditor: Send + Sync {
    /// Audits a single Kubernetes manifest against rules CG-IAC-001 through CG-IAC-006.
    fn audit_manifest(
        &self,
        manifest: &K8sManifest,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<IacFinding>, IacError>;
}

/// Static auditor for Terraform resources, variables, and locals.
pub trait TerraformAuditor: Send + Sync {
    /// Audits extracted Terraform blocks against rules CG-IAC-007 through CG-IAC-010.
    fn audit_terraform(
        &self,
        resources: &[TerraformResource],
        variables: &[TerraformVariable],
        locals: &[TerraformLocal],
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<IacFinding>, IacError>;
}
